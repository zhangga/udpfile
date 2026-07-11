package cli

import (
	"bufio"
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"time"

	"udpfile/internal/appconfig"
	"udpfile/internal/client"
	"udpfile/internal/pairing"
)

func runClient(arguments []string, output, diagnostics io.Writer) error {
	if err := appconfig.LoadDefault(); err != nil {
		return fmt.Errorf("加载 .env：%w", err)
	}
	environmentPort, err := appconfig.Int("UDPFILE_TARGET_PORT", 9000)
	if err != nil {
		return err
	}
	defaultServerAddress := net.JoinHostPort(appconfig.String("UDPFILE_TARGET_IP", "127.0.0.1"), strconv.Itoa(environmentPort))
	flags := newFlagSet("client", diagnostics)
	serverAddress := flags.String("server", defaultServerAddress, "UDP 服务器地址")
	requestedPath := flags.String("path", "", "服务器共享根目录下的相对文件夹路径")
	destination := flags.String("out", "", "本地输出目录（必须尚不存在）")
	timeout := flags.Duration("timeout", 10*time.Minute, "整个传输的超时时间")
	retry := flags.Duration("retry", client.DefaultRetryInterval, "未收到数据包时的重试间隔")
	maxArchive := flags.Uint64("max-archive", client.DefaultMaxArchive, "客户端接受的最大压缩归档字节数")
	pairingFile := flags.String("pair-file", "", "从权限为 0600 的文件读取首次配对令牌；- 表示标准输入")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *requestedPath == "" || *destination == "" {
		flags.Usage()
		return errors.New("必须同时提供 -path 和 -out")
	}
	sharedSecret, serverIdentity, credentialStore, shouldCache, err := resolveClientCredentials(
		*serverAddress,
		appconfig.String("UDPFILE_PAIRING_TOKEN", ""),
		*pairingFile,
	)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	logger := log.New(output, "udpfile client: ", log.LstdFlags)
	if err := client.Receive(ctx, client.Config{
		ServerAddress:  *serverAddress,
		RequestedPath:  *requestedPath,
		Destination:    *destination,
		RetryInterval:  *retry,
		MaxArchiveSize: *maxArchive,
		SharedSecret:   sharedSecret,
		ServerIdentity: serverIdentity,
		Logger:         logger,
	}); err != nil {
		return err
	}
	if shouldCache {
		if err := credentialStore.Save(*serverAddress, sharedSecret, serverIdentity); err != nil {
			return fmt.Errorf("保存配对凭据：%w", err)
		}
		logger.Printf("已保存 %s 的配对凭据，后续无需再次输入令牌", *serverAddress)
	}
	return nil
}

func resolveClientCredentials(serverAddress, pairingToken, pairingFile string) ([]byte, *rsa.PublicKey, *appconfig.ClientCredentialStore, bool, error) {
	if os.Getenv("UDPFILE_SHARED_SECRET") != "" || os.Getenv("UDPFILE_RSA_PUBLIC_KEY") != "" {
		sharedSecret, serverIdentity, err := appconfig.LoadClientCredentials()
		return sharedSecret, serverIdentity, nil, false, err
	}
	credentialStore, err := appconfig.NewDefaultClientCredentialStore()
	if err != nil {
		return nil, nil, nil, false, err
	}
	sharedSecret, serverIdentity, found, err := credentialStore.Load(serverAddress)
	if err != nil {
		return nil, nil, nil, false, err
	}
	if pairingToken != "" && pairingFile != "" {
		return nil, nil, nil, false, errors.New("UDPFILE_PAIRING_TOKEN 和 -pair-file 不能同时使用")
	}
	if pairingFile != "" {
		pairingToken, err = readPairingTokenFile(pairingFile)
		if err != nil {
			return nil, nil, nil, false, err
		}
	}
	if found {
		if pairingToken != "" {
			pairedSecret, pairedIdentity, decodeErr := pairing.Decode(pairingToken)
			if decodeErr != nil {
				return nil, nil, nil, false, fmt.Errorf("解析配对令牌：%w", decodeErr)
			}
			if saveErr := credentialStore.Save(serverAddress, pairedSecret, pairedIdentity); saveErr != nil {
				return nil, nil, nil, false, saveErr
			}
		}
		return sharedSecret, serverIdentity, credentialStore, false, nil
	}
	if pairingToken == "" {
		pairingToken, err = promptPairingToken()
		if err != nil {
			return nil, nil, nil, false, err
		}
	}
	sharedSecret, serverIdentity, err = pairing.Decode(pairingToken)
	if err != nil {
		return nil, nil, nil, false, fmt.Errorf("解析配对令牌：%w", err)
	}
	return sharedSecret, serverIdentity, credentialStore, true, nil
}

func readPairingTokenFile(path string) (string, error) {
	var input io.Reader
	if path == "-" {
		input = os.Stdin
	} else {
		info, err := os.Lstat(path)
		if err != nil {
			return "", fmt.Errorf("读取配对令牌文件：%w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return "", errors.New("配对令牌文件必须是普通文件，不能是符号链接")
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			return "", fmt.Errorf("配对令牌文件权限必须为 0600：chmod 600 %s", path)
		}
		file, err := os.Open(path)
		if err != nil {
			return "", fmt.Errorf("打开配对令牌文件：%w", err)
		}
		defer file.Close()
		input = file
	}
	contents, err := io.ReadAll(io.LimitReader(input, 16<<10+1))
	if err != nil {
		return "", fmt.Errorf("读取配对令牌：%w", err)
	}
	if len(contents) > 16<<10 {
		return "", errors.New("配对令牌文件过大")
	}
	token := strings.TrimSpace(string(contents))
	if token == "" {
		return "", errors.New("配对令牌为空")
	}
	return token, nil
}

func promptPairingToken() (string, error) {
	terminal, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", errors.New("首次连接需要配对令牌；请在终端运行，或使用 UDPFILE_PAIRING_TOKEN / -pair-file")
	}
	defer terminal.Close()
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, pairingPromptSignals()...)
	defer signal.Stop(interrupts)
	restoreEcho, err := disableTerminalEcho(terminal)
	if err != nil {
		return "", errors.New("无法安全关闭终端回显；请改用 UDPFILE_PAIRING_TOKEN 或权限为 0600 的 -pair-file")
	}
	restored := false
	restore := func() {
		if !restored {
			_ = restoreEcho()
			restored = true
		}
	}
	defer restore()
	if _, err := fmt.Fprint(terminal, "首次连接，请粘贴服务器配对令牌："); err != nil {
		return "", err
	}
	type readResult struct {
		token string
		err   error
	}
	result := make(chan readResult, 1)
	go func() {
		token, readErr := bufio.NewReader(io.LimitReader(terminal, 16<<10)).ReadString('\n')
		result <- readResult{token: token, err: readErr}
	}()
	var token string
	var readErr error
	select {
	case interruptedBy := <-interrupts:
		restore()
		_, _ = fmt.Fprintln(terminal)
		return "", fmt.Errorf("读取配对令牌被 %s 中断", interruptedBy)
	case read := <-result:
		token = read.token
		readErr = read.err
	}
	_, _ = fmt.Fprintln(terminal)
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return "", fmt.Errorf("读取配对令牌：%w", readErr)
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return "", errors.New("配对令牌为空")
	}
	return token, nil
}
