package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"time"

	"udpfile/internal/appconfig"
	"udpfile/internal/client"
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
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *requestedPath == "" || *destination == "" {
		flags.Usage()
		return errors.New("必须同时提供 -path 和 -out")
	}
	sharedSecret, serverIdentity, err := appconfig.LoadClientCredentials()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	logger := log.New(output, "udpfile client: ", log.LstdFlags)
	return client.Receive(ctx, client.Config{
		ServerAddress:  *serverAddress,
		RequestedPath:  *requestedPath,
		Destination:    *destination,
		RetryInterval:  *retry,
		MaxArchiveSize: *maxArchive,
		SharedSecret:   sharedSecret,
		ServerIdentity: serverIdentity,
		Logger:         logger,
	})
}
