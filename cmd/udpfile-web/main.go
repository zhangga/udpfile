package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"udpfile/internal/appconfig"
	"udpfile/internal/webui"
)

func main() {
	if err := run(); err != nil {
		log.Printf("本地 Web 助手退出：%v", err)
		os.Exit(1)
	}
}

func run() error {
	if err := appconfig.LoadDefault(); err != nil {
		return fmt.Errorf("加载 .env：%w", err)
	}
	environmentPort, err := appconfig.Int("UDPFILE_TARGET_PORT", 9000)
	if err != nil {
		return err
	}
	listenAddress := flag.String("listen", appconfig.String("UDPFILE_WEB_LISTEN", "127.0.0.1:8080"), "本地 Web 监听地址（仅允许回环地址）")
	defaultServer := flag.String("server", appconfig.String("UDPFILE_TARGET_IP", ""), "页面中预填的目标 UDP 服务器 IP")
	defaultPort := flag.Int("port", environmentPort, "页面中预填的目标 UDP 端口")
	transferTimeout := flag.Duration("timeout", 10*time.Minute, "单次 UDP 下载的超时时间")
	retryInterval := flag.Duration("retry", webui.DefaultRetryInterval, "UDP 数据包重试间隔")
	maxArchive := flag.Uint64("max-archive", webui.DefaultMaxArchive, "允许下载的最大压缩包字节数")
	maxDownloads := flag.Int("max-downloads", 2, "最大并发浏览器下载数")
	tempDir := flag.String("temp-dir", "", "临时下载目录（默认使用系统临时目录）")
	flag.Parse()
	sharedSecret, serverIdentity, err := appconfig.LoadClientCredentials()
	if err != nil {
		return err
	}

	resolvedListenAddress, err := resolveLoopbackListenAddress(*listenAddress)
	if err != nil {
		return err
	}
	logger := log.New(os.Stdout, "udpfile-web: ", log.LstdFlags)
	handler, err := webui.NewHandler(webui.Config{
		DefaultServer:   *defaultServer,
		DefaultPort:     *defaultPort,
		TempDir:         *tempDir,
		TransferTimeout: *transferTimeout,
		RetryInterval:   *retryInterval,
		MaxArchiveSize:  *maxArchive,
		MaxConcurrent:   *maxDownloads,
		SharedSecret:    sharedSecret,
		ServerIdentity:  serverIdentity,
		Logger:          logger,
	})
	if err != nil {
		return err
	}
	listener, err := net.ListenTCP("tcp", resolvedListenAddress)
	if err != nil {
		return fmt.Errorf("启动本地 Web 监听：%w", err)
	}
	defer listener.Close()

	webServer := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       time.Minute,
		MaxHeaderBytes:    16 << 10,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := webServer.Shutdown(shutdownCtx); err != nil {
			logger.Printf("停止本地 Web 服务：%v", err)
		}
	}()

	logger.Printf("浏览器打开 http://%s（跨电脑通信仅使用 UDP）", *listenAddress)
	serveErr := webServer.Serve(listener)
	stop()
	<-shutdownDone
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return fmt.Errorf("运行本地 Web 服务：%w", serveErr)
	}
	return nil
}

func resolveLoopbackListenAddress(address string) (*net.TCPAddr, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("无效的本地 Web 监听地址：%w", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("本地 Web 监听端口必须在 1 到 65535 之间")
	}
	resolved, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(host, portText))
	if err != nil {
		return nil, fmt.Errorf("解析本地 Web 监听地址：%w", err)
	}
	if resolved.IP == nil || !resolved.IP.IsLoopback() {
		return nil, errors.New("本地 Web 助手只能监听解析到回环 IP 的地址")
	}
	return resolved, nil
}
