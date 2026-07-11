package cli

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"udpfile/internal/appconfig"
	"udpfile/internal/server"
)

func runServer(arguments []string, output, diagnostics io.Writer) error {
	if err := appconfig.LoadDefault(); err != nil {
		return fmt.Errorf("加载 .env：%w", err)
	}
	flags := newFlagSet("server", diagnostics)
	address := flags.String("addr", appconfig.String("UDPFILE_SERVER_ADDR", "127.0.0.1:9000"), "UDP 监听地址")
	root := flags.String("root", appconfig.String("UDPFILE_ROOT", "."), "允许客户端读取的根目录")
	maxBytes := flags.Int64("max-bytes", 10<<30, "单次请求允许读取的源文件总字节数")
	maxSessions := flags.Int("max-sessions", 32, "最大并发传输会话数")
	sessionTTL := flags.Duration("session-ttl", 5*time.Minute, "会话失效及临时归档清理时间")
	tempDir := flags.String("temp-dir", "", "临时归档目录（默认使用系统临时目录）")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	sharedSecret, serverIdentity, err := appconfig.LoadServerCredentials()
	if err != nil {
		return err
	}
	udpAddress, err := net.ResolveUDPAddr("udp", *address)
	if err != nil {
		return fmt.Errorf("解析监听地址：%w", err)
	}
	connection, err := net.ListenUDP("udp", udpAddress)
	if err != nil {
		return fmt.Errorf("监听 UDP：%w", err)
	}
	defer connection.Close()

	logger := log.New(output, "udpfile server: ", log.LstdFlags)
	instance, err := server.New(connection, server.Config{
		Root:           *root,
		TempDir:        *tempDir,
		MaxSourceBytes: *maxBytes,
		SessionTTL:     *sessionTTL,
		MaxSessions:    *maxSessions,
		SharedSecret:   sharedSecret,
		ServerIdentity: serverIdentity,
		Logger:         logger,
	})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logger.Printf("监听 %s，共享根目录 %s", connection.LocalAddr(), *root)
	return instance.Serve(ctx)
}
