package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"udpfile/internal/server"
)

func main() {
	if err := run(); err != nil {
		log.Printf("服务器退出：%v", err)
		os.Exit(1)
	}
}

func run() error {
	address := flag.String("addr", "127.0.0.1:9000", "UDP 监听地址")
	root := flag.String("root", ".", "允许客户端读取的根目录")
	maxBytes := flag.Int64("max-bytes", 10<<30, "单次请求允许读取的源文件总字节数")
	maxSessions := flag.Int("max-sessions", 32, "最大并发传输会话数")
	sessionTTL := flag.Duration("session-ttl", 5*time.Minute, "完成传输后服务端保留临时归档的时间")
	tempDir := flag.String("temp-dir", "", "临时归档目录（默认使用系统临时目录）")
	flag.Parse()

	udpAddress, err := net.ResolveUDPAddr("udp", *address)
	if err != nil {
		return fmt.Errorf("解析监听地址：%w", err)
	}
	connection, err := net.ListenUDP("udp", udpAddress)
	if err != nil {
		return fmt.Errorf("监听 UDP：%w", err)
	}
	defer connection.Close()

	logger := log.New(os.Stdout, "udpfile-server: ", log.LstdFlags)
	instance, err := server.New(connection, server.Config{
		Root:           *root,
		TempDir:        *tempDir,
		MaxSourceBytes: *maxBytes,
		SessionTTL:     *sessionTTL,
		MaxSessions:    *maxSessions,
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
