package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"udpfile/internal/appconfig"
	"udpfile/internal/client"
)

func main() {
	if err := run(); err != nil {
		log.Printf("接收失败：%v", err)
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
	defaultServerAddress := net.JoinHostPort(appconfig.String("UDPFILE_TARGET_IP", "127.0.0.1"), strconv.Itoa(environmentPort))
	serverAddress := flag.String("server", defaultServerAddress, "UDP 服务器地址")
	requestedPath := flag.String("path", "", "服务器共享根目录下的相对文件夹路径")
	destination := flag.String("out", "", "本地输出目录（必须尚不存在）")
	timeout := flag.Duration("timeout", 10*time.Minute, "整个传输的超时时间")
	retry := flag.Duration("retry", client.DefaultRetryInterval, "未收到数据包时的重试间隔")
	maxArchive := flag.Uint64("max-archive", client.DefaultMaxArchive, "客户端接受的最大压缩归档字节数")
	flag.Parse()

	if *requestedPath == "" || *destination == "" {
		flag.Usage()
		return fmt.Errorf("必须同时提供 -path 和 -out")
	}
	sharedSecret, serverIdentity, err := appconfig.LoadClientCredentials()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	logger := log.New(os.Stdout, "udpfile-client: ", log.LstdFlags)
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
