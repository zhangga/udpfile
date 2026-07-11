package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"udpfile/internal/appconfig"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "密钥生成失败：%v\n", err)
		os.Exit(1)
	}
}

func run() error {
	keyDirectory := flag.String("keys", "keys", "RSA 密钥输出目录")
	environmentPath := flag.String("env", ".env", "环境配置输出路径")
	rsaBits := flag.Int("rsa-bits", 3072, "RSA 密钥位数（2048 至 4096）")
	flag.Parse()

	if _, err := os.Lstat(*environmentPath); err == nil {
		return fmt.Errorf("配置文件已存在，不会覆盖：%s", *environmentPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	material, err := appconfig.GenerateKeyMaterial(*keyDirectory, *rsaBits)
	if err != nil {
		return err
	}
	configuration := fmt.Sprintf(`# udpfile 安全配置；不要提交此文件或 server-private.pem
UDPFILE_SERVER_ADDR=127.0.0.1:9000
UDPFILE_ROOT=./shared
UDPFILE_WEB_LISTEN=127.0.0.1:8080
UDPFILE_TARGET_IP=127.0.0.1
UDPFILE_TARGET_PORT=9000
UDPFILE_SHARED_SECRET=%s
UDPFILE_RSA_PRIVATE_KEY=%s
UDPFILE_RSA_PUBLIC_KEY=%s
`, material.SharedSecret, filepath.ToSlash(material.PrivateKeyPath), filepath.ToSlash(material.PublicKeyPath))
	output, err := os.OpenFile(*environmentPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("创建 %s：%w", *environmentPath, err)
	}
	if _, err := output.WriteString(configuration); err != nil {
		_ = output.Close()
		_ = os.Remove(*environmentPath)
		return fmt.Errorf("写入 %s：%w", *environmentPath, err)
	}
	if err := output.Close(); err != nil {
		_ = os.Remove(*environmentPath)
		return fmt.Errorf("关闭 %s：%w", *environmentPath, err)
	}
	fmt.Printf("已生成 %s、%s 和 %s\n", material.PrivateKeyPath, material.PublicKeyPath, *environmentPath)
	return nil
}
