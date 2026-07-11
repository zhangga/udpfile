package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"udpfile/internal/appconfig"
)

func runKeygen(arguments []string, output, diagnostics io.Writer) error {
	configurationDirectory, err := appconfig.DefaultConfigDirectory()
	if err != nil {
		return err
	}
	manualDirectory := filepath.Join(configurationDirectory, "manual")
	flags := newFlagSet("keygen", diagnostics)
	keyDirectory := flags.String("keys", filepath.Join(manualDirectory, "keys"), "RSA 密钥输出目录")
	environmentPath := flags.String("env", filepath.Join(manualDirectory, ".env"), "环境配置输出路径")
	rsaBits := flags.Int("rsa-bits", 3072, "RSA 密钥位数（2048 至 4096）")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
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
UDPFILE_SERVER_ADDR=0.0.0.0:30033
UDPFILE_ROOT=.
UDPFILE_WEB_LISTEN=127.0.0.1:8080
UDPFILE_TARGET_IP=127.0.0.1
UDPFILE_TARGET_PORT=30033
UDPFILE_SHARED_SECRET=%s
UDPFILE_RSA_PRIVATE_KEY=%s
UDPFILE_RSA_PUBLIC_KEY=%s
`, material.SharedSecret, filepath.ToSlash(material.PrivateKeyPath), filepath.ToSlash(material.PublicKeyPath))
	configFile, err := os.OpenFile(*environmentPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("创建 %s：%w", *environmentPath, err)
	}
	if _, err := configFile.WriteString(configuration); err != nil {
		_ = configFile.Close()
		_ = os.Remove(*environmentPath)
		return fmt.Errorf("写入 %s：%w", *environmentPath, err)
	}
	if err := configFile.Close(); err != nil {
		_ = os.Remove(*environmentPath)
		return fmt.Errorf("关闭 %s：%w", *environmentPath, err)
	}
	fmt.Fprintf(output, "已生成 %s、%s 和 %s\n", material.PrivateKeyPath, material.PublicKeyPath, *environmentPath)
	fmt.Fprintf(output, "使用此配置启动：UDPFILE_ENV=%q udpfile server\n", *environmentPath)
	return nil
}
