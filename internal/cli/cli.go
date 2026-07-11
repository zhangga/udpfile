package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
)

func Run(arguments []string, stdout, stderr io.Writer) error {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	if len(arguments) == 0 {
		writeRootHelp(stderr)
		return errors.New("必须指定一个子命令")
	}
	if arguments[0] == "help" || arguments[0] == "-help" || arguments[0] == "--help" {
		writeRootHelp(stdout)
		return nil
	}

	var err error
	switch arguments[0] {
	case "server":
		err = runServer(arguments[1:], stdout, stderr)
	case "client":
		err = runClient(arguments[1:], stdout, stderr)
	case "web":
		err = runWeb(arguments[1:], stdout, stderr)
	case "keygen":
		err = runKeygen(arguments[1:], stdout, stderr)
	default:
		writeRootHelp(stderr)
		return fmt.Errorf("未知子命令 %q", arguments[0])
	}
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	return err
}

func writeRootHelp(output io.Writer) {
	fmt.Fprintln(output, `udpfile — 加密 UDP 目录传输

用法:
  udpfile <command> [options]

命令:
  server   启动 UDP 文件服务器
  client   通过命令行下载并解压目录
  web      启动仅限本机访问的 Web 下载助手
  keygen   生成 .env、共享密钥和 RSA 密钥

运行 udpfile <command> -help 查看子命令参数。`)
}

func newFlagSet(name string, diagnostics io.Writer) *flag.FlagSet {
	flags := flag.NewFlagSet("udpfile "+name, flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	return flags
}
