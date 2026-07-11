//go:build linux || darwin

package cli

import (
	"os"
	"syscall"
)

func pairingPromptSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGTSTP}
}
