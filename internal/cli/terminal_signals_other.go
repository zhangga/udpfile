//go:build !linux && !darwin

package cli

import "os"

func pairingPromptSignals() []os.Signal {
	return []os.Signal{os.Interrupt}
}
