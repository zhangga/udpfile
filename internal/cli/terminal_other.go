//go:build !linux && !darwin

package cli

import (
	"errors"
	"os"
)

func disableTerminalEcho(_ *os.File) (func() error, error) {
	return nil, errors.New("hidden terminal input is not supported on this platform")
}
