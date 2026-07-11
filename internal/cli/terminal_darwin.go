//go:build darwin

package cli

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

func disableTerminalEcho(terminal *os.File) (func() error, error) {
	var original syscall.Termios
	if err := terminalIOCTL(terminal.Fd(), syscall.TIOCGETA, &original); err != nil {
		return nil, fmt.Errorf("read terminal settings: %w", err)
	}
	updated := original
	updated.Lflag &^= syscall.ECHO
	if err := terminalIOCTL(terminal.Fd(), syscall.TIOCSETA, &updated); err != nil {
		return nil, fmt.Errorf("disable terminal echo: %w", err)
	}
	return func() error {
		return terminalIOCTL(terminal.Fd(), syscall.TIOCSETA, &original)
	}, nil
}

func terminalIOCTL(fileDescriptor uintptr, request uintptr, settings *syscall.Termios) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fileDescriptor, request, uintptr(unsafe.Pointer(settings)))
	if errno != 0 {
		return errno
	}
	return nil
}
