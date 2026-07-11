//go:build linux || darwin

package appconfig

import (
	"fmt"
	"os"
	"syscall"
)

func acquireServerCredentialLock(path string) (func() error, error) {
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("server credential lock must not be a symlink: %s", path)
	} else if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	lockFile, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open server credential lock: %w", err)
	}
	info, err := lockFile.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = lockFile.Close()
		return nil, fmt.Errorf("server credential lock is not a regular file: %s", path)
	}
	if err := lockFile.Chmod(0o600); err != nil {
		_ = lockFile.Close()
		return nil, fmt.Errorf("secure server credential lock: %w", err)
	}
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		_ = lockFile.Close()
		return nil, fmt.Errorf("lock server credentials: %w", err)
	}
	return func() error {
		unlockErr := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
		closeErr := lockFile.Close()
		if unlockErr != nil {
			return unlockErr
		}
		return closeErr
	}, nil
}
