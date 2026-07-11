//go:build !linux && !darwin

package appconfig

import "sync"

var serverCredentialMutex sync.Mutex

func acquireServerCredentialLock(_ string) (func() error, error) {
	serverCredentialMutex.Lock()
	return func() error {
		serverCredentialMutex.Unlock()
		return nil
	}, nil
}
