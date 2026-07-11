package appconfig

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"udpfile/internal/pairing"
)

const automaticRSABits = 2048

type DefaultServerCredentials struct {
	SharedSecret []byte
	Identity     *rsa.PrivateKey
	PairingToken string
	Directory    string
	Created      bool
}

type serverCredentialState struct {
	Version      int    `json:"version"`
	SharedSecret string `json:"shared_secret"`
}

func DefaultConfigDirectory() (string, error) {
	if configured := os.Getenv("UDPFILE_CONFIG_DIR"); configured != "" {
		absolute, err := filepath.Abs(configured)
		if err != nil {
			return "", fmt.Errorf("resolve UDPFILE_CONFIG_DIR: %w", err)
		}
		return absolute, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("find user configuration directory: %w", err)
	}
	return filepath.Join(base, "udpfile"), nil
}

func LoadOrCreateDefaultServerCredentials() (DefaultServerCredentials, error) {
	configurationDirectory, err := DefaultConfigDirectory()
	if err != nil {
		return DefaultServerCredentials{}, err
	}
	if err := ensureConfigurationRoot(configurationDirectory); err != nil {
		return DefaultServerCredentials{}, err
	}
	releaseLock, err := acquireServerCredentialLock(filepath.Join(configurationDirectory, ".server.lock"))
	if err != nil {
		return DefaultServerCredentials{}, err
	}
	defer releaseLock()

	serverDirectory := filepath.Join(configurationDirectory, "server")
	statePath := filepath.Join(serverDirectory, "credentials.json")
	if info, statErr := os.Lstat(serverDirectory); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return DefaultServerCredentials{}, fmt.Errorf("automatic server credential path must be a directory, not a symlink: %s", serverDirectory)
		}
		if err := os.Chmod(serverDirectory, 0o700); err != nil {
			return DefaultServerCredentials{}, fmt.Errorf("secure automatic server credential directory: %w", err)
		}
		if _, stateErr := os.Lstat(statePath); stateErr == nil {
			credentials, loadErr := loadDefaultServerCredentials(serverDirectory, statePath)
			if loadErr != nil {
				return DefaultServerCredentials{}, loadErr
			}
			return credentials, nil
		} else if errors.Is(stateErr, os.ErrNotExist) {
			if err := os.RemoveAll(serverDirectory); err != nil {
				return DefaultServerCredentials{}, fmt.Errorf("remove interrupted server credential creation: %w", err)
			}
			if err := syncDirectory(configurationDirectory); err != nil {
				return DefaultServerCredentials{}, fmt.Errorf("sync interrupted credential cleanup: %w", err)
			}
		} else {
			return DefaultServerCredentials{}, stateErr
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return DefaultServerCredentials{}, statErr
	}

	stagingDirectory, err := os.MkdirTemp(configurationDirectory, ".server-staging-")
	if err != nil {
		return DefaultServerCredentials{}, fmt.Errorf("create server credential staging directory: %w", err)
	}
	defer os.RemoveAll(stagingDirectory)
	if err := os.Chmod(stagingDirectory, 0o700); err != nil {
		return DefaultServerCredentials{}, fmt.Errorf("secure server credential staging directory: %w", err)
	}
	material, err := GenerateKeyMaterial(filepath.Join(stagingDirectory, "keys"), automaticRSABits)
	if err != nil {
		return DefaultServerCredentials{}, err
	}
	stateBytes, err := json.Marshal(serverCredentialState{Version: 1, SharedSecret: material.SharedSecret})
	if err != nil {
		return DefaultServerCredentials{}, err
	}
	stateBytes = append(stateBytes, '\n')
	if err := writeExclusiveFile(filepath.Join(stagingDirectory, "credentials.json"), stateBytes, 0o600); err != nil {
		return DefaultServerCredentials{}, err
	}
	if err := syncDirectory(stagingDirectory); err != nil {
		return DefaultServerCredentials{}, fmt.Errorf("sync server credential staging directory: %w", err)
	}
	if err := os.Rename(stagingDirectory, serverDirectory); err != nil {
		if credentials, loadErr := loadDefaultServerCredentials(serverDirectory, statePath); loadErr == nil {
			return credentials, nil
		}
		return DefaultServerCredentials{}, fmt.Errorf("publish automatic server credentials: %w", err)
	}
	if err := syncDirectory(configurationDirectory); err != nil {
		return DefaultServerCredentials{}, fmt.Errorf("sync published server credentials: %w", err)
	}
	credentials, err := loadDefaultServerCredentials(serverDirectory, statePath)
	if err != nil {
		return DefaultServerCredentials{}, err
	}
	credentials.Created = true
	return credentials, nil
}

func ensureConfigurationRoot(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create udpfile configuration directory: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("udpfile configuration path must be a directory, not a symlink: %s", path)
	}
	return nil
}

func ensurePrivateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("credential path must be a directory, not a symlink: %s", path)
	}
	return os.Chmod(path, 0o700)
}

func loadDefaultServerCredentials(directory, statePath string) (DefaultServerCredentials, error) {
	if err := validateConfigurationFile(statePath, true); err != nil {
		return DefaultServerCredentials{}, err
	}
	contents, err := os.ReadFile(statePath)
	if err != nil {
		return DefaultServerCredentials{}, err
	}
	var state serverCredentialState
	if err := json.Unmarshal(contents, &state); err != nil {
		return DefaultServerCredentials{}, fmt.Errorf("parse automatic server credentials: %w", err)
	}
	if state.Version != 1 {
		return DefaultServerCredentials{}, fmt.Errorf("unsupported automatic server credential version %d", state.Version)
	}
	sharedSecret, err := DecodeSharedSecret(state.SharedSecret)
	if err != nil {
		return DefaultServerCredentials{}, fmt.Errorf("load automatic shared secret: %w", err)
	}
	privateKey, err := LoadRSAPrivateKey(filepath.Join(directory, "keys", PrivateKeyFilename))
	if err != nil {
		return DefaultServerCredentials{}, err
	}
	publicKey, err := LoadRSAPublicKey(filepath.Join(directory, "keys", PublicKeyFilename))
	if err != nil {
		return DefaultServerCredentials{}, err
	}
	if privateKey.PublicKey.N.Cmp(publicKey.N) != 0 || privateKey.PublicKey.E != publicKey.E {
		return DefaultServerCredentials{}, errors.New("automatic server public key does not match private key")
	}
	pairingToken, err := pairing.Encode(sharedSecret, publicKey)
	if err != nil {
		return DefaultServerCredentials{}, err
	}
	return DefaultServerCredentials{
		SharedSecret: sharedSecret,
		Identity:     privateKey,
		PairingToken: pairingToken,
		Directory:    directory,
	}, nil
}

func writeExclusiveFile(path string, contents []byte, mode os.FileMode) error {
	output, err := os.CreateTemp(filepath.Dir(path), ".udpfile-credential-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary credential file for %s: %w", path, err)
	}
	temporaryPath := output.Name()
	defer os.Remove(temporaryPath)
	if err := output.Chmod(mode); err != nil {
		_ = output.Close()
		return fmt.Errorf("secure temporary credential file for %s: %w", path, err)
	}
	if _, err := output.Write(contents); err != nil {
		_ = output.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := output.Sync(); err != nil {
		_ = output.Close()
		return fmt.Errorf("sync %s: %w", path, err)
	}
	if err := output.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	if err := os.Link(temporaryPath, path); err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
