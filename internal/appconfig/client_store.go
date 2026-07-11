package appconfig

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"udpfile/internal/pairing"
)

type ClientCredentialStore struct {
	directory string
}

type clientCredentialState struct {
	Version      int    `json:"version"`
	Server       string `json:"server"`
	PairingToken string `json:"pairing_token"`
}

func NewDefaultClientCredentialStore() (*ClientCredentialStore, error) {
	configurationDirectory, err := DefaultConfigDirectory()
	if err != nil {
		return nil, err
	}
	if err := ensureConfigurationRoot(configurationDirectory); err != nil {
		return nil, err
	}
	directory := filepath.Join(configurationDirectory, "clients")
	if err := ensurePrivateDirectory(directory); err != nil {
		return nil, fmt.Errorf("create client credential directory: %w", err)
	}
	return &ClientCredentialStore{directory: directory}, nil
}

func (store *ClientCredentialStore) Load(serverAddress string) ([]byte, *rsa.PublicKey, bool, error) {
	path, err := store.path(serverAddress)
	if err != nil {
		return nil, nil, false, err
	}
	if err := validateConfigurationFile(path, true); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, false, nil
		}
		return nil, nil, false, err
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, false, err
	}
	var state clientCredentialState
	if err := json.Unmarshal(contents, &state); err != nil {
		return nil, nil, false, fmt.Errorf("parse cached credentials for %s: %w", serverAddress, err)
	}
	if state.Version != 1 || state.Server != serverAddress {
		return nil, nil, false, fmt.Errorf("cached credentials for %s are invalid", serverAddress)
	}
	secret, identity, err := pairing.Decode(state.PairingToken)
	if err != nil {
		return nil, nil, false, fmt.Errorf("parse cached pairing token for %s: %w", serverAddress, err)
	}
	return secret, identity, true, nil
}

func (store *ClientCredentialStore) Save(serverAddress string, sharedSecret []byte, serverIdentity *rsa.PublicKey) error {
	path, err := store.path(serverAddress)
	if err != nil {
		return err
	}
	pairingToken, err := pairing.Encode(sharedSecret, serverIdentity)
	if err != nil {
		return err
	}
	if existingSecret, existingIdentity, found, loadErr := store.Load(serverAddress); loadErr != nil {
		return loadErr
	} else if found {
		if bytes.Equal(existingSecret, sharedSecret) && existingIdentity.N.Cmp(serverIdentity.N) == 0 && existingIdentity.E == serverIdentity.E {
			return nil
		}
		return fmt.Errorf("server identity for %s differs from the cached identity; remove %s only if the server was intentionally re-keyed", serverAddress, path)
	}
	contents, err := json.Marshal(clientCredentialState{Version: 1, Server: serverAddress, PairingToken: pairingToken})
	if err != nil {
		return err
	}
	contents = append(contents, '\n')
	if err := writeExclusiveFile(path, contents, 0o600); err != nil {
		if errors.Is(err, os.ErrExist) {
			return store.Save(serverAddress, sharedSecret, serverIdentity)
		}
		return err
	}
	if err := syncDirectory(store.directory); err != nil {
		return fmt.Errorf("sync cached credentials for %s: %w", serverAddress, err)
	}
	return nil
}

func (store *ClientCredentialStore) path(serverAddress string) (string, error) {
	if store == nil || store.directory == "" {
		return "", errors.New("client credential store is not initialized")
	}
	serverAddress = strings.TrimSpace(serverAddress)
	if serverAddress == "" {
		return "", errors.New("server address is required for cached credentials")
	}
	digest := sha256.Sum256([]byte(serverAddress))
	return filepath.Join(store.directory, hex.EncodeToString(digest[:])+".json"), nil
}
