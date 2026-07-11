package appconfig_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"udpfile/internal/appconfig"
	"udpfile/internal/pairing"
)

func TestDefaultServerCredentialsAreCreatedThenReused(t *testing.T) {
	configurationDirectory := t.TempDir()
	t.Setenv("UDPFILE_CONFIG_DIR", configurationDirectory)

	created, err := appconfig.LoadOrCreateDefaultServerCredentials()
	if err != nil {
		t.Fatalf("first LoadOrCreateDefaultServerCredentials() error = %v", err)
	}
	if !created.Created {
		t.Fatal("first LoadOrCreateDefaultServerCredentials() did not report creation")
	}
	if created.Directory != filepath.Join(configurationDirectory, "server") {
		t.Fatalf("Directory = %q", created.Directory)
	}
	pairedSecret, pairedIdentity, err := pairing.Decode(created.PairingToken)
	if err != nil {
		t.Fatalf("Decode(PairingToken) error = %v", err)
	}
	if !bytes.Equal(pairedSecret, created.SharedSecret) {
		t.Fatal("PairingToken contains a different shared secret")
	}
	if pairedIdentity.N.Cmp(created.Identity.N) != 0 || pairedIdentity.E != created.Identity.E {
		t.Fatal("PairingToken contains a different server identity")
	}

	loaded, err := appconfig.LoadOrCreateDefaultServerCredentials()
	if err != nil {
		t.Fatalf("second LoadOrCreateDefaultServerCredentials() error = %v", err)
	}
	if loaded.Created {
		t.Fatal("second LoadOrCreateDefaultServerCredentials() reported creation")
	}
	if loaded.PairingToken != created.PairingToken || !bytes.Equal(loaded.SharedSecret, created.SharedSecret) {
		t.Fatal("second LoadOrCreateDefaultServerCredentials() returned different credentials")
	}
	if loaded.Identity.N.Cmp(created.Identity.N) != 0 || loaded.Identity.E != created.Identity.E {
		t.Fatal("second LoadOrCreateDefaultServerCredentials() returned a different identity")
	}

	if runtime.GOOS != "windows" {
		assertMode(t, filepath.Join(configurationDirectory, "server", "credentials.json"), 0o600)
		assertMode(t, filepath.Join(configurationDirectory, "server", "keys", appconfig.PrivateKeyFilename), 0o600)
	}
}

func TestDefaultServerCredentialsAreStableAcrossConcurrentInitialization(t *testing.T) {
	configurationDirectory := t.TempDir()
	t.Setenv("UDPFILE_CONFIG_DIR", configurationDirectory)
	const callers = 2
	results := make([]appconfig.DefaultServerCredentials, callers)
	errors := make([]error, callers)
	start := make(chan struct{})
	var wait sync.WaitGroup
	for index := 0; index < callers; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			results[index], errors[index] = appconfig.LoadOrCreateDefaultServerCredentials()
		}(index)
	}
	close(start)
	wait.Wait()
	created := 0
	for index := range results {
		if errors[index] != nil {
			t.Fatalf("caller %d error = %v", index, errors[index])
		}
		if results[index].Created {
			created++
		}
		if results[index].PairingToken != results[0].PairingToken {
			t.Fatal("concurrent initialization returned different server identities")
		}
	}
	if created != 1 {
		t.Fatalf("created results = %d, want 1", created)
	}
}

func TestClientCredentialStoreCachesCredentialsByServerAddress(t *testing.T) {
	configurationDirectory := t.TempDir()
	t.Setenv("UDPFILE_CONFIG_DIR", configurationDirectory)
	store, err := appconfig.NewDefaultClientCredentialStore()
	if err != nil {
		t.Fatalf("NewDefaultClientCredentialStore() error = %v", err)
	}
	secret := bytes.Repeat([]byte{0x47}, 32)
	identity, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	_, _, found, err := store.Load("192.0.2.10:9000")
	if err != nil || found {
		t.Fatalf("Load() before Save() found=%v err=%v", found, err)
	}
	if err := store.Save("192.0.2.10:9000", secret, &identity.PublicKey); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	loadedSecret, loadedIdentity, found, err := store.Load("192.0.2.10:9000")
	if err != nil || !found {
		t.Fatalf("Load() after Save() found=%v err=%v", found, err)
	}
	if !bytes.Equal(loadedSecret, secret) || loadedIdentity.N.Cmp(identity.N) != 0 || loadedIdentity.E != identity.E {
		t.Fatal("Load() returned different credentials")
	}
	if err := store.Save("192.0.2.10:9000", secret, &identity.PublicKey); err != nil {
		t.Fatalf("Save() same credentials error = %v", err)
	}

	otherIdentity, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save("192.0.2.10:9000", secret, &otherIdentity.PublicKey); err == nil {
		t.Fatal("Save() replaced an already trusted server identity")
	}
	files, err := filepath.Glob(filepath.Join(configurationDirectory, "clients", "*.json"))
	if err != nil || len(files) != 1 {
		t.Fatalf("credential files = %v, err=%v", files, err)
	}
	if runtime.GOOS != "windows" {
		assertMode(t, files[0], 0o600)
	}
}

func TestDefaultServerCredentialsRecoverFromInterruptedCreation(t *testing.T) {
	configurationDirectory := t.TempDir()
	t.Setenv("UDPFILE_CONFIG_DIR", configurationDirectory)
	interruptedDirectory := filepath.Join(configurationDirectory, "server")
	if err := os.MkdirAll(filepath.Join(interruptedDirectory, "keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(interruptedDirectory, "keys", "partial"), []byte("incomplete"), 0o600); err != nil {
		t.Fatal(err)
	}

	credentials, err := appconfig.LoadOrCreateDefaultServerCredentials()
	if err != nil {
		t.Fatalf("LoadOrCreateDefaultServerCredentials() error = %v", err)
	}
	if !credentials.Created {
		t.Fatal("recovered credentials did not report creation")
	}
	if _, _, err := pairing.Decode(credentials.PairingToken); err != nil {
		t.Fatalf("Decode(recovered PairingToken) error = %v", err)
	}
}

func TestDefaultServerCredentialsDoNotRekeyWhenFinalStateLosesAKey(t *testing.T) {
	configurationDirectory := t.TempDir()
	t.Setenv("UDPFILE_CONFIG_DIR", configurationDirectory)
	credentials, err := appconfig.LoadOrCreateDefaultServerCredentials()
	if err != nil {
		t.Fatal(err)
	}
	privateKeyPath := filepath.Join(credentials.Directory, "keys", appconfig.PrivateKeyFilename)
	if err := os.Remove(privateKeyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := appconfig.LoadOrCreateDefaultServerCredentials(); err == nil {
		t.Fatal("LoadOrCreateDefaultServerCredentials() silently replaced a missing final private key")
	}
	if _, err := os.Stat(filepath.Join(credentials.Directory, "credentials.json")); err != nil {
		t.Fatalf("final credential state was removed: %v", err)
	}
}

func TestDefaultConfigRootKeepsExistingPermissionsAndRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission and symlink behavior")
	}
	parent := t.TempDir()
	configurationDirectory := filepath.Join(parent, "configuration")
	if err := os.Mkdir(configurationDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("UDPFILE_CONFIG_DIR", configurationDirectory)
	if _, err := appconfig.NewDefaultClientCredentialStore(); err != nil {
		t.Fatal(err)
	}
	assertMode(t, configurationDirectory, 0o755)

	target := filepath.Join(parent, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(parent, "symlink")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}
	t.Setenv("UDPFILE_CONFIG_DIR", symlink)
	if _, err := appconfig.NewDefaultClientCredentialStore(); err == nil {
		t.Fatal("NewDefaultClientCredentialStore() accepted a symlink configuration root")
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%q) error = %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %o, want %o", path, got, want)
	}
}
