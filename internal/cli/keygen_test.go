package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKeygenDefaultsKeepSecretsOutsideSharedWorkingDirectory(t *testing.T) {
	configurationDirectory := t.TempDir()
	sharedDirectory := t.TempDir()
	t.Setenv("UDPFILE_CONFIG_DIR", configurationDirectory)
	t.Chdir(sharedDirectory)

	var output bytes.Buffer
	if err := Run([]string{"keygen", "-rsa-bits", "2048"}, &output, &output); err != nil {
		t.Fatalf("Run(keygen) error = %v", err)
	}
	for _, unsafePath := range []string{filepath.Join(sharedDirectory, ".env"), filepath.Join(sharedDirectory, "keys")} {
		if _, err := os.Lstat(unsafePath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("keygen created secret material inside shared directory: %s", unsafePath)
		}
	}

	environmentPath := filepath.Join(configurationDirectory, "manual", ".env")
	contents, err := os.ReadFile(environmentPath)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", environmentPath, err)
	}
	configuration := string(contents)
	if !strings.Contains(configuration, "UDPFILE_ROOT=.\n") {
		t.Fatalf("generated configuration does not preserve current-directory root: %s", configuration)
	}
	privateKeyPath := filepath.Join(configurationDirectory, "manual", "keys", "server-private.pem")
	if !strings.Contains(configuration, "UDPFILE_RSA_PRIVATE_KEY="+filepath.ToSlash(privateKeyPath)) {
		t.Fatalf("generated configuration does not use external private key path: %s", configuration)
	}
	if !strings.Contains(output.String(), "UDPFILE_ENV=") {
		t.Fatalf("keygen output does not explain how to load generated configuration: %s", output.String())
	}
}
