package appconfig

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoadFileSetsValuesWithoutOverridingEnvironment(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	contents := "UDPFILE_TEST_ADDR=0.0.0.0:9000\nUDPFILE_TEST_ROOT=\"./shared files\"\nUDPFILE_TEST_KEEP=from-file\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	t.Setenv("UDPFILE_TEST_ADDR", "")
	if err := os.Unsetenv("UDPFILE_TEST_ADDR"); err != nil {
		t.Fatalf("Unsetenv() error = %v", err)
	}
	if err := os.Unsetenv("UDPFILE_TEST_ROOT"); err != nil {
		t.Fatalf("Unsetenv() error = %v", err)
	}
	t.Setenv("UDPFILE_TEST_KEEP", "from-environment")

	if err := LoadFile(path); err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	if got := os.Getenv("UDPFILE_TEST_ADDR"); got != "0.0.0.0:9000" {
		t.Fatalf("UDPFILE_TEST_ADDR = %q", got)
	}
	if got := os.Getenv("UDPFILE_TEST_ROOT"); got != "./shared files" {
		t.Fatalf("UDPFILE_TEST_ROOT = %q", got)
	}
	if got := os.Getenv("UDPFILE_TEST_KEEP"); got != "from-environment" {
		t.Fatalf("UDPFILE_TEST_KEEP = %q, want existing environment value", got)
	}
}

func TestLoadFileRejectsWorldReadableSecrets(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose Unix permission bits")
	}
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte("UDPFILE_SHARED_SECRET=secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := LoadFile(path); err == nil {
		t.Fatal("LoadFile() accepted a group/world-readable secret file")
	}
}

func TestDecodeSharedSecretRequires32RandomBytes(t *testing.T) {
	want := make([]byte, 32)
	for index := range want {
		want[index] = byte(index + 1)
	}
	encoded := base64.RawStdEncoding.EncodeToString(want)
	got, err := DecodeSharedSecret(encoded)
	if err != nil {
		t.Fatalf("DecodeSharedSecret() error = %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("DecodeSharedSecret() = %v, want %v", got, want)
	}
	if _, err := DecodeSharedSecret(base64.RawStdEncoding.EncodeToString([]byte("too short"))); err == nil {
		t.Fatal("DecodeSharedSecret() accepted a short secret")
	}
}
