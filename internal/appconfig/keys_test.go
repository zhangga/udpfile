package appconfig

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestGenerateAndLoadKeyMaterial(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "keys")
	material, err := GenerateKeyMaterial(directory, 2048)
	if err != nil {
		t.Fatalf("GenerateKeyMaterial() error = %v", err)
	}
	secret, err := DecodeSharedSecret(material.SharedSecret)
	if err != nil || len(secret) != 32 {
		t.Fatalf("generated shared secret invalid: len=%d err=%v", len(secret), err)
	}
	privateKey, err := LoadRSAPrivateKey(material.PrivateKeyPath)
	if err != nil {
		t.Fatalf("LoadRSAPrivateKey() error = %v", err)
	}
	publicKey, err := LoadRSAPublicKey(material.PublicKeyPath)
	if err != nil {
		t.Fatalf("LoadRSAPublicKey() error = %v", err)
	}
	if privateKey.PublicKey.N.Cmp(publicKey.N) != 0 || privateKey.PublicKey.E != publicKey.E {
		t.Fatal("loaded public key does not match private key")
	}
	if mode := fileMode(t, material.PrivateKeyPath); mode != 0o600 {
		t.Fatalf("private key permissions = %o, want 600", mode)
	}
	if mode := fileMode(t, material.PublicKeyPath); mode != 0o644 {
		t.Fatalf("public key permissions = %o, want 644", mode)
	}
	if _, err := GenerateKeyMaterial(directory, 2048); err == nil {
		t.Fatal("GenerateKeyMaterial() overwrote existing key material")
	}
}

func TestLoadRSAPrivateKeyRejectsUnsafePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose Unix permission bits")
	}
	material, err := GenerateKeyMaterial(filepath.Join(t.TempDir(), "keys"), 2048)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(material.PrivateKeyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRSAPrivateKey(material.PrivateKeyPath); err == nil {
		t.Fatal("LoadRSAPrivateKey() accepted a group/world-readable private key")
	}
}

func TestGenerateKeyMaterialRejectsRSAKeyTooLargeForProtocol(t *testing.T) {
	if _, err := GenerateKeyMaterial(filepath.Join(t.TempDir(), "keys"), 8192); err == nil {
		t.Fatal("GenerateKeyMaterial() accepted an RSA signature too large for a UDP handshake")
	}
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%q) error = %v", path, err)
	}
	return info.Mode().Perm()
}
