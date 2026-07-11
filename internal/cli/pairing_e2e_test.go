package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"udpfile/internal/pairing"
	"udpfile/internal/server"
)

func TestClientPairsOnceThenUsesCachedCredentials(t *testing.T) {
	configurationDirectory := t.TempDir()
	t.Setenv("UDPFILE_CONFIG_DIR", configurationDirectory)
	t.Setenv("UDPFILE_ENV", filepath.Join(configurationDirectory, "missing.env"))
	t.Setenv("UDPFILE_SHARED_SECRET", "")
	t.Setenv("UDPFILE_RSA_PUBLIC_KEY", "")

	root := t.TempDir()
	sharedDirectory := filepath.Join(root, "shared")
	if err := os.Mkdir(sharedDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	want := []byte("paired udp transfer\n")
	if err := os.WriteFile(filepath.Join(sharedDirectory, "hello.txt"), want, 0o644); err != nil {
		t.Fatal(err)
	}
	secret := bytes.Repeat([]byte{0x6c}, 32)
	identity, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	token, err := pairing.Encode(secret, &identity.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	serverAddress, stopServer := startPairingTestServer(t, root, secret, identity)
	defer stopServer()
	pairingFile := filepath.Join(configurationDirectory, "pairing-token")
	if err := os.WriteFile(pairingFile, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	firstDestination := filepath.Join(t.TempDir(), "first")
	arguments := []string{
		"client", "-server", serverAddress, "-path", "shared", "-out", firstDestination,
		"-pair-file", pairingFile, "-retry", "20ms", "-timeout", "5s",
	}
	if err := Run(arguments, io.Discard, io.Discard); err != nil {
		t.Fatalf("first paired client Run() error = %v", err)
	}
	assertPairingTestFile(t, filepath.Join(firstDestination, "hello.txt"), want)

	secondDestination := filepath.Join(t.TempDir(), "second")
	arguments = []string{
		"client", "-server", serverAddress, "-path", "shared", "-out", secondDestination,
		"-retry", "20ms", "-timeout", "5s",
	}
	if err := Run(arguments, io.Discard, io.Discard); err != nil {
		t.Fatalf("second cached client Run() error = %v", err)
	}
	assertPairingTestFile(t, filepath.Join(secondDestination, "hello.txt"), want)
}

func TestClientRejectsWorldReadablePairingFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file permissions")
	}
	configurationDirectory := t.TempDir()
	t.Setenv("UDPFILE_CONFIG_DIR", configurationDirectory)
	t.Setenv("UDPFILE_ENV", filepath.Join(configurationDirectory, "missing.env"))
	t.Setenv("UDPFILE_SHARED_SECRET", "")
	t.Setenv("UDPFILE_RSA_PUBLIC_KEY", "")
	pairingFile := filepath.Join(configurationDirectory, "pairing-token")
	if err := os.WriteFile(pairingFile, []byte("UDF2-not-a-real-token\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(pairingFile, 0o644); err != nil {
		t.Fatal(err)
	}
	err := Run([]string{
		"client", "-server", "127.0.0.1:9", "-path", ".",
		"-out", filepath.Join(t.TempDir(), "out"), "-pair-file", pairingFile,
	}, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("Run() error = %v, want secure pairing file permission error", err)
	}
}

func startPairingTestServer(t *testing.T, root string, secret []byte, identity *rsa.PrivateKey) (string, func()) {
	t.Helper()
	connection, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	instance, err := server.New(connection, server.Config{
		Root:           root,
		SharedSecret:   secret,
		ServerIdentity: identity,
		Logger:         log.New(io.Discard, "", 0),
	})
	if err != nil {
		connection.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- instance.Serve(ctx) }()
	return connection.LocalAddr().String(), func() {
		cancel()
		select {
		case err := <-done:
			_ = connection.Close()
			if err != nil {
				t.Errorf("Serve() error = %v", err)
			}
		case <-time.After(time.Second):
			_ = connection.Close()
			t.Error("server did not stop")
		}
	}
}

func assertPairingTestFile(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s = %q, want %q", path, got, want)
	}
}
