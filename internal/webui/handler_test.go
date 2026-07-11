package webui_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	archivefile "udpfile/internal/archive"
	"udpfile/internal/pairing"
	"udpfile/internal/server"
	"udpfile/internal/webui"
)

var (
	webTestSecret       = bytes.Repeat([]byte{0x73}, 32)
	webTestIdentityOnce sync.Once
	webTestIdentity     *rsa.PrivateKey
	webTestIdentityErr  error
)

func TestHomePageCollectsUDPServerAndDirectory(t *testing.T) {
	handler := newHandler(t)
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, want %d", response.Code, http.StatusOK)
	}
	body := response.Body.String()
	for _, expected := range []string{
		`<form`, `action="/download"`, `method="post"`,
		`name="server"`, `name="port"`, `name="path"`, `name="pair"`, `name="csrf_token"`,
		`UDP 文件接收站`, `下载目录`,
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("GET / body does not contain %q", expected)
		}
	}
	if got := response.Header().Get("Content-Security-Policy"); got == "" {
		t.Error("GET / did not set Content-Security-Policy")
	}
}

func TestDownloadPairsThenUsesCachedCredentials(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "documents")
	mustMkdirAll(t, source)
	mustWriteFile(t, filepath.Join(source, "paired.txt"), []byte("paired through web\n"))
	udpAddress, stopServer := startUDPServer(t, root)
	defer stopServer()
	store := &memoryCredentialStore{}
	handler, err := webui.NewHandler(webui.Config{
		DefaultPort:     udpAddress.Port,
		CredentialStore: store,
		Logger:          log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	pairingToken, err := pairing.Encode(webTestSecret, &webRSAIdentity(t).PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	for attempt := 0; attempt < 2; attempt++ {
		form := url.Values{
			"csrf_token": {readCSRFToken(t, handler)},
			"server":     {"127.0.0.1"},
			"port":       {strconv.Itoa(udpAddress.Port)},
			"path":       {"documents"},
		}
		if attempt == 0 {
			form.Set("pair", pairingToken)
		}
		request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/download", strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("attempt %d status = %d, want %d; body=%s", attempt+1, response.Code, http.StatusOK, response.Body.String())
		}
	}
	if store.saves != 1 {
		t.Fatalf("credential saves = %d, want 1", store.saves)
	}
}

func TestDownloadBridgesBrowserRequestToUDPArchive(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "documents")
	mustMkdirAll(t, filepath.Join(source, "nested"))
	mustWriteFile(t, filepath.Join(source, "hello.txt"), []byte("hello through the bridge\n"))
	mustWriteFile(t, filepath.Join(source, "nested", "data.bin"), []byte{0, 1, 2, 255})
	udpAddress, stopServer := startUDPServer(t, root)
	defer stopServer()

	handler, err := webui.NewHandler(webui.Config{
		DefaultPort:    udpAddress.Port,
		SharedSecret:   webTestSecret,
		ServerIdentity: &webRSAIdentity(t).PublicKey,
		Logger:         log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	token := readCSRFToken(t, handler)
	form := url.Values{
		"csrf_token": {token},
		"server":     {"127.0.0.1"},
		"port":       {strconv.Itoa(udpAddress.Port)},
		"path":       {"documents"},
	}
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/download", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("POST /download status = %d, want %d; body=%s", response.Code, http.StatusOK, response.Body.String())
	}
	if got := response.Header().Get("Content-Type"); got != "application/gzip" {
		t.Fatalf("Content-Type = %q, want application/gzip", got)
	}
	if disposition := response.Header().Get("Content-Disposition"); !strings.Contains(disposition, "documents.tar.gz") {
		t.Fatalf("Content-Disposition = %q, want documents.tar.gz", disposition)
	}

	archivePath := filepath.Join(t.TempDir(), "download.tar.gz")
	mustWriteFile(t, archivePath, response.Body.Bytes())
	destination := filepath.Join(t.TempDir(), "received")
	if err := archivefile.Extract(archivePath, destination); err != nil {
		t.Fatalf("Extract(download) error = %v", err)
	}
	assertFile(t, filepath.Join(destination, "hello.txt"), []byte("hello through the bridge\n"))
	assertFile(t, filepath.Join(destination, "nested", "data.bin"), []byte{0, 1, 2, 255})
}

func TestLocalBridgeRejectsUntrustedHostAndMissingToken(t *testing.T) {
	handler := newHandler(t)

	untrustedRequest := httptest.NewRequest(http.MethodGet, "http://attacker.example/", nil)
	untrustedResponse := httptest.NewRecorder()
	handler.ServeHTTP(untrustedResponse, untrustedRequest)
	if untrustedResponse.Code != http.StatusForbidden {
		t.Fatalf("untrusted Host status = %d, want %d", untrustedResponse.Code, http.StatusForbidden)
	}

	form := url.Values{"server": {"127.0.0.1"}, "port": {"9000"}, "path": {"documents"}}
	missingTokenRequest := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/download", strings.NewReader(form.Encode()))
	missingTokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	missingTokenResponse := httptest.NewRecorder()
	handler.ServeHTTP(missingTokenResponse, missingTokenRequest)
	if missingTokenResponse.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF token status = %d, want %d", missingTokenResponse.Code, http.StatusForbidden)
	}
}

func TestDownloadRejectsHostnameInsteadOfExplicitIP(t *testing.T) {
	handler := newHandler(t)
	form := url.Values{
		"csrf_token": {readCSRFToken(t, handler)},
		"server":     {"files.example.com"},
		"port":       {"9000"},
		"path":       {"documents"},
	}
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/download", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("hostname status = %d, want %d", response.Code, http.StatusBadRequest)
	}
}

func newHandler(t *testing.T) http.Handler {
	t.Helper()
	handler, err := webui.NewHandler(webui.Config{
		DefaultPort:    9000,
		SharedSecret:   webTestSecret,
		ServerIdentity: &webRSAIdentity(t).PublicKey,
		Logger:         log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	return handler
}

func readCSRFToken(t *testing.T, handler http.Handler) string {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	match := regexp.MustCompile(`name="csrf_token" value="([^"]+)"`).FindStringSubmatch(response.Body.String())
	if len(match) != 2 {
		t.Fatal("home page did not contain a CSRF token")
	}
	return match[1]
}

func startUDPServer(t *testing.T, root string) (*net.UDPAddr, func()) {
	t.Helper()
	connection, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	instance, err := server.New(connection, server.Config{
		Root:           root,
		MaxSourceBytes: 1 << 20,
		SessionTTL:     time.Minute,
		MaxSessions:    4,
		SharedSecret:   webTestSecret,
		ServerIdentity: webRSAIdentity(t),
		Logger:         log.New(io.Discard, "", 0),
	})
	if err != nil {
		connection.Close()
		t.Fatalf("server.New() error = %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- instance.Serve(ctx) }()
	return connection.LocalAddr().(*net.UDPAddr), func() {
		cancel()
		connection.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve() error = %v", err)
			}
		case <-time.After(time.Second):
			t.Error("UDP server did not stop")
		}
	}
}

func webRSAIdentity(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	webTestIdentityOnce.Do(func() {
		webTestIdentity, webTestIdentityErr = rsa.GenerateKey(rand.Reader, 2048)
	})
	if webTestIdentityErr != nil {
		t.Fatalf("generate test RSA identity: %v", webTestIdentityErr)
	}
	return webTestIdentity
}

type memoryCredentialStore struct {
	serverAddress string
	sharedSecret  []byte
	identity      *rsa.PublicKey
	saves         int
}

func (store *memoryCredentialStore) Load(serverAddress string) ([]byte, *rsa.PublicKey, bool, error) {
	if store.serverAddress != serverAddress || store.identity == nil {
		return nil, nil, false, nil
	}
	return append([]byte(nil), store.sharedSecret...), store.identity, true, nil
}

func (store *memoryCredentialStore) Save(serverAddress string, sharedSecret []byte, identity *rsa.PublicKey) error {
	store.serverAddress = serverAddress
	store.sharedSecret = append([]byte(nil), sharedSecret...)
	store.identity = identity
	store.saves++
	return nil
}

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q) error = %v", path, err)
	}
}

func mustWriteFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", path, err)
	}
}

func assertFile(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", path, err)
	}
	if string(got) != string(want) {
		t.Fatalf("contents of %q = %v, want %v", path, got, want)
	}
}
