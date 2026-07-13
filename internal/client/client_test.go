package client_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	archivefile "udpfile/internal/archive"
	"udpfile/internal/client"
	"udpfile/internal/protocol"
	"udpfile/internal/server"
)

var (
	testSharedSecret = bytes.Repeat([]byte{0x42}, 32)
	testIdentityOnce sync.Once
	testIdentity     *rsa.PrivateKey
	testIdentityErr  error
)

func TestReceiveRestoresDirectoryOverUDP(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "shared")
	mustMkdirAll(t, filepath.Join(source, "nested"))
	mustWriteFile(t, filepath.Join(source, "hello.txt"), []byte("hello over real udp\n"))
	mustWriteFile(t, filepath.Join(source, "nested", "large.bin"), bytesPattern(8_000))
	mustMkdirAll(t, filepath.Join(source, "empty"))

	serverAddress, stopServer := startServer(t, root)
	defer stopServer()

	destination := filepath.Join(t.TempDir(), "received")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := client.Receive(ctx, secureClientConfig(t, client.Config{
		ServerAddress:  serverAddress,
		RequestedPath:  "shared",
		Destination:    destination,
		RetryInterval:  30 * time.Millisecond,
		MaxArchiveSize: 10 << 20,
	}))
	if err != nil {
		t.Fatalf("Receive() error = %v", err)
	}

	assertFile(t, filepath.Join(destination, "hello.txt"), []byte("hello over real udp\n"))
	assertFile(t, filepath.Join(destination, "nested", "large.bin"), bytesPattern(8_000))
	if stat, err := os.Stat(filepath.Join(destination, "empty")); err != nil || !stat.IsDir() {
		t.Fatalf("empty directory was not restored: stat=%v err=%v", stat, err)
	}
}

func TestDownloadArchiveReturnsBrowserReadyTarGzip(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "shared")
	mustMkdirAll(t, source)
	mustWriteFile(t, filepath.Join(source, "browser.txt"), []byte("download me\n"))
	serverAddress, stopServer := startServer(t, root)
	defer stopServer()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var downloaded bytes.Buffer
	info, err := client.DownloadArchive(ctx, secureClientConfig(t, client.Config{
		ServerAddress:  serverAddress,
		RequestedPath:  "shared",
		RetryInterval:  30 * time.Millisecond,
		MaxArchiveSize: 1 << 20,
	}), &downloaded)
	if err != nil {
		t.Fatalf("DownloadArchive() error = %v", err)
	}
	if info.Size != uint64(downloaded.Len()) || info.SHA256 == [32]byte{} {
		t.Fatalf("DownloadArchive() info = %+v for %d downloaded bytes", info, downloaded.Len())
	}

	archivePath := filepath.Join(t.TempDir(), "browser.tar.gz")
	mustWriteFile(t, archivePath, downloaded.Bytes())
	destination := filepath.Join(t.TempDir(), "received")
	if err := archivefile.Extract(archivePath, destination); err != nil {
		t.Fatalf("Extract() error = %v", err)
	}
	assertFile(t, filepath.Join(destination, "browser.txt"), []byte("download me\n"))
}

func TestReceiveReturnsServerPathError(t *testing.T) {
	root := t.TempDir()
	serverAddress, stopServer := startServer(t, root)
	defer stopServer()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := client.Receive(ctx, secureClientConfig(t, client.Config{
		ServerAddress:  serverAddress,
		RequestedPath:  "missing",
		Destination:    filepath.Join(t.TempDir(), "received"),
		RetryInterval:  30 * time.Millisecond,
		MaxArchiveSize: 1 << 20,
	}))
	if err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("Receive() error = %v, want missing-path error", err)
	}
}

func TestReceiveRejectsWrongSharedSecret(t *testing.T) {
	root := t.TempDir()
	serverAddress, stopServer := startServer(t, root)
	defer stopServer()
	config := secureClientConfig(t, client.Config{
		ServerAddress: serverAddress,
		RequestedPath: "shared",
		Destination:   filepath.Join(t.TempDir(), "received"),
		RetryInterval: 20 * time.Millisecond,
	})
	config.SharedSecret = bytes.Repeat([]byte{0xff}, 32)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if err := client.Receive(ctx, config); err == nil {
		t.Fatal("Receive() accepted the wrong shared secret")
	}
}

func TestDownloadArchiveStopsAfterInactivity(t *testing.T) {
	root := t.TempDir()
	serverAddress, stopServer := startServer(t, root)
	defer stopServer()
	config := secureClientConfig(t, client.Config{
		ServerAddress:     serverAddress,
		RequestedPath:     "shared",
		RetryInterval:     10 * time.Millisecond,
		InactivityTimeout: 80 * time.Millisecond,
	})
	config.SharedSecret = bytes.Repeat([]byte{0xff}, 32)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	started := time.Now()
	_, err := client.DownloadArchive(ctx, config, io.Discard)
	elapsed := time.Since(started)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DownloadArchive() error = %v, want inactivity deadline", err)
	}
	if elapsed >= 500*time.Millisecond {
		t.Fatalf("DownloadArchive() stopped after %s, want inactivity timeout before parent deadline", elapsed)
	}
}

func TestDownloadArchiveStopsWhenProgressCeasesAfterHandshake(t *testing.T) {
	root := t.TempDir()
	mustMkdirAll(t, filepath.Join(root, "shared"))
	serverAddress, stopServer := startServer(t, root)
	defer stopServer()
	proxyAddress, stopProxy := startStallingAfterHandshakeProxy(t, serverAddress)
	defer stopProxy()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	started := time.Now()
	_, err := client.DownloadArchive(ctx, secureClientConfig(t, client.Config{
		ServerAddress:     proxyAddress,
		RequestedPath:     "shared",
		RetryInterval:     10 * time.Millisecond,
		InactivityTimeout: 80 * time.Millisecond,
	}), io.Discard)
	elapsed := time.Since(started)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DownloadArchive() error = %v, want inactivity deadline", err)
	}
	if elapsed >= 500*time.Millisecond {
		t.Fatalf("DownloadArchive() stopped after %s, want inactivity timeout after handshake", elapsed)
	}
}

func TestDownloadArchiveContinuesWhileChunksMakeProgress(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "shared")
	mustMkdirAll(t, source)
	mustWriteFile(t, filepath.Join(source, "slow.bin"), bytesPattern(6_000))
	serverAddress, stopServer := startServer(t, root)
	defer stopServer()
	proxyAddress, stopProxy := startDelayingResponsesProxy(t, serverAddress, 20*time.Millisecond)
	defer stopProxy()

	const inactivityTimeout = 70 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	started := time.Now()
	_, err := client.DownloadArchive(ctx, secureClientConfig(t, client.Config{
		ServerAddress:     proxyAddress,
		RequestedPath:     "shared",
		RetryInterval:     50 * time.Millisecond,
		InactivityTimeout: inactivityTimeout,
		MaxArchiveSize:    1 << 20,
	}), io.Discard)
	elapsed := time.Since(started)

	if err != nil {
		t.Fatalf("DownloadArchive() error = %v", err)
	}
	if elapsed <= inactivityTimeout {
		t.Fatalf("DownloadArchive() completed in %s; test did not exceed inactivity timeout %s", elapsed, inactivityTimeout)
	}
}

func TestServerDoesNotAnswerPlaintextDirectoryRequest(t *testing.T) {
	root := t.TempDir()
	serverAddress, stopServer := startServer(t, root)
	defer stopServer()
	address, err := net.ResolveUDPAddr("udp", serverAddress)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := net.DialUDP("udp", nil, address)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	id, err := protocol.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := protocol.EncodeRequest(id, "shared")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := connection.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, protocol.MaxDatagramSize)
	if _, err := connection.Read(buffer); err == nil {
		t.Fatal("server responded to an unencrypted directory request")
	} else if networkError, ok := err.(net.Error); !ok || !networkError.Timeout() {
		t.Fatalf("plaintext request read error = %v, want timeout", err)
	}
}

func TestReceiveRetriesDroppedRequestAndDataPackets(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "shared")
	mustMkdirAll(t, source)
	want := bytesPattern(5_000)
	mustWriteFile(t, filepath.Join(source, "random.bin"), want)

	serverAddress, stopServer := startServer(t, root)
	defer stopServer()
	proxyAddress, stopProxy := startDroppingProxy(t, serverAddress)
	defer stopProxy()

	destination := filepath.Join(t.TempDir(), "received")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := client.Receive(ctx, secureClientConfig(t, client.Config{
		ServerAddress:  proxyAddress,
		RequestedPath:  "shared",
		Destination:    destination,
		RetryInterval:  30 * time.Millisecond,
		MaxArchiveSize: 10 << 20,
	}))
	if err != nil {
		t.Fatalf("Receive() with dropped packets error = %v", err)
	}
	assertFile(t, filepath.Join(destination, "random.bin"), want)
}

func TestCompletedTransferImmediatelyReleasesServerSession(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "shared")
	mustMkdirAll(t, source)
	mustWriteFile(t, filepath.Join(source, "hello.txt"), []byte("hello"))

	serverAddress, stopServer := startServerWithMaxSessions(t, root, 1)
	defer stopServer()
	for transfer := 0; transfer < 2; transfer++ {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err := client.Receive(ctx, secureClientConfig(t, client.Config{
			ServerAddress:  serverAddress,
			RequestedPath:  "shared",
			Destination:    filepath.Join(t.TempDir(), "received"),
			RetryInterval:  30 * time.Millisecond,
			MaxArchiveSize: 1 << 20,
		}))
		cancel()
		if err != nil {
			t.Fatalf("Receive() transfer %d error = %v", transfer+1, err)
		}
	}
}

func startServer(t *testing.T, root string) (string, func()) {
	t.Helper()
	return startServerWithMaxSessions(t, root, 8)
}

func startServerWithMaxSessions(t *testing.T, root string, maxSessions int) (string, func()) {
	t.Helper()
	connection, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	instance, err := server.New(connection, server.Config{
		Root:           root,
		MaxSourceBytes: 10 << 20,
		SessionTTL:     time.Minute,
		MaxSessions:    maxSessions,
		SharedSecret:   testSharedSecret,
		ServerIdentity: testRSAIdentity(t),
		Logger:         log.New(io.Discard, "", 0),
	})
	if err != nil {
		connection.Close()
		t.Fatalf("server.New() error = %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- instance.Serve(ctx) }()
	return connection.LocalAddr().String(), func() {
		cancel()
		connection.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve() error = %v", err)
			}
		case <-time.After(time.Second):
			t.Error("server did not stop")
		}
	}
}

func startDroppingProxy(t *testing.T, backendAddress string) (string, func()) {
	t.Helper()
	backend, err := net.ResolveUDPAddr("udp", backendAddress)
	if err != nil {
		t.Fatalf("ResolveUDPAddr() error = %v", err)
	}
	connection, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP() proxy error = %v", err)
	}
	var clientAddress *net.UDPAddr
	var droppedRequest bool
	var droppedData bool
	var plaintextLeaked bool
	var mu sync.Mutex
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, protocol.MaxDatagramSize+1)
		for {
			length, from, readErr := connection.ReadFromUDP(buffer)
			if readErr != nil {
				return
			}
			packet := append([]byte(nil), buffer[:length]...)
			packetType, _, headerErr := protocol.Header(packet)
			if headerErr != nil {
				continue
			}
			mu.Lock()
			if bytes.Contains(packet, []byte("shared")) {
				plaintextLeaked = true
			}
			mu.Unlock()
			if from.String() == backend.String() {
				mu.Lock()
				shouldDrop := packetType == protocol.TypeSecure && !droppedData
				if shouldDrop {
					droppedData = true
				}
				target := clientAddress
				mu.Unlock()
				if !shouldDrop && target != nil {
					_, _ = connection.WriteToUDP(packet, target)
				}
				continue
			}

			mu.Lock()
			clientAddress = from
			shouldDrop := packetType == protocol.TypeClientHello && !droppedRequest
			if shouldDrop {
				droppedRequest = true
			}
			mu.Unlock()
			if !shouldDrop {
				_, _ = connection.WriteToUDP(packet, backend)
			}
		}
	}()
	return connection.LocalAddr().String(), func() {
		connection.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("UDP proxy did not stop")
		}
		mu.Lock()
		defer mu.Unlock()
		if !droppedRequest || !droppedData {
			t.Errorf("proxy did not exercise both retries: request=%v data=%v", droppedRequest, droppedData)
		}
		if plaintextLeaked {
			t.Error("UDP traffic exposed the requested directory path in plaintext")
		}
	}
}

func startStallingAfterHandshakeProxy(t *testing.T, backendAddress string) (string, func()) {
	return startResponseProxy(t, backendAddress, func(packetType protocol.Type) (bool, time.Duration) {
		return packetType != protocol.TypeSecure, 0
	})
}

func startDelayingResponsesProxy(t *testing.T, backendAddress string, delay time.Duration) (string, func()) {
	return startResponseProxy(t, backendAddress, func(protocol.Type) (bool, time.Duration) {
		return true, delay
	})
}

func startResponseProxy(t *testing.T, backendAddress string, responsePolicy func(protocol.Type) (bool, time.Duration)) (string, func()) {
	t.Helper()
	backend, err := net.ResolveUDPAddr("udp", backendAddress)
	if err != nil {
		t.Fatalf("ResolveUDPAddr() error = %v", err)
	}
	connection, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP() proxy error = %v", err)
	}
	var clientAddress *net.UDPAddr
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, protocol.MaxDatagramSize+1)
		for {
			length, from, readErr := connection.ReadFromUDP(buffer)
			if readErr != nil {
				return
			}
			packet := append([]byte(nil), buffer[:length]...)
			if from.String() == backend.String() {
				packetType, _, headerErr := protocol.Header(packet)
				if headerErr != nil {
					continue
				}
				forward, delay := responsePolicy(packetType)
				if !forward {
					continue
				}
				target := clientAddress
				if target != nil {
					if delay > 0 {
						time.Sleep(delay)
					}
					_, _ = connection.WriteToUDP(packet, target)
				}
				continue
			}
			clientAddress = from
			_, _ = connection.WriteToUDP(packet, backend)
		}
	}()
	return connection.LocalAddr().String(), func() {
		connection.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("response proxy did not stop")
		}
	}
}

func secureClientConfig(t *testing.T, config client.Config) client.Config {
	t.Helper()
	identity := testRSAIdentity(t)
	config.SharedSecret = testSharedSecret
	config.ServerIdentity = &identity.PublicKey
	return config
}

func testRSAIdentity(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	testIdentityOnce.Do(func() {
		testIdentity, testIdentityErr = rsa.GenerateKey(rand.Reader, 2048)
	})
	if testIdentityErr != nil {
		t.Fatalf("generate test RSA identity: %v", testIdentityErr)
	}
	return testIdentity
}

func bytesPattern(size int) []byte {
	result := make([]byte, size)
	state := uint32(0x9e3779b9)
	for i := range result {
		state ^= state << 13
		state ^= state >> 17
		state ^= state << 5
		result[i] = byte(state)
	}
	return result
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
		t.Fatalf("contents of %q differ: got %d bytes, want %d bytes", path, len(got), len(want))
	}
}
