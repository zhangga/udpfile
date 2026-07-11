package client_test

import (
	"context"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"udpfile/internal/client"
	"udpfile/internal/protocol"
	"udpfile/internal/server"
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
	err := client.Receive(ctx, client.Config{
		ServerAddress:  serverAddress,
		RequestedPath:  "shared",
		Destination:    destination,
		RetryInterval:  30 * time.Millisecond,
		MaxArchiveSize: 10 << 20,
	})
	if err != nil {
		t.Fatalf("Receive() error = %v", err)
	}

	assertFile(t, filepath.Join(destination, "hello.txt"), []byte("hello over real udp\n"))
	assertFile(t, filepath.Join(destination, "nested", "large.bin"), bytesPattern(8_000))
	if stat, err := os.Stat(filepath.Join(destination, "empty")); err != nil || !stat.IsDir() {
		t.Fatalf("empty directory was not restored: stat=%v err=%v", stat, err)
	}
}

func TestReceiveReturnsServerPathError(t *testing.T) {
	root := t.TempDir()
	serverAddress, stopServer := startServer(t, root)
	defer stopServer()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := client.Receive(ctx, client.Config{
		ServerAddress:  serverAddress,
		RequestedPath:  "missing",
		Destination:    filepath.Join(t.TempDir(), "received"),
		RetryInterval:  30 * time.Millisecond,
		MaxArchiveSize: 1 << 20,
	})
	if err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("Receive() error = %v, want missing-path error", err)
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
	err := client.Receive(ctx, client.Config{
		ServerAddress:  proxyAddress,
		RequestedPath:  "shared",
		Destination:    destination,
		RetryInterval:  30 * time.Millisecond,
		MaxArchiveSize: 10 << 20,
	})
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
		err := client.Receive(ctx, client.Config{
			ServerAddress:  serverAddress,
			RequestedPath:  "shared",
			Destination:    filepath.Join(t.TempDir(), "received"),
			RetryInterval:  30 * time.Millisecond,
			MaxArchiveSize: 1 << 20,
		})
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
			if from.String() == backend.String() {
				mu.Lock()
				shouldDrop := packetType == protocol.TypeData && !droppedData
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
			shouldDrop := packetType == protocol.TypeRequest && !droppedRequest
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
	}
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
