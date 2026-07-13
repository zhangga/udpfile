package client

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	archivefile "udpfile/internal/archive"
	transferprogress "udpfile/internal/progress"
	"udpfile/internal/protocol"
	securetransport "udpfile/internal/secure"
)

const (
	DefaultRetryInterval     = 300 * time.Millisecond
	DefaultInactivityTimeout = 10 * time.Minute
	DefaultMaxArchive        = uint64(11 << 30)
	transferWindowSize       = uint32(64)
)

type Config struct {
	ServerAddress     string
	RequestedPath     string
	Destination       string
	RetryInterval     time.Duration
	InactivityTimeout time.Duration
	MaxArchiveSize    uint64
	SharedSecret      []byte
	ServerIdentity    *rsa.PublicKey
	Logger            *log.Logger
	Progress          func(transferprogress.Snapshot)
}

type ArchiveInfo struct {
	Size   uint64
	SHA256 [sha256.Size]byte
}

func Receive(ctx context.Context, config Config) error {
	var err error
	config, err = normalizeConfig(config)
	if err != nil {
		return err
	}
	if config.Destination == "" {
		return errors.New("destination is required")
	}
	if _, err := os.Lstat(config.Destination); err == nil {
		return fmt.Errorf("destination already exists: %s", config.Destination)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect destination: %w", err)
	}

	parent := filepath.Dir(config.Destination)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return fmt.Errorf("create destination parent: %w", err)
	}
	temporary, err := os.CreateTemp(parent, ".udpfile-download-*.tar.gz")
	if err != nil {
		return fmt.Errorf("create temporary download: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)

	if _, err := downloadArchive(ctx, config, temporary); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync downloaded archive: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close downloaded archive: %w", err)
	}
	if err := archivefile.Extract(temporaryPath, config.Destination); err != nil {
		return fmt.Errorf("extract downloaded directory: %w", err)
	}
	if config.Logger != nil {
		config.Logger.Printf("restored directory to %s", config.Destination)
	}
	return nil
}

// DownloadArchive receives and verifies a tar.gz archive through the UDP
// protocol without extracting it. The writer is left open for the caller.
func DownloadArchive(ctx context.Context, config Config, destination io.Writer) (ArchiveInfo, error) {
	var err error
	config, err = normalizeConfig(config)
	if err != nil {
		return ArchiveInfo{}, err
	}
	if destination == nil {
		return ArchiveInfo{}, errors.New("archive destination writer is required")
	}
	return downloadArchive(ctx, config, destination)
}

func normalizeConfig(config Config) (Config, error) {
	if config.ServerAddress == "" || config.RequestedPath == "" {
		return Config{}, errors.New("server address and requested path are required")
	}
	if len(config.SharedSecret) != 32 {
		return Config{}, errors.New("32-byte shared secret is required")
	}
	if config.ServerIdentity == nil || config.ServerIdentity.N.BitLen() < 2048 {
		return Config{}, errors.New("RSA server identity of at least 2048 bits is required")
	}
	if config.RetryInterval <= 0 {
		config.RetryInterval = DefaultRetryInterval
	}
	if config.InactivityTimeout <= 0 {
		config.InactivityTimeout = DefaultInactivityTimeout
	}
	if config.MaxArchiveSize == 0 {
		config.MaxArchiveSize = DefaultMaxArchive
	}
	return config, nil
}

func downloadArchive(ctx context.Context, config Config, destination io.Writer) (ArchiveInfo, error) {
	serverAddress, err := net.ResolveUDPAddr("udp", config.ServerAddress)
	if err != nil {
		return ArchiveInfo{}, fmt.Errorf("resolve server address: %w", err)
	}
	connection, err := net.DialUDP("udp", nil, serverAddress)
	if err != nil {
		return ArchiveInfo{}, fmt.Errorf("connect to server: %w", err)
	}
	defer connection.Close()

	id, err := protocol.NewRequestID()
	if err != nil {
		return ArchiveInfo{}, err
	}
	handshake, clientHello, err := securetransport.NewClientHandshake(id, config.SharedSecret)
	if err != nil {
		return ArchiveInfo{}, err
	}
	activity := newInactivityTimer(config.InactivityTimeout)
	secureSession, err := awaitServerHandshake(ctx, connection, id, clientHello, handshake, config.ServerIdentity, config.RetryInterval, activity)
	if err != nil {
		return ArchiveInfo{}, err
	}
	innerRequest, err := protocol.EncodeRequest(id, config.RequestedPath)
	if err != nil {
		return ArchiveInfo{}, err
	}
	meta, err := awaitMeta(ctx, connection, secureSession, id, innerRequest, config.RetryInterval, activity)
	if err != nil {
		return ArchiveInfo{}, err
	}
	if meta.Size > config.MaxArchiveSize {
		return ArchiveInfo{}, fmt.Errorf("server archive is %d bytes, exceeding client limit of %d bytes", meta.Size, config.MaxArchiveSize)
	}
	if config.Logger != nil {
		config.Logger.Printf("receiving %d bytes in %d chunks", meta.Size, meta.Chunks)
	}
	progressReporter := transferprogress.New(config.Logger, "接收", meta.Size, meta.Chunks)
	progressReporter.Observe(config.Progress)
	progressReporter.Report(0, 0)

	hash := sha256.New()
	writer := io.MultiWriter(destination, hash)
	received, err := receiveChunks(ctx, connection, secureSession, id, meta, config.RetryInterval, activity, writer, progressReporter)
	if err != nil {
		return ArchiveInfo{}, err
	}
	if received != meta.Size {
		return ArchiveInfo{}, fmt.Errorf("received %d bytes, want %d", received, meta.Size)
	}
	if !bytes.Equal(hash.Sum(nil), meta.SHA256[:]) {
		return ArchiveInfo{}, errors.New("downloaded archive checksum does not match server metadata")
	}
	completionCtx, cancelCompletion := context.WithTimeout(ctx, 3*config.RetryInterval)
	completionErr := finishSession(completionCtx, connection, secureSession, id, config.RetryInterval, activity)
	cancelCompletion()
	if completionErr != nil && config.Logger != nil {
		config.Logger.Printf("warning: server will clean this session after its TTL: %v", completionErr)
	}
	return ArchiveInfo{Size: meta.Size, SHA256: meta.SHA256}, nil
}

func awaitServerHandshake(
	ctx context.Context,
	connection *net.UDPConn,
	id protocol.RequestID,
	clientHello []byte,
	handshake *securetransport.ClientHandshake,
	identity *rsa.PublicKey,
	retryInterval time.Duration,
	activity *inactivityTimer,
) (*securetransport.Session, error) {
	for {
		if err := transferError(ctx, activity); err != nil {
			return nil, err
		}
		if _, err := connection.Write(clientHello); err != nil {
			return nil, fmt.Errorf("send secure handshake: %w", err)
		}
		deadline := attemptDeadlineWithInactivity(ctx, retryInterval, activity)
		for {
			packet, packetType, readErr := readPacket(connection, id, deadline)
			if isTimeout(readErr) {
				break
			}
			if readErr != nil {
				return nil, readErr
			}
			if packetType != protocol.TypeServerHello {
				continue
			}
			session, completeErr := handshake.Complete(packet, identity)
			if completeErr == nil {
				activity.reset()
			}
			return session, completeErr
		}
	}
}

func finishSession(ctx context.Context, connection *net.UDPConn, secureSession *securetransport.Session, id protocol.RequestID, retryInterval time.Duration, activity *inactivityTimer) error {
	innerRequest, err := protocol.EncodeDone(id)
	if err != nil {
		return err
	}
	return exchangeWithRetry(ctx, connection, secureSession, id, innerRequest, retryInterval, activity, func(packet []byte, packetType protocol.Type) (bool, error) {
		if packetType != protocol.TypeDone {
			return false, nil
		}
		_, err := protocol.DecodeDone(packet)
		return true, err
	})
}

func awaitMeta(ctx context.Context, connection *net.UDPConn, secureSession *securetransport.Session, id protocol.RequestID, innerRequest []byte, retryInterval time.Duration, activity *inactivityTimer) (protocol.Meta, error) {
	var meta protocol.Meta
	err := exchangeWithRetry(ctx, connection, secureSession, id, innerRequest, retryInterval, activity, func(packet []byte, packetType protocol.Type) (bool, error) {
		if packetType != protocol.TypeMeta {
			return false, nil
		}
		_, decoded, err := protocol.DecodeMeta(packet)
		if err == nil {
			meta = decoded
		}
		return true, err
	})
	return meta, err
}

func receiveChunks(
	ctx context.Context,
	connection *net.UDPConn,
	secureSession *securetransport.Session,
	id protocol.RequestID,
	meta protocol.Meta,
	retryInterval time.Duration,
	activity *inactivityTimer,
	destination io.Writer,
	progressReporter *transferprogress.Reporter,
) (uint64, error) {
	buffered := make(map[uint32][]byte, transferWindowSize)
	var nextWrite, nextRequest uint32
	var received uint64

	fillWindow := func() error {
		windowEnd := uint64(nextWrite) + uint64(transferWindowSize)
		for nextRequest < meta.Chunks && uint64(nextRequest) < windowEnd {
			if err := sendChunkRequest(connection, secureSession, id, nextRequest); err != nil {
				return err
			}
			nextRequest++
		}
		return nil
	}
	if err := fillWindow(); err != nil {
		return 0, err
	}

	for nextWrite < meta.Chunks {
		if err := transferError(ctx, activity); err != nil {
			return 0, err
		}
		deadline := attemptDeadlineWithInactivity(ctx, retryInterval, activity)
		encryptedPacket, outerType, readErr := readPacket(connection, id, deadline)
		if isTimeout(readErr) {
			for index := nextWrite; index < nextRequest; index++ {
				if _, alreadyReceived := buffered[index]; alreadyReceived {
					continue
				}
				if err := sendChunkRequest(connection, secureSession, id, index); err != nil {
					return 0, err
				}
			}
			continue
		}
		if readErr != nil {
			return 0, readErr
		}
		if outerType != protocol.TypeSecure {
			continue
		}
		packet, decryptErr := secureSession.Open(encryptedPacket)
		if decryptErr != nil {
			continue
		}
		packetType, _, headerErr := protocol.Header(packet)
		if headerErr != nil {
			continue
		}
		if packetType == protocol.TypeError {
			_, message, decodeErr := protocol.DecodeError(packet)
			if decodeErr != nil {
				return 0, decodeErr
			}
			return 0, errors.New(message)
		}
		if packetType != protocol.TypeData {
			continue
		}
		_, index, data, decodeErr := protocol.DecodeData(packet)
		if decodeErr != nil {
			return 0, decodeErr
		}
		if index < nextWrite || index >= nextRequest {
			continue
		}
		if _, alreadyReceived := buffered[index]; alreadyReceived {
			continue
		}
		expectedLength := expectedChunkLength(meta, index)
		if uint64(len(data)) != expectedLength {
			return 0, fmt.Errorf("chunk %d has %d bytes, want %d", index, len(data), expectedLength)
		}
		buffered[index] = data
		activity.reset()

		for {
			data, ready := buffered[nextWrite]
			if !ready {
				break
			}
			if _, err := destination.Write(data); err != nil {
				return 0, fmt.Errorf("write downloaded chunk: %w", err)
			}
			delete(buffered, nextWrite)
			received += uint64(len(data))
			nextWrite++
			progressReporter.Report(received, nextWrite)
		}
		if err := fillWindow(); err != nil {
			return 0, err
		}
	}
	return received, nil
}

func sendChunkRequest(connection *net.UDPConn, secureSession *securetransport.Session, id protocol.RequestID, index uint32) error {
	innerRequest, err := protocol.EncodeGet(id, index)
	if err != nil {
		return err
	}
	request, err := secureSession.Seal(innerRequest)
	if err != nil {
		return err
	}
	if _, err := connection.Write(request); err != nil {
		return fmt.Errorf("send UDP chunk request: %w", err)
	}
	return nil
}

func expectedChunkLength(meta protocol.Meta, index uint32) uint64 {
	offset := uint64(index) * uint64(meta.ChunkSize)
	remaining := meta.Size - offset
	if remaining < uint64(meta.ChunkSize) {
		return remaining
	}
	return uint64(meta.ChunkSize)
}

func exchangeWithRetry(
	ctx context.Context,
	connection *net.UDPConn,
	secureSession *securetransport.Session,
	id protocol.RequestID,
	innerRequest []byte,
	retryInterval time.Duration,
	activity *inactivityTimer,
	handle func([]byte, protocol.Type) (bool, error),
) error {
	for {
		if err := transferError(ctx, activity); err != nil {
			return err
		}
		request, err := secureSession.Seal(innerRequest)
		if err != nil {
			return err
		}
		if _, err := connection.Write(request); err != nil {
			return fmt.Errorf("send UDP request: %w", err)
		}
		deadline := attemptDeadlineWithInactivity(ctx, retryInterval, activity)
		for {
			encryptedPacket, outerType, readErr := readPacket(connection, id, deadline)
			if isTimeout(readErr) {
				break
			}
			if readErr != nil {
				return readErr
			}
			if outerType != protocol.TypeSecure {
				continue
			}
			packet, decryptErr := secureSession.Open(encryptedPacket)
			if decryptErr != nil {
				continue
			}
			packetType, _, headerErr := protocol.Header(packet)
			if headerErr != nil {
				continue
			}
			if packetType == protocol.TypeError {
				_, message, decodeErr := protocol.DecodeError(packet)
				if decodeErr != nil {
					return decodeErr
				}
				return errors.New(message)
			}
			done, handleErr := handle(packet, packetType)
			if handleErr != nil {
				return handleErr
			}
			if done {
				activity.reset()
				return nil
			}
		}
	}
}

func readPacket(connection *net.UDPConn, id protocol.RequestID, deadline time.Time) ([]byte, protocol.Type, error) {
	if err := connection.SetReadDeadline(deadline); err != nil {
		return nil, 0, fmt.Errorf("set UDP read deadline: %w", err)
	}
	buffer := make([]byte, protocol.MaxDatagramSize+1)
	for {
		length, err := connection.Read(buffer)
		if err != nil {
			return nil, 0, err
		}
		packet := buffer[:length]
		packetType, packetID, err := protocol.Header(packet)
		if err != nil || packetID != id {
			continue
		}
		return append([]byte(nil), packet...), packetType, nil
	}
}

func attemptDeadline(ctx context.Context, retryInterval time.Duration) time.Time {
	deadline := time.Now().Add(retryInterval)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		return contextDeadline
	}
	return deadline
}

type inactivityTimer struct {
	timeout  time.Duration
	deadline time.Time
}

func newInactivityTimer(timeout time.Duration) *inactivityTimer {
	return &inactivityTimer{timeout: timeout, deadline: time.Now().Add(timeout)}
}

func (timer *inactivityTimer) reset() {
	timer.deadline = time.Now().Add(timer.timeout)
}

func (timer *inactivityTimer) err() error {
	if !time.Now().Before(timer.deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

func attemptDeadlineWithInactivity(ctx context.Context, retryInterval time.Duration, activity *inactivityTimer) time.Time {
	deadline := attemptDeadline(ctx, retryInterval)
	if activity.deadline.Before(deadline) {
		return activity.deadline
	}
	return deadline
}

func transferError(ctx context.Context, activity *inactivityTimer) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := activity.err(); err != nil {
		return fmt.Errorf("transfer stopped after %s without progress: %w", activity.timeout, err)
	}
	return nil
}

func contextError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("transfer stopped: %w", err)
	}
	return nil
}

func isTimeout(err error) bool {
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}
