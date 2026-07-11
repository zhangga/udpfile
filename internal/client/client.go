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
	DefaultRetryInterval = 300 * time.Millisecond
	DefaultMaxArchive    = uint64(11 << 30)
)

type Config struct {
	ServerAddress  string
	RequestedPath  string
	Destination    string
	RetryInterval  time.Duration
	MaxArchiveSize uint64
	SharedSecret   []byte
	ServerIdentity *rsa.PublicKey
	Logger         *log.Logger
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
	secureSession, err := awaitServerHandshake(ctx, connection, id, clientHello, handshake, config.ServerIdentity, config.RetryInterval)
	if err != nil {
		return ArchiveInfo{}, err
	}
	innerRequest, err := protocol.EncodeRequest(id, config.RequestedPath)
	if err != nil {
		return ArchiveInfo{}, err
	}
	meta, err := awaitMeta(ctx, connection, secureSession, id, innerRequest, config.RetryInterval)
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
	progressReporter.Report(0, 0)

	hash := sha256.New()
	writer := io.MultiWriter(destination, hash)
	var received uint64
	for index := uint32(0); index < meta.Chunks; index++ {
		data, receiveErr := fetchChunk(ctx, connection, secureSession, id, index, config.RetryInterval)
		if receiveErr != nil {
			return ArchiveInfo{}, receiveErr
		}
		expectedLength := uint64(meta.ChunkSize)
		if remaining := meta.Size - received; remaining < expectedLength {
			expectedLength = remaining
		}
		if uint64(len(data)) != expectedLength {
			return ArchiveInfo{}, fmt.Errorf("chunk %d has %d bytes, want %d", index, len(data), expectedLength)
		}
		if _, err := writer.Write(data); err != nil {
			return ArchiveInfo{}, fmt.Errorf("write downloaded chunk: %w", err)
		}
		received += uint64(len(data))
		progressReporter.Report(received, index+1)
	}
	if received != meta.Size {
		return ArchiveInfo{}, fmt.Errorf("received %d bytes, want %d", received, meta.Size)
	}
	if !bytes.Equal(hash.Sum(nil), meta.SHA256[:]) {
		return ArchiveInfo{}, errors.New("downloaded archive checksum does not match server metadata")
	}
	completionCtx, cancelCompletion := context.WithTimeout(ctx, 3*config.RetryInterval)
	completionErr := finishSession(completionCtx, connection, secureSession, id, config.RetryInterval)
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
) (*securetransport.Session, error) {
	for {
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		if _, err := connection.Write(clientHello); err != nil {
			return nil, fmt.Errorf("send secure handshake: %w", err)
		}
		deadline := attemptDeadline(ctx, retryInterval)
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
			return handshake.Complete(packet, identity)
		}
	}
}

func finishSession(ctx context.Context, connection *net.UDPConn, secureSession *securetransport.Session, id protocol.RequestID, retryInterval time.Duration) error {
	innerRequest, err := protocol.EncodeDone(id)
	if err != nil {
		return err
	}
	return exchangeWithRetry(ctx, connection, secureSession, id, innerRequest, retryInterval, func(packet []byte, packetType protocol.Type) (bool, error) {
		if packetType != protocol.TypeDone {
			return false, nil
		}
		_, err := protocol.DecodeDone(packet)
		return true, err
	})
}

func awaitMeta(ctx context.Context, connection *net.UDPConn, secureSession *securetransport.Session, id protocol.RequestID, innerRequest []byte, retryInterval time.Duration) (protocol.Meta, error) {
	var meta protocol.Meta
	err := exchangeWithRetry(ctx, connection, secureSession, id, innerRequest, retryInterval, func(packet []byte, packetType protocol.Type) (bool, error) {
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

func fetchChunk(ctx context.Context, connection *net.UDPConn, secureSession *securetransport.Session, id protocol.RequestID, index uint32, retryInterval time.Duration) ([]byte, error) {
	innerRequest, err := protocol.EncodeGet(id, index)
	if err != nil {
		return nil, err
	}
	var result []byte
	err = exchangeWithRetry(ctx, connection, secureSession, id, innerRequest, retryInterval, func(packet []byte, packetType protocol.Type) (bool, error) {
		if packetType != protocol.TypeData {
			return false, nil
		}
		_, gotIndex, data, err := protocol.DecodeData(packet)
		if err != nil || gotIndex != index {
			return false, nil
		}
		result = append([]byte(nil), data...)
		return true, nil
	})
	return result, err
}

func exchangeWithRetry(
	ctx context.Context,
	connection *net.UDPConn,
	secureSession *securetransport.Session,
	id protocol.RequestID,
	innerRequest []byte,
	retryInterval time.Duration,
	handle func([]byte, protocol.Type) (bool, error),
) error {
	for {
		if err := contextError(ctx); err != nil {
			return err
		}
		request, err := secureSession.Seal(innerRequest)
		if err != nil {
			return err
		}
		if _, err := connection.Write(request); err != nil {
			return fmt.Errorf("send UDP request: %w", err)
		}
		deadline := attemptDeadline(ctx, retryInterval)
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
			if handleErr != nil || done {
				return handleErr
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
