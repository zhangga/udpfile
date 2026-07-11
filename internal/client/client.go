package client

import (
	"bytes"
	"context"
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
	"udpfile/internal/protocol"
)

const (
	defaultRetryInterval = 300 * time.Millisecond
	defaultMaxArchive    = uint64(11 << 30)
)

type Config struct {
	ServerAddress  string
	RequestedPath  string
	Destination    string
	RetryInterval  time.Duration
	MaxArchiveSize uint64
	Logger         *log.Logger
}

func Receive(ctx context.Context, config Config) error {
	if config.ServerAddress == "" || config.RequestedPath == "" || config.Destination == "" {
		return errors.New("server address, requested path, and destination are required")
	}
	if config.RetryInterval <= 0 {
		config.RetryInterval = defaultRetryInterval
	}
	if config.MaxArchiveSize == 0 {
		config.MaxArchiveSize = defaultMaxArchive
	}
	if _, err := os.Lstat(config.Destination); err == nil {
		return fmt.Errorf("destination already exists: %s", config.Destination)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect destination: %w", err)
	}

	serverAddress, err := net.ResolveUDPAddr("udp", config.ServerAddress)
	if err != nil {
		return fmt.Errorf("resolve server address: %w", err)
	}
	connection, err := net.DialUDP("udp", nil, serverAddress)
	if err != nil {
		return fmt.Errorf("connect to server: %w", err)
	}
	defer connection.Close()

	id, err := protocol.NewRequestID()
	if err != nil {
		return err
	}
	request, err := protocol.EncodeRequest(id, config.RequestedPath)
	if err != nil {
		return err
	}
	meta, err := awaitMeta(ctx, connection, id, request, config.RetryInterval)
	if err != nil {
		return err
	}
	if meta.Size > config.MaxArchiveSize {
		return fmt.Errorf("server archive is %d bytes, exceeding client limit of %d bytes", meta.Size, config.MaxArchiveSize)
	}
	if config.Logger != nil {
		config.Logger.Printf("receiving %d bytes in %d chunks", meta.Size, meta.Chunks)
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

	hash := sha256.New()
	writer := io.MultiWriter(temporary, hash)
	var received uint64
	for index := uint32(0); index < meta.Chunks; index++ {
		data, receiveErr := fetchChunk(ctx, connection, id, index, config.RetryInterval)
		if receiveErr != nil {
			temporary.Close()
			return receiveErr
		}
		expectedLength := uint64(meta.ChunkSize)
		if remaining := meta.Size - received; remaining < expectedLength {
			expectedLength = remaining
		}
		if uint64(len(data)) != expectedLength {
			temporary.Close()
			return fmt.Errorf("chunk %d has %d bytes, want %d", index, len(data), expectedLength)
		}
		if _, err := writer.Write(data); err != nil {
			temporary.Close()
			return fmt.Errorf("write downloaded chunk: %w", err)
		}
		received += uint64(len(data))
	}
	if received != meta.Size {
		temporary.Close()
		return fmt.Errorf("received %d bytes, want %d", received, meta.Size)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync downloaded archive: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close downloaded archive: %w", err)
	}
	if !bytes.Equal(hash.Sum(nil), meta.SHA256[:]) {
		return errors.New("downloaded archive checksum does not match server metadata")
	}
	completionCtx, cancelCompletion := context.WithTimeout(ctx, 3*config.RetryInterval)
	completionErr := finishSession(completionCtx, connection, id, config.RetryInterval)
	cancelCompletion()
	if completionErr != nil && config.Logger != nil {
		config.Logger.Printf("warning: server will clean this session after its TTL: %v", completionErr)
	}
	if err := archivefile.Extract(temporaryPath, config.Destination); err != nil {
		return fmt.Errorf("extract downloaded directory: %w", err)
	}
	if config.Logger != nil {
		config.Logger.Printf("restored directory to %s", config.Destination)
	}
	return nil
}

func finishSession(ctx context.Context, connection *net.UDPConn, id protocol.RequestID, retryInterval time.Duration) error {
	request, err := protocol.EncodeDone(id)
	if err != nil {
		return err
	}
	return exchangeWithRetry(ctx, connection, id, request, retryInterval, func(packet []byte, packetType protocol.Type) (bool, error) {
		if packetType != protocol.TypeDone {
			return false, nil
		}
		_, err := protocol.DecodeDone(packet)
		return true, err
	})
}

func awaitMeta(ctx context.Context, connection *net.UDPConn, id protocol.RequestID, request []byte, retryInterval time.Duration) (protocol.Meta, error) {
	var meta protocol.Meta
	err := exchangeWithRetry(ctx, connection, id, request, retryInterval, func(packet []byte, packetType protocol.Type) (bool, error) {
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

func fetchChunk(ctx context.Context, connection *net.UDPConn, id protocol.RequestID, index uint32, retryInterval time.Duration) ([]byte, error) {
	request, err := protocol.EncodeGet(id, index)
	if err != nil {
		return nil, err
	}
	var result []byte
	err = exchangeWithRetry(ctx, connection, id, request, retryInterval, func(packet []byte, packetType protocol.Type) (bool, error) {
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
	id protocol.RequestID,
	request []byte,
	retryInterval time.Duration,
	handle func([]byte, protocol.Type) (bool, error),
) error {
	for {
		if err := contextError(ctx); err != nil {
			return err
		}
		if _, err := connection.Write(request); err != nil {
			return fmt.Errorf("send UDP request: %w", err)
		}
		deadline := attemptDeadline(ctx, retryInterval)
		for {
			packet, packetType, readErr := readPacket(connection, id, deadline)
			if isTimeout(readErr) {
				break
			}
			if readErr != nil {
				return readErr
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
