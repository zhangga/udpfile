package server

import (
	"bytes"
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	archivefile "udpfile/internal/archive"
	transferprogress "udpfile/internal/progress"
	"udpfile/internal/protocol"
	securetransport "udpfile/internal/secure"
)

const (
	defaultMaxSourceBytes = int64(10 << 30)
	defaultSessionTTL     = 5 * time.Minute
	defaultMaxSessions    = 32
	sendWindowSize        = 256
	sendWindowWords       = sendWindowSize / 64
)

type Config struct {
	Root           string
	TempDir        string
	MaxSourceBytes int64
	SessionTTL     time.Duration
	MaxSessions    int
	SharedSecret   []byte
	ServerIdentity *rsa.PrivateKey
	Logger         *log.Logger
}

type Server struct {
	connection *net.UDPConn
	config     Config
	root       string

	mu       sync.Mutex
	sessions map[protocol.RequestID]*session
}

type session struct {
	security        *securetransport.Session
	clientHello     []byte
	serverHello     []byte
	clientAddress   string
	requestedPath   string
	lastAccess      time.Time
	preparing       bool
	file            *os.File
	filePath        string
	meta            protocol.Meta
	progress        *transferprogress.Reporter
	sentBytes       uint64
	sentChunks      uint32
	sentWindowBase  uint32
	sentChunkWindow [sendWindowWords]uint64
}

func New(connection *net.UDPConn, config Config) (*Server, error) {
	if connection == nil {
		return nil, errors.New("UDP connection is required")
	}
	if config.Root == "" {
		return nil, errors.New("shared root is required")
	}
	if len(config.SharedSecret) != 32 {
		return nil, errors.New("32-byte shared secret is required")
	}
	if config.ServerIdentity == nil || config.ServerIdentity.N.BitLen() < 2048 {
		return nil, errors.New("RSA server identity of at least 2048 bits is required")
	}
	root, err := filepath.Abs(config.Root)
	if err != nil {
		return nil, fmt.Errorf("resolve shared root: %w", err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("resolve shared root: %w", err)
	}
	stat, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("stat shared root: %w", err)
	}
	if !stat.IsDir() {
		return nil, errors.New("shared root is not a directory")
	}
	if config.MaxSourceBytes <= 0 {
		config.MaxSourceBytes = defaultMaxSourceBytes
	}
	if config.SessionTTL <= 0 {
		config.SessionTTL = defaultSessionTTL
	}
	if config.MaxSessions <= 0 {
		config.MaxSessions = defaultMaxSessions
	}
	if config.TempDir == "" {
		config.TempDir = os.TempDir()
	}
	if config.Logger == nil {
		config.Logger = log.New(io.Discard, "", 0)
	}
	return &Server{
		connection: connection,
		config:     config,
		root:       root,
		sessions:   make(map[protocol.RequestID]*session),
	}, nil
}

func (server *Server) Serve(ctx context.Context) error {
	defer server.closeSessions()
	buffer := make([]byte, protocol.MaxDatagramSize+1)
	lastCleanup := time.Now()
	for {
		if err := server.connection.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			return fmt.Errorf("set UDP read deadline: %w", err)
		}
		length, clientAddress, err := server.connection.ReadFromUDP(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var networkError net.Error
			if errors.As(err, &networkError) && networkError.Timeout() {
				server.cleanupExpired()
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read UDP packet: %w", err)
		}
		packet := append([]byte(nil), buffer[:length]...)
		packetType, _, err := protocol.Header(packet)
		if err != nil {
			server.config.Logger.Printf("ignored malformed packet from %s: %v", clientAddress, err)
			continue
		}
		switch packetType {
		case protocol.TypeClientHello:
			server.handleClientHello(packet, clientAddress)
		case protocol.TypeSecure:
			server.handleSecure(packet, clientAddress)
		default:
			server.config.Logger.Printf("ignored unexpected packet type %d from %s", packetType, clientAddress)
		}
		if time.Since(lastCleanup) >= time.Second {
			server.cleanupExpired()
			lastCleanup = time.Now()
		}
	}
}

func (server *Server) handleClientHello(packet []byte, clientAddress *net.UDPAddr) {
	_, id, err := protocol.Header(packet)
	if err != nil {
		return
	}
	address := clientAddress.String()
	server.mu.Lock()
	if existing, ok := server.sessions[id]; ok {
		if existing.clientAddress == address && bytes.Equal(existing.clientHello, packet) {
			response := append([]byte(nil), existing.serverHello...)
			server.mu.Unlock()
			server.send(response, clientAddress)
			return
		}
		server.mu.Unlock()
		return
	}
	if len(server.sessions) >= server.config.MaxSessions {
		server.mu.Unlock()
		return
	}
	server.mu.Unlock()

	serverHello, security, err := securetransport.AcceptClientHandshake(packet, server.config.SharedSecret, server.config.ServerIdentity)
	if err != nil {
		return
	}
	now := time.Now()
	current := &session{
		security:      security,
		clientHello:   append([]byte(nil), packet...),
		serverHello:   append([]byte(nil), serverHello...),
		clientAddress: address,
		lastAccess:    now,
	}
	server.mu.Lock()
	if _, exists := server.sessions[id]; exists || len(server.sessions) >= server.config.MaxSessions {
		server.mu.Unlock()
		return
	}
	server.sessions[id] = current
	server.mu.Unlock()
	server.send(serverHello, clientAddress)
}

func (server *Server) handleSecure(packet []byte, clientAddress *net.UDPAddr) {
	_, id, err := protocol.Header(packet)
	if err != nil {
		return
	}
	server.mu.Lock()
	current, ok := server.sessions[id]
	if !ok || current.clientAddress != clientAddress.String() {
		server.mu.Unlock()
		return
	}
	innerPacket, err := current.security.Open(packet)
	if err != nil {
		server.mu.Unlock()
		return
	}
	current.lastAccess = time.Now()
	server.mu.Unlock()
	innerType, _, err := protocol.Header(innerPacket)
	if err != nil {
		return
	}
	switch innerType {
	case protocol.TypeRequest:
		server.handleRequest(innerPacket, clientAddress)
	case protocol.TypeGet:
		server.handleGet(innerPacket, clientAddress)
	case protocol.TypeDone:
		server.handleDone(innerPacket, clientAddress)
	}
}

func (server *Server) handleRequest(packet []byte, clientAddress *net.UDPAddr) {
	id, requestedPath, err := protocol.DecodeRequest(packet)
	if err != nil {
		return
	}

	server.mu.Lock()
	current, ok := server.sessions[id]
	if !ok || current.clientAddress != clientAddress.String() {
		server.mu.Unlock()
		return
	}
	current.lastAccess = time.Now()
	if current.requestedPath != "" {
		if current.requestedPath != requestedPath {
			server.mu.Unlock()
			server.sendError(current, id, clientAddress, "request ID was reused with a different path")
			return
		}
		if !current.preparing && current.file != nil {
			meta := current.meta
			server.mu.Unlock()
			server.sendMeta(current, id, meta, clientAddress)
			return
		}
		server.mu.Unlock()
		return
	}
	current.requestedPath = requestedPath
	current.preparing = true
	server.mu.Unlock()

	server.config.Logger.Printf("preparing %q for %s", requestedPath, clientAddress)
	go server.prepare(id, current, clientAddress)
}

func (server *Server) prepare(id protocol.RequestID, current *session, clientAddress *net.UDPAddr) {
	temporary, err := os.CreateTemp(server.config.TempDir, "udpfile-*.tar.gz")
	if err != nil {
		server.failPreparation(id, current, clientAddress, fmt.Errorf("create temporary archive: %w", err))
		return
	}
	archivePath := temporary.Name()
	if closeErr := temporary.Close(); closeErr != nil {
		_ = os.Remove(archivePath)
		server.failPreparation(id, current, clientAddress, fmt.Errorf("close temporary archive: %w", closeErr))
		return
	}

	archiveInfo, err := archivefile.Create(server.root, current.requestedPath, archivePath, server.config.MaxSourceBytes)
	if err != nil {
		server.failPreparation(id, current, clientAddress, err)
		return
	}
	chunks := uint64(0)
	if archiveInfo.Size > 0 {
		chunks = (uint64(archiveInfo.Size) + protocol.ChunkSize - 1) / protocol.ChunkSize
	}
	if chunks > math.MaxUint32 {
		_ = os.Remove(archivePath)
		server.failPreparation(id, current, clientAddress, errors.New("archive has too many chunks"))
		return
	}
	input, err := os.Open(archivePath)
	if err != nil {
		_ = os.Remove(archivePath)
		server.failPreparation(id, current, clientAddress, fmt.Errorf("open prepared archive: %w", err))
		return
	}
	meta := protocol.Meta{Size: uint64(archiveInfo.Size), Chunks: uint32(chunks), ChunkSize: protocol.ChunkSize}
	meta.SHA256 = archiveInfo.SHA256
	progressReporter := transferprogress.New(server.config.Logger, "发送", meta.Size, meta.Chunks)

	server.mu.Lock()
	if server.sessions[id] != current {
		server.mu.Unlock()
		input.Close()
		os.Remove(archivePath)
		return
	}
	current.preparing = false
	current.file = input
	current.filePath = archivePath
	current.meta = meta
	current.progress = progressReporter
	current.lastAccess = time.Now()
	server.mu.Unlock()

	server.config.Logger.Printf("ready %q: %d bytes in %d chunks", current.requestedPath, meta.Size, meta.Chunks)
	progressReporter.Report(0, 0)
	server.sendMeta(current, id, meta, clientAddress)
}

func (server *Server) failPreparation(id protocol.RequestID, current *session, clientAddress *net.UDPAddr, err error) {
	server.mu.Lock()
	if server.sessions[id] == current {
		delete(server.sessions, id)
	}
	server.mu.Unlock()
	server.config.Logger.Printf("cannot prepare %q: %v", current.requestedPath, err)
	server.sendError(current, id, clientAddress, fmt.Sprintf("cannot send %q: %v", current.requestedPath, err))
}

func (server *Server) handleGet(packet []byte, clientAddress *net.UDPAddr) {
	id, index, err := protocol.DecodeGet(packet)
	if err != nil {
		return
	}
	server.mu.Lock()
	current, ok := server.sessions[id]
	if !ok || current.preparing || index >= current.meta.Chunks || !chunkWithinSendWindow(current, index) {
		server.mu.Unlock()
		return
	}
	current.lastAccess = time.Now()
	offset := int64(index) * int64(current.meta.ChunkSize)
	length := int64(current.meta.ChunkSize)
	if remaining := int64(current.meta.Size) - offset; remaining < length {
		length = remaining
	}
	data := make([]byte, length)
	read, readErr := current.file.ReadAt(data, offset)
	server.mu.Unlock()
	if readErr != nil && !errors.Is(readErr, io.EOF) || read != len(data) {
		server.sendError(current, id, clientAddress, "could not read prepared archive")
		return
	}
	response, err := protocol.EncodeData(id, index, data)
	if err != nil {
		return
	}
	if !server.sendEncrypted(current, response, clientAddress) {
		return
	}
	var (
		reporter   *transferprogress.Reporter
		sentBytes  uint64
		sentChunks uint32
	)
	server.mu.Lock()
	if server.sessions[id] == current && markChunkSent(current, index) {
		current.sentChunks++
		current.sentBytes += uint64(len(data))
		reporter = current.progress
		sentBytes = current.sentBytes
		sentChunks = current.sentChunks
	}
	server.mu.Unlock()
	if reporter != nil {
		reporter.Report(sentBytes, sentChunks)
	}
}

func markChunkSent(current *session, index uint32) bool {
	if index < current.sentWindowBase {
		return false
	}
	distance := index - current.sentWindowBase
	if distance >= sendWindowSize {
		return false
	}
	word := distance / 64
	mask := uint64(1) << (distance % 64)
	if current.sentChunkWindow[word]&mask != 0 {
		return false
	}
	current.sentChunkWindow[word] |= mask
	for current.sentChunkWindow[0]&1 != 0 {
		shiftSentChunkWindow(&current.sentChunkWindow)
		current.sentWindowBase++
	}
	return true
}

func chunkWithinSendWindow(current *session, index uint32) bool {
	return index < current.sentWindowBase || uint64(index)-uint64(current.sentWindowBase) < uint64(sendWindowSize)
}

func shiftSentChunkWindow(window *[sendWindowWords]uint64) {
	for word := 0; word < sendWindowWords; word++ {
		window[word] >>= 1
		if word+1 < sendWindowWords {
			window[word] |= window[word+1] << 63
		}
	}
}

func (server *Server) handleDone(packet []byte, clientAddress *net.UDPAddr) {
	id, err := protocol.DecodeDone(packet)
	if err != nil {
		return
	}
	server.mu.Lock()
	if current, ok := server.sessions[id]; ok && current.clientAddress == clientAddress.String() {
		acknowledgement, encodeErr := protocol.EncodeDone(id)
		if encodeErr == nil {
			server.sendEncrypted(current, acknowledgement, clientAddress)
		}
		server.closeSession(current)
		delete(server.sessions, id)
	}
	server.mu.Unlock()
}

func (server *Server) sendMeta(current *session, id protocol.RequestID, meta protocol.Meta, address *net.UDPAddr) {
	packet, err := protocol.EncodeMeta(id, meta)
	if err == nil {
		server.sendEncrypted(current, packet, address)
	}
}

func (server *Server) sendError(current *session, id protocol.RequestID, address *net.UDPAddr, message string) {
	packet, err := protocol.EncodeError(id, message)
	if err == nil {
		server.sendEncrypted(current, packet, address)
	}
}

func (server *Server) sendEncrypted(current *session, innerPacket []byte, address *net.UDPAddr) bool {
	packet, err := current.security.Seal(innerPacket)
	if err != nil {
		server.config.Logger.Printf("encrypt packet for %s: %v", address, err)
		return false
	}
	return server.send(packet, address)
}

func (server *Server) send(packet []byte, address *net.UDPAddr) bool {
	if _, err := server.connection.WriteToUDP(packet, address); err != nil {
		if !errors.Is(err, net.ErrClosed) {
			server.config.Logger.Printf("send packet to %s: %v", address, err)
		}
		return false
	}
	return true
}

func (server *Server) cleanupExpired() {
	cutoff := time.Now().Add(-server.config.SessionTTL)
	server.mu.Lock()
	defer server.mu.Unlock()
	for id, current := range server.sessions {
		if current.lastAccess.After(cutoff) {
			continue
		}
		server.closeSession(current)
		delete(server.sessions, id)
	}
}

func (server *Server) closeSessions() {
	server.mu.Lock()
	defer server.mu.Unlock()
	for id, current := range server.sessions {
		server.closeSession(current)
		delete(server.sessions, id)
	}
}

func (server *Server) closeSession(current *session) {
	if current.file != nil {
		_ = current.file.Close()
	}
	if current.filePath != "" {
		_ = os.Remove(current.filePath)
	}
}
