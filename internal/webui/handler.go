package webui

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"udpfile/internal/client"
	"udpfile/internal/pairing"
	transferprogress "udpfile/internal/progress"
)

//go:embed index.html
var indexHTML string

const (
	DefaultRetryInterval = client.DefaultRetryInterval
	DefaultMaxArchive    = client.DefaultMaxArchive
	progressRetention    = 10 * time.Minute
	maxRetainedTransfers = 128
)

type Config struct {
	DefaultServer     string
	DefaultPort       int
	TempDir           string
	InactivityTimeout time.Duration
	RetryInterval     time.Duration
	MaxArchiveSize    uint64
	MaxConcurrent     int
	SharedSecret      []byte
	ServerIdentity    *rsa.PublicKey
	CredentialStore   CredentialStore
	Logger            *log.Logger
}

type CredentialStore interface {
	Load(serverAddress string) ([]byte, *rsa.PublicKey, bool, error)
	Save(serverAddress string, sharedSecret []byte, serverIdentity *rsa.PublicKey) error
}

type Handler struct {
	page              *template.Template
	csrfToken         string
	defaultServer     string
	defaultPort       int
	tempDir           string
	inactivityTimeout time.Duration
	retryInterval     time.Duration
	maxArchive        uint64
	sharedSecret      []byte
	serverIdentity    *rsa.PublicKey
	credentialStore   CredentialStore
	downloadSlots     chan struct{}
	logger            *log.Logger
	progressMu        sync.Mutex
	transfers         map[string]browserProgress
}

type browserProgress struct {
	Status          string    `json:"status"`
	Percent         int       `json:"percent"`
	CompletedBytes  uint64    `json:"completed_bytes"`
	TotalBytes      uint64    `json:"total_bytes"`
	CompletedChunks uint32    `json:"completed_chunks"`
	TotalChunks     uint32    `json:"total_chunks"`
	UpdatedAt       time.Time `json:"-"`
}

type pageData struct {
	CSRFToken     string
	CSPNonce      string
	DefaultServer string
	DefaultPort   int
}

func NewHandler(config Config) (http.Handler, error) {
	if config.DefaultPort == 0 {
		config.DefaultPort = 30033
	}
	if config.DefaultPort < 1 || config.DefaultPort > 65535 {
		return nil, errors.New("default UDP port must be between 1 and 65535")
	}
	hasFixedCredentials := len(config.SharedSecret) != 0 || config.ServerIdentity != nil
	if hasFixedCredentials {
		if len(config.SharedSecret) != 32 {
			return nil, errors.New("32-byte shared secret is required")
		}
		if config.ServerIdentity == nil || config.ServerIdentity.N.BitLen() < 2048 {
			return nil, errors.New("RSA server identity of at least 2048 bits is required")
		}
	} else if config.CredentialStore == nil {
		return nil, errors.New("fixed credentials or a credential store is required")
	}
	if config.Logger == nil {
		config.Logger = log.New(io.Discard, "", 0)
	}
	if config.TempDir == "" {
		config.TempDir = os.TempDir()
	}
	if stat, err := os.Stat(config.TempDir); err != nil || !stat.IsDir() {
		return nil, fmt.Errorf("temporary download directory is unavailable: %s", config.TempDir)
	}
	if config.InactivityTimeout <= 0 {
		config.InactivityTimeout = client.DefaultInactivityTimeout
	}
	if config.RetryInterval <= 0 {
		config.RetryInterval = DefaultRetryInterval
	}
	if config.MaxArchiveSize == 0 {
		config.MaxArchiveSize = DefaultMaxArchive
	}
	if config.MaxConcurrent <= 0 {
		config.MaxConcurrent = 2
	}
	csrfToken, err := randomToken(32)
	if err != nil {
		return nil, err
	}
	page, err := template.New("index").Parse(indexHTML)
	if err != nil {
		return nil, err
	}
	return &Handler{
		page:              page,
		csrfToken:         csrfToken,
		defaultServer:     config.DefaultServer,
		defaultPort:       config.DefaultPort,
		tempDir:           config.TempDir,
		inactivityTimeout: config.InactivityTimeout,
		retryInterval:     config.RetryInterval,
		maxArchive:        config.MaxArchiveSize,
		sharedSecret:      append([]byte(nil), config.SharedSecret...),
		serverIdentity:    config.ServerIdentity,
		credentialStore:   config.CredentialStore,
		downloadSlots:     make(chan struct{}, config.MaxConcurrent),
		logger:            config.Logger,
		transfers:         make(map[string]browserProgress),
	}, nil
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	nonce := ""
	if request.URL.Path == "/" {
		var err error
		nonce, err = randomToken(18)
		if err != nil {
			http.Error(response, "无法生成页面安全令牌", http.StatusInternalServerError)
			return
		}
	}
	handler.setSecurityHeaders(response, nonce)
	if !requestHostIsLoopback(request.Host) {
		http.Error(response, "仅允许通过 localhost 访问", http.StatusForbidden)
		return
	}
	switch request.URL.Path {
	case "/":
		handler.serveHome(response, request, nonce)
	case "/download":
		handler.serveDownload(response, request)
	case "/progress":
		handler.serveProgress(response, request)
	default:
		http.NotFound(response, request)
	}
}

func (handler *Handler) serveDownload(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		response.Header().Set("Allow", http.MethodPost)
		http.Error(response, "仅支持 POST", http.StatusMethodNotAllowed)
		return
	}
	request.Body = http.MaxBytesReader(response, request.Body, 16<<10)
	if err := request.ParseForm(); err != nil {
		http.Error(response, "请求表单无效", http.StatusBadRequest)
		return
	}
	providedToken := request.FormValue("csrf_token")
	if subtle.ConstantTimeCompare([]byte(providedToken), []byte(handler.csrfToken)) != 1 {
		http.Error(response, "页面令牌已失效，请刷新后重试", http.StatusForbidden)
		return
	}
	taskID := strings.TrimSpace(request.FormValue("task_id"))
	if taskID != "" && !validTaskID(taskID) {
		http.Error(response, "下载任务编号无效", http.StatusBadRequest)
		return
	}

	serverIP := net.ParseIP(strings.TrimSpace(request.FormValue("server")))
	if serverIP == nil {
		http.Error(response, "目标服务器必须是有效的 IPv4 或 IPv6 地址", http.StatusBadRequest)
		return
	}
	port, err := strconv.Atoi(request.FormValue("port"))
	if err != nil || port < 1 || port > 65535 {
		http.Error(response, "UDP 端口必须在 1 到 65535 之间", http.StatusBadRequest)
		return
	}
	requestedPath := request.FormValue("path")
	if strings.TrimSpace(requestedPath) == "" {
		http.Error(response, "远端目录不能为空", http.StatusBadRequest)
		return
	}

	select {
	case handler.downloadSlots <- struct{}{}:
		defer func() { <-handler.downloadSlots }()
	default:
		http.Error(response, "本机已有过多下载任务，请稍后重试", http.StatusTooManyRequests)
		return
	}
	tracked := taskID != ""
	transferFinished := false
	if tracked {
		if !handler.beginTransfer(taskID) {
			http.Error(response, "下载任务编号已存在或任务记录已满", http.StatusConflict)
			return
		}
		defer func() {
			if !transferFinished {
				handler.finishTransfer(taskID, "failed")
			}
		}()
	}

	temporary, err := os.CreateTemp(handler.tempDir, "udpfile-web-*.tar.gz")
	if err != nil {
		handler.logger.Printf("create temporary browser download: %v", err)
		http.Error(response, "无法创建本地临时文件", http.StatusInternalServerError)
		return
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()

	serverAddress := net.JoinHostPort(serverIP.String(), strconv.Itoa(port))
	sharedSecret := handler.sharedSecret
	serverIdentity := handler.serverIdentity
	shouldCacheCredentials := false
	if handler.credentialStore != nil {
		var found bool
		sharedSecret, serverIdentity, found, err = handler.credentialStore.Load(serverAddress)
		if err != nil {
			handler.logger.Printf("load cached credentials for %s: %v", serverAddress, err)
			http.Error(response, "无法读取本地配对凭据", http.StatusInternalServerError)
			return
		}
		providedPairingToken := strings.TrimSpace(request.FormValue("pair"))
		if !found {
			if providedPairingToken == "" {
				http.Error(response, "首次连接该服务器请输入配对令牌", http.StatusBadRequest)
				return
			}
			sharedSecret, serverIdentity, err = pairing.Decode(providedPairingToken)
			if err != nil {
				http.Error(response, "配对令牌无效："+err.Error(), http.StatusBadRequest)
				return
			}
			shouldCacheCredentials = true
		} else if providedPairingToken != "" {
			pairedSecret, pairedIdentity, decodeErr := pairing.Decode(providedPairingToken)
			if decodeErr != nil {
				http.Error(response, "配对令牌无效："+decodeErr.Error(), http.StatusBadRequest)
				return
			}
			if saveErr := handler.credentialStore.Save(serverAddress, pairedSecret, pairedIdentity); saveErr != nil {
				http.Error(response, "配对身份与本地缓存不一致："+saveErr.Error(), http.StatusConflict)
				return
			}
		}
	}
	ctx, cancel := context.WithCancel(request.Context())
	info, downloadErr := client.DownloadArchive(ctx, client.Config{
		ServerAddress:     serverAddress,
		RequestedPath:     requestedPath,
		RetryInterval:     handler.retryInterval,
		InactivityTimeout: handler.inactivityTimeout,
		MaxArchiveSize:    handler.maxArchive,
		SharedSecret:      sharedSecret,
		ServerIdentity:    serverIdentity,
		Logger:            handler.logger,
		Progress:          handler.progressObserver(taskID),
	}, temporary)
	cancel()
	if downloadErr != nil {
		status := http.StatusBadGateway
		if errors.Is(downloadErr, context.DeadlineExceeded) {
			status = http.StatusGatewayTimeout
		}
		handler.logger.Printf("UDP download from %s path %q: %v", serverAddress, requestedPath, downloadErr)
		http.Error(response, "UDP 下载失败："+downloadErr.Error(), status)
		return
	}
	if shouldCacheCredentials {
		if err := handler.credentialStore.Save(serverAddress, sharedSecret, serverIdentity); err != nil {
			handler.logger.Printf("save paired credentials for %s: %v", serverAddress, err)
			http.Error(response, "下载成功但无法安全保存配对凭据", http.StatusInternalServerError)
			return
		}
	}
	if err := temporary.Sync(); err != nil {
		http.Error(response, "无法同步本地临时文件", http.StatusInternalServerError)
		return
	}
	if _, err := temporary.Seek(0, io.SeekStart); err != nil {
		http.Error(response, "无法读取本地临时文件", http.StatusInternalServerError)
		return
	}
	if tracked {
		handler.finishTransfer(taskID, "completed")
		transferFinished = true
	}

	filename := downloadFilename(requestedPath)
	response.Header().Set("Content-Type", "application/gzip")
	response.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": filename}))
	response.Header().Set("Content-Length", strconv.FormatUint(info.Size, 10))
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Archive-SHA256", hex.EncodeToString(info.SHA256[:]))
	if _, err := io.Copy(response, temporary); err != nil {
		handler.logger.Printf("send browser download %q: %v", filename, err)
	}
}

func (handler *Handler) serveProgress(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		response.Header().Set("Allow", http.MethodGet)
		http.Error(response, "仅支持 GET", http.StatusMethodNotAllowed)
		return
	}
	taskID := strings.TrimSpace(request.URL.Query().Get("id"))
	if !validTaskID(taskID) {
		http.Error(response, "下载任务编号无效", http.StatusBadRequest)
		return
	}
	handler.progressMu.Lock()
	handler.removeExpiredTransfersLocked(time.Now())
	progress, ok := handler.transfers[taskID]
	handler.progressMu.Unlock()
	if !ok {
		http.Error(response, "下载任务不存在", http.StatusNotFound)
		return
	}
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(response).Encode(progress); err != nil {
		handler.logger.Printf("write browser progress: %v", err)
	}
}

func (handler *Handler) beginTransfer(taskID string) bool {
	handler.progressMu.Lock()
	defer handler.progressMu.Unlock()
	now := time.Now()
	handler.removeExpiredTransfersLocked(now)
	if _, exists := handler.transfers[taskID]; exists {
		return false
	}
	if len(handler.transfers) >= maxRetainedTransfers && !handler.removeOldestTerminalTransferLocked() {
		return false
	}
	handler.transfers[taskID] = browserProgress{Status: "starting", UpdatedAt: now}
	return true
}

func (handler *Handler) progressObserver(taskID string) func(transferprogress.Snapshot) {
	if taskID == "" {
		return nil
	}
	return func(snapshot transferprogress.Snapshot) {
		handler.progressMu.Lock()
		progress, ok := handler.transfers[taskID]
		if ok {
			progress.Status = "downloading"
			progress.Percent = snapshot.Percent
			progress.CompletedBytes = snapshot.CompletedBytes
			progress.TotalBytes = snapshot.TotalBytes
			progress.CompletedChunks = snapshot.CompletedChunks
			progress.TotalChunks = snapshot.TotalChunks
			progress.UpdatedAt = time.Now()
			handler.transfers[taskID] = progress
		}
		handler.progressMu.Unlock()
	}
}

func (handler *Handler) finishTransfer(taskID string, status string) {
	handler.progressMu.Lock()
	progress, ok := handler.transfers[taskID]
	if ok {
		progress.Status = status
		if status == "completed" {
			progress.Percent = 100
		}
		progress.UpdatedAt = time.Now()
		handler.transfers[taskID] = progress
	}
	handler.progressMu.Unlock()
}

func (handler *Handler) removeExpiredTransfersLocked(now time.Time) {
	for taskID, progress := range handler.transfers {
		if isTerminalProgress(progress.Status) && now.Sub(progress.UpdatedAt) > progressRetention {
			delete(handler.transfers, taskID)
		}
	}
}

func (handler *Handler) removeOldestTerminalTransferLocked() bool {
	oldestTaskID := ""
	var oldestUpdate time.Time
	for taskID, progress := range handler.transfers {
		if !isTerminalProgress(progress.Status) {
			continue
		}
		if oldestTaskID == "" || progress.UpdatedAt.Before(oldestUpdate) {
			oldestTaskID = taskID
			oldestUpdate = progress.UpdatedAt
		}
	}
	if oldestTaskID == "" {
		return false
	}
	delete(handler.transfers, oldestTaskID)
	return true
}

func isTerminalProgress(status string) bool {
	return status == "completed" || status == "failed"
}

func validTaskID(taskID string) bool {
	if len(taskID) != 32 {
		return false
	}
	_, err := hex.DecodeString(taskID)
	return err == nil
}

func downloadFilename(requestedPath string) string {
	base := filepath.Base(filepath.Clean(requestedPath))
	if base == "." || base == string(filepath.Separator) || base == "" {
		base = "shared"
	}
	base = strings.Map(func(character rune) rune {
		if character < 32 || character == 127 || character == '/' || character == '\\' {
			return -1
		}
		return character
	}, base)
	if base == "" {
		base = "shared"
	}
	return base + ".tar.gz"
}

func (handler *Handler) serveHome(response http.ResponseWriter, request *http.Request, nonce string) {
	if request.Method != http.MethodGet {
		response.Header().Set("Allow", http.MethodGet)
		http.Error(response, "仅支持 GET", http.StatusMethodNotAllowed)
		return
	}
	response.Header().Set("Content-Type", "text/html; charset=utf-8")
	response.Header().Set("Cache-Control", "no-store")
	if err := handler.page.Execute(response, pageData{
		CSRFToken:     handler.csrfToken,
		CSPNonce:      nonce,
		DefaultServer: handler.defaultServer,
		DefaultPort:   handler.defaultPort,
	}); err != nil {
		handler.logger.Printf("render home page: %v", err)
	}
}

func (handler *Handler) setSecurityHeaders(response http.ResponseWriter, nonce string) {
	policy := "default-src 'none'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
	if nonce != "" {
		policy += "; script-src 'nonce-" + nonce + "'"
	}
	response.Header().Set("Content-Security-Policy", policy)
	response.Header().Set("Referrer-Policy", "no-referrer")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.Header().Set("X-Frame-Options", "DENY")
}

func randomToken(byteCount int) (string, error) {
	tokenBytes := make([]byte, byteCount)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(tokenBytes), nil
}

func requestHostIsLoopback(hostPort string) bool {
	host := hostPort
	if parsedHost, _, err := net.SplitHostPort(hostPort); err == nil {
		host = parsedHost
	} else if strings.HasPrefix(hostPort, "[") && strings.HasSuffix(hostPort, "]") {
		host = strings.Trim(hostPort, "[]")
	} else if colon := strings.LastIndex(hostPort, ":"); colon > 0 {
		if _, err := strconv.Atoi(hostPort[colon+1:]); err == nil {
			host = hostPort[:colon]
		}
	}
	return isLoopbackHost(host)
}

func isLoopbackHost(host string) bool {
	host = strings.Trim(strings.TrimSuffix(strings.ToLower(host), "."), "[]")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
