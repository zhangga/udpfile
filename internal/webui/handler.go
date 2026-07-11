package webui

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
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
	"time"

	"udpfile/internal/client"
)

//go:embed index.html
var indexHTML string

const (
	DefaultRetryInterval = client.DefaultRetryInterval
	DefaultMaxArchive    = client.DefaultMaxArchive
)

type Config struct {
	DefaultServer   string
	DefaultPort     int
	TempDir         string
	TransferTimeout time.Duration
	RetryInterval   time.Duration
	MaxArchiveSize  uint64
	MaxConcurrent   int
	SharedSecret    []byte
	ServerIdentity  *rsa.PublicKey
	Logger          *log.Logger
}

type Handler struct {
	page           *template.Template
	csrfToken      string
	defaultServer  string
	defaultPort    int
	tempDir        string
	timeout        time.Duration
	retryInterval  time.Duration
	maxArchive     uint64
	sharedSecret   []byte
	serverIdentity *rsa.PublicKey
	downloadSlots  chan struct{}
	logger         *log.Logger
}

type pageData struct {
	CSRFToken     string
	DefaultServer string
	DefaultPort   int
}

func NewHandler(config Config) (http.Handler, error) {
	if config.DefaultPort == 0 {
		config.DefaultPort = 9000
	}
	if config.DefaultPort < 1 || config.DefaultPort > 65535 {
		return nil, errors.New("default UDP port must be between 1 and 65535")
	}
	if len(config.SharedSecret) != 32 {
		return nil, errors.New("32-byte shared secret is required")
	}
	if config.ServerIdentity == nil || config.ServerIdentity.N.BitLen() < 2048 {
		return nil, errors.New("RSA server identity of at least 2048 bits is required")
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
	if config.TransferTimeout <= 0 {
		config.TransferTimeout = 10 * time.Minute
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
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, err
	}
	page, err := template.New("index").Parse(indexHTML)
	if err != nil {
		return nil, err
	}
	return &Handler{
		page:           page,
		csrfToken:      base64.RawURLEncoding.EncodeToString(tokenBytes),
		defaultServer:  config.DefaultServer,
		defaultPort:    config.DefaultPort,
		tempDir:        config.TempDir,
		timeout:        config.TransferTimeout,
		retryInterval:  config.RetryInterval,
		maxArchive:     config.MaxArchiveSize,
		sharedSecret:   append([]byte(nil), config.SharedSecret...),
		serverIdentity: config.ServerIdentity,
		downloadSlots:  make(chan struct{}, config.MaxConcurrent),
		logger:         config.Logger,
	}, nil
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	setSecurityHeaders(response)
	if !requestHostIsLoopback(request.Host) {
		http.Error(response, "仅允许通过 localhost 访问", http.StatusForbidden)
		return
	}
	switch request.URL.Path {
	case "/":
		handler.serveHome(response, request)
	case "/download":
		handler.serveDownload(response, request)
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
	ctx, cancel := context.WithTimeout(request.Context(), handler.timeout)
	info, downloadErr := client.DownloadArchive(ctx, client.Config{
		ServerAddress:  serverAddress,
		RequestedPath:  requestedPath,
		RetryInterval:  handler.retryInterval,
		MaxArchiveSize: handler.maxArchive,
		SharedSecret:   handler.sharedSecret,
		ServerIdentity: handler.serverIdentity,
		Logger:         handler.logger,
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
	if err := temporary.Sync(); err != nil {
		http.Error(response, "无法同步本地临时文件", http.StatusInternalServerError)
		return
	}
	if _, err := temporary.Seek(0, io.SeekStart); err != nil {
		http.Error(response, "无法读取本地临时文件", http.StatusInternalServerError)
		return
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

func (handler *Handler) serveHome(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		response.Header().Set("Allow", http.MethodGet)
		http.Error(response, "仅支持 GET", http.StatusMethodNotAllowed)
		return
	}
	response.Header().Set("Content-Type", "text/html; charset=utf-8")
	response.Header().Set("Cache-Control", "no-store")
	if err := handler.page.Execute(response, pageData{
		CSRFToken:     handler.csrfToken,
		DefaultServer: handler.defaultServer,
		DefaultPort:   handler.defaultPort,
	}); err != nil {
		handler.logger.Printf("render home page: %v", err)
	}
}

func setSecurityHeaders(response http.ResponseWriter) {
	response.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	response.Header().Set("Referrer-Policy", "no-referrer")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.Header().Set("X-Frame-Options", "DENY")
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
