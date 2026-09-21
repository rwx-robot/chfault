package rpc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ServerConfig 是 RPC 服务配置。
type ServerConfig struct {
	// HTTPPort JSON-RPC over HTTP 端口。
	HTTPPort int
	// MaxBodyBytes 请求体上限。
	MaxBodyBytes int64
	// MaxBatchSize 批量请求上限（防放大攻击）。
	MaxBatchSize int
	// ReadTimeout 读超时。
	ReadTimeout time.Duration
	// WriteTimeout 写超时。
	WriteTimeout time.Duration
	// PerIPRateLimit 每 IP 每秒请求上限（0 = 不限）。
	PerIPRateLimit int
}

// DefaultServerConfig 返回默认配置。
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		HTTPPort:       8545,
		MaxBodyBytes:   1 << 20, // 1 MiB
		MaxBatchSize:   10,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   60 * time.Second,
		PerIPRateLimit: 100,
	}
}

// Server 是 JSON-RPC HTTP 服务。
type Server struct {
	cfg        ServerConfig
	dispatcher *Dispatcher
	registry   *Registry
	httpServer *http.Server

	mu       sync.Mutex
	limiter  map[string]*bucket
	started  bool
	listener net.Listener
}

// NewServer 创建服务。
func NewServer(cfg ServerConfig, reg *Registry, disp *Dispatcher) *Server {
	if cfg.MaxBodyBytes == 0 {
		cfg = DefaultServerConfig()
	}
	disp.MaxBatchSize = cfg.MaxBatchSize

	s := &Server{
		cfg:        cfg,
		registry:   reg,
		dispatcher: disp,
		limiter:    make(map[string]*bucket),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRPC)
	mux.HandleFunc("/health", s.handleHealth)

	s.httpServer = &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.HTTPPort),
		Handler:      mux,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	}
	return s
}

// Start 启动服务（阻塞）。
func (s *Server) Start() error {
	s.mu.Lock()
	s.started = true
	s.mu.Unlock()
	return s.httpServer.ListenAndServe()
}

// StartAsync 在后台启动服务。
func (s *Server) StartAsync() error {
	s.mu.Lock()
	s.started = true
	s.mu.Unlock()

	ln, err := net.Listen("tcp", s.httpServer.Addr)
	if err != nil {
		return err
	}
	s.listener = ln
	go func() {
		_ = s.httpServer.Serve(ln)
	}()
	return nil
}

// Stop 优雅关闭。
func (s *Server) Stop(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

// Addr 返回实际监听地址（端口为 0 时返回系统分配的端口）。
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return s.httpServer.Addr
}

// ============================================================================
// HTTP 处理
// ============================================================================

func (s *Server) handleRPC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "只支持 POST", http.StatusMethodNotAllowed)
		return
	}

	// 限流
	if s.cfg.PerIPRateLimit > 0 {
		ip := clientIP(r)
		if !s.allow(ip) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(&Response{
				JSONRPC: "2.0",
				Error:   NewError(CodeLimitExceeded, "请求过于频繁"),
			})
			return
		}
	}

	// 限制请求体大小
	body := http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)
	raw, err := io.ReadAll(body)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		_ = json.NewEncoder(w).Encode(&Response{
			JSONRPC: "2.0",
			Error:   NewError(CodeLimitExceeded, "请求体过大"),
		})
		return
	}

	trimmed := strings.TrimSpace(string(raw))
	w.Header().Set("Content-Type", "application/json")

	// 批量请求
	if len(trimmed) > 0 && trimmed[0] == '[' {
		resps := s.dispatcher.HandleBatch(r.Context(), raw)
		if resps == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_ = json.NewEncoder(w).Encode(resps)
		return
	}

	resp := s.dispatcher.Handle(r.Context(), raw)
	if resp == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":  "ok",
		"methods": s.registry.Count(),
		"version": ClientVersion,
	})
}

// ============================================================================
// 限流（简单的令牌桶）
// ============================================================================

type bucket struct {
	tokens   int
	lastSeen time.Time
}

// allow 判断某 IP 是否允许本次请求。
func (s *Server) allow(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	b, ok := s.limiter[ip]
	if !ok {
		s.limiter[ip] = &bucket{tokens: s.cfg.PerIPRateLimit - 1, lastSeen: now}
		return true
	}

	// 按秒补充令牌
	elapsed := now.Sub(b.lastSeen)
	refill := int(elapsed.Seconds()) * s.cfg.PerIPRateLimit
	if refill > 0 {
		b.tokens += refill
		if b.tokens > s.cfg.PerIPRateLimit {
			b.tokens = s.cfg.PerIPRateLimit
		}
		b.lastSeen = now
	}

	if b.tokens <= 0 {
		return false
	}
	b.tokens--
	return true
}

// clientIP 提取客户端 IP（支持 X-Forwarded-For）。
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	addr := r.RemoteAddr
	if i := strings.LastIndex(addr, ":"); i > 0 {
		return addr[:i]
	}
	return addr
}

// ============================================================================
// 便利函数
// ============================================================================

// ParsePort 从字符串解析端口。
func ParsePort(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("端口为空")
	}
	p, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("端口非法: %w", err)
	}
	if p < 1 || p > 65535 {
		return 0, fmt.Errorf("端口超出范围: %d", p)
	}
	return p, nil
}
