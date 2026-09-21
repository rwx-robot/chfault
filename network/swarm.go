package network

import (
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// ============================================================================
// Swarm：连接管理 + 广播 + 消息分发
// ============================================================================

// Config 是 Swarm 配置。
type Config struct {
	// Listen 本节点监听地址（":9000"）。
	Listen string
	// StaticPeers 静态 peer 地址列表（联盟链成员，拨号方向）。
	StaticPeers []string
	// NodeID 本节点标识（v0 用监听地址）。
	NodeID string
	// HandshakeTimeout 握手超时。
	HandshakeTimeout time.Duration
	// Logger
	Logger *slog.Logger
}

// DefaultConfig 返回默认配置。
func DefaultConfig(listen string) Config {
	return Config{
		Listen:           listen,
		HandshakeTimeout: handshakeTimeout,
		Logger:           slog.Default(),
	}
}

// Handler 是消息处理回调（由上层注入：共识/交易分派）。
// 返回错误仅记录，不中断连接（除非是协议级错误）。
type Handler func(from string, env *Envelope)

// Swarm 是网络层门面：监听 + 拨号 + 广播。
type Swarm struct {
	cfg     Config
	handler Handler

	mu     sync.RWMutex
	peers  map[string]*Peer // NodeID → Peer
	listen net.Listener

	closed chan struct{}
	wg     sync.WaitGroup
}

// NewSwarm 创建 Swarm 并开始监听。
func NewSwarm(cfg Config, handler Handler) (*Swarm, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("network: 监听失败 %s: %w", cfg.Listen, err)
	}
	// NodeID 默认 = 实际监听地址（空 NodeID 会让多个 peer 注册到同一 key）
	if cfg.NodeID == "" {
		cfg.NodeID = ln.Addr().String()
	}
	s := &Swarm{
		cfg:     cfg,
		handler: handler,
		peers:   make(map[string]*Peer),
		listen:  ln,
		closed:  make(chan struct{}),
	}

	// 接受入站连接
	s.wg.Add(1)
	go s.acceptLoop()

	// 拨号静态 peers
	for _, addr := range cfg.StaticPeers {
		peer := addr
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.dialLoop(peer)
		}()
	}

	return s, nil
}

// Addr 返回实际监听地址。
func (s *Swarm) Addr() string { return s.listen.Addr().String() }

// acceptLoop 接受入站连接。
func (s *Swarm) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.listen.Accept()
		if err != nil {
			select {
			case <-s.closed:
				return
			default:
			}
			s.cfg.Logger.Warn("accept 失败", "err", err)
			continue
		}
		go s.handleInbound(conn)
	}
}

// handleInbound 处理入站连接：握手 → 注册 → 读循环。
func (s *Swarm) handleInbound(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	if s.cfg.HandshakeTimeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(s.cfg.HandshakeTimeout))
	}
	peer := newPeer(conn)
	self := HandshakeInfo{NodeID: s.cfg.NodeID, Listen: s.cfg.Listen, Protocol: ProtocolVersion}
	peerInfo, err := DoHandshake(peer, self)
	if err != nil {
		s.cfg.Logger.Warn("入站握手失败", "remote", conn.RemoteAddr(), "err", err)
		return
	}
	_ = conn.SetDeadline(time.Time{}) // 清除握手超时

	s.cfg.Logger.Info("peer 已连接（入站）", "node", peerInfo.NodeID)
	s.register(peer, peerInfo.NodeID)
	s.readLoop(peer)
}

// dialLoop 持续拨号直到成功或 Swarm 关闭（指数退避由 time.Sleep 近似）。
func (s *Swarm) dialLoop(addr string) {
	backoff := time.Second
	for {
		select {
		case <-s.closed:
			return
		default:
		}
		if s.tryDial(addr) {
			return // 连接建立，读循环接管
		}
		time.Sleep(backoff)
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

// tryDial 拨号 + 握手 + 注册。
func (s *Swarm) tryDial(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, handshakeTimeout)
	if err != nil {
		return false
	}
	peer := newPeer(conn)
	self := HandshakeInfo{NodeID: s.cfg.NodeID, Listen: s.cfg.Listen, Protocol: ProtocolVersion}
	peerInfo, err := DoHandshake(peer, self)
	if err != nil {
		s.cfg.Logger.Warn("出站握手失败", "addr", addr, "err", err)
		_ = conn.Close()
		return false
	}
	_ = conn.SetDeadline(time.Time{})

	s.cfg.Logger.Info("peer 已连接（出站）", "node", peerInfo.NodeID)
	s.register(peer, peerInfo.NodeID)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.readLoop(peer)
	}()
	return true
}

// register 注册 peer（重复连接：保留新的，关闭旧的）。
func (s *Swarm) register(peer *Peer, nodeID string) {
	s.mu.Lock()
	if old, ok := s.peers[nodeID]; ok {
		old.Close()
	}
	s.peers[nodeID] = peer
	s.mu.Unlock()
}

// readLoop 持续读取并分发消息。
func (s *Swarm) readLoop(peer *Peer) {
	defer func() {
		peer.Close()
		s.mu.Lock()
		if s.peers[peer.Address] == peer {
			delete(s.peers, peer.Address)
		}
		s.mu.Unlock()
		s.cfg.Logger.Info("peer 已断开", "node", peer.Address)
	}()

	for {
		env, err := peer.Recv()
		if err != nil {
			return
		}
		if s.handler != nil {
			s.handler(peer.Address, env)
		}
	}
}

// Broadcast 向所有已连接 peer 广播信封。
//
// 逐 peer 发送（不中断：某 peer 失败不影响其他）。
// 返回成功发送的 peer 数。
func (s *Swarm) Broadcast(env *Envelope) int {
	s.mu.RLock()
	peers := make([]*Peer, 0, len(s.peers))
	for _, p := range s.peers {
		peers = append(peers, p)
	}
	s.mu.RUnlock()

	// 按 NodeID 排序保证发送顺序确定（同进程多 peer 场景）
	for i := 1; i < len(peers); i++ {
		for j := i; j > 0 && peers[j].Address < peers[j-1].Address; j-- {
			peers[j], peers[j-1] = peers[j-1], peers[j]
		}
	}

	sent := 0
	for _, p := range peers {
		if err := p.Send(env); err != nil {
			s.cfg.Logger.Warn("发送失败", "node", p.Address, "err", err)
			continue
		}
		sent++
	}
	return sent
}

// PeerCount 当前连接数。
func (s *Swarm) PeerCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.peers)
}

// Close 关闭 Swarm（所有连接与监听）。
func (s *Swarm) Close() error {
	close(s.closed)
	_ = s.listen.Close()
	s.mu.Lock()
	for _, p := range s.peers {
		p.Close()
	}
	s.peers = make(map[string]*Peer)
	s.mu.Unlock()
	s.wg.Wait()
	return nil
}

// Connect 主动连接一个 peer（动态加节点 —— 运维与测试用）。
//
// 已连接的地址会被静默跳过（幂等）。
func (s *Swarm) Connect(addr string) error {
	s.mu.RLock()
	for _, p := range s.peers {
		if p.Addr == addr || p.Address == addr {
			s.mu.RUnlock()
			return nil // 已连接
		}
	}
	s.mu.RUnlock()

	conn, err := net.DialTimeout("tcp", addr, handshakeTimeout)
	if err != nil {
		return fmt.Errorf("network: 拨号失败 %s: %w", addr, err)
	}
	peer := newPeer(conn)
	self := HandshakeInfo{NodeID: s.cfg.NodeID, Listen: s.cfg.Listen, Protocol: ProtocolVersion}
	peerInfo, err := DoHandshake(peer, self)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("network: 握手失败 %s: %w", addr, err)
	}
	_ = conn.SetDeadline(time.Time{})

	s.cfg.Logger.Info("peer 已连接（动态）", "node", peerInfo.NodeID)
	s.register(peer, peerInfo.NodeID)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.readLoop(peer)
	}()
	return nil
}
