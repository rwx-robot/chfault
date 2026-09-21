package network

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// ============================================================================
// 帧协议：4 字节大端长度 + JSON 载荷
// ============================================================================

const (
	// maxFrameSize 帧上限（1 MiB —— 区块上限 2 MiB 的一半，
	// 大区块分片在 M2.x；实际由配置项覆盖）。
	maxFrameSize = 4 << 20
	// handshakeTimeout 连接握手超时。
	handshakeTimeout = 5 * time.Second
	// writeTimeout 单次写超时。
	writeTimeout = 10 * time.Second
)

// writeFrame 写一帧（长度前缀 + JSON）。
func writeFrame(w *bufio.Writer, env *Envelope) error {
	data, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("network: 编码信封失败: %w", err)
	}
	if len(data) > maxFrameSize {
		return fmt.Errorf("network: 帧超过上限 %d", maxFrameSize)
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))

	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	return w.Flush()
}

// readFrame 读一帧。
func readFrame(r *bufio.Reader) (*Envelope, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err // EOF 视为连接关闭
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length == 0 || length > maxFrameSize {
		return nil, fmt.Errorf("network: 非法帧长度 %d", length)
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}
	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("network: 解码信封失败: %w", err)
	}
	return &env, nil
}

// ============================================================================
// Peer
// ============================================================================

// Peer 是一个已建立的连接。
type Peer struct {
	Addr    string // 对端拨号地址（host:port）
	Address string // 对端节点标识（握手后填充，v0 用监听地址）

	conn net.Conn
	w    *bufio.Writer
	r    *bufio.Reader

	writeMu sync.Mutex // 写串行化（多 goroutine 广播）

	closed chan struct{}
	once   sync.Once
}

// newPeer 封装连接。
func newPeer(conn net.Conn) *Peer {
	return &Peer{
		Addr:   conn.RemoteAddr().String(),
		conn:   conn,
		w:      bufio.NewWriter(conn),
		r:      bufio.NewReader(conn),
		closed: make(chan struct{}),
	}
}

// Send 发送一帧（线程安全）。
func (p *Peer) Send(env *Envelope) error {
	select {
	case <-p.closed:
		return fmt.Errorf("network: 连接已关闭")
	default:
	}
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	return writeFrame(p.w, env)
}

// Recv 阻塞读一帧。
func (p *Peer) Recv() (*Envelope, error) {
	env, err := readFrame(p.r)
	if err != nil {
		p.Close()
		return nil, err
	}
	return env, nil
}

// Close 关闭连接（幂等）。
func (p *Peer) Close() {
	p.once.Do(func() {
		close(p.closed)
		_ = p.conn.Close()
	})
}

// IsClosed 查询连接状态。
func (p *Peer) IsClosed() bool {
	select {
	case <-p.closed:
		return true
	default:
		return false
	}
}

// ============================================================================
// 握手：交换节点信息
// ============================================================================

// HandshakeInfo 是握手载荷。
type HandshakeInfo struct {
	NodeID   string `json:"nodeId"`   // v0 用监听地址标识；M2.x 换公钥
	Listen   string `json:"listen"`   // 本节点监听地址
	Protocol uint32 `json:"protocol"` // 协议版本
}

// 协议版本（不兼容的协议版本拒绝连接 —— 硬分叉保护）。
const ProtocolVersion = 1

// DoHandshake 交换握手信息。
func DoHandshake(p *Peer, info HandshakeInfo) (HandshakeInfo, error) {
	// 并发读写的握手：各自先写后读（简单双工约定）
	p.writeMu.Lock()
	err := writeFrame(p.w, &Envelope{
		Type:    "handshake",
		Payload: mustJSON(info),
	})
	p.writeMu.Unlock()
	if err != nil {
		return HandshakeInfo{}, fmt.Errorf("network: 发送握手失败: %w", err)
	}

	env, err := readFrame(p.r)
	if err != nil {
		return HandshakeInfo{}, fmt.Errorf("network: 读取握手失败: %w", err)
	}
	if env.Type != "handshake" {
		return HandshakeInfo{}, fmt.Errorf("network: 期望 handshake，实际 %s", env.Type)
	}
	var peerInfo HandshakeInfo
	if err := json.Unmarshal(env.Payload, &peerInfo); err != nil {
		return HandshakeInfo{}, fmt.Errorf("network: 解析握手失败: %w", err)
	}
	if peerInfo.Protocol != ProtocolVersion {
		return HandshakeInfo{}, fmt.Errorf(
			"network: 协议版本不匹配（本方 %d，对方 %d）—— 硬分叉保护",
			ProtocolVersion, peerInfo.Protocol)
	}
	p.Address = peerInfo.NodeID
	return peerInfo, nil
}

// ============================================================================
// 导出的连接辅助（测试与工具用）
// ============================================================================

// WriteEnvelope 直接向连接写一帧（不走 Peer 封装）。
func WriteEnvelope(conn net.Conn, env *Envelope) error {
	w := bufio.NewWriter(conn)
	return writeFrame(w, env)
}

// ReadEnvelope 直接从连接读一帧。
func ReadEnvelope(conn net.Conn) (*Envelope, error) {
	r := bufio.NewReader(conn)
	return readFrame(r)
}
