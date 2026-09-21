package network_test

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	cconsensus "github.com/chfault/chfault/consensus"
	"github.com/chfault/chfault/crypto"
	"github.com/chfault/chfault/network"
	"github.com/chfault/chfault/types"
)

// ============================================================================
// 协议编解码
// ============================================================================

func TestConsensusMessageRoundTrip(t *testing.T) {
	key := newTestKey()

	// Proposal
	prop := cconsensus.Message{
		Height: 5, Round: 2, From: key.Addr,
		Body: cconsensus.Proposal{
			POLRound:  types.NoPOLRound,
			Block:     []byte{1, 2, 3},
			BlockHash: crypto.Keccak256([]byte("block")),
			Signature: types.Signature{0xaa},
		},
	}
	env, err := network.NewConsensusEnvelope(&prop)
	if err != nil {
		t.Fatalf("编码失败: %v", err)
	}
	if env.Type != network.TypeConsensus {
		t.Fatalf("信封类型错误: %s", env.Type)
	}
	got, err := network.UnmarshalConsensusMessage(env.Payload)
	if err != nil {
		t.Fatalf("解码失败: %v", err)
	}
	if got.Height != 5 || got.Round != 2 || got.From != key.Addr {
		t.Fatalf("头部不一致: %+v", got)
	}
	if p, ok := got.Body.(cconsensus.Proposal); !ok {
		t.Fatalf("Body 类型错误: %T", got.Body)
	} else if p.BlockHash != (crypto.Keccak256([]byte("block"))) {
		t.Fatal("BlockHash 不一致")
	} else if string(p.Block) != "\x01\x02\x03" {
		t.Fatal("Block 不一致")
	}

	// Vote
	vote := cconsensus.Message{
		Height: 5, Round: 2, From: key.Addr,
		Body: cconsensus.Vote{
			Type:      cconsensus.Precommit,
			BlockHash: crypto.Keccak256([]byte("v")),
		},
	}
	env, _ = network.NewConsensusEnvelope(&vote)
	got, err = network.UnmarshalConsensusMessage(env.Payload)
	if err != nil {
		t.Fatalf("vote 解码失败: %v", err)
	}
	if v, ok := got.Body.(cconsensus.Vote); !ok || v.Type != cconsensus.Precommit {
		t.Fatalf("vote 解码错误: %+v", got.Body)
	}

	// QC
	qc := cconsensus.Message{
		Height: 5, Round: 2, From: key.Addr,
		Body: cconsensus.QC{
			Type:      cconsensus.Prevote,
			Height:    5,
			Round:     2,
			BlockHash: crypto.Keccak256([]byte("q")),
			Signatures: []cconsensus.QCSignature{
				{Validator: key.Addr, Sig: types.Signature{0x01}},
			},
		},
	}
	env, _ = network.NewConsensusEnvelope(&qc)
	got, err = network.UnmarshalConsensusMessage(env.Payload)
	if err != nil {
		t.Fatalf("QC 解码失败: %v", err)
	}
	if q, ok := got.Body.(cconsensus.QC); !ok || len(q.Signatures) != 1 {
		t.Fatalf("QC 解码错误: %+v", got.Body)
	}
}

// TestUnmarshalRejectsGarbage 验证垃圾输入被拒绝。
func TestUnmarshalRejectsGarbage(t *testing.T) {
	if _, err := network.UnmarshalConsensusMessage([]byte{0x99, 0x01}); err == nil {
		t.Fatal("未知 tag 应报错")
	}
	if _, err := network.UnmarshalConsensusMessage(nil); err == nil {
		t.Fatal("空载荷应报错")
	}
}

// ============================================================================
// TCP 传输端到端（真实 localhost 连接）
// ============================================================================

func newTestKey() *testKey { return &testKey{Addr: types.Address{0x42}} }

type testKey struct{ Addr types.Address }

// TestSwarm_TwoNodesExchange 验证两个 Swarm 通过真实 TCP 互联并交换消息。
func TestSwarm_TwoNodesExchange(t *testing.T) {
	received := make(chan string, 10)

	// 节点 B：监听
	handlerB := func(from string, env *network.Envelope) {
		received <- env.Type
	}
	swarmB, err := network.NewSwarm(network.DefaultConfig("127.0.0.1:0"), handlerB)
	if err != nil {
		t.Fatalf("启动 B 失败: %v", err)
	}
	defer func() { _ = swarmB.Close() }()

	// 节点 A：拨号 B
	cfgA := network.DefaultConfig("127.0.0.1:0")
	cfgA.NodeID = "node-a"
	cfgA.StaticPeers = []string{swarmB.Addr()}
	swarmA, err := network.NewSwarm(cfgA, nil)
	if err != nil {
		t.Fatalf("启动 A 失败: %v", err)
	}
	defer func() { _ = swarmA.Close() }()

	// 等待连接建立
	deadline := time.Now().Add(3 * time.Second)
	for swarmB.PeerCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if swarmB.PeerCount() != 1 {
		t.Fatalf("B 应有 1 个 peer，实际 %d", swarmB.PeerCount())
	}

	// A 广播共识消息
	msg := &cconsensus.Message{
		Height: 1, Round: 0, From: types.Address{0x42},
		Body: cconsensus.Vote{Type: cconsensus.Prevote, BlockHash: crypto.Keccak256([]byte("x"))},
	}
	env, err := network.NewConsensusEnvelope(msg)
	if err != nil {
		t.Fatal(err)
	}
	if sent := swarmA.Broadcast(env); sent != 1 {
		t.Fatalf("应发送 1 个 peer，实际 %d", sent)
	}

	// B 收到
	select {
	case typ := <-received:
		if typ != network.TypeConsensus {
			t.Fatalf("应收到 consensus，实际 %s", typ)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("3 秒内未收到消息")
	}
}

// TestSwarm_ThreeNodesGossip 验证三节点互通（A↔B、A↔C）。
func TestSwarm_ThreeNodesGossip(t *testing.T) {
	counts := make(chan string, 20)

	mkHandler := func(name string) network.Handler {
		return func(from string, env *network.Envelope) {
			counts <- name + ":" + env.Type
		}
	}

	// B 与 C 监听
	swarmB, _ := network.NewSwarm(network.DefaultConfig("127.0.0.1:0"), mkHandler("B"))
	defer func() { _ = swarmB.Close() }()
	swarmC, _ := network.NewSwarm(network.DefaultConfig("127.0.0.1:0"), mkHandler("C"))
	defer func() { _ = swarmC.Close() }()

	// A 连接 B、C
	cfgA := network.DefaultConfig("127.0.0.1:0")
	cfgA.NodeID = "A"
	cfgA.StaticPeers = []string{swarmB.Addr(), swarmC.Addr()}
	swarmA, _ := network.NewSwarm(cfgA, mkHandler("A"))
	defer func() { _ = swarmA.Close() }()

	// 等待 A 与两者都建立连接（A 视角）
	deadline := time.Now().Add(3 * time.Second)
	for swarmA.PeerCount() < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if swarmA.PeerCount() != 2 {
		t.Fatalf("A 应有 2 个 peer，实际 %d", swarmA.PeerCount())
	}

	// A 广播
	env := &network.Envelope{Type: network.TypePing, Payload: json.RawMessage(`{}`)}
	if sent := swarmA.Broadcast(env); sent != 2 {
		t.Fatalf("应发 2 个 peer，实际 %d", sent)
	}

	// B 与 C 各收到 1 条
	got := map[string]int{}
	timeout := time.After(3 * time.Second)
	for len(got) < 2 {
		select {
		case r := <-counts:
			got[r]++
		case <-timeout:
			t.Fatalf("超时，收到 %v", got)
		}
	}
	if got["B:ping"] != 1 || got["C:ping"] != 1 {
		t.Fatalf("收到的消息: %v", got)
	}
}

// TestSwarm_ProtocolVersionMismatch 验证协议版本不匹配被拒（硬分叉保护）。
func TestSwarm_ProtocolVersionMismatch(t *testing.T) {
	handlerB := func(from string, env *network.Envelope) {}

	swarmB, err := network.NewSwarm(network.DefaultConfig("127.0.0.1:0"), handlerB)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = swarmB.Close() }()

	// A 用不兼容协议版本直连握手
	conn, err := dialWithTimeout(swarmB.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	// 发送错误版本的握手
	bad := network.HandshakeInfo{NodeID: "bad", Protocol: 999}
	env := &network.Envelope{Type: "handshake", Payload: json.RawMessage(mustJSONRaw(bad))}
	if err := network.WriteEnvelope(conn, env); err != nil {
		t.Fatalf("写握手失败: %v", err)
	}

	// A 先读到 B 的握手响应（B 先写后读）—— 该响应本身有效；
	// B 随后发现 A 的版本不匹配会关闭连接 → A 的下一次读应得到错误。
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := network.ReadEnvelope(conn); err != nil {
		t.Fatalf("应先读到 B 的握手: %v", err)
	}
	// 连接应被 B 关闭（版本不匹配 → 硬分叉保护）
	deadline := time.Now().Add(3 * time.Second)
	closed := false
	for time.Now().Before(deadline) {
		if _, err := network.ReadEnvelope(conn); err != nil {
			closed = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !closed {
		t.Fatal("版本不匹配后连接应被对端关闭（硬分叉保护）")
	}
}

func mustJSONRaw(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func dialWithTimeout(addr string) (net.Conn, error) {
	return net.DialTimeout("tcp", addr, 5*time.Second)
}
