// Package network 实现节点间的 TCP 传输与消息广播。
//
// v0 设计（联盟链定位，docs/blueprint/06 §6.4）：
//   - **静态 peer 配置**（联盟链成员已知，无需 DHT 发现 —— DHT 是 M4 公链路径）
//   - TCP 长连接 + 4 字节长度前缀帧 + JSON 编码（简单可靠；M2.x 评估二进制）
//   - Swarm 管理连接与广播，**不解析消息内容** —— 共识/交易分层处理
//
// 确定性约束不适用于本包（网络是 IO 边界层）；共识核心仍由 sim 保证。
package network

import (
	"encoding/json"
	"errors"
	"fmt"

	cconsensus "github.com/chfault/chfault/consensus"
	"github.com/chfault/chfault/types"
)

// 消息类型（Envelope.Type）。
const (
	TypeConsensus = "consensus" // 共识消息（proposal/vote/qc）
	TypeTx        = "tx"        // 交易广播（原始字节）
	TypePing      = "ping"      // 连接保活
	TypePong      = "pong"
)

// Envelope 是网络传输的统一信封。
type Envelope struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

// 错误。
var (
	// ErrUnknownType 未知消息类型。
	ErrUnknownType = errors.New("network: 未知消息类型")
	// ErrEmptyPayload 空载荷。
	ErrEmptyPayload = errors.New("network: 空载荷")
)

// ============================================================================
// 共识消息编解码
// ============================================================================

// consensusBodyTag 是 Body 具体类型的判别标签。
type consensusBodyTag uint8

const (
	tagProposal consensusBodyTag = 0x01
	tagVote     consensusBodyTag = 0x02
	tagQC       consensusBodyTag = 0x03
)

// wireProposal / wireVote / wireQC 是共识消息体的 JSON 形态。
// （Message.Body 是接口，JSON 需要具体类型 + 类型标签。）
type wireProposal struct {
	POLRound  uint32          `json:"polRound"`
	Block     []byte          `json:"block"`     // base64（encoding/json 默认）
	BlockHash types.Hash      `json:"blockHash"` // hex
	Signature types.Signature `json:"sig"`
}

type wireVote struct {
	Type      uint8           `json:"type"`
	BlockHash types.Hash      `json:"blockHash"`
	Signature types.Signature `json:"sig"`
}

type wireQC struct {
	Type       uint8             `json:"type"`
	Height     uint64            `json:"height"`
	Round      uint32            `json:"round"`
	BlockHash  types.Hash        `json:"blockHash"`
	Signatures []wireQCSignature `json:"sigs"`
}

type wireQCSignature struct {
	Validator types.Address   `json:"addr"`
	Sig       types.Signature `json:"sig"`
}

// wireMessage 是共识消息的完整 wire 形态（含头部 ——
// 曾漏掉 Height/Round/From 导致解码后消息丢失路由信息）。
type wireMessage struct {
	Height uint64          `json:"h"`
	Round  uint32          `json:"r"`
	From   types.Address   `json:"from"`
	Tag    uint8           `json:"tag"`
	Body   json.RawMessage `json:"body"`
}

// MarshalConsensusMessage 把共识消息编码为 Envelope 载荷。
func MarshalConsensusMessage(msg *cconsensus.Message) ([]byte, error) {
	var tag consensusBodyTag
	var body any

	switch b := msg.Body.(type) {
	case cconsensus.Proposal:
		tag = tagProposal
		body = wireProposal{
			POLRound:  uint32(b.POLRound),
			Block:     b.Block,
			BlockHash: b.BlockHash,
			Signature: b.Signature,
		}
	case cconsensus.Vote:
		tag = tagVote
		body = wireVote{
			Type:      uint8(b.Type),
			BlockHash: b.BlockHash,
			Signature: b.Signature,
		}
	case cconsensus.QC:
		tag = tagQC
		sigs := make([]wireQCSignature, 0, len(b.Signatures))
		for _, s := range b.Signatures {
			sigs = append(sigs, wireQCSignature{Validator: s.Validator, Sig: s.Sig})
		}
		body = wireQC{
			Type:       uint8(b.Type),
			Height:     uint64(b.Height),
			Round:      uint32(b.Round),
			BlockHash:  b.BlockHash,
			Signatures: sigs,
		}
	default:
		return nil, fmt.Errorf("%w: 未知共识消息体 %T", ErrUnknownType, msg.Body)
	}

	inner, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return json.Marshal(wireMessage{
		Height: uint64(msg.Height),
		Round:  uint32(msg.Round),
		From:   msg.From,
		Tag:    uint8(tag),
		Body:   inner,
	})
}

// UnmarshalConsensusMessage 从 Envelope 载荷解码共识消息。
func UnmarshalConsensusMessage(data []byte) (*cconsensus.Message, error) {
	if len(data) == 0 {
		return nil, ErrEmptyPayload
	}
	var wire wireMessage
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, err
	}
	tag := consensusBodyTag(wire.Tag)
	inner := wire.Body

	msg := &cconsensus.Message{
		Height: types.Height(wire.Height),
		Round:  types.Round(wire.Round),
		From:   wire.From,
	}
	switch tag {
	case tagProposal:
		var w wireProposal
		if err := json.Unmarshal(inner, &w); err != nil {
			return nil, err
		}
		msg.Body = cconsensus.Proposal{
			POLRound:  types.Round(w.POLRound),
			Block:     w.Block,
			BlockHash: w.BlockHash,
			Signature: w.Signature,
		}
	case tagVote:
		var w wireVote
		if err := json.Unmarshal(inner, &w); err != nil {
			return nil, err
		}
		msg.Body = cconsensus.Vote{
			Type:      cconsensus.VoteType(w.Type),
			BlockHash: w.BlockHash,
			Signature: w.Signature,
		}
	case tagQC:
		var w wireQC
		if err := json.Unmarshal(inner, &w); err != nil {
			return nil, err
		}
		sigs := make([]cconsensus.QCSignature, 0, len(w.Signatures))
		for _, s := range w.Signatures {
			sigs = append(sigs, cconsensus.QCSignature{Validator: s.Validator, Sig: s.Sig})
		}
		msg.Body = cconsensus.QC{
			Type:       cconsensus.VoteType(w.Type),
			Height:     types.Height(w.Height),
			Round:      types.Round(w.Round),
			BlockHash:  w.BlockHash,
			Signatures: sigs,
		}
	default:
		return nil, fmt.Errorf("%w: tag %d", ErrUnknownType, tag)
	}
	return msg, nil
}

// ============================================================================
// Envelope 编解码辅助
// ============================================================================

// NewConsensusEnvelope 构造共识信封。
func NewConsensusEnvelope(msg *cconsensus.Message) (*Envelope, error) {
	payload, err := MarshalConsensusMessage(msg)
	if err != nil {
		return nil, err
	}
	return &Envelope{Type: TypeConsensus, Payload: payload}, nil
}

// NewTxEnvelope 构造交易信封（payload = {"raw": base64}，
// 与 node.handleNetworkMessage 的解析端匹配）。
func NewTxEnvelope(rawTx []byte) *Envelope {
	b, _ := json.Marshal(struct {
		Raw []byte `json:"raw"`
	}{Raw: rawTx})
	return &Envelope{Type: TypeTx, Payload: b}
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
