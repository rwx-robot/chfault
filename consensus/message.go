// Package consensus 实现 Tendermint 式三阶段 BFT 共识。
//
// 设计红线（docs/blueprint/09 §9.12，AI 开发模式）：
//   - **单 goroutine actor 模式**：每个共识实例串行处理消息，杜绝锁
//   - **时间由外部注入**（Ticker 接口），核心代码禁止 time.Now —— 仿真
//     harness 用确定性时钟驱动，同 seed 同结果
//   - 消息哈希、验证者排序、QC 聚合全部确定性（spec/50）
//
// 简化说明（v0 范围）：
//   - 全节点诚实（拜占庭容错测试在仿真 harness 的故障注入里做）
//   - 块验证委托给上层回调（ValidateBlock func），共识层只管流程
//   - 投票聚合用 BLS 聚合签名接口的**预留位**（v0 逐个验签，ADR-014）
package consensus

import (
	"fmt"

	"github.com/chfault/chfault/crypto"
	"github.com/chfault/chfault/types"
)

// ============================================================================
// 常量
// ============================================================================

// VoteType 是投票类型。
type VoteType uint8

const (
	// Prevote 预投票（对 Proposal 的块）。
	Prevote VoteType = 0
	// Precommit 预提交（对 prevote QC 的块）。
	Precommit VoteType = 1
)

func (v VoteType) String() string {
	if v == Prevote {
		return "PREVOTE"
	}
	return "PRECOMMIT"
}

// Step 是状态机的阶段。
type Step uint8

const (
	StepNewHeight Step = 0
	StepPropose   Step = 1
	StepPrevote   Step = 2
	StepPrecommit Step = 3
	StepCommit    Step = 4
)

func (s Step) String() string {
	switch s {
	case StepNewHeight:
		return "NEW_HEIGHT"
	case StepPropose:
		return "PROPOSE"
	case StepPrevote:
		return "PREVOTE"
	case StepPrecommit:
		return "PRECOMMIT"
	case StepCommit:
		return "COMMIT"
	default:
		return "UNKNOWN"
	}
}

// ============================================================================
// 消息（spec/50）
// ============================================================================

// Message 是共识消息的统一封装（网络上传输的形态）。
type Message struct {
	Height types.Height
	Round  types.Round
	From   types.Address
	Body   isMessage
}

// isMessage 消息体接口（sealed interface，防外部实现）。
type isMessage interface{ isConsensusMsg() }

// Proposal 是提议消息。
type Proposal struct {
	POLRound  types.Round // 本提议引用的POL轮次（-1 表示无）
	Block     []byte      // 编码后的区块
	BlockHash types.Hash
	Signature types.Signature
}

func (Proposal) isConsensusMsg() {}

// Vote 是投票消息（prevote / precommit 共用）。
type Vote struct {
	Type      VoteType
	BlockHash types.Hash // 零值 = nil vote（对该轮投反对票）
	Signature types.Signature
}

func (Vote) isConsensusMsg() {}

// QC 是聚合证书（n/3*2+1 票的聚合证明）。
//
// 两级签名验证（ADR-014 落地）：
//   - AggSig 非空：BLS 聚合签名（优先 —— 一次配对验证，O(1)）
//   - AggSig 为空：退回逐个验签（兼容 v3.1 早期与调试模式）
//
// Signatures 在两种模式下都保留：块同步方需要重建聚合，
// 审计方需要逐个核对（QC 的证据材料）。
type QC struct {
	Type      VoteType
	Height    types.Height
	Round     types.Round
	BlockHash types.Hash
	// Signatures 签名列表（按验证者地址排序 —— 确定性）。
	Signatures []QCSignature
	// AggSig BLS 聚合签名（48 字节，可空 —— 兼容模式）。
	AggSig []byte
	// AggBitmap 签名者位图（按验证者集排序的第 i 位 = 第 i 个验证者已签）。
	// nil 时 AggSig 无效（逐个验签模式）。
	AggBitmap []byte
}

func (QC) isConsensusMsg() {}

// QCSignature 是 QC 里的单个签名。
type QCSignature struct {
	Validator types.Address
	Sig       types.Signature
}

// Hash 计算消息哈希（去重与签名用）。
func (m *Message) Hash() types.Hash {
	var buf []byte
	buf = append(buf, crypto.Uint64BE(uint64(m.Height))...)
	buf = append(buf, crypto.Uint32BE(uint32(m.Round))...)
	buf = append(buf, m.From.Bytes()...)
	switch b := m.Body.(type) {
	case Proposal:
		buf = append(buf, 0x01)
		buf = append(buf, crypto.Uint32BE(uint32(b.POLRound))...)
		buf = append(buf, b.BlockHash.Bytes()...)
	case Vote:
		buf = append(buf, 0x02, byte(b.Type))
		buf = append(buf, b.BlockHash.Bytes()...)
	case QC:
		buf = append(buf, 0x03, byte(b.Type))
		buf = append(buf, crypto.Uint64BE(uint64(b.Height))...)
		buf = append(buf, crypto.Uint32BE(uint32(b.Round))...)
		buf = append(buf, b.BlockHash.Bytes()...)
	default:
		buf = append(buf, 0xff)
	}
	return crypto.Keccak256(buf)
}

// String 调试输出。
func (m *Message) String() string {
	switch b := m.Body.(type) {
	case Proposal:
		return fmt.Sprintf("Proposal(h=%d r=%d pol=%d proposer=%s)",
			m.Height, m.Round, b.POLRound, m.From.String()[:10])
	case Vote:
		return fmt.Sprintf("Vote(%s h=%d r=%d from=%s block=%s)",
			b.Type, m.Height, m.Round, m.From.String()[:10], shortHash(b.BlockHash))
	case QC:
		return fmt.Sprintf("QC(%s h=%d r=%d sigs=%d block=%s)",
			b.Type, b.Height, b.Round, len(b.Signatures), shortHash(b.BlockHash))
	default:
		return "Unknown"
	}
}

func shortHash(h types.Hash) string {
	s := h.String()
	if len(s) > 10 {
		return s[:10]
	}
	return s
}

// ============================================================================
// 验证者集（spec/50 §3）
// ============================================================================

// Validator 是一个验证者。
type Validator struct {
	Address types.Address
	Power   uint64 // v0 全部为 1（power 加权在 v2 PoS 引入）
}

// ValidatorSet 是验证者集合（按地址排序，确定性）。
type ValidatorSet struct {
	vals []Validator
	// byAddr 快速查找
	byAddr map[types.Address]int
	// totalPower 总权重
	totalPower uint64
}

// NewValidatorSet 创建验证者集（自动按地址排序）。
func NewValidatorSet(vals []Validator) *ValidatorSet {
	vs := &ValidatorSet{byAddr: make(map[types.Address]int)}
	// 按 Address 字节序排序（spec/01 §8）—— 与 genesis 的排序规则一致
	sorted := make([]Validator, len(vals))
	copy(sorted, vals)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j].Address.Compare(sorted[j-1].Address) < 0; j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	vs.vals = sorted
	for i, v := range vs.vals {
		vs.byAddr[v.Address] = i
		vs.totalPower += v.Power
	}
	return vs
}

// Size 验证者数量。
func (vs *ValidatorSet) Size() int { return len(vs.vals) }

// TotalPower 总权重。
func (vs *ValidatorSet) TotalPower() uint64 { return vs.totalPower }

// Get 按地址查 index（-1 = 不在集内）。
func (vs *ValidatorSet) Get(addr types.Address) int {
	if i, ok := vs.byAddr[addr]; ok {
		return i
	}
	return -1
}

// At 按下标取。
func (vs *ValidatorSet) At(i int) (Validator, bool) {
	if i < 0 || i >= len(vs.vals) {
		return Validator{}, false
	}
	return vs.vals[i], true
}

// ProposerOf 计算某 height/round 的提议者。
//
// 轮转规则：`(height + round) % size` —— 确定性、可独立验证。
// ⚠️ 不能用 height*常数 —— 常数若是 size 的倍数，所有高度的 round 0
// 提议者都相同，轮转失效（实测踩过：1000 % 4 == 0）。
// power 加权轮转在 v2 引入（ADR-015 预留点 1）。
func (vs *ValidatorSet) ProposerOf(height types.Height, round types.Round) types.Address {
	if len(vs.vals) == 0 {
		return types.Address{}
	}
	idx := (uint64(height) + uint64(round)) % uint64(len(vs.vals))
	return vs.vals[idx].Address
}

// Quorum 阈值：>= 2/3 总权重（Tendermint 语义，取上取整）。
func (vs *ValidatorSet) Quorum() uint64 {
	return vs.totalPower/3*2 + 1
}

// HasQuorum 判断票数是否达到法定人数。
func (vs *ValidatorSet) HasQuorum(power uint64) bool {
	return power >= vs.Quorum()
}
