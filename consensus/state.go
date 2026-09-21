package consensus

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"

	"github.com/chfault/chfault/crypto"
	"github.com/chfault/chfault/types"
)

// ============================================================================
// 共识状态机（单 goroutine actor，所有方法非并发安全 —— 由外部串行调用）
// ============================================================================

// 错误。
var (
	// ErrNotProposer 不是本轮提议者。
	ErrNotProposer = errors.New("consensus: 不是本轮提议者")
	// ErrInvalidMessage 非法消息。
	ErrInvalidMessage = errors.New("consensus: 非法消息")
	// ErrOldHeight 消息高度落后。
	ErrOldHeight = errors.New("consensus: 消息高度落后")
	// ErrUnknownValidator 验证者不在集内。
	ErrUnknownValidator = errors.New("consensus: 未知验证者")
	// ErrBadSignature 签名验证失败。
	ErrBadSignature = errors.New("consensus: 签名验证失败")
)

// Config 是共识配置。
type Config struct {
	// Self 本节点地址。
	Self types.Address
	// Validators 验证者集。
	Validators *ValidatorSet
	// Signer 签名器（仿真环境用假签名器，真实环境用 keystore）。
	Signer Signer
	// ValidateBlock 块验证回调（委托上层：chain 校验 + EVM 执行）。
	// 返回 nil 表示合法。
	ValidateBlock func(blockData []byte, height types.Height, parentHash types.BlockHash) error
}

// Signer 是签名抽象（确定性注入：仿真与真实环境共用接口）。
type Signer interface {
	// Sign 对 consensus 消息摘要签名。
	Sign(digest types.Hash) (types.Signature, error)
	// Verify 验证某地址的签名。
	Verify(digest types.Hash, sig types.Signature, addr types.Address) bool
}

// Ticker 是时间抽象（确定性注入：仿真时钟 / 真实 wall clock）。
//
// 共识不自己起 goroutine 计时 —— 由外部驱动 Tick 事件，
// 这使得仿真可以精确控制超时顺序。
type Ticker interface {
	// Now 返回当前逻辑时间（毫秒）。
	Now() uint64
}

// Outgoing 是共识引擎对外发送消息的出口。
type Outgoing interface {
	// Broadcast 向其他所有验证者广播消息。
	Broadcast(msg *Message)
}

// BlockProposal 是上层（node）交给共识的出块结果。
type BlockProposal struct {
	// BlockData 编码后的区块。
	BlockData []byte
	// Hash 区块哈希。
	Hash types.BlockHash
}

// CommitSink 是共识提交区块的出口（node 层持久化）。
type CommitSink interface {
	// CommitBlock 提交一个达成最终性的区块。
	CommitBlock(blockData []byte, height types.Height) error
}

// ============================================================================
// 投票收集
// ============================================================================

// voteSet 收集某一 (height, round, type) 的投票。
//
// 关键不变量：**每个验证者每轮每类型只能投一票**（重复投票直接拒绝）。
// 这保证了 power 统计不会重复计数。
type voteSet struct {
	typ      VoteType
	round    types.Round
	votes    map[types.Address]Vote
	power    uint64 // 已投有效票的总权重
	byBlock  map[types.Hash]uint64
	maxBlock types.Hash // 当前 power 最高的块（零值 = nil 占多数）
	maxPower uint64
	// nilPower 投给"空块"（反对）的权重总和。
	// 达到法定人数 = 该轮无法就任何块达成一致 → 跳轮（活性保证）。
	nilPower uint64
}

func newVoteSet(typ VoteType, round types.Round) *voteSet {
	return &voteSet{
		typ:     typ,
		round:   round,
		votes:   make(map[types.Address]Vote),
		byBlock: make(map[types.Hash]uint64),
	}
}

// add 记录一票。返回该块是否新达到法定人数。
func (vs *voteSet) add(v Vote, addr types.Address, power uint64, quorum uint64) (bool, error) {
	if _, dup := vs.votes[addr]; dup {
		return false, fmt.Errorf("%w: %s 重复投票", ErrInvalidMessage, addr.String()[:10])
	}
	vs.votes[addr] = v
	vs.power += power

	// nil vote（零哈希）：计入 nilPower，用于跳轮判定
	if v.BlockHash == (types.Hash{}) {
		vs.nilPower += power
		return vs.nilPower >= quorum, nil
	}
	vs.byBlock[v.BlockHash] += power
	if vs.byBlock[v.BlockHash] > vs.maxPower {
		vs.maxPower = vs.byBlock[v.BlockHash]
		vs.maxBlock = v.BlockHash
	}
	return vs.byBlock[v.BlockHash] >= quorum, nil
}

// QCOf 若某块已达法定人数，构造 QC。
func (vs *voteSet) QCOf(height types.Height) *QC {
	if vs.maxPower == 0 {
		return nil
	}
	// 收集投给 maxBlock 的签名。
	// ⚠️ 确定性关键：必须按验证者地址排序后遍历（不能 range map）——
	// QC 签名顺序决定 QC 的字节表示与后续聚合哈希，顺序不稳定 = 分叉。
	// determinism linter 抓到过这里用 range map 的版本。
	addrs := slices.SortedFunc(maps.Keys(vs.votes),
		func(a, b types.Address) int { return a.Compare(b) })

	sigs := make([]QCSignature, 0, len(addrs))
	for _, addr := range addrs {
		if v := vs.votes[addr]; v.BlockHash == vs.maxBlock {
			sigs = append(sigs, QCSignature{Validator: addr, Sig: v.Signature})
		}
	}
	return &QC{
		Type:       vs.typ,
		Height:     height,
		Round:      vs.round,
		BlockHash:  vs.maxBlock,
		Signatures: sigs,
	}
}

// ============================================================================
// 共识状态机
// ============================================================================

// State 是单个共识实例（一个验证者）的状态机。
type State struct {
	cfg    Config
	out    Outgoing
	commit CommitSink

	mu     sync.Mutex
	height types.Height
	round  types.Round
	step   Step

	// 当前高度的状态
	proposal    *Message
	lockedHash  types.Hash
	lockedRound types.Round

	// 投票收集（当前 round）
	prevotes   *voteSet
	precommits *voteSet

	// 已收到的 QC（跨轮传播）
	anyPrevoteQC   *QC
	anyPrecommitQC *QC

	// 已提交高度（防重放）
	lastCommitted types.Height

	// makeProposal 出块回调（node 注入）
	makeProposal func(height types.Height, timestamp uint64) *BlockProposal

	// pendingSelf 待自投递消息（跳轮时从缓存取出，由 harness 投回给自己）。
	pendingSelf *Message

	// futureHeightProps 未来高度的 proposal 缓存。
	// ⚠️ 必要性（多节点实测）：各节点 StartNewHeight 的时刻不可能精确同步，
	// 提议者的 proposal 先于慢节点的 StartNewHeight 到达时会被"未来高度"
	// 丢弃 → 慢节点永远收不到 proposal → 全网卡死。
	// 缓存后 StartNewHeight 立即消费。
	futureHeightProps map[types.Height]*Message

	// futureProps 未来轮次的 proposal 缓存。
	// ⚠️ 必要性（实测踩过）：proposal 只广播一次，若节点因分区/超时
	// 轮次落后，跳轮后永远收不到该轮 proposal → 卡死。
	// Tendermint 同款解法：缓存未来轮 proposal，跳轮时立即消费。
	futureProps map[types.Round]*Message
}

// NewState 创建共识状态机。
func NewState(cfg Config, out Outgoing, commit CommitSink) (*State, error) {
	if cfg.Validators == nil {
		return nil, errors.New("consensus: 缺少验证者集")
	}
	if cfg.Signer == nil {
		return nil, errors.New("consensus: 缺少签名器")
	}
	if cfg.Validators.Get(cfg.Self) < 0 {
		return nil, fmt.Errorf("%w: %s", ErrUnknownValidator, cfg.Self.String()[:10])
	}
	return &State{
		cfg:               cfg,
		out:               out,
		commit:            commit,
		futureProps:       make(map[types.Round]*Message),
		futureHeightProps: make(map[types.Height]*Message),
	}, nil
}

// StartNewHeight 开始一个新高度（由外部在提交后 / 启动时调用）。
func (s *State) StartNewHeight(height types.Height, timestamp uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if height <= s.lastCommitted && s.lastCommitted > 0 {
		return fmt.Errorf("%w: %d <= 已提交 %d", ErrOldHeight, height, s.lastCommitted)
	}

	s.height = height
	s.round = 0
	s.step = StepPropose
	s.proposal = nil
	s.lockedHash = types.Hash{}
	s.lockedRound = 0
	s.prevotes = newVoteSet(Prevote, 0)
	s.precommits = newVoteSet(Precommit, 0)
	s.anyPrevoteQC = nil
	s.anyPrecommitQC = nil

	// 若本节点是提议者 → 立即提议
	proposer := s.cfg.Validators.ProposerOf(height, 0)
	if proposer == s.cfg.Self && s.cfg.Signer != nil {
		s.proposeCurrentRound(timestamp)
		return nil
	}
	// 非提议者：若已有该高度缓存的 proposal（提议者更快），重新自投递
	if cached, ok := s.futureHeightProps[height]; ok {
		delete(s.futureHeightProps, height)
		s.pendingSelf = cached
	}
	return nil
}

// Height / Round / Step 访问器。
func (s *State) Height() types.Height { s.mu.Lock(); defer s.mu.Unlock(); return s.height }
func (s *State) Round() types.Round   { s.mu.Lock(); defer s.mu.Unlock(); return s.round }
func (s *State) Step() Step           { s.mu.Lock(); defer s.mu.Unlock(); return s.step }

// proposeCurrentRound 发起提议（调用方必须已持有锁、且本节点是提议者）。
func (s *State) proposeCurrentRound(timestamp uint64) {
	// 出块回调：上层生成并编码区块
	if s.makeProposal == nil {
		return
	}
	blk := s.makeProposal(s.height, timestamp)
	if blk == nil {
		return
	}

	prop := Proposal{
		POLRound:  types.NoPOLRound, // 无 POL（spec/50 §2）
		Block:     blk.BlockData,
		BlockHash: types.Hash(blk.Hash),
	}

	// 签名提议摘要
	digest := s.proposalDigest(s.height, s.round, prop)
	if sig, err := s.cfg.Signer.Sign(digest); err == nil {
		prop.Signature = sig
	}

	msg := &Message{Height: s.height, Round: s.round, From: s.cfg.Self, Body: prop}
	s.out.Broadcast(msg)
	s.proposal = msg
	// 提议后进入 prevote 阶段（自己先投）
	s.enterPrevote()
}

// SetProposalMaker 注入出块回调（node 层调用）。
func (s *State) SetProposalMaker(fn func(height types.Height, timestamp uint64) *BlockProposal) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.makeProposal = fn
}

// proposalDigest 计算提议的签名摘要。
func (s *State) proposalDigest(height types.Height, round types.Round, p Proposal) types.Hash {
	buf := make([]byte, 0, 64)
	buf = append(buf, []byte("chfault-proposal")...)
	buf = append(buf, crypto.Uint64BE(uint64(height))...)
	buf = append(buf, crypto.Uint32BE(uint32(round))...)
	buf = append(buf, crypto.Uint32BE(uint32(p.POLRound))...)
	buf = append(buf, p.BlockHash.Bytes()...)
	return crypto.Keccak256(buf)
}

// voteDigest 计算投票的签名摘要。
func (s *State) voteDigest(height types.Height, round types.Round, v Vote) types.Hash {
	return VoteDigest(height, round, v)
}

// VoteDigest 计算投票摘要（导出：仿真拜占庭测试需要按拜占庭节点重签）。
func VoteDigest(height types.Height, round types.Round, v Vote) types.Hash {
	buf := make([]byte, 0, 64)
	buf = append(buf, []byte("chfault-vote")...)
	buf = append(buf, byte(v.Type))
	buf = append(buf, crypto.Uint64BE(uint64(height))...)
	buf = append(buf, crypto.Uint32BE(uint32(round))...)
	buf = append(buf, v.BlockHash.Bytes()...)
	return crypto.Keccak256(buf)
}

// HandleMessage 处理一条共识消息（actor 主入口）。
func (s *State) HandleMessage(msg *Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if msg.Height < s.height {
		return fmt.Errorf("%w: %d < %d", ErrOldHeight, msg.Height, s.height)
	}
	if msg.Height > s.height {
		// 未来高度：缓存 proposal（StartNewHeight 时消费）；
		// 投票等其他消息仍丢弃（新高度开始后重新投票）
		if _, ok := msg.Body.(Proposal); ok {
			if _, dup := s.futureHeightProps[msg.Height]; !dup {
				s.futureHeightProps[msg.Height] = msg
			}
		}
		return nil
	}

	// 验证者必须在集内
	idx := s.cfg.Validators.Get(msg.From)
	if idx < 0 {
		return fmt.Errorf("%w: %s", ErrUnknownValidator, msg.From.String()[:10])
	}
	val, _ := s.cfg.Validators.At(idx)

	switch body := msg.Body.(type) {
	case Proposal:
		return s.handleProposal(msg, &body, val)
	case Vote:
		return s.handleVote(msg, &body, val)
	case QC:
		return s.handleQC(msg, &body)
	default:
		return fmt.Errorf("%w: 未知消息体", ErrInvalidMessage)
	}
}

// handleProposal 处理提议。
func (s *State) handleProposal(msg *Message, prop *Proposal, val Validator) error {
	// 只有本轮提议者能提议
	want := s.cfg.Validators.ProposerOf(msg.Height, msg.Round)
	if msg.From != want {
		return fmt.Errorf("%w: 期望 %s，实际 %s",
			ErrNotProposer, want.String()[:10], msg.From.String()[:10])
	}

	// 未来轮的 proposal：缓存（跳轮时消费）
	if msg.Round > s.round {
		if _, dup := s.futureProps[msg.Round]; !dup {
			s.futureProps[msg.Round] = msg
		}
		return nil
	}
	if msg.Round < s.round {
		return nil // 过去轮：丢弃
	}

	if s.step != StepPropose {
		return nil // 非提议阶段收到提议：v0 丢弃
	}
	if s.proposal != nil {
		return nil // 已有提议（重复提议是拜占庭行为，v0 丢弃第一份）
	}

	// 验证签名
	digest := s.proposalDigest(msg.Height, msg.Round, *prop)
	if !s.cfg.Signer.Verify(digest, prop.Signature, msg.From) {
		return fmt.Errorf("%w: proposal", ErrBadSignature)
	}

	// 验证块（委托上层）
	if s.cfg.ValidateBlock != nil {
		if err := s.cfg.ValidateBlock(prop.Block, msg.Height,
			types.BlockHash{}); err != nil { // parentHash 由上层从缓存取；v0 简化
			return fmt.Errorf("%w: 块校验失败: %v", ErrInvalidMessage, err)
		}
	}

	s.proposal = msg
	s.enterPrevote()
	return nil
}

// enterPrevote 进入 prevote 阶段：对本轮提议投票。
func (s *State) enterPrevote() {
	if s.step != StepPropose {
		return
	}
	s.step = StepPrevote

	var blockHash types.Hash
	if s.proposal != nil {
		if p, ok := s.proposal.Body.(Proposal); ok {
			blockHash = p.BlockHash
		}
	}
	s.castVote(Prevote, blockHash)
}

// castVote 投出一票并广播。
func (s *State) castVote(typ VoteType, blockHash types.Hash) {
	v := Vote{Type: typ, BlockHash: blockHash}
	digest := s.voteDigest(s.height, s.round, v)
	if sig, err := s.cfg.Signer.Sign(digest); err == nil {
		v.Signature = sig
	}
	msg := &Message{Height: s.height, Round: s.round, From: s.cfg.Self, Body: v}
	s.out.Broadcast(msg)
	// 自己的票也计入（actor 内直接处理）
	_ = s.recordVote(msg, &v)
}

// handleQC 处理他人广播的 QC。
//
// QC 的合法性验证（签名数量、成员）在 VerifyQC 完成；
// 收到合法 prevote QC 且自己在 prevote 阶段 → 锁块进 precommit；
// 收到合法 precommit QC 且块与已知提议一致 → 提交。
func (s *State) handleQC(msg *Message, qc *QC) error {
	// 与当前轮不符：v0 丢弃
	if qc.Height != s.height || qc.Round != s.round {
		return nil
	}
	if !s.VerifyQC(qc) {
		return fmt.Errorf("%w: QC", ErrBadSignature)
	}

	switch qc.Type {
	case Prevote:
		if s.step == StepPropose || s.step == StepPrevote {
			s.anyPrevoteQC = qc
			s.lockedHash = qc.BlockHash
			s.lockedRound = qc.Round
			s.step = StepPrecommit
			s.castVote(Precommit, qc.BlockHash)
		}
	case Precommit:
		if s.step == StepPrecommit || s.step == StepPrevote {
			s.anyPrecommitQC = qc
			s.commitByHash(qc.BlockHash)
		}
	}
	return nil
}

// commitByHash 按块哈希提交（前提：本节点持有对应提议）。
func (s *State) commitByHash(blockHash types.Hash) {
	if s.proposal != nil {
		if p, ok := s.proposal.Body.(Proposal); ok && p.BlockHash == blockHash {
			if s.commit != nil {
				_ = s.commit.CommitBlock(p.Block, s.height)
			}
			s.lastCommitted = s.height
			s.step = StepCommit
		}
	}
}

// VerifyQC 验证 QC：签名数量达到法定人数 + 每个签名可验证。
//
// v0 逐个验签（ADR-014 预留 BLS 聚合）。
func (s *State) VerifyQC(qc *QC) bool {
	quorum := s.cfg.Validators.Quorum()
	if uint64(len(qc.Signatures)) < quorum {
		return false
	}
	// 签名必须按地址排序（确定性检查）
	for i := 1; i < len(qc.Signatures); i++ {
		if qc.Signatures[i].Validator.Compare(qc.Signatures[i-1].Validator) < 0 {
			return false
		}
	}
	v := Vote{Type: qc.Type, BlockHash: qc.BlockHash}
	digest := s.voteDigest(qc.Height, qc.Round, v)
	for _, sig := range qc.Signatures {
		if s.cfg.Validators.Get(sig.Validator) < 0 {
			return false
		}
		if !s.cfg.Signer.Verify(digest, sig.Sig, sig.Validator) {
			return false
		}
	}
	return true
}

// handleVote 处理投票。
func (s *State) handleVote(msg *Message, vote *Vote, val Validator) error {
	// 只处理当前轮的投票（跨轮投票：v0 丢弃，真实实现收集用于跳轮）
	if msg.Round != s.round {
		return nil
	}

	var vs *voteSet
	switch vote.Type {
	case Prevote:
		vs = s.prevotes
	case Precommit:
		vs = s.precommits
	default:
		return fmt.Errorf("%w: 未知投票类型", ErrInvalidMessage)
	}

	// 验证签名
	digest := s.voteDigest(msg.Height, msg.Round, *vote)
	if !s.cfg.Signer.Verify(digest, vote.Signature, msg.From) {
		return fmt.Errorf("%w: vote", ErrBadSignature)
	}

	newQC, err := s.recordVoteTo(vs, msg, vote, val)
	if err != nil {
		return err
	}
	if newQC {
		s.onQuorum(vote.Type)
	}
	return nil
}

// recordVote 记录自己的票（不广播）。
func (s *State) recordVote(msg *Message, vote *Vote) error {
	var vs *voteSet
	if vote.Type == Prevote {
		vs = s.prevotes
	} else {
		vs = s.precommits
	}
	idx := s.cfg.Validators.Get(msg.From)
	val, _ := s.cfg.Validators.At(idx)
	newQC, err := s.recordVoteTo(vs, msg, vote, val)
	if err != nil {
		return err
	}
	if newQC {
		s.onQuorum(vote.Type)
	}
	return nil
}

// recordVoteTo 向指定 voteSet 记录。
func (s *State) recordVoteTo(vs *voteSet, msg *Message, vote *Vote, val Validator) (bool, error) {
	quorum := s.cfg.Validators.Quorum()
	return vs.add(*vote, msg.From, val.Power, quorum)
}

// onQuorum 某类型的票达到法定人数（块 QC 或 nil QC）。
func (s *State) onQuorum(typ VoteType) {
	switch typ {
	case Prevote:
		if s.step != StepPrevote {
			return
		}
		// nil prevote 达到法定人数 → 本轮无块可投 → 跳轮
		if s.prevotes.nilPower >= s.cfg.Validators.Quorum() &&
			s.prevotes.maxPower < s.cfg.Validators.Quorum() {
			s.step = StepPrecommit // 占位离开当前步
			s.enterNewRound(s.round + 1)
			return
		}
		qc := s.prevotes.QCOf(s.height)
		if qc == nil {
			return
		}
		s.anyPrevoteQC = qc
		// 记录锁定块
		s.lockedHash = qc.BlockHash
		s.lockedRound = qc.Round
		// 广播 QC 并进入 precommit
		s.out.Broadcast(&Message{Height: s.height, Round: s.round, From: s.cfg.Self, Body: *qc})
		s.step = StepPrecommit
		// 立即对锁定的块投 precommit
		s.castVote(Precommit, qc.BlockHash)

	case Precommit:
		// nil precommit 达到法定人数 → 跳轮
		if s.precommits.nilPower >= s.cfg.Validators.Quorum() &&
			s.precommits.maxPower < s.cfg.Validators.Quorum() {
			s.enterNewRound(s.round + 1)
			return
		}
		if s.step != StepPrecommit {
			return
		}
		qc := s.precommits.QCOf(s.height)
		if qc == nil {
			return
		}
		s.anyPrecommitQC = qc
		// 达成最终性 → 提交
		s.commitCurrent(qc)
	}
}

// commitCurrent 提交当前轮的块。
func (s *State) commitCurrent(qc *QC) {
	s.step = StepCommit

	// 从提议中取出块数据
	if s.proposal != nil {
		if p, ok := s.proposal.Body.(Proposal); ok && p.BlockHash == qc.BlockHash {
			if s.commit != nil {
				_ = s.commit.CommitBlock(p.Block, s.height)
			}
			s.lastCommitted = s.height
		}
	}
}

// ============================================================================
// 超时与轮次跳跃（活性保证）
//
// Tendermint 语义：每一步都有超时；超时后投 nil 票推进流程。
// nil 票达到法定人数 = 本轮无法就任何块达成一致 → 全体跳入下一轮。
// 提议者按 (height+round) 轮转 → 新轮大概率换提议者（除非拜占庭占多数）。
// ============================================================================

// OnTimeoutPropose 提议超时：仍在 propose 步 → 投 nil prevote 进入 prevote。
func (s *State) OnTimeoutPropose(round types.Round) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.step != StepPropose || s.round != round {
		return nil // 已离开该步，忽略
	}
	s.step = StepPrevote
	s.castVote(Prevote, types.Hash{}) // nil vote
	return nil
}

// OnTimeoutPrevote prevote 超时：投 nil prevote 并进入 precommit 步。
//
// 注意：只换步不跳轮 —— precommit 超时负责跳轮（分层推进）。
func (s *State) OnTimeoutPrevote(round types.Round) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.step != StepPrevote || s.round != round {
		return nil
	}
	s.castVote(Prevote, types.Hash{})
	s.step = StepPrecommit
	return nil
}

// OnTimeoutPrecommit precommit 超时：**直接跳入下一轮**。
//
// ⚠️ 关键语义（实测死锁后修正）：跳轮**不需要** nil QC ——
// 若等 nil quorum 才跳轮，当其他节点已离开该轮时，
// 本节点永远凑不齐旧轮的 nil 票 → 永久卡死（分区恢复场景实测复现）。
// 超时本身就是 FLP 下的活性保证：即使没有任何票，超时也推进轮次。
// nil QC 只是"加速同步"的优化路径，不是跳轮的必要条件。
func (s *State) OnTimeoutPrecommit(round types.Round) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.step != StepPrecommit || s.round != round {
		return nil
	}
	s.castVote(Precommit, types.Hash{}) // 仍投出 nil 票（帮助他人同步判断）
	s.enterNewRound(round + 1)
	return nil
}

// enterNewRound 跳入新轮（nil QC 达到法定人数后调用）。
func (s *State) enterNewRound(newRound types.Round) {
	if newRound <= s.round {
		return
	}
	s.round = newRound
	s.step = StepPropose
	s.proposal = nil
	s.prevotes = newVoteSet(Prevote, newRound)
	s.precommits = newVoteSet(Precommit, newRound)
	s.anyPrevoteQC = nil
	s.anyPrecommitQC = nil
	// 锁定块保留（Tendermint 锁定规则：locked block 跨轮携带）
	// 若本节点是新轮提议者 → 提议（优先提议锁定块 —— v0 简化为重新出块）
	proposer := s.cfg.Validators.ProposerOf(s.height, s.round)
	if proposer == s.cfg.Self && s.makeProposal != nil {
		s.proposeCurrentRound(1700000000 + uint64(s.height)*1000 + uint64(s.round))
		return
	}
	// 不是提议者：检查是否有该轮的缓存 proposal（分区恢复场景）
	if cached, ok := s.futureProps[s.round]; ok {
		delete(s.futureProps, s.round)
		// 异步处理避免锁重入：直接同步调用（此时持锁，handleProposal 需要锁……）
		// 拷贝消息后解锁处理不可行 —— 改为标记，由外层驱动再次投递。
		// v0 折衷：直接内联处理（handleProposal 不加锁，由 HandleMessage 统一加锁）
		// 这里通过延迟到锁外：把消息重新放回处理队列由 harness 投递给自己。
		s.pendingSelf = cached
	}
}

// TakePendingSelf 返回并清空待自投递消息（harness 在解锁后调用）。
func (s *State) TakePendingSelf() *Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.pendingSelf
	s.pendingSelf = nil
	return m
}

// IsCommitted 报告指定高度是否已提交（node 轮询用）。
func (s *State) IsCommitted(height types.Height) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastCommitted >= height
}

// Validators 返回验证者集（只读用途）。
func (s *State) Validators() *ValidatorSet { return s.cfg.Validators }

// LastCommitted 返回最后提交的高度（0 = 尚未提交）。
func (s *State) LastCommitted() types.Height {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastCommitted
}
