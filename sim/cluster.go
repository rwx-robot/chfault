// Package sim 是确定性仿真测试框架（docs/blueprint/09 §9.12 的 M2 前置要求）。
//
// 设计目标：**同 seed 同结果** —— 网络延迟、消息顺序、时钟推进全部由
// 仿真器确定性控制，任何随机性（拜占庭行为、分区）都来自带种子的伪随机。
//
// 模型：
//
//	Cluster —— N 个 SimNode + 消息总线 + 确定性时钟
//	SimNode —— 包一层 consensus.State（出块回调、提交持久化）
//	Delivery —— 消息不立即投递，进带序号的投递队列，harness 按序投递
//
// 与真实网络的关系：harness 的投递队列对应"全连接、固定延迟"网络。
// 分区/丢包通过 harness API 注入（DropRoute），不在共识代码里出现 ——
// 共识核心保持纯粹，只管状态机。
package sim

import (
	"fmt"

	"github.com/chfault/chfault/consensus"
	"github.com/chfault/chfault/crypto"
	"github.com/chfault/chfault/types"
)

// ============================================================================
// 确定性时钟
// ============================================================================

// Clock 是确定性时钟（禁用 wall clock —— 共识代码只见此接口）。
type Clock struct {
	now uint64 // 毫秒
}

// NewClock 创建时钟。
func NewClock() *Clock { return &Clock{} }

// Now 当前时间。
func (c *Clock) Now() uint64 { return c.now }

// Advance 推进时间。
func (c *Clock) Advance(ms uint64) { c.now += ms }

// ============================================================================
// 消息投递
// ============================================================================

// Delivery 是一条待投递消息。
type Delivery struct {
	Seq  uint64 // 全局序号（决定投递顺序）
	To   types.Address
	From types.Address
	Msg  *consensus.Message
}

// Cluster 是仿真集群。
type Cluster struct {
	Clock *Clock

	// DeliveryQueue 待投递消息（按 Seq 排序投递）。
	// 用 slice + 插入排序保证确定性（不用 map 迭代）。
	Queue []Delivery
	seq   uint64

	Nodes  []*SimNode
	valSet *consensus.ValidatorSet
	muted  map[types.Address]bool // 被静音的节点（出站消息丢弃）
	keys   []*TestKey

	// DropRate 确定性丢包率（0-100，用 LCG 判定 —— 可复现）。
	DropRate uint32
	lcgState uint64

	// Dropped 丢包计数（断言用）。
	Dropped int
}

// SimNode 是仿真节点。
type SimNode struct {
	Address types.Address
	State   *consensus.State
	Cluster *Cluster

	// Committed 记录已提交的块（哈希 → 高度），断言用。
	Committed map[types.Hash]types.Height
	// commitOrder 提交顺序（哈希列表）。
	commitOrder []types.Hash
	// stepSince 进入当前共识步的仿真时间（超时判定用）。
	stepSince uint64

	// MsgMutator 拜占庭注入点：非 nil 时按目标修改出站消息。
	// 返回 nil = 丢弃该消息。仅在测试中使用 —— 生产节点没有这个钩子。
	MsgMutator func(msg *consensus.Message, to types.Address) *consensus.Message
}

// ============================================================================
// 构建
// ============================================================================

// NewCluster 创建 N 节点集群。
//
// 每个节点持有独立的确定性私钥（seed = i+1），签名真实可验证 ——
// 与生产环境的差异只在密钥来源，不在签名逻辑。
func NewCluster(n int) (*Cluster, error) {
	c := &Cluster{Clock: NewClock()}

	vals := make([]consensus.Validator, 0, n)
	keys := make([]*TestKey, 0, n)

	for i := 0; i < n; i++ {
		key := NewTestKey(byte(i + 1))
		vals = append(vals, consensus.Validator{Address: key.Addr, Power: 1})
		keys = append(keys, key)
	}

	c.keys = keys
	c.valSet = consensus.NewValidatorSet(vals)
	valSet := c.valSet

	for i := 0; i < n; i++ {
		node := &SimNode{
			Address:   vals[i].Address,
			Cluster:   c,
			Committed: make(map[types.Hash]types.Height),
		}
		cfg := consensus.Config{
			Self:       vals[i].Address,
			Validators: valSet,
			Signer:     &signerAdapter{key: keys[i]},
			// ValidateBlock：仿真环境不做真实块验证（M2.x 接 chain 校验）
		}
		st, err := consensus.NewState(cfg, node, node)
		if err != nil {
			return nil, err
		}
		node.State = st
		c.Nodes = append(c.Nodes, node)
	}
	return c, nil
}

// ProposerOf 暴露提议者查询（测试断言用）。
// valSet 在 NewCluster 中创建并保存在此。
func (c *Cluster) ProposerOf(h types.Height, r types.Round) types.Address {
	return c.valSet.ProposerOf(h, r)
}

// SetProposalMaker 为所有节点注入出块回调。
func (c *Cluster) SetProposalMaker(fn func(node *SimNode, height types.Height, ts uint64) *consensus.BlockProposal) {
	for _, n := range c.Nodes {
		node := n
		n.State.SetProposalMaker(func(height types.Height, ts uint64) *consensus.BlockProposal {
			return fn(node, height, ts)
		})
	}
}

// ============================================================================
// 消息路由
// ============================================================================

// Broadcast 实现 consensus.Outgoing：消息进投递队列。
//
// 顺序 = 节点创建顺序（确定性）。
func (n *SimNode) Broadcast(msg *consensus.Message) {
	c := n.Cluster
	if c.IsMuted(n.Address) {
		return // 沉默节点：出站消息全部丢弃
	}
	for _, peer := range c.Nodes {
		if peer.Address == n.Address {
			continue // 不发给自己
		}
		out := msg
		if n.MsgMutator != nil {
			out = n.MsgMutator(msg, peer.Address)
			if out == nil {
				continue // 拜占庭丢弃
			}
		}
		if c.shouldDrop() {
			c.Dropped++
			continue
		}
		c.seq++
		c.Queue = append(c.Queue, Delivery{
			Seq:  c.seq,
			To:   peer.Address,
			From: n.Address,
			Msg:  out,
		})
	}
}

// shouldDrop 确定性丢包判定（LCG，同 seed 同结果）。
func (c *Cluster) shouldDrop() bool {
	if c.DropRate == 0 {
		return false
	}
	c.lcgState = c.lcgState*6364136223846793005 + 1442695040888963407
	return (c.lcgState>>33)%100 < uint64(c.DropRate)
}

// SetSeed 设置丢包随机的种子（必须在产生任何流量前调用）。
func (c *Cluster) SetSeed(seed uint64) { c.lcgState = seed }

// Drain 投递队列中的所有消息（按 Seq 排序）。
//
// 投递过程中新产生的消息进入下一轮 Drain —— 这模拟了"一批消息
// 被处理 → 触发下一批"的传播波次，是 Tendermint 消息传播的近似。
// 返回本轮投递的消息数。
func (c *Cluster) Drain() int {
	if len(c.Queue) == 0 {
		return 0
	}

	// 按 Seq 排序（插入排序：数量小且要求确定性）
	q := c.Queue
	for i := 1; i < len(q); i++ {
		for j := i; j > 0 && q[j].Seq < q[j-1].Seq; j-- {
			q[j], q[j-1] = q[j-1], q[j]
		}
	}

	// ⚠️ 必须拷贝：若用 c.Queue[:0] 截断后继续 append，
	// 会覆盖 batch 引用的底层数组，导致消息被篡改/丢失
	// （实测踩过：同一投票被投递多次、proposal 丢失）。
	batch := make([]Delivery, len(q))
	copy(batch, q)
	c.Queue = c.Queue[:0]

	for _, d := range batch {
		node := c.nodeByAddr(d.To)
		if node == nil {
			continue
		}
		_ = node.State.HandleMessage(d.Msg) // 错误由统计断言，不中断仿真
	}
	return len(batch)
}

// RunRound 运行至消息队列清空（一个"传播波次"集合）。
func (c *Cluster) RunRound() int {
	total := 0
	for {
		n := c.Drain()
		total += n
		if n == 0 {
			break
		}
	}
	return total
}

func (c *Cluster) nodeByAddr(addr types.Address) *SimNode {
	for _, n := range c.Nodes {
		if n.Address == addr {
			return n
		}
	}
	return nil
}

// ============================================================================
// 共识接口实现
// ============================================================================

// CommitBlock 实现 consensus.CommitSink。
func (n *SimNode) CommitBlock(blockData []byte, height types.Height) error {
	// 块哈希从共识层传入太绕 —— 仿真用 keccak(blockData) 作为标识
	h := simBlockHash(blockData)
	if _, dup := n.Committed[h]; dup {
		return fmt.Errorf("sim: 高度 %d 重复提交", height)
	}
	n.Committed[h] = height
	n.commitOrder = append(n.commitOrder, h)
	return nil
}

// CommitOrder 返回提交顺序（断言用）。
func (n *SimNode) CommitOrder() []types.Hash { return n.commitOrder }

// StartHeight 让所有节点开始指定高度。
func (c *Cluster) StartHeight(h types.Height) {
	now := c.Clock.Now()
	for _, n := range c.Nodes {
		_ = n.State.StartNewHeight(h, now)
		n.MarkStep(now)
	}
}

// BlockHash 仿真块的哈希（测试用）。
func BlockHash(data []byte) types.Hash { return crypto.Keccak256(data) }

// simBlockHash 仿真块的标识（M2.x 换成真正的 BlockHeader.Hash）。
func simBlockHash(data []byte) types.Hash {
	return crypto.Keccak256(data)
}

// hexSeed 生成确定性测试私钥的十六进制（保留给可能的调试用途）。
func hexSeedUnused() string { return "" }

// DrainDebug 投递一批消息并打印（调试用）。
func (c *Cluster) DrainDebug() int {
	if len(c.Queue) == 0 {
		return 0
	}
	q := c.Queue
	for i := 1; i < len(q); i++ {
		for j := i; j > 0 && q[j].Seq < q[j-1].Seq; j-- {
			q[j], q[j-1] = q[j-1], q[j]
		}
	}
	batch := make([]Delivery, len(q))
	copy(batch, q)
	c.Queue = c.Queue[:0]
	fmt.Printf("  delivering %d msgs:", len(batch))
	for _, d := range batch {
		fmt.Printf(" %s", d.Msg.String())
		node := c.nodeByAddr(d.To)
		if node == nil {
			continue
		}
		if err := node.State.HandleMessage(d.Msg); err != nil {
			fmt.Printf(" [ERR: %v]", err)
		}
	}
	fmt.Println()
	return len(batch)
}

// ============================================================================
// 故障注入（拜占庭 / 分区）
// ============================================================================

// DropFrom 静音某节点（其出站消息不再投递）。
func (c *Cluster) DropFrom(addr types.Address) {
	if c.muted == nil {
		c.muted = make(map[types.Address]bool)
	}
	c.muted[addr] = true
}

// Unmute 解除静音（分区恢复）。
func (c *Cluster) Unmute(addr types.Address) {
	delete(c.muted, addr)
}

// IsMuted 查询静音状态。
func (c *Cluster) IsMuted(addr types.Address) bool { return c.muted[addr] }

// TimeoutDriver 超时驱动：在每个仿真 tick 调用，
// 对仍在旧步骤的节点触发超时事件。
//
// roundTimeoutMs 是每步的超时（v0 全步骤同值；Tendermint 的指数退避在
// M2.x 加入）。返回触发超时的节点数。
func (c *Cluster) TimeoutSweep(roundTimeoutMs uint64) int {
	triggered := 0
	c.Clock.Advance(roundTimeoutMs)
	now := c.Clock.Now()
	for _, n := range c.Nodes {
		st := n.State
		// 每个节点的"进入当前步的时间"由 harness 记录（见 nodeStepSince）
		if since := now - n.stepSince; since < roundTimeoutMs {
			continue
		}
		round := st.Round()
		fired := false
		switch st.Step() {
		case consensus.StepPropose:
			_ = st.OnTimeoutPropose(round)
			fired = true
		case consensus.StepPrevote:
			_ = st.OnTimeoutPrevote(round)
			fired = true
		case consensus.StepPrecommit:
			_ = st.OnTimeoutPrecommit(round)
			fired = true
		}
		if fired {
			n.stepSince = now
			triggered++
		}
		// 处理跳轮时缓存的 proposal 自投递（未来消息缓存消费）
		if pm := n.State.TakePendingSelf(); pm != nil {
			c.seq++
			c.Queue = append(c.Queue, Delivery{Seq: c.seq, To: n.Address, From: pm.From, Msg: pm})
		}
	}
	return triggered
}

// MarkStep 记录节点进入当前步的时间（harness 内部使用）。
func (n *SimNode) MarkStep(now uint64) { n.stepSince = now }

// AllCommitted 判断所有节点是否都已提交指定高度。
func (c *Cluster) AllCommitted(h types.Height) bool {
	for _, n := range c.Nodes {
		if !n.State.IsCommitted(h) {
			return false
		}
	}
	return true
}

// keys 保存各节点的测试密钥（拜占庭重签测试用）。
// 在 NewCluster 中填充。
var _ = 0

// SignVoteAs 用指定地址的密钥签署投票（拜占庭双投测试专用 ——
// 生产节点只能用自己的密钥签名，这里模拟攻击者"拥有自己密钥"的事实）。
func (c *Cluster) SignVoteAs(addr types.Address, height types.Height, round types.Round, v consensus.Vote) (types.Signature, error) {
	for _, k := range c.keys {
		if k.Addr == addr {
			return crypto.Sign(consensus.VoteDigest(height, round, v), k.Priv)
		}
	}
	return types.Signature{}, fmt.Errorf("sim: 未知地址 %s", addr.String()[:10])
}
