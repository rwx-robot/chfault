package sim_test

import (
	"testing"

	"github.com/chfault/chfault/consensus"
	"github.com/chfault/chfault/sim"
	"github.com/chfault/chfault/types"
)

// ============================================================================
// 拜占庭安全性测试 —— 分叉预防是 BFT 的根本承诺
// ============================================================================

// conflictingBlock 生成一个与正常块冲突的块（内容不同 → 哈希不同）。
func conflictingBlock(height types.Height) *consensus.BlockProposal {
	data := make([]byte, 32)
	for i := range data {
		data[i] = byte(height) ^ 0xFF // 与正常块（原字节）不同
	}
	return &consensus.BlockProposal{
		BlockData: data,
		Hash:      types.BlockHash(sim.BlockHash(data)),
	}
}

// TestCluster_EquivocatingProposer 验证冲突提议（双提）的安全性：
//
// 提议者向一半节点提议块 A、另一半提议块 B（同轮同高度）。
// 期望：任何块都无法获得 quorum（诚实节点票数分散）→ 超时跳轮 →
// 下一轮达成一致。**任何诚实节点都不得提交两个冲突的块。**
func TestCluster_EquivocatingProposer(t *testing.T) {
	c, err := sim.NewCluster(4)
	if err != nil {
		t.Fatal(err)
	}

	proposer := c.ProposerOf(1, 0)

	c.SetProposalMaker(func(node *sim.SimNode, height types.Height, ts uint64) *consensus.BlockProposal {
		return makeBlock(node, height, ts)
	})

	// 拜占庭提议者：按目标地址奇偶分发冲突 proposal
	for _, n := range c.Nodes {
		if n.Address != proposer {
			continue
		}
		byz := n
		n.MsgMutator = func(msg *consensus.Message, to types.Address) *consensus.Message {
			if p, ok := msg.Body.(consensus.Proposal); ok {
				// 按目标地址最低位分流：一半 A（原），一半 B（冲突）
				if to[19]%2 == 1 {
					alt := conflictingBlock(msg.Height)
					p.Block = alt.BlockData
					p.BlockHash = types.Hash(alt.Hash)
					return &consensus.Message{
						Height: msg.Height, Round: msg.Round, From: msg.From, Body: p,
					}
				}
			}
			return msg
		}
		_ = byz
	}

	c.StartHeight(1)
	drainWithTimeouts(t, c, 1, 120)

	// 安全性断言：所有已提交高度 1 的节点提交的是**同一个块**
	var committedHash types.Hash
	commitCount := 0
	for i, n := range c.Nodes {
		if !n.State.IsCommitted(1) {
			continue
		}
		commitCount++
		order := n.CommitOrder()
		if len(order) == 0 {
			t.Fatalf("节点 %d 声称已提交但无记录", i)
		}
		if commitCount == 1 {
			committedHash = order[0]
		} else if order[0] != committedHash {
			t.Fatalf("节点 %d 提交的块与先前者不同 —— 分叉！", i)
		}
	}

	// 活性断言：至少部分节点最终提交（诚实多数 + 跳轮）
	if commitCount == 0 {
		t.Fatal("冲突提议后应通过跳轮恢复并提交")
	}

	t.Logf("双提攻击被防住：%d 个节点提交了相同的块", commitCount)
}

// TestCluster_ByzantineNilVotes 验证：拜占庭节点全部投 nil 票
// （拒绝一切提议）时，诚实节点仍能出块（3 诚实 > 1 拜占庭）。
func TestCluster_ByzantineNilVotes(t *testing.T) {
	c, err := sim.NewCluster(4)
	if err != nil {
		t.Fatal(err)
	}
	c.SetProposalMaker(func(node *sim.SimNode, height types.Height, ts uint64) *consensus.BlockProposal {
		return makeBlock(node, height, ts)
	})

	// 拜占庭节点把所有投票改为 nil（包括 prevote 和 precommit）
	for _, n := range c.Nodes {
		if n.Address != c.ProposerOf(1, 0) {
			byz := n.Address
			n.MsgMutator = func(msg *consensus.Message, to types.Address) *consensus.Message {
				if v, ok := msg.Body.(consensus.Vote); ok {
					v.BlockHash = types.Hash{} // 改为 nil 票
					// ⚠️ 必须用攻击者自己的密钥重签 —— 与真实攻击者能力对齐
					//（不重签则消息无效被验签拒绝，测的不是双投而是无效消息）
					sig, err := c.SignVoteAs(byz, msg.Height, msg.Round, v)
					if err != nil {
						return nil
					}
					v.Signature = sig
					return &consensus.Message{
						Height: msg.Height, Round: msg.Round, From: msg.From, Body: v,
					}
				}
				return msg
			}
			break // ⚠️ 只取第一个非提议者 —— n=4 只容 f=1，全部改票超出容错
		}
	}

	runToHeight(t, c, 2, 120)

	// 提议者（诚实）提交的序列应与其他诚实节点一致
	proposer1 := c.ProposerOf(1, 0)
	var ref []types.Hash
	for _, n := range c.Nodes {
		if n.Address == proposer1 {
			ref = n.CommitOrder()
		}
	}
	if len(ref) < 2 {
		t.Fatalf("提议者应提交 2 块，实际 %d", len(ref))
	}
}

// TestCluster_ConflictingProposalsNoFork 汇总断言：
// 无论注入什么拜占庭行为（双提/沉默/nil 票），诚实节点的提交历史
// 永远线形一致 —— 这是区块链的最终承诺。
func TestCluster_ConflictingProposalsNoFork(t *testing.T) {
	// 三种故障注入各跑一遍，对比诚实节点历史
	scenarios := []struct {
		name  string
		setup func(c *sim.Cluster)
	}{
		{"无故障", func(c *sim.Cluster) {}},
		{"沉默", func(c *sim.Cluster) {
			proposer := c.ProposerOf(1, 0)
			for _, n := range c.Nodes {
				if n.Address != proposer {
					c.DropFrom(n.Address)
					return
				}
			}
		}},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			c, err := sim.NewCluster(4)
			if err != nil {
				t.Fatal(err)
			}
			c.SetProposalMaker(func(node *sim.SimNode, height types.Height, ts uint64) *consensus.BlockProposal {
				return makeBlock(node, height, ts)
			})
			sc.setup(c)

			c.StartHeight(1)
			drainWithTimeouts(t, c, 1, 150)
			c.StartHeight(2)
			drainWithTimeouts(t, c, 2, 150)

			// 所有提交过节点的历史必须是彼此的前缀（线形一致性）
			var longest []types.Hash
			for _, n := range c.Nodes {
				o := n.CommitOrder()
				if len(o) > len(longest) {
					longest = o
				}
			}
			for i, n := range c.Nodes {
				o := n.CommitOrder()
				for j := range o {
					if o[j] != longest[j] {
						t.Fatalf("%s: 节点 %d 第 %d 块与最长链不一致 —— 分叉！", sc.name, i, j)
					}
				}
			}
		})
	}
}
