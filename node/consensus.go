package node

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	gethTypes "github.com/ethereum/go-ethereum/core/types"

	"github.com/chfault/chfault/chain"
	"github.com/chfault/chfault/consensus"
	"github.com/chfault/chfault/crypto"
	"github.com/chfault/chfault/network"
	"github.com/chfault/chfault/types"
)

// ============================================================================
// 共识接线（M2）：把 sim 里验证过的共识状态机接入真实节点
//
// 单节点模式（v0）：ValidatorSet 只有自己 → 1 票即 quorum →
// 共识立即提交（语义与多节点完全一致，只是没有通信）。
// M2.x 多节点：ValidatorSet 来自创世，Outgoing 接真实网络层。
// ============================================================================

// devSigner 是开发模式签名器。
//
// ⚠️ 私钥来自固定 dev 种子 —— 仅用于单节点/开发网。
// M3 接入 keystore / HSM 后移除（生产节点必须持有受保护的密钥）。
type devSigner struct {
	priv *secp256k1.PrivateKey
	addr types.Address
}

// newDevSigner 从种子创建开发签名器。
func newDevSigner(seed byte) *devSigner {
	buf := make([]byte, 32)
	for i := range buf {
		buf[i] = seed
	}
	priv := secp256k1.PrivKeyFromBytes(buf)
	addr, _ := crypto.PubKeyToAddress(priv.PubKey().SerializeUncompressed())
	return &devSigner{priv: priv, addr: addr}
}

// Sign 实现 consensus.Signer。
func (d *devSigner) Sign(digest types.Hash) (types.Signature, error) {
	return crypto.Sign(digest, d.priv)
}

// Verify 实现 consensus.Signer。
func (d *devSigner) Verify(digest types.Hash, sig types.Signature, expected types.Address) bool {
	return crypto.Verify(digest, sig, expected)
}

// consensusOutgoing 是共识消息的出站通道：
// 有 Swarm 时广播到网络；单节点模式（无网络）为 no-op。
// 自己的票由 castVote→recordVote 本地计入，不需要网络回环。
type consensusOutgoing struct {
	swarm *network.Swarm
}

// Broadcast 实现 consensus.Outgoing。
func (o *consensusOutgoing) Broadcast(msg *consensus.Message) {
	if o.swarm == nil {
		return // 单节点模式
	}
	env, err := network.NewConsensusEnvelope(msg)
	if err != nil {
		return
	}
	o.swarm.Broadcast(env)
}

// initConsensus 初始化共识状态机。
//
// 验证者集来源：
//   - cfg.Consensus.Validators 为空 → 单节点模式（只有自己）
//   - 非空 → 多节点模式：验证者集来自配置，**必须包含自己的地址**
//     （每个节点用不同 KeySeed 派生不同地址）
func (n *Node) initConsensus() error {
	chainID, _ := parseChainID(n.cfg.Chain.ChainID)
	_ = chainID

	signer := newDevSigner(byte(n.cfg.Consensus.KeySeed))

	var valSet *consensus.ValidatorSet
	if len(n.cfg.Consensus.Validators) == 0 {
		// 单节点模式
		valSet = consensus.NewValidatorSet([]consensus.Validator{
			{Address: signer.addr, Power: 1},
		})
	} else {
		// 多节点模式：解析配置的验证者地址
		vals := make([]consensus.Validator, 0, len(n.cfg.Consensus.Validators))
		for i, vs := range n.cfg.Consensus.Validators {
			addr, err := parseAddrHex(vs)
			if err != nil {
				return fmt.Errorf("node: validators[%d] 非法: %w", i, err)
			}
			vals = append(vals, consensus.Validator{Address: addr, Power: 1})
		}
		valSet = consensus.NewValidatorSet(vals)
		// fail fast：自己的地址必须在集合内，否则永远无法参与共识
		if valSet.Get(signer.addr) < 0 {
			return fmt.Errorf(
				"node: 本节点地址 %s 不在 consensus.validators 中（检查 keySeed 是否与该验证者匹配）",
				signer.addr.String())
		}
	}

	// 网络层（可选）：cfg.Network.Listen 配置了监听地址时启动
	out := &consensusOutgoing{}
	if len(n.cfg.Network.Listen) > 0 {
		cfg := network.Config{
			Listen:      n.cfg.Network.Listen[0],
			NodeID:      signer.addr.String(),
			StaticPeers: n.cfg.Network.Bootstrap,
			Logger:      n.logger,
		}
		swarm, err := network.NewSwarm(cfg, n.handleNetworkMessage)
		if err != nil {
			return fmt.Errorf("node: 网络启动失败: %w", err)
		}
		n.swarm = swarm
		out.swarm = swarm
		n.logger.Info("网络已就绪", "addr", swarm.Addr())
	}

	cfg := consensus.Config{
		Self:       signer.addr,
		Validators: valSet,
		Signer:     signer,
		// ValidateBlock：单节点模式自己出块自己验证，
		// 完整校验在 BuildBlock→AppendBlock 里做（链层拒绝非法块）
	}
	st, err := consensus.NewState(cfg, out, n)
	if err != nil {
		return fmt.Errorf("node: 初始化共识失败: %w", err)
	}
	n.logger.Info("共识已就绪", "validators", valSet.Size(),
		"self", signer.addr.String()[:10])
	st.SetProposalMaker(func(height types.Height, ts uint64) *consensus.BlockProposal {
		built, err := n.blockBuilder().BuildBlock(n.chain.Head())
		if err != nil {
			n.logger.Error("出块失败", "err", err)
			return nil
		}
		n.pendingBuilt = built
		blkHash, herr := built.Block.Header.Hash()
		if herr != nil {
			n.logger.Error("计算块哈希失败", "err", herr)
			return nil
		}
		blkData, derr := built.Block.Encode()
		if derr != nil {
			n.logger.Error("编码区块失败", "err", derr)
			return nil
		}
		return &consensus.BlockProposal{
			BlockData: blkData,
			Hash:      types.BlockHash(blkHash),
		}
	})
	n.consensus = st
	n.devKey = signer
	return nil
}

// CommitBlock 实现 consensus.CommitSink：持久化达成最终性的区块。
//
// 两种来源：
//   - 本节点是提议者：pendingBuilt 有完整 BuiltBlock（含收据与 geth 交易）
//   - 本节点是其他验证者：只有共识消息携带的 blockData → 解码区块
//     （收据需要重新执行生成 —— v0 简化：从块携带的收据列表解码；
//     M2.x 块同步协议统一收据格式）
func (n *Node) CommitBlock(blockData []byte, height types.Height) error {
	var blk *chain.Block
	var gethTxs []*gethTypes.Transaction

	if n.pendingBuilt != nil && uint64(n.pendingBuilt.Block.Header.Height) == uint64(height) {
		// 提议者路径
		blk = n.pendingBuilt.Block
		gethTxs = n.pendingBuilt.GethTxs
		n.pendingBuilt = nil
	} else {
		// 非提议者路径：从共识消息解码
		b, err := chain.DecodeBlock(blockData)
		if err != nil {
			n.logger.Error("CommitBlock 解码失败", "height", uint64(height), "err", err)
			return fmt.Errorf("node: 解码共识区块失败: %w", err)
		}
		blk = b
		// gethTxs 为 nil → 跳过池清理（TODO M2.x：统一块同步清理）
	}

	if err := n.chain.AppendBlock(blk, nil); err != nil {
		n.logger.Error("CommitBlock 追加失败", "height", uint64(height), "err", err)
		return err
	}
	if gethTxs != nil {
		_ = n.pool.RemoveAll(gethTxs)
		for _, tx := range gethTxs {
			if from, err := txFrom(tx); err == nil {
				n.pool.SetAccountNonce(from, types.Nonce(tx.Nonce()+1))
			}
		}
	}

	head := n.chain.Head()
	n.logger.Info("共识出块",
		"height", uint64(head.Height),
		"txs", len(blk.Transactions),
		"gasUsed", uint64(blk.Header.GasUsed),
	)
	return nil
}

// txFrom 恢复 geth 交易的发送者。
func txFrom(gt *gethTypes.Transaction) (types.Address, error) {
	signer := gethTypes.LatestSignerForChainID(big.NewInt(int64(gt.ChainId().Uint64())))
	from, err := gethTypes.Sender(signer, gt)
	return types.Address(from), err
}

// StartConsensusProduction 启动共识驱动的出块循环（M2，替换定时出块）。
//
// 循环：StartNewHeight(h+1) → 共识自动完成（单节点即时提交）→
// 等待 blockTime → 下一高度。多节点模式下"等待提交"由共识消息驱动，
// 这里的轮询写法是单节点简化 —— M2.x 网络接入后改为事件驱动。
func (n *Node) StartConsensusProduction(ctx context.Context, blockTime time.Duration) {
	go func() {
		ticker := time.NewTicker(blockTime)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				head := n.chain.Head()
				next := head.Height + 1
				if err := n.consensus.StartNewHeight(next, uint64(time.Now().UnixMilli())); err != nil {
					n.logger.Error("开始新高度失败", "height", uint64(next), "err", err)
					continue
				}
				// 等待共识完成（单节点即时；多节点时改为事件等待）
				deadline := time.Now().Add(5 * time.Second)
				for !n.consensus.IsCommitted(next) && time.Now().Before(deadline) {
					time.Sleep(10 * time.Millisecond)
				}
			}
		}
	}()
}

// AdvanceConsensus 手动推进一个高度（测试用；生产由 StartConsensusProduction 驱动）。
func (n *Node) AdvanceConsensus() error {
	head := n.chain.Head()
	next := head.Height + 1
	if err := n.consensus.StartNewHeight(next, uint64(time.Now().UnixMilli())); err != nil {
		return err
	}
	deadline := time.Now().Add(5 * time.Second)
	for !n.consensus.IsCommitted(next) && time.Now().Before(deadline) {
		// 消费跳轮/新高度时缓存的待自投递消息（proposal）
		if pm := n.consensus.TakePendingSelf(); pm != nil {
			_ = n.consensus.HandleMessage(pm)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !n.consensus.IsCommitted(next) {
		return fmt.Errorf("node: 共识未在 5 秒内提交高度 %d", uint64(next))
	}
	return nil
}

// Consensus 返回共识状态机（测试与监控用）。
func (n *Node) Consensus() *consensus.State { return n.consensus }

// handleNetworkMessage 处理收到的网络消息（分派到共识状态机）。
func (n *Node) handleNetworkMessage(from string, env *network.Envelope) {
	switch env.Type {
	case network.TypeConsensus:
		msg, err := network.UnmarshalConsensusMessage(env.Payload)
		if err != nil {
			n.logger.Warn("共识消息解码失败", "from", from, "err", err)
			return
		}
		if err := n.consensus.HandleMessage(msg); err != nil {
			// 非法消息只记录（重复投票等由发送者负责）
			n.logger.Debug("共识消息处理失败", "err", err)
		}
	case network.TypeTx:
		// 交易 gossip：收到邻居的交易 → 入本地池 → 转发给其他邻居
		var payload struct {
			Raw []byte `json:"raw"`
		}
		if err := json.Unmarshal(env.Payload, &payload); err != nil || len(payload.Raw) == 0 {
			n.logger.Warn("交易消息非法", "from", from)
			return
		}
		if _, err := n.SubmitRawTx(payload.Raw); err != nil {
			// 重复/非法交易静默（gossip 冗余是正常的）
			n.logger.Debug("gossip 交易入池失败", "err", err)
			return
		}
		// 继续转发（SubmitRawTx 内部也会广播 —— 用 seen set 防循环，
		// 见 gossipTx 的 seen 检查）
		n.gossipTx(payload.Raw)
	case network.TypePing:
		// 保活：v0 忽略
	default:
		n.logger.Debug("未知消息类型", "type", env.Type)
	}
}

// gossipTx 把原始交易广播给所有 peer（SubmitRawTx 成功后调用）。
//
// 防循环：seen 哈希集合（gossipSeen），上限 4096 简单清理。
func (n *Node) gossipTx(raw []byte) {
	h := types.TxHash(crypto.Keccak256(raw))
	n.gossipMu.Lock()
	if n.gossipSeen == nil {
		n.gossipSeen = make(map[types.TxHash]bool)
	}
	if n.gossipSeen[h] {
		n.gossipMu.Unlock()
		return
	}
	n.gossipSeen[h] = true
	if len(n.gossipSeen) > 4096 {
		n.gossipSeen = make(map[types.TxHash]bool) // v0：粗暴清理
	}
	n.gossipMu.Unlock()

	if n.swarm != nil {
		n.swarm.Broadcast(network.NewTxEnvelope(raw))
	}
}

// parseAddrHex 解析 0x 前缀的 20 字节地址。
func parseAddrHex(s string) (types.Address, error) {
	var addr types.Address
	if len(s) != 42 || s[:2] != "0x" {
		return addr, errors.New("需要 0x 前缀 + 40 个十六进制字符")
	}
	b, err := hex.DecodeString(s[2:])
	if err != nil {
		return addr, err
	}
	copy(addr[:], b)
	return addr, nil
}

// SwarmAddr 返回网络监听地址（测试与运维用）。
func (n *Node) SwarmAddr() string {
	if n.swarm == nil {
		return ""
	}
	return n.swarm.Addr()
}

// PeerCount 返回当前连接的 peer 数（测试与运维用）。
func (n *Node) PeerCount() int {
	if n.swarm == nil {
		return 0
	}
	return n.swarm.PeerCount()
}

// ConnectPeer 主动连接一个 peer（动态组网 —— 测试与运维用）。
func (n *Node) ConnectPeer(addr string) error {
	if n.swarm == nil {
		return errors.New("node: 网络未启用")
	}
	return n.swarm.Connect(addr)
}

// PoolGet 按哈希查询池内交易（测试与运维用）。
func (n *Node) PoolGet(hash types.TxHash) (*gethTypes.Transaction, bool) {
	return n.pool.Get(hash)
}
