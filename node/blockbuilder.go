package node

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"strings"
	"time"

	gethTypes "github.com/ethereum/go-ethereum/core/types"

	"github.com/chfault/chfault/chain"
	"github.com/chfault/chfault/crypto"
	"github.com/chfault/chfault/mempool"
	"github.com/chfault/chfault/types"
	"github.com/chfault/chfault/vm"
)

// ============================================================================
// 出块器（M1 单节点模式）
//
// M1 无共识：节点自己按 blockTime 打包出块（类似 devnet）。
// M2 接入共识后，"何时打包、谁打包"由共识层决定，
// 但"打包与执行的过程"复用 BuildBlock —— 所以它被设计为纯函数。
// ============================================================================

// BlockBuilder 从交易池打包并执行交易，构建区块。
type BlockBuilder struct {
	chain    *chain.Chain
	pool     *mempool.Pool
	evm      *vm.Engine
	baseFee  types.Uint256
	gasLimit types.Gas
	logger   *slog.Logger
	// proposer M1 固定占位；M2 由共识提供
	proposer types.Address
}

// NewBlockBuilder 创建出块器。
func NewBlockBuilder(c *chain.Chain, pool *mempool.Pool, eng *vm.Engine,
	baseFee types.Uint256, gasLimit types.Gas, logger *slog.Logger) *BlockBuilder {
	if logger == nil {
		logger = slog.Default()
	}
	return &BlockBuilder{
		chain:    c,
		pool:     pool,
		evm:      eng,
		baseFee:  baseFee,
		gasLimit: gasLimit,
		logger:   logger,
		proposer: types.Address{0x01}, // M1 单节点占位
	}
}

// BuildBlock 从池中选取、执行交易，构建新区块。
//
// 流程：
//  1. pool.Select（确定性排序，返回交易+sender 对）
//  2. 逐笔执行（revert → savepoint 回滚，gas 仍扣 —— EVM 语义）
//  3. 计算三根与 bloom
//  4. 返回完整区块（调用方决定追加还是交给共识）
//
// **确定性关键**：Select 顺序、执行顺序、收据顺序全部确定，
// 相同池子状态在任何节点产出相同区块。
// BuiltBlock 是出块结果：区块 + 收据 + 原始 geth 交易
// （geth 交易用于池清理与 nonce 推进）。
type BuiltBlock struct {
	Block    *chain.Block
	Receipts []*chain.Receipt
	GethTxs  []*gethTypes.Transaction
}

func (b *BlockBuilder) BuildBlock(parent chain.Head) (*BuiltBlock, error) {
	sess, err := b.chain.State().Begin(parent.StateRoot)
	if err != nil {
		return nil, fmt.Errorf("blockbuilder: 打开会话失败: %w", err)
	}

	execCtx := &vm.ExecutionContext{
		Height:    parent.Height + 1,
		Timestamp: uint64(parent.Height+1) + 1700000000, // v0：确定性递增
		Proposer:  b.proposer,
		BaseFee:   b.baseFee,
		GasLimit:  b.gasLimit,
		PrevHash:  types.Hash(parent.Hash),
	}

	// 1. 选取（含 sender）
	selected := b.pool.Select(b.gasLimit)

	// 2. 逐笔执行
	var (
		receipts    []*chain.Receipt
		executedTxs []*chain.Transaction
		gethTxs     []*gethTypes.Transaction
		cumulative  types.Gas
		bloom       types.Bloom
	)
	for _, sel := range selected {
		result, err := b.evm.RunTx(sess, sel.Tx, sel.Sender, execCtx)
		if err != nil {
			// 执行层错误（非 revert）：跳过该交易，不入块
			b.logger.Warn("交易执行异常，跳过", "err", err)
			continue
		}
		if !result.Success && result.VMError != "" {
			b.logger.Warn("交易 revert",
				"vmErr", result.VMError, "gasUsed", uint64(result.GasUsed))
		}

		cumulative += result.GasUsed // 失败的交易也计 gas

		txHash := types.TxHash(sel.Tx.Hash())
		r := &chain.Receipt{
			Status:            statusOf(result.Success),
			TxHash:            txHash,
			GasUsed:           result.GasUsed,
			CumulativeGasUsed: cumulative,
			Logs:              convertLogs(result.Logs),
			ContractAddress:   result.ContractAddress,
			EffectiveGasPrice: result.EffectiveGasPrice,
		}
		r.LogsBloom = r.ComputeLogsBloom()
		bloom = mergeBlooms(bloom, r.LogsBloom)
		receipts = append(receipts, r)
		executedTxs = append(executedTxs, chainTxFrom(sel.Tx, sel.Sender))
		gethTxs = append(gethTxs, sel.Tx)
	}

	// 3. 提交状态
	newRoot, err := sess.Commit()
	if err != nil {
		return nil, fmt.Errorf("blockbuilder: 提交状态失败: %w", err)
	}

	// 4. 构造区块
	vsHash, _ := b.validatorSetHash()
	header := &chain.BlockHeader{
		Version:          1,
		ChainID:          b.chain.ChainID(),
		Height:           execCtx.Height,
		Round:            0,
		Timestamp:        execCtx.Timestamp,
		PrevHash:         parent.Hash,
		Proposer:         b.proposer,
		TxRoot:           computeTxRoot(executedTxs),
		ReceiptRoot:      chain.ComputeReceiptRoot(receipts),
		StateRoot:        newRoot,
		LogsBloom:        bloom,
		GasUsed:          cumulative,
		GasLimit:         b.gasLimit,
		BaseFeePerGas:    b.baseFee,
		ValidatorSetHash: vsHash,
	}

	return &BuiltBlock{
		Block:    &chain.Block{Header: header, Transactions: executedTxs},
		Receipts: receipts,
		GethTxs:  gethTxs,
	}, nil
}

// validatorSetHash v0 返回占位哈希（M2 由验证者集提供）。
func (b *BlockBuilder) validatorSetHash() (types.Hash, error) {
	return types.Hash{0xab}, nil
}

// ============================================================================
// Node 的出块驱动
// ============================================================================

// blockBuilder 构造出块器（依赖注入集中点）。
func (n *Node) blockBuilder() *BlockBuilder {
	return NewBlockBuilder(n.chain, n.pool, n.evm, n.pool.BaseFee(), 30_000_000, n.logger)
}

// ProduceBlockOnce 打包并追加一个区块（导出供测试与 M2 共识调用）。
//
// 空块不追加（保持链干净）。
func (n *Node) ProduceBlockOnce() {
	if err := n.produceBlock(); err != nil {
		n.logger.Error("出块失败", "err", err)
	}
}

// produceBlock 内部实现。
func (n *Node) produceBlock() error {
	n.mu.Lock()
	if !n.started || n.stopped || n.chain == nil || n.pool == nil || n.evm == nil {
		n.mu.Unlock()
		return nil
	}
	n.mu.Unlock()

	builder := n.blockBuilder()
	parent := n.chain.Head()

	built, err := builder.BuildBlock(parent)
	if err != nil {
		return fmt.Errorf("node: 构建区块失败: %w", err)
	}

	// 空块不追加（保持链干净）
	if len(built.Block.Transactions) == 0 {
		return nil
	}

	if err := n.chain.AppendBlock(built.Block, built.Receipts); err != nil {
		return fmt.Errorf("node: 追加区块失败: %w", err)
	}

	// 从池中移除已打包交易，并推进各发送者的 nonce
	_ = n.pool.RemoveAll(built.GethTxs)
	signer := gethTypes.LatestSignerForChainID(big.NewInt(int64(n.chain.ChainID())))
	for _, tx := range built.GethTxs {
		if from, err := gethTypes.Sender(signer, tx); err == nil {
			n.pool.SetAccountNonce(types.Address(from), types.Nonce(tx.Nonce()+1))
		}
	}

	head := n.chain.Head()
	n.logger.Info("出块",
		"height", uint64(head.Height),
		"txs", len(built.Block.Transactions),
		"gasUsed", uint64(built.Block.Header.GasUsed),
		"hash", head.Hash.String()[:18],
	)
	return nil
}

// StartBlockProduction 启动定时出块循环（M1 单节点模式）。
//
// ⚠️ M2 迁移点：定时器只是 M1 的驱动方式，不是架构的一部分。
// ctx 取消时循环退出。
func (n *Node) StartBlockProduction(ctx context.Context, blockTime time.Duration) {
	go func() {
		ticker := time.NewTicker(blockTime)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				n.ProduceBlockOnce()
			}
		}
	}()
}

// ============================================================================
// 辅助
// ============================================================================

func statusOf(success bool) uint8 {
	if success {
		return 1
	}
	return 0
}

func mergeBlooms(a, b types.Bloom) types.Bloom {
	var out types.Bloom
	for i := range out {
		out[i] = a[i] | b[i]
	}
	return out
}

func computeTxRoot(txs []*chain.Transaction) types.TxRoot {
	leaves := make([]types.Hash, 0, len(txs))
	for _, tx := range txs {
		h, err := tx.Hash()
		if err != nil {
			leaves = append(leaves, types.Hash{})
			continue
		}
		leaves = append(leaves, types.Hash(crypto.Keccak256(h.Bytes())))
	}
	return types.TxRoot(crypto.MerkleRoot(leaves))
}

// convertLogs geth 日志 → chfault 日志。
func convertLogs(gethLogs []*gethTypes.Log) []*chain.Log {
	out := make([]*chain.Log, 0, len(gethLogs))
	for _, gl := range gethLogs {
		if gl == nil {
			continue
		}
		cl := &chain.Log{
			Address: types.Address(gl.Address),
			Data:    gl.Data,
		}
		for _, t := range gl.Topics {
			cl.Topics = append(cl.Topics, types.Hash(t))
		}
		out = append(out, cl)
	}
	return out
}

// chainTxFrom geth 交易 → chain.Transaction（区块体存储用）。
//
// ⚠️ 这是当前架构的一个已知妥协：geth 的签名交易与 chfault 的
// Transaction 在此转换。M2 讨论是否让区块体直接存 geth 编码
// （SSZ 目标 vs RLP 现实的权衡，见 spec/20 §5）。
func chainTxFrom(gt *gethTypes.Transaction, sender types.Address) *chain.Transaction {
	out := &chain.Transaction{
		// ⚠️ 交易哈希统一用 geth 的规范值（keccak(0x02‖rlp(payload))）——
		// SubmitRawTx 返回给用户的哈希、交易索引、查询必须三者一致。
		// chfault 自己的简化 Hash() 只用于未签名的内部场景。
		Hash_:    ghHashPtr(gt),
		ChainID:  types.ChainID(gt.ChainId().Uint64()),
		Nonce:    types.Nonce(gt.Nonce()),
		GasLimit: types.Gas(gt.Gas()),
		Data:     gt.Data(),
		From:     sender,
	}
	if gt.To() != nil {
		to := types.Address(*gt.To())
		out.To = &to
	}
	if v, err := types.Uint256FromBig(gt.Value()); err == nil {
		out.Value = v
	}
	if gt.Type() == gethTypes.DynamicFeeTxType {
		out.Type = chain.TxTypeDynamicFee
		if v, err := types.Uint256FromBig(gt.GasFeeCap()); err == nil {
			out.MaxFeePerGas = v
		}
		if v, err := types.Uint256FromBig(gt.GasTipCap()); err == nil {
			out.MaxPriorityFeePerGas = v
		}
	} else {
		out.Type = chain.TxTypeLegacy
		if v, err := types.Uint256FromBig(gt.GasPrice()); err == nil {
			out.GasPrice = v
		}
	}
	vVal, rVal, sVal := gt.RawSignatureValues()
	if rVal != nil && sVal != nil {
		var sig types.Signature
		rb, sb := rVal.Bytes(), sVal.Bytes()
		copy(sig[32-len(rb):32], rb)
		copy(sig[64-len(sb):64], sb)
		sig[64] = byte(vVal.Uint64())
		out.Signature = sig
	}
	return out
}

// WriteGenesis 生成一份创世文件（CLI init 与测试用）。
func WriteGenesis(path string, chainID uint64, alloc map[string]AllocAccount, validators int) error {
	genesis := map[string]any{
		"chain_id":         fmt.Sprintf("%d", chainID),
		"timestamp":        "1700000000",
		"gas_limit":        "30000000",
		"initial_base_fee": "1000000000",
		"version":          "1",
		"extra_data":       "0x",
		"alloc":            alloc,
		"validators":       defaultValidators(validators),
	}
	data, err := json.MarshalIndent(genesis, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// defaultValidators 生成 N 个占位验证者（开发用，公钥为重复字节）。
func defaultValidators(n int) []map[string]string {
	out := make([]map[string]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, map[string]string{
			"address": fmt.Sprintf("0x%040x", i+1),
			"pubkey":  "0x02" + strings.Repeat("ab", 32),
			"power":   "1",
			"moniker": fmt.Sprintf("validator-%d", i+1),
		})
	}
	return out
}

// ghHashPtr 返回 geth 交易哈希的指针（供 chain.Transaction 的哈希缓存）。
func ghHashPtr(gt *gethTypes.Transaction) *types.TxHash {
	h := types.TxHash(gt.Hash())
	return &h
}
