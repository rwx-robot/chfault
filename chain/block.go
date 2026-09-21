// Package chain 定义区块、交易、收据结构与链级别的计算。
//
// 本包**不得** import consensus（依赖方向规则，见 docs/blueprint/02 §2.3）。
package chain

import (
	"github.com/chfault/chfault/crypto"
	"github.com/chfault/chfault/types"
)

// ============================================================================
// 区块头
// ============================================================================

// BlockHeader 是区块头（spec/20 §1）。
//
// 字段顺序即 SSZ 序列化顺序，不可调整。
type BlockHeader struct {
	// Version 硬分叉版本，按高度激活。
	Version types.Version
	// ChainID 链标识（EIP-155 重放保护）。
	ChainID types.ChainID
	// Height 区块高度，创世为 0。
	Height types.Height
	// Round 共识轮次（逻辑时钟），非 wall clock。
	Round types.Round
	// Timestamp 秒级 Unix 时间，受共识规则约束。
	Timestamp uint64
	// PrevHash 前一区块哈希；创世为 32 字节零。
	PrevHash types.BlockHash
	// Proposer 提议者地址。
	Proposer types.Address
	// TxRoot 交易列表的 Merkle 根。
	TxRoot types.TxRoot
	// ReceiptRoot 收据列表的 Merkle 根。
	ReceiptRoot types.ReceiptRoot
	// StateRoot 执行后的状态根。
	StateRoot types.StateRoot
	// LogsBloom 日志布隆过滤器（256 字节）。
	LogsBloom types.Bloom
	// GasUsed 本区块消耗的 gas。
	GasUsed types.Gas
	// GasLimit 本区块 gas 上限。
	GasLimit types.Gas
	// BaseFeePerGas EIP-1559 基础费。
	BaseFeePerGas types.Uint256
	// ValidatorSetHash 当前验证者集哈希（使 header 可自证）。
	ValidatorSetHash types.Hash
	// ExtraData 运营方自定义数据，<= 32 字节。
	ExtraData []byte
}

// Encode 序列化区块头。
//
// 固定字段用大端；ExtraData 是唯一的变长字段，前缀 1 字节长度。
// （完整 SSZ 的可变长 offset 机制在 M1 引入，M0 先用简化布局，
//
//	但大端原则与字段顺序已经固化，后续不会破坏兼容。）
func (h *BlockHeader) Encode() ([]byte, error) {
	if len(h.ExtraData) > types.MaxExtraData {
		return nil, types.ErrOversized
	}

	buf := make([]byte, 0, 512)
	buf = append(buf, crypto.Uint64BE(uint64(h.Version))[:2]...) // uint16
	buf = append(buf, crypto.Uint64BE(uint64(h.ChainID))...)
	buf = append(buf, crypto.Uint64BE(uint64(h.Height))...)
	buf = append(buf, crypto.Uint64BE(uint64(h.Round))[:4]...) // uint32
	buf = append(buf, crypto.Uint64BE(h.Timestamp)...)
	buf = append(buf, h.PrevHash.Bytes()...)
	buf = append(buf, h.Proposer.Bytes()...)
	buf = append(buf, h.TxRoot.Bytes()...)
	buf = append(buf, h.ReceiptRoot.Bytes()...)
	buf = append(buf, h.StateRoot.Bytes()...)
	buf = append(buf, h.LogsBloom[:]...)
	buf = append(buf, crypto.Uint64BE(uint64(h.GasUsed))...)
	buf = append(buf, crypto.Uint64BE(uint64(h.GasLimit))...)
	buf = append(buf, h.BaseFeePerGas.Bytes()...)
	buf = append(buf, h.ValidatorSetHash.Bytes()...)
	// 变长：1 字节长度 + 数据（<= 32）
	buf = append(buf, byte(len(h.ExtraData)))
	buf = append(buf, h.ExtraData...)

	return buf, nil
}

// Hash 计算区块哈希。
//
// block_hash = keccak256(ssz(header))
// 只哈希头部，区块体通过 tx_root 绑定 —— 这样轻客户端只需头即可验证链。
func (h *BlockHeader) Hash() (types.BlockHash, error) {
	enc, err := h.Encode()
	if err != nil {
		return types.BlockHash{}, err
	}
	return types.BlockHash(crypto.Keccak256(enc)), nil
}

// ============================================================================
// 区块
// ============================================================================

// Block 是完整区块（头 + 体）。
type Block struct {
	Header *BlockHeader
	// Transactions 交易列表，顺序即执行顺序（打包顺序决定，不重排）。
	Transactions []*Transaction
}

// ComputeTxRoot 计算交易 Merkle 根。
//
// 叶节点是每笔交易的 keccak256(tx_hash)。
// 空列表返回 32 字节零（spec/01 §7）。
func (b *Block) ComputeTxRoot() types.TxRoot {
	leaves := make([]types.Hash, 0, len(b.Transactions))
	for _, tx := range b.Transactions {
		h, err := tx.Hash()
		if err != nil {
			// 编码失败视为零哈希；真实实现中交易在准入时已校验过
			leaves = append(leaves, types.Hash{})
			continue
		}
		leaves = append(leaves, types.Hash(crypto.Keccak256(h.Bytes())))
	}
	return types.TxRoot(crypto.MerkleRoot(leaves))
}

// ============================================================================
// 收据
// ============================================================================

// Receipt 是交易执行后的收据（spec/30 §1）。
type Receipt struct {
	// Status 1 = 成功，0 = 失败（revert）。禁止其他值。
	Status uint8
	// TxHash 交易哈希。
	TxHash types.TxHash
	// GasUsed 本笔交易消耗。
	GasUsed types.Gas
	// CumulativeGasUsed 区块内累计（含本笔）。
	CumulativeGasUsed types.Gas
	// LogsBloom 本笔交易日志的布隆过滤器。
	LogsBloom types.Bloom
	// Logs 日志列表，按产生顺序。
	Logs []*Log
	// ContractAddress 合约创建交易的新地址；否则为 nil。
	ContractAddress *types.Address
	// EffectiveGasPrice 实际单价 = base_fee + priority。
	EffectiveGasPrice types.Uint256
}

// Log 是 EVM 日志（spec/30 §2）。
type Log struct {
	// Address 产生日志的合约地址。
	Address types.Address
	// Topics 索引参数，最多 4 个。
	Topics []types.Hash
	// Data 非索引数据。
	Data []byte
}

// ComputeLogsBloom 计算本笔收据的布隆过滤器。
func (r *Receipt) ComputeLogsBloom() types.Bloom {
	var bloom types.Bloom
	for _, lg := range r.Logs {
		bloom = mergeBloom(bloom, crypto.BloomFromLogs(lg.Address, lg.Topics))
	}
	return bloom
}

// mergeBloom 合并两个布隆过滤器（按位或）。
func mergeBloom(a, b types.Bloom) types.Bloom {
	var out types.Bloom
	for i := range out {
		out[i] = a[i] | b[i]
	}
	return out
}

// ComputeReceiptRoot 计算收据列表的 Merkle 根。
func ComputeReceiptRoot(receipts []*Receipt) types.ReceiptRoot {
	leaves := make([]types.Hash, 0, len(receipts))
	for _, r := range receipts {
		leaves = append(leaves, receiptLeaf(r))
	}
	return types.ReceiptRoot(crypto.MerkleRoot(leaves))
}

// receiptLeaf 计算单条收据的叶子哈希。
func receiptLeaf(r *Receipt) types.Hash {
	buf := make([]byte, 0, 256)
	buf = append(buf, r.Status)
	buf = append(buf, r.TxHash.Bytes()...)
	buf = append(buf, crypto.Uint64BE(uint64(r.GasUsed))...)
	buf = append(buf, crypto.Uint64BE(uint64(r.CumulativeGasUsed))...)
	buf = append(buf, r.LogsBloom[:]...)
	buf = append(buf, r.EffectiveGasPrice.Bytes()...)
	for _, lg := range r.Logs {
		buf = append(buf, lg.Address.Bytes()...)
		buf = append(buf, byte(len(lg.Topics)))
		for _, t := range lg.Topics {
			buf = append(buf, t.Bytes()...)
		}
		buf = append(buf, crypto.Uint64BE(uint64(len(lg.Data)))...)
		buf = append(buf, lg.Data...)
	}
	return crypto.Keccak256(buf)
}

// ComputeBlockLogsBloom 计算区块级布隆过滤器（所有收据的合并）。
func ComputeBlockLogsBloom(receipts []*Receipt) types.Bloom {
	var bloom types.Bloom
	for _, r := range receipts {
		bloom = mergeBloom(bloom, r.LogsBloom)
	}
	return bloom
}
