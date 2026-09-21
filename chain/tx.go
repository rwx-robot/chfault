package chain

import (
	"github.com/chfault/chfault/types"
)

// TxType 是 EIP-2718 交易类型。
type TxType byte

// 交易类型定义（spec/10 §1）。
const (
	// TxTypeLegacy 是 legacy 交易（无类型前缀，RLP 列表首字节 >= 0xc0）。
	TxTypeLegacy TxType = 0
	// TxTypeAccessList 是 EIP-2930 访问列表交易。
	TxTypeAccessList TxType = 0x01
	// TxTypeDynamicFee 是 EIP-1559 动态费用交易（v0 主要类型）。
	TxTypeDynamicFee TxType = 0x02
)

// Transaction 是一笔已签名的交易。
//
// M0 阶段只定义结构与哈希计算；完整的 RLP 编解码与签名恢复在 M1 实现
// （依赖 spec/10 的测试向量）。
type Transaction struct {
	// Type 交易类型。
	Type TxType
	// ChainID 防跨链重放。
	ChainID types.ChainID
	// Nonce 发送者交易序号。
	Nonce types.Nonce
	// MaxPriorityFeePerGas 给 proposer 的小费上限（EIP-1559）。
	MaxPriorityFeePerGas types.Uint256
	// MaxFeePerGas 总费用上限（含 baseFee）。
	MaxFeePerGas types.Uint256
	// GasPrice legacy 交易的 gas 价格。
	GasPrice types.Uint256
	// GasLimit gas 上限。
	GasLimit types.Gas
	// To 接收方；nil 表示合约创建。
	To *types.Address
	// Value 转账金额。
	Value types.Uint256
	// Data 调用数据 / 构造代码。
	Data []byte
	// Signature 65 字节 secp256k1 签名（r ‖ s ‖ v）。
	Signature types.Signature

	// ---- 派生字段（不参与哈希）----
	// From 发送者地址，由签名恢复得出。
	From types.Address
	// Hash_ 缓存的交易哈希。
	Hash_ *types.TxHash
}

// AccessTuple 是 EIP-2930 访问列表条目。
type AccessTuple struct {
	Address     types.Address
	StorageKeys []types.Hash
}

// AccessList 是 EIP-2930 访问列表。
type AccessList []AccessTuple

// ============================================================================
// 哈希
// ============================================================================

// Hash 计算交易哈希。
//
// typed:  tx_hash = keccak256(type ‖ rlp(signing_payload))
// legacy: tx_hash = keccak256(rlp(...))
//
// M0 简化：用规范化的字节拼接代替完整 RLP，
// RLP 的准确实现在 M1 随测试向量一起落地（spec/10 §7）。
func (tx *Transaction) Hash() (types.TxHash, error) {
	if tx.Hash_ != nil {
		return *tx.Hash_, nil
	}

	payload, err := tx.SigningPayload()
	if err != nil {
		return types.TxHash{}, err
	}

	var preimage []byte
	if tx.Type != TxTypeLegacy {
		preimage = append(preimage, byte(tx.Type))
	}
	preimage = append(preimage, payload...)

	h := types.TxHash(cryptoKeccak256(preimage))
	tx.Hash_ = &h
	return h, nil
}

// SigningPayload 构造参与签名与哈希的载荷。
//
// 注意：不含签名字段（y_parity/r/s）。
func (tx *Transaction) SigningPayload() ([]byte, error) {
	buf := make([]byte, 0, 256)

	// typed transaction 的 chain_id 参与签名；legacy 不参与
	buf = append(buf, beUint64(uint64(tx.ChainID))...)
	buf = append(buf, beUint64(uint64(tx.Nonce))...)

	if tx.Type == TxTypeDynamicFee {
		buf = append(buf, tx.MaxPriorityFeePerGas.Bytes()...)
		buf = append(buf, tx.MaxFeePerGas.Bytes()...)
	} else {
		buf = append(buf, tx.GasPrice.Bytes()...)
	}

	buf = append(buf, beUint64(uint64(tx.GasLimit))...)

	if tx.To != nil {
		buf = append(buf, tx.To.Bytes()...)
	} else {
		buf = append(buf, make([]byte, types.AddressLen)...) // 空地址 = 合约创建
	}

	buf = append(buf, tx.Value.Bytes()...)

	// 变长 data：8 字节长度前缀 + 内容
	buf = append(buf, beUint64(uint64(len(tx.Data)))...)
	buf = append(buf, tx.Data...)

	return buf, nil
}

// Encode 编码完整交易（含签名）。
func (tx *Transaction) Encode() ([]byte, error) {
	payload, err := tx.SigningPayload()
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, len(payload)+65+1+types.HashLen+1)
	if tx.Type != TxTypeLegacy {
		out = append(out, byte(tx.Type))
	}
	out = append(out, payload...)
	out = append(out, tx.Signature[:]...)

	// 规范哈希段（v3.1 新增）：
	// 0x00 = 无缓存（接收方按自己的布局计算）
	// 0x01 = 后跟 32 字节规范哈希（geth 语义）
	// ⚠️ 必须持久化：tx_root / FindTx 索引 / SubmitRawTx 返回值三者
	// 都依赖这个哈希 —— 不持久化则编码-解码往返后哈希改变（tx_root 校验
	// 会失败，多节点实测复现）。
	if tx.Hash_ != nil {
		out = append(out, 0x01)
		out = append(out, (*tx.Hash_).Bytes()...)
	} else {
		out = append(out, 0x00)
	}

	if len(out) > types.MaxTxSize+types.HashLen+1 {
		return nil, types.ErrOversized
	}
	return out, nil
}

// EffectivePriorityFee 计算有效小费（用于 mempool 排序）。
//
//	effective = min(max_priority_fee, max_fee - base_fee)
func (tx *Transaction) EffectivePriorityFee(baseFee types.Uint256) types.Uint256 {
	if tx.Type != TxTypeDynamicFee {
		// legacy：effective = gasPrice - baseFee（下溢则 0）
		if tx.GasPrice.Cmp(baseFee) <= 0 {
			return types.ZeroUint256()
		}
		p, err := tx.GasPrice.Sub(baseFee)
		if err != nil {
			return types.ZeroUint256()
		}
		return p
	}

	// maxFee - baseFee，下溢则 0
	if tx.MaxFeePerGas.Cmp(baseFee) <= 0 {
		return types.ZeroUint256()
	}
	headroom, err := tx.MaxFeePerGas.Sub(baseFee)
	if err != nil {
		return types.ZeroUint256()
	}

	// min(maxPriority, headroom)
	if tx.MaxPriorityFeePerGas.Cmp(headroom) < 0 {
		return tx.MaxPriorityFeePerGas
	}
	return headroom
}
