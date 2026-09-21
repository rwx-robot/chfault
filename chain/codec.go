package chain

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/chfault/chfault/types"
)

// 区块编解码。
//
// 布局（spec/20 §5）：
//
//	block = uint32_le(header_len) ‖ header_bytes ‖ uint32_le(body_len) ‖ body_bytes
//	body  = uint32_le(tx_count) ‖ (uint32_le(tx_len) ‖ tx_bytes) × tx_count
//
// ⚠️ 这里的长度前缀用**小端** uint32，与 spec/01 §3 的 SSZ offset 一致
// （offset 属于 SSZ 内部结构，不是协议整数，所以不走大端约定）。
// 协议字段（高度、gas、金额）仍然严格大端。

// ErrCodec 是编解码错误。
var ErrCodec = errors.New("chain: 编解码错误")

// ============================================================================
// 交易
// ============================================================================

// EncodeTx 编码一笔交易（含签名）。
func EncodeTx(tx *Transaction) ([]byte, error) {
	return tx.Encode()
}

// DecodeTx 解码一笔交易。
//
// 注意：完整的 EIP-1559 RLP 解析需要签名恢复与字段校验，
// 属于 M1 的交易所工作。当前实现支持 chfault 自身的紧凑布局，
// 以及与 spec/10 对应的最小字段集。
func DecodeTx(data []byte) (*Transaction, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: 交易为空", ErrCodec)
	}
	if len(data) > types.MaxTxSize {
		return nil, fmt.Errorf("%w: 交易超过 %d 字节", types.ErrOversized, types.MaxTxSize)
	}

	tx := &Transaction{Type: TxTypeLegacy}
	rest := data

	// 类型前缀
	if rest[0] <= 0x7f {
		tx.Type = TxType(rest[0])
		rest = rest[1:]
	}

	read8 := func() (uint64, bool) {
		if len(rest) < 8 {
			return 0, false
		}
		v := binary.BigEndian.Uint64(rest[:8])
		rest = rest[8:]
		return v, true
	}
	read32 := func() ([]byte, bool) {
		if len(rest) < 32 {
			return nil, false
		}
		v := make([]byte, 32)
		copy(v, rest[:32])
		rest = rest[32:]
		return v, true
	}

	// chain_id
	v, ok := read8()
	if !ok {
		return nil, fmt.Errorf("%w: chain_id 被截断", ErrCodec)
	}
	tx.ChainID = types.ChainID(v)

	// nonce
	v, ok = read8()
	if !ok {
		return nil, fmt.Errorf("%w: nonce 被截断", ErrCodec)
	}
	tx.Nonce = types.Nonce(v)

	// fee 字段
	if tx.Type == TxTypeDynamicFee {
		b, ok := read32()
		if !ok {
			return nil, fmt.Errorf("%w: max_priority_fee 被截断", ErrCodec)
		}
		_ = tx.MaxPriorityFeePerGas.SetBytes(b)
		b, ok = read32()
		if !ok {
			return nil, fmt.Errorf("%w: max_fee 被截断", ErrCodec)
		}
		_ = tx.MaxFeePerGas.SetBytes(b)
	} else {
		b, ok := read32()
		if !ok {
			return nil, fmt.Errorf("%w: gas_price 被截断", ErrCodec)
		}
		_ = tx.GasPrice.SetBytes(b)
	}

	// gas_limit
	v, ok = read8()
	if !ok {
		return nil, fmt.Errorf("%w: gas_limit 被截断", ErrCodec)
	}
	tx.GasLimit = types.Gas(v)

	// to
	if len(rest) < types.AddressLen {
		return nil, fmt.Errorf("%w: to 被截断", ErrCodec)
	}
	var to types.Address
	copy(to[:], rest[:types.AddressLen])
	rest = rest[types.AddressLen:]
	if to.IsZero() {
		tx.To = nil // 零地址表示合约创建
	} else {
		tx.To = &to
	}

	// value
	b, ok := read32()
	if !ok {
		return nil, fmt.Errorf("%w: value 被截断", ErrCodec)
	}
	_ = tx.Value.SetBytes(b)

	// data
	dataLen, ok := read8()
	if !ok {
		return nil, fmt.Errorf("%w: data 长度被截断", ErrCodec)
	}
	if uint64(len(rest)) < dataLen || dataLen > uint64(types.MaxTxSize) {
		return nil, fmt.Errorf("%w: data 长度 %d 非法", ErrCodec, dataLen)
	}
	tx.Data = make([]byte, dataLen)
	copy(tx.Data, rest[:dataLen])
	rest = rest[dataLen:]

	// 签名（可选：编码时带，解码时可能用于签名验证前的中间态）
	if len(rest) >= types.SignatureLen {
		copy(tx.Signature[:], rest[:types.SignatureLen])
		rest = rest[types.SignatureLen:]
	}

	// 规范哈希段（v3.1）：0x00 无 / 0x01 + 32 字节
	if len(rest) >= 1 {
		flag := rest[0]
		rest = rest[1:]
		switch flag {
		case 0x00:
			// 无缓存哈希
		case 0x01:
			if len(rest) < types.HashLen {
				return nil, fmt.Errorf("%w: 规范哈希被截断", ErrCodec)
			}
			h := types.TxHash(rest[:types.HashLen])
			tx.Hash_ = &h
			rest = rest[types.HashLen:]
		default:
			return nil, fmt.Errorf("%w: 未知哈希段标记 %d", ErrCodec, flag)
		}
	}

	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: 交易解析后仍有 %d 字节剩余", ErrCodec, len(rest))
	}

	return tx, nil
}

// ============================================================================
// 区块
// ============================================================================

// Encode 序列化完整区块。
func (b *Block) Encode() ([]byte, error) {
	if b.Header == nil {
		return nil, fmt.Errorf("%w: 区块头为空", ErrCodec)
	}

	headerBytes, err := b.Header.Encode()
	if err != nil {
		return nil, err
	}

	// body
	body := make([]byte, 0, 64)
	body = append(body, leUint32(uint32(len(b.Transactions)))...)
	for i, tx := range b.Transactions {
		txBytes, err := tx.Encode()
		if err != nil {
			return nil, fmt.Errorf("%w: 交易 %d 编码失败: %v", ErrCodec, i, err)
		}
		body = append(body, leUint32(uint32(len(txBytes)))...)
		body = append(body, txBytes...)
	}

	out := make([]byte, 0, 8+len(headerBytes)+len(body))
	out = append(out, leUint32(uint32(len(headerBytes)))...)
	out = append(out, headerBytes...)
	out = append(out, leUint32(uint32(len(body)))...)
	out = append(out, body...)

	if len(out) > types.MaxBlockSize {
		return nil, fmt.Errorf("%w: 区块 %d 字节超过上限 %d",
			types.ErrOversized, len(out), types.MaxBlockSize)
	}
	return out, nil
}

// DecodeBlock 反序列化区块。
func DecodeBlock(data []byte) (*Block, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("%w: 区块数据不足", ErrCodec)
	}

	headerLen := binary.LittleEndian.Uint32(data[:4])
	rest := data[4:]
	if uint32(len(rest)) < headerLen {
		return nil, fmt.Errorf("%w: 区块头长度 %d 超过剩余 %d", ErrCodec, headerLen, len(rest))
	}
	headerBytes := rest[:headerLen]
	rest = rest[headerLen:]

	header, err := DecodeHeader(headerBytes)
	if err != nil {
		return nil, err
	}

	if len(rest) < 4 {
		return nil, fmt.Errorf("%w: 缺少区块体长度", ErrCodec)
	}
	bodyLen := binary.LittleEndian.Uint32(rest[:4])
	rest = rest[4:]
	if uint32(len(rest)) < bodyLen {
		return nil, fmt.Errorf("%w: 区块体长度 %d 超过剩余 %d", ErrCodec, bodyLen, len(rest))
	}
	body := rest[:bodyLen]
	rest = rest[bodyLen:]

	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: 区块解析后仍有 %d 字节剩余", ErrCodec, len(rest))
	}

	txs, err := decodeBody(body)
	if err != nil {
		return nil, err
	}

	return &Block{Header: header, Transactions: txs}, nil
}

func decodeBody(body []byte) ([]*Transaction, error) {
	if len(body) < 4 {
		return nil, fmt.Errorf("%w: 区块体缺少交易数量", ErrCodec)
	}
	count := binary.LittleEndian.Uint32(body[:4])
	rest := body[4:]

	// 防御：数量不能超过合理上限（每笔交易至少几十字节）
	if count > uint32(types.MaxBlockSize/32)+1 {
		return nil, fmt.Errorf("%w: 交易数量 %d 不合理", ErrCodec, count)
	}

	txs := make([]*Transaction, 0, count)
	for i := uint32(0); i < count; i++ {
		if len(rest) < 4 {
			return nil, fmt.Errorf("%w: 第 %d 笔交易长度被截断", ErrCodec, i)
		}
		txLen := binary.LittleEndian.Uint32(rest[:4])
		rest = rest[4:]
		if uint32(len(rest)) < txLen {
			return nil, fmt.Errorf("%w: 第 %d 笔交易长度 %d 超过剩余 %d",
				ErrCodec, i, txLen, len(rest))
		}
		tx, err := DecodeTx(rest[:txLen])
		if err != nil {
			return nil, fmt.Errorf("%w: 第 %d 笔交易解码失败: %v", ErrCodec, i, err)
		}
		txs = append(txs, tx)
		rest = rest[txLen:]
	}

	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: 区块体解析后仍有 %d 字节剩余", ErrCodec, len(rest))
	}
	return txs, nil
}

// DecodeHeader 反序列化区块头。
func DecodeHeader(data []byte) (*BlockHeader, error) {
	const fixedSize = 2 + 8 + 8 + 4 + 8 + 32 + 20 + 32 + 32 + 32 + 256 + 8 + 8 + 32 + 32

	if len(data) < fixedSize+1 {
		return nil, fmt.Errorf("%w: 区块头需要至少 %d 字节，实际 %d",
			ErrCodec, fixedSize+1, len(data))
	}

	h := &BlockHeader{}
	pos := 0
	take := func(n int) []byte {
		b := data[pos : pos+n]
		pos += n
		return b
	}

	h.Version = types.Version(binary.BigEndian.Uint16(take(2)))
	h.ChainID = types.ChainID(binary.BigEndian.Uint64(take(8)))
	h.Height = types.Height(binary.BigEndian.Uint64(take(8)))
	h.Round = types.Round(binary.BigEndian.Uint32(take(4)))
	h.Timestamp = binary.BigEndian.Uint64(take(8))
	copy(h.PrevHash[:], take(32))
	copy(h.Proposer[:], take(20))
	copy(h.TxRoot[:], take(32))
	copy(h.ReceiptRoot[:], take(32))
	copy(h.StateRoot[:], take(32))
	copy(h.LogsBloom[:], take(256))
	h.GasUsed = types.Gas(binary.BigEndian.Uint64(take(8)))
	h.GasLimit = types.Gas(binary.BigEndian.Uint64(take(8)))
	copy(h.BaseFeePerGas[:], take(32))
	copy(h.ValidatorSetHash[:], take(32))

	extraLen := int(take(1)[0])
	if extraLen > types.MaxExtraData {
		return nil, fmt.Errorf("%w: extra_data 长度 %d 超过上限", ErrCodec, extraLen)
	}
	if len(data)-pos < extraLen {
		return nil, fmt.Errorf("%w: extra_data 被截断", ErrCodec)
	}
	h.ExtraData = append([]byte(nil), take(extraLen)...)

	if pos != len(data) {
		return nil, fmt.Errorf("%w: 区块头解析后仍有 %d 字节剩余", ErrCodec, len(data)-pos)
	}
	return h, nil
}

// ============================================================================
// 辅助
// ============================================================================

func leUint32(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}
