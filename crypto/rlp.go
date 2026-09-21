package crypto

import (
	"errors"
	"fmt"
	"math/big"
)

// RLP（Recursive Length Prefix）编解码。
//
// 用于交易与区块的序列化 —— 这是以太坊的既定格式，
// chfault 需要与它逐字节一致才能保证 EVM 生态兼容。
//
// 规范回顾：
//
//	单字节 0x00–0x7f  → 自身
//	字符串 0–55 字节   → 0x80+len ‖ data
//	字符串 >55 字节    → 0xb7+lenOfLen ‖ len ‖ data
//	列表 payload ≤55   → 0xc0+len ‖ payload
//	列表 payload >55   → 0xf7+lenOfLen ‖ len ‖ payload
//
// ⚠️ 确定性地雷：
//   - 整数必须用**最短字节表示**（去前导零），0 编码为空串 0x80。
//     RLP 的"非规范编码"（如把 0 编成 0x00，或 5 编成 0x05 之外的 0x0005）
//     必须被拒绝，否则同一笔交易会有多个合法编码 → 交易哈希不唯一 → 分叉。
//   - 列表长度必须与实际内容完全匹配，多余字节视为错误（不允许 trailing bytes）。

// ErrRLP 是 RLP 编解码错误。
var ErrRLP = errors.New("rlp: 编码错误")

// ============================================================================
// 编码
// ============================================================================

// EncodeBytes 编码一个字节串。
func EncodeBytes(b []byte) []byte {
	if len(b) == 1 && b[0] < 0x80 {
		// 单字节且 < 0x80：直接是自身
		return []byte{b[0]}
	}
	return append(encodeLength(len(b), 0x80), b...)
}

// EncodeUint64 编码一个整数。
//
// 0 编码为空串（0x80）；其他用最短大端表示（去前导零）。
func EncodeUint64(v uint64) []byte {
	if v == 0 {
		return []byte{0x80}
	}
	return EncodeBytes(Uint64BE(v)[leadingZeroCount8(v):])
}

// EncodeBigInt 编码一个大整数。
func EncodeBigInt(v *big.Int) []byte {
	if v == nil || v.Sign() == 0 {
		return []byte{0x80}
	}
	return EncodeBytes(v.Bytes())
}

// EncodeList 编码一个列表。
//
// items 中每个元素应已经是编码后的字节。
func EncodeList(items ...[]byte) []byte {
	var payload []byte
	for _, it := range items {
		payload = append(payload, it...)
	}
	return append(encodeLength(len(payload), 0xc0), payload...)
}

// encodeLength 生成长度前缀。
//
// offset: 0x80 用于字符串，0xc0 用于列表。
func encodeLength(length int, offset byte) []byte {
	if length < 56 {
		return []byte{offset + byte(length)}
	}
	// 长形式：0xb7/0xf7 + lenOfLen，后跟长度本身的大端
	lenBytes := uintToMinimalBytes(uint64(length))
	out := make([]byte, 0, 1+len(lenBytes))
	out = append(out, offset+55+byte(len(lenBytes)))
	out = append(out, lenBytes...)
	return out
}

// uintToMinimalBytes 返回 uint64 的最短大端字节表示。
func uintToMinimalBytes(v uint64) []byte {
	if v == 0 {
		return nil
	}
	b := Uint64BE(v)
	return b[leadingZeroCount8(v):]
}

// leadingZeroCount8 返回 uint64 的大端表示中前导零字节数。
func leadingZeroCount8(v uint64) int {
	n := 0
	for i := 7; i >= 0; i-- {
		if (v>>(uint(i)*8))&0xff != 0 {
			break
		}
		n++
	}
	return n
}

// ============================================================================
// 解码
// ============================================================================

// RLPItem 是解码出的一个 RLP 项。
type RLPItem struct {
	// IsList 标识这是列表还是字节串。
	IsList bool
	// Bytes 字节串的内容（IsList 为 false 时有效）。
	Bytes []byte
	// List 列表的元素（IsList 为 true 时有效）。
	List []RLPItem
	// raw 是该项在原始输入中的完整编码（含前缀）。
	raw []byte
}

// Raw 返回该项的原始编码字节。
func (r *RLPItem) Raw() []byte { return r.raw }

// Uint64 把字节串项解析为 uint64（拒绝非规范编码）。
func (r *RLPItem) Uint64() (uint64, error) {
	if r.IsList {
		return 0, fmt.Errorf("%w: 期望字节串，实际是列表", ErrRLP)
	}
	if len(r.Bytes) == 0 {
		return 0, nil // 空串 = 0
	}
	if len(r.Bytes) > 8 {
		return 0, fmt.Errorf("%w: uint64 最多 8 字节，实际 %d", ErrRLP, len(r.Bytes))
	}
	// 非规范编码检查：不允许前导零
	if r.Bytes[0] == 0 {
		return 0, fmt.Errorf("%w: 整数存在前导零（非规范编码）", ErrRLP)
	}
	var v uint64
	for _, b := range r.Bytes {
		v = v<<8 | uint64(b)
	}
	return v, nil
}

// BigInt 把字节串项解析为 big.Int。
func (r *RLPItem) BigInt() (*big.Int, error) {
	if r.IsList {
		return nil, fmt.Errorf("%w: 期望字节串，实际是列表", ErrRLP)
	}
	if len(r.Bytes) == 0 {
		return big.NewInt(0), nil
	}
	if r.Bytes[0] == 0 {
		return nil, fmt.Errorf("%w: 整数存在前导零（非规范编码）", ErrRLP)
	}
	return new(big.Int).SetBytes(r.Bytes), nil
}

// Decode 解码一个 RLP 项，返回该项与消耗的字节数。
func Decode(data []byte) (*RLPItem, int, error) {
	if len(data) == 0 {
		return nil, 0, fmt.Errorf("%w: 空输入", ErrRLP)
	}

	prefix := data[0]

	switch {
	case prefix < 0x80:
		// 单字节
		item := &RLPItem{Bytes: []byte{prefix}, raw: data[:1]}
		return item, 1, nil

	case prefix < 0xb8:
		// 短字符串：0x80 + len
		length := int(prefix - 0x80)
		if length == 1 && len(data) > 1 && data[1] < 0x80 {
			return nil, 0, fmt.Errorf("%w: 单字节值使用了非规范的长编码", ErrRLP)
		}
		if len(data) < 1+length {
			return nil, 0, fmt.Errorf("%w: 短字符串长度 %d 超过剩余 %d 字节",
				ErrRLP, length, len(data)-1)
		}
		item := &RLPItem{
			Bytes: data[1 : 1+length],
			raw:   data[:1+length],
		}
		return item, 1 + length, nil

	case prefix < 0xc0:
		// 长字符串：0xb7 + lenOfLen
		lenOfLen := int(prefix - 0xb7)
		if len(data) < 1+lenOfLen {
			return nil, 0, fmt.Errorf("%w: 长度字段被截断", ErrRLP)
		}
		length, err := decodeLength(data[1:1+lenOfLen], "字符串")
		if err != nil {
			return nil, 0, err
		}
		total := 1 + lenOfLen + length
		if len(data) < total {
			return nil, 0, fmt.Errorf("%w: 长字符串长度 %d 超过剩余 %d 字节",
				ErrRLP, length, len(data)-1-lenOfLen)
		}
		item := &RLPItem{
			Bytes: data[1+lenOfLen : total],
			raw:   data[:total],
		}
		return item, total, nil

	case prefix < 0xf8:
		// 短列表：0xc0 + len
		length := int(prefix - 0xc0)
		if len(data) < 1+length {
			return nil, 0, fmt.Errorf("%w: 短列表长度 %d 超过剩余 %d 字节",
				ErrRLP, length, len(data)-1)
		}
		payload := data[1 : 1+length]
		item, err := decodeListPayload(payload)
		if err != nil {
			return nil, 0, err
		}
		item.raw = data[:1+length]
		return item, 1 + length, nil

	default:
		// 长列表：0xf7 + lenOfLen
		lenOfLen := int(prefix - 0xf7)
		if len(data) < 1+lenOfLen {
			return nil, 0, fmt.Errorf("%w: 长度字段被截断", ErrRLP)
		}
		length, err := decodeLength(data[1:1+lenOfLen], "列表")
		if err != nil {
			return nil, 0, err
		}
		total := 1 + lenOfLen + length
		if len(data) < total {
			return nil, 0, fmt.Errorf("%w: 长列表长度 %d 超过剩余 %d 字节",
				ErrRLP, length, len(data)-1-lenOfLen)
		}
		payload := data[1+lenOfLen : total]
		item, err := decodeListPayload(payload)
		if err != nil {
			return nil, 0, err
		}
		item.raw = data[:total]
		return item, total, nil
	}
}

// DecodeStrict 解码并要求消耗完全部输入（不允许 trailing bytes）。
//
// 交易与区块的解析必须用这个版本：多余字节意味着数据损坏或攻击。
func DecodeStrict(data []byte) (*RLPItem, error) {
	item, n, err := Decode(data)
	if err != nil {
		return nil, err
	}
	if n != len(data) {
		return nil, fmt.Errorf("%w: 解析后仍有 %d 字节剩余", ErrRLP, len(data)-n)
	}
	return item, nil
}

// decodeLength 解析长度字段，并做非规范编码检查。
func decodeLength(b []byte, kind string) (int, error) {
	// 非规范：长度 < 56 不应该用长形式
	if len(b) > 0 && b[0] == 0 {
		return 0, fmt.Errorf("%w: %s长度存在前导零（非规范编码）", ErrRLP, kind)
	}
	var length uint64
	for _, x := range b {
		if length > (1 << 40) {
			return 0, fmt.Errorf("%w: %s长度过大", ErrRLP, kind)
		}
		length = length<<8 | uint64(x)
	}
	if length <= 55 {
		return 0, fmt.Errorf("%w: %s长度 %d 应使用短形式（非规范编码）", ErrRLP, kind, length)
	}
	if length > (1 << 31) {
		return 0, fmt.Errorf("%w: %s长度过大", ErrRLP, kind)
	}
	return int(length), nil
}

// decodeListPayload 解析列表的 payload 部分。
func decodeListPayload(payload []byte) (*RLPItem, error) {
	item := &RLPItem{IsList: true}
	rest := payload
	for len(rest) > 0 {
		child, n, err := Decode(rest)
		if err != nil {
			return nil, err
		}
		item.List = append(item.List, *child)
		rest = rest[n:]
	}
	return item, nil
}

// ============================================================================
// 便捷函数
// ============================================================================

// EncodeUint256 编码 Uint256（按最短大端表示）。
func EncodeUint256Bytes(b []byte) []byte {
	// 去掉前导零
	i := 0
	for i < len(b) && b[i] == 0 {
		i++
	}
	return EncodeBytes(b[i:])
}
