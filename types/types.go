// Package types 定义 chfault 的领域类型。
//
// 设计原则：使用 Go 的具名类型（而非裸 []byte 或 [32]byte），
// 让编译器阻止把 TxRoot 当 StateRoot 传 —— 这是区块链代码里最常见、
// 最难查的一类 bug。
//
// 本包是依赖图的叶子节点，不得依赖任何其他 chfault 包。
package types

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
)

// ============================================================================
// 常量
// ============================================================================

const (
	// AddressLen 地址长度（与以太坊一致）。
	AddressLen = 20
	// HashLen 哈希长度。
	HashLen = 32
	// BloomLen 日志布隆过滤器长度。
	BloomLen = 256
	// SignatureLen secp256k1 签名长度：r(32) ‖ s(32) ‖ v(1)。
	SignatureLen = 65
	// PubKeyLen secp256k1 压缩公钥长度。
	PubKeyLen = 33
	// Uint256Len 定长 256 位整数的字节长度。
	Uint256Len = 32

	// MaxTxSize 单笔交易编码后的上限（128 KiB）。
	MaxTxSize = 128 * 1024
	// MaxBlockSize 单区块编码后的上限（2 MiB）。
	MaxBlockSize = 2 * 1024 * 1024
	// MaxExtraData 区块头 extra_data 上限。
	MaxExtraData = 32
)

// ============================================================================
// 哈希与地址类型
// ============================================================================

// Hash 是 32 字节哈希的通用类型。
type Hash [HashLen]byte

// Address 是 20 字节账户地址。
type Address [AddressLen]byte

// 语义不同的具名类型。它们底层都是 Hash，
// 但 Go 的类型系统会把它们当作不同的类型，从而阻止混用。
type (
	// BlockHash 是区块哈希。
	BlockHash Hash
	// TxHash 是交易哈希。
	TxHash Hash
	// StateRoot 是状态树根。
	StateRoot Hash
	// TxRoot 是交易 Merkle 树根。
	TxRoot Hash
	// ReceiptRoot 是收据 Merkle 树根。
	ReceiptRoot Hash
)

// Signature 是 65 字节的 secp256k1 签名（r ‖ s ‖ v）。
type Signature [SignatureLen]byte

// Bloom 是 256 字节的日志布隆过滤器。
type Bloom [BloomLen]byte

// ============================================================================
// 标量类型
// ============================================================================

type (
	// Height 是区块高度。
	Height uint64
	// Nonce 是账户交易序号。
	Nonce uint64
	// Gas 是 gas 数量。
	Gas uint64
	// Round 是共识轮次。
	Round uint32
	// Power 是验证者投票权重。
	Power uint64
	// ChainID 是链标识。
	ChainID uint64
	// Version 是协议/数据格式版本。
	Version uint32
)

// ============================================================================
// Uint256：定长 256 位无符号整数
// ============================================================================

// Uint256 是定长 32 字节的大端无符号整数。
//
// 为什么不用 *big.Int：
//   - 定长结构体可值传递，无堆分配、无 GC 压力
//   - 序列化固定 32 字节，无需处理变长
//   - 避免 big.Int 共享底层数组导致的隐式修改（金额错误）
//
// 运算必须显式检查溢出，不允许静默回绕。
type Uint256 [Uint256Len]byte

// ZeroUint256 返回 0。
func ZeroUint256() Uint256 { return Uint256{} }

// Uint256FromUint64 从 uint64 构造。
func Uint256FromUint64(v uint64) Uint256 {
	var u Uint256
	u[24] = byte(v >> 56)
	u[25] = byte(v >> 48)
	u[26] = byte(v >> 40)
	u[27] = byte(v >> 32)
	u[28] = byte(v >> 24)
	u[29] = byte(v >> 16)
	u[30] = byte(v >> 8)
	u[31] = byte(v)
	return u
}

// Uint256FromBig 从 big.Int 构造。超出 256 位或为负则返回错误。
func Uint256FromBig(b *big.Int) (Uint256, error) {
	var u Uint256
	if b == nil {
		return u, errors.New("types: nil big.Int")
	}
	if b.Sign() < 0 {
		return u, errors.New("types: 负数不能转换为 Uint256")
	}
	if b.BitLen() > 256 {
		return u, errors.New("types: big.Int 超过 256 位")
	}
	b.FillBytes(u[:])
	return u, nil
}

// ToBig 转换为 big.Int（用于与 geth 等外部库交互）。
//
// 注意：返回的是新分配的值，调用方对它的修改不会影响原 Uint256。
func (u Uint256) ToBig() *big.Int {
	return new(big.Int).SetBytes(u[:])
}

// IsZero 判断是否为 0。
func (u Uint256) IsZero() bool {
	for _, b := range u {
		if b != 0 {
			return false
		}
	}
	return true
}

// Bytes 返回底层字节（大端，定长 32 字节）。
func (u Uint256) Bytes() []byte { return u[:] }

// SetBytes 从大端字节填充。长度必须 <= 32，不足则左侧补零。
func (u *Uint256) SetBytes(b []byte) error {
	if len(b) > Uint256Len {
		return fmt.Errorf("types: 字节长度 %d 超过 32", len(b))
	}
	*u = Uint256{}
	copy(u[Uint256Len-len(b):], b)
	return nil
}

// Add 加法，溢出返回错误（禁止静默回绕）。
func (u Uint256) Add(v Uint256) (Uint256, error) {
	sum := new(big.Int).Add(u.ToBig(), v.ToBig())
	return Uint256FromBig(sum)
}

// Sub 减法，下溢返回错误。
func (u Uint256) Sub(v Uint256) (Uint256, error) {
	if u.ToBig().Cmp(v.ToBig()) < 0 {
		return Uint256{}, errors.New("types: Uint256 减法下溢")
	}
	diff := new(big.Int).Sub(u.ToBig(), v.ToBig())
	return Uint256FromBig(diff)
}

// Mul 乘法，溢出返回错误。
func (u Uint256) Mul(v Uint256) (Uint256, error) {
	prod := new(big.Int).Mul(u.ToBig(), v.ToBig())
	return Uint256FromBig(prod)
}

// Cmp 比较：-1 小于，0 等于，1 大于。
func (u Uint256) Cmp(v Uint256) int { return u.ToBig().Cmp(v.ToBig()) }

// ============================================================================
// Hash 方法
// ============================================================================

// Bytes 返回底层字节切片。
func (h Hash) Bytes() []byte { return h[:] }

// SetBytes 从字节填充，长度必须恰好 32。
func (h *Hash) SetBytes(b []byte) error {
	if len(b) != HashLen {
		return fmt.Errorf("types: 哈希需要 32 字节，实际 %d", len(b))
	}
	copy(h[:], b)
	return nil
}

// IsZero 判断是否为全零。
func (h Hash) IsZero() bool { return h == Hash{} }

// String 返回 0x 前缀的十六进制表示（小写）。
func (h Hash) String() string { return "0x" + hex.EncodeToString(h[:]) }

// Hex 是 String 的别名，语义更明确。
func (h Hash) Hex() string { return h.String() }

// ============================================================================
// Address 方法
// ============================================================================

// Bytes 返回底层字节切片。
func (a Address) Bytes() []byte { return a[:] }

// SetBytes 从字节填充，长度必须恰好 20。
func (a *Address) SetBytes(b []byte) error {
	if len(b) != AddressLen {
		return fmt.Errorf("types: 地址需要 20 字节，实际 %d", len(b))
	}
	copy(a[:], b)
	return nil
}

// IsZero 判断是否为零地址。
func (a Address) IsZero() bool { return a == Address{} }

// String 返回 0x 前缀的小写十六进制表示。
//
// 注意：内部计算与存储一律用二进制形式；
// EIP-55 校验和只在显示/RPC 输出时使用（见 spec/01 §4）。
func (a Address) String() string { return "0x" + hex.EncodeToString(a[:]) }

// Hex 是 String 的别名。
func (a Address) Hex() string { return a.String() }

// Compare 提供确定性的地址比较（字节序）。
// 用于验证者集排序等需要确定性顺序的场景。
func (a Address) Compare(b Address) int {
	for i := range a {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

// ============================================================================
// 语义 Hash 类型的通用方法
//
// Go 的具名类型（type StateRoot Hash）不会继承底层类型的方法，
// 所以必须为每个语义类型显式定义。这种"重复"是有意为之：
// 换来的是编译期阻止把 TxRoot 当 StateRoot 传。
// ============================================================================

// Bytes 返回底层字节。
func (h BlockHash) Bytes() []byte { return h[:] }

// String 返回 0x 前缀十六进制。
func (h BlockHash) String() string { return "0x" + hex.EncodeToString(h[:]) }

// IsZero 判断是否为全零。
func (h BlockHash) IsZero() bool { return h == BlockHash{} }

// Bytes 返回底层字节。
func (h TxHash) Bytes() []byte { return h[:] }

// String 返回 0x 前缀十六进制。
func (h TxHash) String() string { return "0x" + hex.EncodeToString(h[:]) }

// Bytes 返回底层字节。
func (h StateRoot) Bytes() []byte { return h[:] }

// String 返回 0x 前缀十六进制。
func (h StateRoot) String() string { return "0x" + hex.EncodeToString(h[:]) }

// IsZero 判断是否为全零。
func (h StateRoot) IsZero() bool { return h == StateRoot{} }

// Bytes 返回底层字节。
func (h TxRoot) Bytes() []byte { return h[:] }

// String 返回 0x 前缀十六进制。
func (h TxRoot) String() string { return "0x" + hex.EncodeToString(h[:]) }

// IsZero 判断是否为全零。
func (h TxRoot) IsZero() bool { return h == TxRoot{} }

// Bytes 返回底层字节。
func (h ReceiptRoot) Bytes() []byte { return h[:] }

// String 返回 0x 前缀十六进制。
func (h ReceiptRoot) String() string { return "0x" + hex.EncodeToString(h[:]) }

// IsZero 判断是否为全零。
func (h ReceiptRoot) IsZero() bool { return h == ReceiptRoot{} }

// ============================================================================
// 错误
// ============================================================================

// 解析层错误码（对应 spec/01 §9）。
var (
	// ErrTruncated 数据不足。
	ErrTruncated = errors.New("E001: 数据被截断")
	// ErrTrailingBytes 解析后仍有剩余字节。
	ErrTrailingBytes = errors.New("E002: 存在多余字节")
	// ErrBadBool bool 值非 0/1。
	ErrBadBool = errors.New("E003: 非法 bool 值")
	// ErrBadOffset SSZ offset 越界或递减。
	ErrBadOffset = errors.New("E004: 非法 SSZ offset")
	// ErrBadLength 长度前缀超过剩余数据。
	ErrBadLength = errors.New("E005: 非法长度前缀")
	// ErrOversized 超过 MAX_* 常量。
	ErrOversized = errors.New("E006: 数据超过上限")
	// ErrBadChainID chainId 不匹配。
	ErrBadChainID = errors.New("E007: chainId 不匹配")
)

// ============================================================================
// 共识相关常量
// ============================================================================

// NoPOLRound 表示提议不引用任何 POL（Tendermint 语义的 -1）。
// Round 是 uint32，无法直接表示 -1，用保留值。
const NoPOLRound Round = 0xFFFFFFFF
