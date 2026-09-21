// Package crypto 提供 chfault 的密码学原语与确定性编码。
//
// 所有函数必须是纯函数：相同输入永远产生相同输出。
// 本包不得使用 time.Now、math/rand 或任何不确定的输入。
package crypto

import (
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/sha3"

	"github.com/chfault/chfault/types"
)

// ============================================================================
// Keccak-256
// ============================================================================

// Keccak256 计算 Keccak-256 哈希。
//
// 注意：这是 Keccak-256，不是 SHA3-256。两者的 padding 常量不同
// （Keccak 用 0x01，SHA3 用 0x06），结果完全不同。
// 以太坊生态（包括地址派生）用的是 Keccak-256。
func Keccak256(data ...[]byte) types.Hash {
	h := sha3.NewLegacyKeccak256()
	for _, d := range data {
		// 写入错误在 hash.Hash 上不会发生，忽略返回值是安全的
		_, _ = h.Write(d)
	}
	var out types.Hash
	copy(out[:], h.Sum(nil))
	return out
}

// Keccak256Hash 是 Keccak256 的类型别名形式，返回 types.Hash。
func Keccak256Hash(data []byte) types.Hash { return Keccak256(data) }

// ============================================================================
// 地址派生
// ============================================================================

// PubKeyToAddress 从 secp256k1 未压缩公钥（65 字节，0x04 前缀）
// 或去掉前缀的 64 字节形式派生地址。
//
// 算法：keccak256(pubkey[1:])[12:]
func PubKeyToAddress(pubkey []byte) (types.Address, error) {
	var addr types.Address

	switch len(pubkey) {
	case 65:
		if pubkey[0] != 0x04 {
			return addr, errors.New("crypto: 未压缩公钥必须以 0x04 开头")
		}
		pubkey = pubkey[1:]
	case 64:
		// 已去掉前缀
	default:
		return addr, fmt.Errorf("crypto: 公钥长度必须 64 或 65，实际 %d", len(pubkey))
	}

	h := Keccak256(pubkey)
	copy(addr[:], h[12:])
	return addr, nil
}

// ============================================================================
// 大端整数编码（spec/00 §2.1：一切多字节整数统一大端）
// ============================================================================

// Uint16BE 编码 uint16 为大端 2 字节。
func Uint16BE(v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}

// Uint32BE 编码 uint32 为大端 4 字节。
func Uint32BE(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

// Uint64BE 编码 uint64 为大端 8 字节。
//
// 大端保证字节字典序 = 数值序，使存储层可以直接用字节序做范围扫描。
func Uint64BE(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}

// Uint64FromBE 从大端字节解析 uint64。
func Uint64FromBE(b []byte) (uint64, error) {
	if len(b) != 8 {
		return 0, fmt.Errorf("crypto: uint64 需要 8 字节，实际 %d", len(b))
	}
	return binary.BigEndian.Uint64(b), nil
}

// Uint32FromBE 从大端字节解析 uint32。
func Uint32FromBE(b []byte) (uint32, error) {
	if len(b) != 4 {
		return 0, fmt.Errorf("crypto: uint32 需要 4 字节，实际 %d", len(b))
	}
	return binary.BigEndian.Uint32(b), nil
}

// ============================================================================
// 确定性随机派生
// ============================================================================

// DeriveRandomness 从区块上下文确定性派生伪随机值。
//
// 这是智能合约唯一可用的"随机"来源。
// 严禁使用 math/rand —— 各节点会产生不同结果导致分叉。
//
//	randomness = keccak256(prevHash ‖ height)
func DeriveRandomness(prevHash types.Hash, height types.Height) types.Hash {
	return Keccak256(prevHash.Bytes(), Uint64BE(uint64(height)))
}

// ============================================================================
// Merkle 树（用于交易树、收据树）
// ============================================================================

// MerkleRoot 计算顺序固定列表的二叉 Merkle 根。
//
// 规则（spec/01 §7）：
//   - 空列表 → 32 字节零
//   - 奇数个叶子时，最后一个叶子与自己配对（h = keccak(x ‖ x)）
//   - 逐层两两拼接哈希，直到只剩一个元素
//
// leaves 中的每个元素应该是已哈希过的 32 字节摘要。
func MerkleRoot(leaves []types.Hash) types.Hash {
	if len(leaves) == 0 {
		return types.Hash{} // 32 字节零
	}

	// 复制一份，避免修改调用方的切片
	level := make([]types.Hash, len(leaves))
	copy(level, leaves)

	for len(level) > 1 {
		next := make([]types.Hash, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 < len(level) {
				next = append(next, Keccak256(level[i].Bytes(), level[i+1].Bytes()))
			} else {
				// 奇数：最后一个与自己配对
				next = append(next, Keccak256(level[i].Bytes(), level[i].Bytes()))
			}
		}
		level = next
	}

	return level[0]
}

// ============================================================================
// 日志布隆过滤器
// ============================================================================

// BloomAdd 向布隆过滤器加入一个 32 字节哈希。
//
// 算法（spec/30 §3，与以太坊一致）：
//   - 取哈希每两字节的低 11 位作为位位置（共 3 组）
//   - 字节索引是反转的：255 - bitpos/8
func BloomAdd(bloom *types.Bloom, hash types.Hash) {
	for i := 0; i < 3; i++ {
		// 低 11 位：hash[2i] 的低 3 位 << 8 | hash[2i+1]
		bitpos := uint16(hash[2*i]&0x07)<<8 | uint16(hash[2*i+1])
		byteIndex := 255 - (bitpos / 8)
		bitIndex := bitpos % 8
		bloom[byteIndex] |= 1 << bitIndex
	}
}

// BloomFromLogs 从日志列表构造布隆过滤器。
//
// 加入：合约地址的 keccak，以及每个 topic 的 keccak。
func BloomFromLogs(address types.Address, topics []types.Hash) types.Bloom {
	var bloom types.Bloom

	h := Keccak256(address.Bytes())
	BloomAdd(&bloom, h)

	for _, t := range topics {
		th := Keccak256(t.Bytes())
		BloomAdd(&bloom, th)
	}
	return bloom
}

// BloomContains 检查布隆过滤器是否可能包含某哈希。
//
// 注意：布隆过滤器有假阳性。返回 true 只表示"可能有"，
// 精确匹配必须回查原始日志。
func BloomContains(bloom types.Bloom, hash types.Hash) bool {
	for i := 0; i < 3; i++ {
		bitpos := uint16(hash[2*i]&0x07)<<8 | uint16(hash[2*i+1])
		byteIndex := 255 - (bitpos / 8)
		bitIndex := bitpos % 8
		if bloom[byteIndex]&(1<<bitIndex) == 0 {
			return false
		}
	}
	return true
}

// ============================================================================
// 常量（与以太坊一致，EVM 兼容性依赖它们）
// ============================================================================

var (
	// EmptyCodeHash 是空代码的哈希（keccak256("")）。
	EmptyCodeHash = types.Hash{
		0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2,
		0xdc, 0xc7, 0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b,
		0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
	}

	// EmptyStorageRoot 是空 MPT 的根。
	EmptyStorageRoot = types.Hash{
		0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6,
		0x92, 0xc0, 0xf8, 0x6e, 0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0,
		0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
	}
)
