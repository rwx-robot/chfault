// Package storage 提供键值存储抽象与 Pebble 实现。
//
// 设计要点：
//   - Pebble 没有列族（Column Family），用 1 字节 namespace 前缀模拟
//   - 整数 key 一律大端编码（见 spec/00 §2.1）
//   - 一次区块提交 = 一个 Batch（原子）
package storage

import (
	"errors"
	"fmt"
)

// Namespace 是 1 字节的键空间前缀，用于隔离不同类型的数据。
//
// Pebble 本身不支持列族，所以用前缀模拟。1 字节前缀 + Pebble 的前缀 bloom
// 可以达到接近列族的效果。
type Namespace byte

// 命名空间定义（spec/40 §5）。
const (
	// NSBlocks 区块与哈希索引。
	NSBlocks Namespace = 0x01
	// NSTxIndex 交易定位索引。
	NSTxIndex Namespace = 0x02
	// NSReceipts 收据。
	NSReceipts Namespace = 0x03
	// NSConsensus 验证者集、QC、证据。
	NSConsensus Namespace = 0x04
	// NSMeta 链头、genesisHash、schemaVersion。
	NSMeta Namespace = 0x05
	// NSState MPT 节点。
	NSState Namespace = 0x06
	// NSCode 合约代码。
	NSCode Namespace = 0x07
)

// 子前缀（在 namespace 之后，用于区分同命名空间下的不同键类型）。
const (
	SubBlockByHeight byte = 0x01
	SubBlockByHash   byte = 0x02

	SubValidatorSet byte = 0x01
	SubQC           byte = 0x02
	SubEvidence     byte = 0x03
)

// Meta 键名。
var (
	// KeyChainTip 链头指针。
	KeyChainTip = []byte("chainTip")
	// KeyGenesisHash 创世区块哈希（防止挂错数据目录）。
	KeyGenesisHash = []byte("genesisHash")
	// KeySchemaVersion 数据格式版本。
	KeySchemaVersion = []byte("schemaVersion")
)

// ============================================================================
// 接口
// ============================================================================

// KVStore 是键值存储抽象。
type KVStore interface {
	// Get 读取值，不存在返回 (nil, nil)。
	Get(ns Namespace, key []byte) ([]byte, error)

	// Has 判断键是否存在。
	Has(ns Namespace, key []byte) (bool, error)

	// NewBatch 创建一个原子批量写。
	NewBatch() Batch

	// Apply 提交批量写。
	Apply(b Batch) error

	// Iterate 在命名空间内按前缀迭代。
	// 调用方必须调用返回的 Iterator 的 Close 方法。
	Iterate(ns Namespace, prefix []byte) (Iterator, error)

	// Checkpoint 创建一致性快照（硬链接，秒级）。
	Checkpoint(dir string) error

	// Stats 返回存储统计。
	Stats() (Stats, error)

	// Close 关闭存储。
	Close() error
}

// Batch 是原子批量写。
type Batch interface {
	Put(ns Namespace, key, value []byte) error
	Delete(ns Namespace, key []byte) error
	// Count 返回批次中的操作数（用于日志与监控）。
	Count() int
	// Reset 清空批次。
	Reset()
	// Close 释放资源。提交后必须调用。
	Close()
}

// Iterator 是键值迭代器。用完后必须 Close。
type Iterator interface {
	// Next 前进到下一个键值对，返回 false 表示结束。
	Next() bool
	// Key 返回当前键（不含 namespace 前缀）。
	Key() []byte
	// Value 返回当前值。
	Value() []byte
	// Error 返回迭代中的错误。
	Error() error
	// Close 释放迭代器。必须调用。
	Close() error
}

// Stats 存储统计。
type Stats struct {
	// SizeBytes 总大小（估算）。
	SizeBytes uint64
	// CompactionPending 是否有待处理的 compaction。
	CompactionPending bool
	// NumLevels LSM 层数。
	NumLevels int
}

// ============================================================================
// 错误
// ============================================================================

var (
	// ErrNotFound 键不存在。
	ErrNotFound = errors.New("storage: 键不存在")
	// ErrClosed 存储已关闭。
	ErrClosed = errors.New("storage: 存储已关闭")
	// ErrEmptyKey 键为空。
	ErrEmptyKey = errors.New("storage: 键不能为空")
	// ErrBatchClosed 批次已关闭。
	ErrBatchClosed = errors.New("storage: 批次已关闭")
)

// ============================================================================
// 键构造辅助
// ============================================================================

// MakeKey 构造完整的内部键：namespace(1) ‖ key。
func MakeKey(ns Namespace, key []byte) []byte {
	out := make([]byte, 0, 1+len(key))
	out = append(out, byte(ns))
	out = append(out, key...)
	return out
}

// SplitKey 拆分内部键，返回 (namespace, key)。
func SplitKey(internal []byte) (Namespace, []byte, error) {
	if len(internal) < 1 {
		return 0, nil, fmt.Errorf("storage: 内部键至少 1 字节，实际 %d", len(internal))
	}
	return Namespace(internal[0]), internal[1:], nil
}

// Prefix 构造 namespace 的前缀（用于迭代）。
func Prefix(ns Namespace) []byte {
	return []byte{byte(ns)}
}
