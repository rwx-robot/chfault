package storage

import (
	"fmt"
	"runtime"

	"github.com/cockroachdb/pebble"
)

// SchemaVersion 是当前数据格式版本。
// 与 spec 的 SCHEMA_VERSION 对应，启动时校验，不兼容即拒绝启动。
const SchemaVersion = uint32(1)

// PebbleStore 是基于 Pebble 的 KVStore 实现。
//
// 选 Pebble 而非 RocksDB 的理由（ADR-010）：
// Pebble 是纯 Go 的 LSM 实现，无 cgo，因此保留了 Go 的
// "静态单二进制 + 交叉编译无障碍"这一核心收益。
// RocksDB 需要 cgo，会把这个收益全部抵消。
type PebbleStore struct {
	db *pebble.DB
}

// Open 打开（必要时创建）Pebble 存储。
func Open(path string) (*PebbleStore, error) {
	opts := &pebble.Options{
		MaxOpenFiles:            4096,
		MemTableSize:            64 << 20, // 64MB
		MaxConcurrentCompactions: func() int {
			n := runtime.NumCPU() / 2
			if n < 1 {
				return 1
			}
			return n
		},
		L0CompactionThreshold: 2,
		L0StopWritesThreshold: 1000,
		// WAL 必须开启：已最终化的区块丢失是不可接受的。
		DisableWAL: false,
	}

	db, err := pebble.Open(path, opts)
	if err != nil {
		return nil, fmt.Errorf("storage: 打开 Pebble 失败: %w", err)
	}
	return &PebbleStore{db: db}, nil
}

// Get 读取值。不存在返回 (nil, nil)。
func (s *PebbleStore) Get(ns Namespace, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, ErrEmptyKey
	}
	val, closer, err := s.db.Get(MakeKey(ns, key))
	if err != nil {
		if err == pebble.ErrNotFound {
			return nil, nil // 不存在不是错误
		}
		return nil, err
	}
	// 必须复制：closer 调用后 val 可能失效
	out := make([]byte, len(val))
	copy(out, val)
	_ = closer.Close()
	return out, nil
}

// Has 判断键是否存在。
func (s *PebbleStore) Has(ns Namespace, key []byte) (bool, error) {
	v, err := s.Get(ns, key)
	if err != nil {
		return false, err
	}
	return v != nil, nil
}

// NewBatch 创建批量写。
func (s *PebbleStore) NewBatch() Batch {
	return &pebbleBatch{b: s.db.NewBatch()}
}

// Apply 提交批量写。
//
// 使用 Sync 写：宁可慢一点，也不能丢已最终化的区块。
func (s *PebbleStore) Apply(b Batch) error {
	pb, ok := b.(*pebbleBatch)
	if !ok {
		return fmt.Errorf("storage: 批次类型不匹配")
	}
	if pb.closed {
		return ErrBatchClosed
	}
	return s.db.Apply(pb.b, pebble.Sync)
}

// Iterate 按前缀迭代。
func (s *PebbleStore) Iterate(ns Namespace, prefix []byte) (Iterator, error) {
	fullPrefix := MakeKey(ns, prefix)
	iter, err := s.db.NewIter(&pebble.IterOptions{
		LowerBound: fullPrefix,
		UpperBound: keyUpperBound(fullPrefix),
	})
	if err != nil {
		return nil, err
	}
	return &pebbleIterator{iter: iter, nsLen: 1}, nil
}

// Checkpoint 创建一致性快照。
func (s *PebbleStore) Checkpoint(dir string) error {
	return s.db.Checkpoint(dir)
}

// Stats 返回统计信息。
func (s *PebbleStore) Stats() (Stats, error) {
	m := s.db.Metrics()
	st := Stats{
		SizeBytes:         uint64(m.Total().Size),
		CompactionPending: m.Compact.Count > 0,
		NumLevels:         len(m.Levels),
	}
	return st, nil
}

// Close 关闭存储。
func (s *PebbleStore) Close() error { return s.db.Close() }

// ============================================================================
// Batch 实现
// ============================================================================

type pebbleBatch struct {
	b      *pebble.Batch
	count  int
	closed bool
}

func (b *pebbleBatch) Put(ns Namespace, key, value []byte) error {
	if b.closed {
		return ErrBatchClosed
	}
	if len(key) == 0 {
		return ErrEmptyKey
	}
	b.count++
	return b.b.Set(MakeKey(ns, key), value, pebble.Sync)
}

func (b *pebbleBatch) Delete(ns Namespace, key []byte) error {
	if b.closed {
		return ErrBatchClosed
	}
	b.count++
	return b.b.Delete(MakeKey(ns, key), pebble.Sync)
}

func (b *pebbleBatch) Count() int { return b.count }

func (b *pebbleBatch) Reset() {
	b.b.Reset()
	b.count = 0
}

func (b *pebbleBatch) Close() {
	if !b.closed {
		_ = b.b.Close()
		b.closed = true
	}
}

// ============================================================================
// Iterator 实现
// ============================================================================

type pebbleIterator struct {
	iter   *pebble.Iterator
	nsLen  int
	curKey []byte
}

func (it *pebbleIterator) Next() bool {
	if !it.iter.Next() {
		return false
	}
	// 去掉 namespace 前缀
	full := it.iter.Key()
	if len(full) > it.nsLen {
		it.curKey = full[it.nsLen:]
	} else {
		it.curKey = nil
	}
	return true
}

func (it *pebbleIterator) Key() []byte { return it.curKey }

func (it *pebbleIterator) Value() []byte { return it.iter.Value() }

func (it *pebbleIterator) Error() error { return it.iter.Error() }

func (it *pebbleIterator) Close() error { return it.iter.Close() }

// ============================================================================
// 辅助
// ============================================================================

// keyUpperBound 计算前缀迭代的上界（前缀最后一个字节 +1 进位）。
func keyUpperBound(prefix []byte) []byte {
	end := make([]byte, len(prefix))
	copy(end, prefix)
	for i := len(end) - 1; i >= 0; i-- {
		if end[i] < 0xff {
			end[i]++
			return end[:i+1]
		}
	}
	return nil // 前缀全为 0xff，无上界
}
