package storage

import (
	"bytes"
	"maps"
	"slices"
	"sync"
)

// MemoryStore 是 KVStore 的内存实现。
//
// 用途：
//  1. 单元测试 —— 不依赖磁盘，快且可重复
//  2. CI —— 不依赖原生模块（Pebble 是纯 Go，但内存实现更快）
//  3. M0 阶段 —— 让 state 包可以在不与 Pebble 耦合的情况下先完成
//
// 实现是并发安全的。
type MemoryStore struct {
	mu     sync.RWMutex
	data   map[string][]byte
	closed bool
}

// NewMemory 创建内存存储。
func NewMemory() *MemoryStore {
	return &MemoryStore{data: make(map[string][]byte)}
}

// Get 读取值。
func (s *MemoryStore) Get(ns Namespace, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, ErrEmptyKey
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrClosed
	}
	v, ok := s.data[string(MakeKey(ns, key))]
	if !ok {
		return nil, nil
	}
	out := make([]byte, len(v))
	copy(out, v)
	return out, nil
}

// Has 判断键是否存在。
func (s *MemoryStore) Has(ns Namespace, key []byte) (bool, error) {
	v, err := s.Get(ns, key)
	if err != nil {
		return false, err
	}
	return v != nil, nil
}

// NewBatch 创建批量写。
func (s *MemoryStore) NewBatch() Batch {
	return &memoryBatch{}
}

// Apply 提交批量写。
func (s *MemoryStore) Apply(b Batch) error {
	mb, ok := b.(*memoryBatch)
	if !ok {
		return ErrBatchClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	for _, op := range mb.ops {
		k := string(MakeKey(op.ns, op.key))
		if op.delete {
			delete(s.data, k)
		} else {
			s.data[k] = op.value
		}
	}
	return nil
}

// Iterate 按前缀迭代。
//
// 注意：内存实现也**必须排序**，否则迭代顺序不确定 —— 这与
// "禁止依赖 map 顺序"的原则一致。
func (s *MemoryStore) Iterate(ns Namespace, prefix []byte) (Iterator, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	fullPrefix := MakeKey(ns, prefix)
	// 收集并排序：Go 的 map 迭代顺序随机，必须显式排序才可复现。
	// （本包受 determinism linter 保护，因此不能用 `for k := range m`。）
	keys := slices.Collect(maps.Keys(s.data))
	slices.Sort(keys)

	entries := make([]kvPair, 0, len(keys))
	for _, k := range keys {
		if !bytes.HasPrefix([]byte(k), fullPrefix) {
			continue
		}
		v := s.data[k]
		entries = append(entries, kvPair{
			key:   []byte(k[len(fullPrefix)-len(prefix):]),
			value: append([]byte(nil), v...),
		})
	}
	return &memoryIterator{entries: entries}, nil
}

// Checkpoint 内存存储不支持快照（仅测试用）。
func (s *MemoryStore) Checkpoint(dir string) error {
	return nil
}

// Stats 返回统计。
func (s *MemoryStore) Stats() (Stats, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	total := 0
	// 同样是"遍历 map 但顺序无关"的场景。
	// 统一走 sortedKeys 模式，保持代码风格一致且不触发 determinism linter。
	for _, k := range slices.Sorted(maps.Keys(s.data)) {
		total += len(s.data[k])
	}
	return Stats{SizeBytes: uint64(total)}, nil
}

// Close 关闭存储。
func (s *MemoryStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

// ============================================================================
// Batch
// ============================================================================

type memOp struct {
	ns     Namespace
	key    []byte
	value  []byte
	delete bool
}

type memoryBatch struct {
	ops []memOp
}

func (b *memoryBatch) Put(ns Namespace, key, value []byte) error {
	if len(key) == 0 {
		return ErrEmptyKey
	}
	// 复制，避免调用方后续修改切片
	b.ops = append(b.ops, memOp{
		ns:    ns,
		key:   append([]byte(nil), key...),
		value: append([]byte(nil), value...),
	})
	return nil
}

func (b *memoryBatch) Delete(ns Namespace, key []byte) error {
	b.ops = append(b.ops, memOp{
		ns:     ns,
		key:    append([]byte(nil), key...),
		delete: true,
	})
	return nil
}

func (b *memoryBatch) Count() int { return len(b.ops) }
func (b *memoryBatch) Reset()     { b.ops = nil }
func (b *memoryBatch) Close()     {}

// ============================================================================
// Iterator
// ============================================================================

type kvPair struct {
	key   []byte
	value []byte
}

type memoryIterator struct {
	entries []kvPair
	idx     int
}

func (it *memoryIterator) Next() bool {
	it.idx++
	return it.idx <= len(it.entries)
}

func (it *memoryIterator) Key() []byte {
	if it.idx == 0 || it.idx > len(it.entries) {
		return nil
	}
	return it.entries[it.idx-1].key
}

func (it *memoryIterator) Value() []byte {
	if it.idx == 0 || it.idx > len(it.entries) {
		return nil
	}
	return it.entries[it.idx-1].value
}

func (it *memoryIterator) Error() error { return nil }
func (it *memoryIterator) Close() error { return nil }
