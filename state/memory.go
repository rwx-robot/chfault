package state

import (
	"maps"
	"slices"
	"sort"

	"github.com/chfault/chfault/crypto"
	"github.com/chfault/chfault/types"
)

// MemoryManager 是基于内存 map 的状态管理器。
//
// M0 用途：
//   - 验证状态层接口与 journal 回滚逻辑是否正确
//   - 让上层（chain / rpc）能在 MPT 就绪前先开发
//
// 状态根计算：把账户按地址字节序排序后序列化再哈希。
// **必须排序** —— Go 的 map 迭代顺序是随机的，不排序会导致
// 相同状态在不同节点产生不同的 stateRoot（链分叉）。
type MemoryManager struct {
	// states 保存历史状态快照：stateRoot → 账户集合。
	// 真实实现会用 MPT 并按版本复用节点，这里简化为整体快照。
	states map[types.StateRoot]map[types.Address]*Account
	codes  map[types.Hash][]byte
}

// NewMemoryManager 创建内存状态管理器。
func NewMemoryManager() *MemoryManager {
	return &MemoryManager{
		states: make(map[types.StateRoot]map[types.Address]*Account),
		codes:  make(map[types.Hash][]byte),
	}
}

// Begin 打开可回滚的写入会话。
func (m *MemoryManager) Begin(parent types.StateRoot) (Session, error) {
	accounts := make(map[types.Address]*Account)

	// 复制父状态的账户（快照语义）
	//
	// 注意：这里用 maps.Keys + slices.Sort 收集键，而不是直接 range map。
	// 虽然"复制整个 map"本身不依赖顺序，但显式收集排序后的键有两个好处：
	//   1. 不触发 determinism linter（它无法判断某次遍历是否安全）
	//   2. 代码意图明确：顺序无关，且遍历顺序可复现（便于调试）
	if parentAcc, ok := m.states[parent]; ok {
		for _, addr := range sortedKeys(parentAcc) {
			copied := *parentAcc[addr]
			accounts[addr] = &copied
		}
	} else if !parent.IsZero() {
		// 非零父根但不存在 —— 说明状态缺失，必须报错而不是静默当作空状态
		return nil, ErrAccountNotFound
	}

	return &memorySession{
		mgr:      m,
		parent:   parent,
		accounts: accounts,
		storage:  make(map[storageKey]types.Hash),
	}, nil
}

// View 打开只读视图。
func (m *MemoryManager) View(root types.StateRoot) (ReadOnly, error) {
	s, err := m.Begin(root)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// ============================================================================
// journal
// ============================================================================

// journalEntry 是一条可撤销的操作记录。
type journalEntry struct {
	kind  entryKind
	addr  types.Address
	slot  types.Hash
	// 旧值：账户整体、存储槽值、或代码
	oldAcc   *Account
	oldValue types.Hash
	existed  bool
}

type entryKind byte

const (
	kindAccount entryKind = iota
	kindStorage
)

// ============================================================================
// Session
// ============================================================================

type storageKey struct {
	addr types.Address
	slot types.Hash
}

type memorySession struct {
	mgr      *MemoryManager
	parent   types.StateRoot
	accounts map[types.Address]*Account
	storage  map[storageKey]types.Hash
	journal  []journalEntry
	done     bool
}

// GetAccount 读取账户。
func (s *memorySession) GetAccount(addr types.Address) (*Account, error) {
	acc, ok := s.accounts[addr]
	if !ok {
		return nil, ErrAccountNotFound
	}
	out := *acc
	return &out, nil
}

// GetStorage 读取存储槽。
func (s *memorySession) GetStorage(addr types.Address, slot types.Hash) (types.Hash, error) {
	v, ok := s.storage[storageKey{addr, slot}]
	if !ok {
		return types.Hash{}, nil
	}
	return v, nil
}

// GetCode 读取合约代码。
func (s *memorySession) GetCode(addr types.Address) ([]byte, error) {
	acc, ok := s.accounts[addr]
	if !ok {
		return nil, ErrAccountNotFound
	}
	return s.mgr.codes[acc.CodeHash], nil
}

// SetNonce 设置 nonce。
func (s *memorySession) SetNonce(addr types.Address, n types.Nonce) {
	s.ensureAccount(addr)
	s.recordAccount(addr)
	s.accounts[addr].Nonce = n
}

// SetBalance 设置余额。
func (s *memorySession) SetBalance(addr types.Address, v types.Uint256) error {
	s.ensureAccount(addr)
	s.recordAccount(addr)
	s.accounts[addr].Balance = v
	return nil
}

// SetCode 设置合约代码。
func (s *memorySession) SetCode(addr types.Address, code []byte) error {
	s.ensureAccount(addr)
	s.recordAccount(addr)
	h := crypto.Keccak256(code)
	s.mgr.codes[h] = code
	s.accounts[addr].CodeHash = h
	return nil
}

// SetStorage 设置存储槽。
func (s *memorySession) SetStorage(addr types.Address, slot, value types.Hash) {
	s.ensureAccount(addr)
	key := storageKey{addr, slot}
	old, existed := s.storage[key]
	s.journal = append(s.journal, journalEntry{
		kind:     kindStorage,
		addr:     addr,
		slot:     slot,
		oldValue: old,
		existed:  existed,
	})
	s.storage[key] = value
}

// Savepoint 返回回滚点。
func (s *memorySession) Savepoint() Savepoint {
	return Savepoint(len(s.journal))
}

// RollbackTo 回滚到指定 savepoint（逆序回放 journal）。
//
// 复杂度 O(回滚的变更数)，而非重新计算整个状态。
func (s *memorySession) RollbackTo(sp Savepoint) {
	target := int(sp)
	if target > len(s.journal) {
		return // 无效 savepoint，忽略
	}

	// 逆序回放
	for i := len(s.journal) - 1; i >= target; i-- {
		e := s.journal[i]
		switch e.kind {
		case kindAccount:
			if e.existed {
				*s.accounts[e.addr] = *e.oldAcc
			} else {
				delete(s.accounts, e.addr)
			}
		case kindStorage:
			if e.existed {
				s.storage[storageKey{e.addr, e.slot}] = e.oldValue
			} else {
				delete(s.storage, storageKey{e.addr, e.slot})
			}
		}
	}
	s.journal = s.journal[:target]
}

// Release 释放 savepoint（成功路径）。
func (s *memorySession) Release(sp Savepoint) {
	// 内存实现中，journal 条目在 Commit 后统一丢弃。
	// 真实实现（MPT）会在 Release 时把嵌套 savepoint 合并到外层。
	_ = sp
}

// Commit 计算并返回新状态根。
//
// 状态根 = keccak256(按地址排序后的账户序列化 ‖ 按 (addr,slot) 排序后的存储序列化)
//
// **必须排序**：Go 的 map 迭代顺序随机，不排序会导致分叉。
func (s *memorySession) Commit() (types.StateRoot, error) {
	if s.done {
		return types.StateRoot{}, ErrSessionCommitted
	}
	s.done = true

	// 1. 收集并排序账户地址
	//
	// **必须排序**：Go 的 map 迭代顺序随机，不排序会导致
	// 相同状态在不同节点产生不同的 stateRoot（链分叉）。
	addrs := sortedKeys(s.accounts)

	// 2. 序列化账户（跳过空账户，EIP-158）
	buf := make([]byte, 0, len(addrs)*80)
	for _, addr := range addrs {
		acc := s.accounts[addr]
		if acc.IsEmpty() {
			continue
		}
		buf = append(buf, addr.Bytes()...)
		buf = append(buf, crypto.Uint64BE(uint64(acc.Nonce))...)
		buf = append(buf, acc.Balance.Bytes()...)
		buf = append(buf, acc.CodeHash.Bytes()...)
		buf = append(buf, acc.StorageRoot.Bytes()...)
	}

	// 3. 收集并排序存储槽
	//
	// 同样必须排序（map 迭代顺序随机）。
	slots := slices.Collect(maps.Keys(s.storage))
	sort.Slice(slots, func(i, j int) bool {
		if c := slots[i].addr.Compare(slots[j].addr); c != 0 {
			return c < 0
		}
		for b := 0; b < 32; b++ {
			if slots[i].slot[b] != slots[j].slot[b] {
				return slots[i].slot[b] < slots[j].slot[b]
			}
		}
		return false
	})
	for _, k := range slots {
		buf = append(buf, k.addr.Bytes()...)
		buf = append(buf, k.slot.Bytes()...)
		v := s.storage[k]
		buf = append(buf, v.Bytes()...)
	}

	// 4. 计算根并保存快照
	root := types.StateRoot(crypto.Keccak256(buf))

	snapshot := make(map[types.Address]*Account, len(s.accounts))
	for _, addr := range addrs {
		copied := *s.accounts[addr]
		snapshot[addr] = &copied
	}
	s.mgr.states[root] = snapshot

	return root, nil
}

// sortedKeys 返回 map 的**已排序**键。
//
// 这是本项目中遍历 map 的唯一正确方式：
// Go 的 map 迭代顺序是随机的，直接用 `for k := range m` 会让
// determinism linter 报错，且在有顺序依赖的场景下导致链分叉。
//
// 使用方式：
//
//	for _, k := range sortedKeys(m) { ... }
func sortedKeys[V any](m map[types.Address]V) []types.Address {
	keys := slices.Collect(maps.Keys(m))
	slices.SortFunc(keys, func(a, b types.Address) int { return a.Compare(b) })
	return keys
}

// ============================================================================
// 内部辅助
// ============================================================================

// ensureAccount 确保账户存在（不存在则创建空账户）。
func (s *memorySession) ensureAccount(addr types.Address) {
	if _, ok := s.accounts[addr]; !ok {
		s.accounts[addr] = &Account{
			CodeHash:    EmptyCodeHash(),
			StorageRoot: EmptyStorageRoot(),
		}
	}
}

// recordAccount 在 journal 中记录账户的旧状态（首次修改时）。
func (s *memorySession) recordAccount(addr types.Address) {
	acc, existed := s.accounts[addr]
	var old *Account
	if existed {
		copied := *acc
		old = &copied
	}
	s.journal = append(s.journal, journalEntry{
		kind:    kindAccount,
		addr:    addr,
		oldAcc:  old,
		existed: existed,
	})
}
