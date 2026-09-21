// Package state 提供状态管理与回滚能力。
//
// 关键设计：树结构本身不提供版本化回滚，所以 chfault 用 **journal** 实现。
// 这使 EVM 的 REVERT 语义（回滚到单笔交易开始处）成为可能。
//
// M0 阶段：提供接口 + journal + 一个简单的 Memory 后端。
// MPT 接入（go-ethereum/trie）依赖 ADR-016 的许可决策，属 M1。
package state

import (
	"errors"

	"github.com/chfault/chfault/types"
)

// ============================================================================
// 账户
// ============================================================================

// Account 是账户状态（Account 模型，非 UTXO）。
type Account struct {
	// Nonce 交易序号，防重放与排序。
	Nonce types.Nonce
	// Balance 余额（Wei，uint256）。
	Balance types.Uint256
	// CodeHash 合约代码哈希；EOA 为 EmptyCodeHash。
	CodeHash types.Hash
	// StorageRoot 合约存储树根；EOA 为 EmptyStorageRoot。
	StorageRoot types.Hash
}

// IsEmpty 判断是否为"空账户"（EIP-158）。
//
// 满足 nonce==0 && balance==0 && codeHash==Empty 的账户应从状态树中删除。
// 不清理会导致状态膨胀，且与其他以太坊实现不一致。
func (a *Account) IsEmpty() bool {
	return a.Nonce == 0 && a.Balance.IsZero() && a.CodeHash == EmptyCodeHash()
}

// ============================================================================
// 接口
// ============================================================================

// Manager 是状态管理器。
type Manager interface {
	// Begin 在指定父根上打开一次可回滚的写入会话。
	Begin(parent types.StateRoot) (Session, error)

	// View 打开只读视图（用于 RPC 查询与 estimateGas）。
	View(root types.StateRoot) (ReadOnly, error)
}

// ReadOnly 是只读状态访问。
type ReadOnly interface {
	GetAccount(addr types.Address) (*Account, error)
	GetStorage(addr types.Address, slot types.Hash) (types.Hash, error)
	GetCode(addr types.Address) ([]byte, error)
}

// Session 是可回滚的写入会话。
type Session interface {
	ReadOnly

	// ---- 写操作 ----
	SetNonce(addr types.Address, n types.Nonce)
	SetBalance(addr types.Address, v types.Uint256) error
	SetCode(addr types.Address, code []byte) error
	SetStorage(addr types.Address, slot, value types.Hash)

	// ---- 回滚（EVM REVERT 语义依赖它）----

	// Savepoint 返回一个回滚点标记。
	Savepoint() Savepoint

	// RollbackTo 回滚到指定 savepoint。
	// 必须是 O(变更数)，而不是重新计算整个状态。
	RollbackTo(sp Savepoint)

	// Release 释放 savepoint（成功路径，释放 journal 条目）。
	Release(sp Savepoint)

	// ---- 提交 ----

	// Commit Merkle 化并返回新状态根。
	Commit() (types.StateRoot, error)
}

// Savepoint 是回滚点标记（journal 长度）。
type Savepoint int

// ============================================================================
// 错误
// ============================================================================

var (
	// ErrAccountNotFound 账户不存在。
	ErrAccountNotFound = errors.New("state: 账户不存在")
	// ErrInvalidSavepoint savepoint 无效（已被回滚过）。
	ErrInvalidSavepoint = errors.New("state: 无效的 savepoint")
	// ErrSessionCommitted 会话已提交，不能再写入。
	ErrSessionCommitted = errors.New("state: 会话已提交")
	// ErrBalanceOverflow 余额溢出。
	ErrBalanceOverflow = errors.New("state: 余额溢出")
	// ErrInsufficientBalance 余额不足。
	ErrInsufficientBalance = errors.New("state: 余额不足")
)

// EmptyCodeHash 返回空代码哈希。
// 单独提出来是为了避免 state 包直接依赖 crypto 包的常量（保持依赖清晰）。
func EmptyCodeHash() types.Hash {
	return types.Hash{
		0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2,
		0xdc, 0xc7, 0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b,
		0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
	}
}

// EmptyStorageRoot 返回空存储树根。
func EmptyStorageRoot() types.Hash {
	return types.Hash{
		0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6,
		0x92, 0xc0, 0xf8, 0x6e, 0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0,
		0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
	}
}
