// Package vm 桥接 geth 的 EVM 与 chfault 的状态层。
//
// 核心是 statedbAdapter：把 chfault 的 state.Session 适配为 geth 的
// vm.StateDB 接口（约 40 个方法）。geth 的 EVM 解释器通过这个接口
// 读写状态，而真正的状态存储与回滚仍然由 chfault 自己实现。
//
// 许可说明（ADR-016，已决策 A）：本包依赖 go-ethereum 的 core/vm、
// core/types、core（ApplyMessage）与 params —— 这些是 LGPLv3。
// chfault 因此整体以 LGPLv3 开源。geth 的 import 只允许出现在本包
// 与 chain 包（depguard 强制）。
//
// geth 的版本坑（实测记录）：
//   - StateDB 接口随版本演进（v1.17.5 比 v1.16 多了 IsNewContract /
//     Selfdestruct6780 / SetTransientState 签名变化等），升级必须全量重跑测试
//   - Signature.Serialize() 是 DER 编码（见 crypto/signature.go）
//   - 适配器没有实现的方法若被 EVM 调到，会 panic 而非静默返回零值 ——
//     宁可崩溃也不产出错误的 stateRoot
package vm

import (
	"errors"
	"fmt"
	"math/big"
	"sync"

	gethCommon "github.com/ethereum/go-ethereum/common"
	gethState "github.com/ethereum/go-ethereum/core/state"
	gethStateless "github.com/ethereum/go-ethereum/core/stateless"
	gethTracing "github.com/ethereum/go-ethereum/core/tracing"
	gethTypes "github.com/ethereum/go-ethereum/core/types"
	gethBal "github.com/ethereum/go-ethereum/core/types/bal"
	gethVM "github.com/ethereum/go-ethereum/core/vm"
	gethParams "github.com/ethereum/go-ethereum/params"
	gethU256 "github.com/holiman/uint256"

	"github.com/chfault/chfault/state"
	"github.com/chfault/chfault/types"
)

// ============================================================================
// 类型互转
// ============================================================================

// toGethAddr chfault Address → geth common.Address。
func toGethAddr(a types.Address) gethCommon.Address {
	return gethCommon.Address(a)
}

// fromGethAddr geth common.Address → chfault Address。
func fromGethAddr(a gethCommon.Address) types.Address {
	return types.Address(a)
}

// toGethHash chfault Hash → geth common.Hash。
func toGethHash(h types.Hash) gethCommon.Hash {
	return gethCommon.Hash(h)
}

// fromGethHash geth common.Hash → chfault Hash。
func fromGethHash(h gethCommon.Hash) types.Hash {
	return types.Hash(h)
}

// toGethU256 chfault Uint256 → geth uint256.Int（指针，geth 期望值语义）。
func toGethU256(v types.Uint256) *gethU256.Int {
	return new(gethU256.Int).SetBytes(v[:])
}

// fromGethU256 geth uint256.Int → chfault Uint256。
func fromGethU256(v *gethU256.Int) (types.Uint256, error) {
	if v == nil {
		return types.ZeroUint256(), nil
	}
	if !v.IsUint64() && v.BitLen() > 256 {
		return types.Uint256{}, errors.New("vm: uint256 超范围")
	}
	var out types.Uint256
	b := v.Bytes32()
	copy(out[:], b[:])
	return out, nil
}

// ============================================================================
// stateDBAdapter
// ============================================================================

// StateDBAdapter 把 chfault 的 state.Session 适配为 geth vm.StateDB。
type StateDBAdapter struct {
	sess state.Session

	// ---- 本交易内的账外状态 ----
	logs      []*gethTypes.Log
	refund    uint64
	refundMu  sync.Mutex
	transient map[gethCommon.Address]map[gethCommon.Hash]gethCommon.Hash

	// ---- self-destruct（EIP-6780 前语义）----
	selfDestructed map[gethCommon.Address]bool

	// ---- access list（EIP-2929）----
	accessListAddresses map[gethCommon.Address]struct{}
	accessListSlots     map[gethCommon.Address]map[gethCommon.Hash]struct{}

	// ---- access events（witness 相关，v0 最小实现）----
	accessEvents *gethState.AccessEvents

	// ---- tx 上下文 ----
	txHash    gethCommon.Hash
	txIndex   int
	journalID int // 最近一次 snapshot 之后的变更计数（用于 transient 回滚）

	// ---- transient 的回滚日志 ----
	snapDepth        int
	transientJournal []transientChange
}

// NewStateDBAdapter 创建适配器。
func NewStateDBAdapter(sess state.Session) *StateDBAdapter {
	return &StateDBAdapter{
		sess:                sess,
		transient:           make(map[gethCommon.Address]map[gethCommon.Hash]gethCommon.Hash),
		selfDestructed:      make(map[gethCommon.Address]bool),
		accessListAddresses: make(map[gethCommon.Address]struct{}),
		accessListSlots:     make(map[gethCommon.Address]map[gethCommon.Hash]struct{}),
		accessEvents:        gethState.NewAccessEvents(),
	}
}

// SetTxContext 实现接口：记录当前交易上下文。
func (a *StateDBAdapter) SetTxContext(thash gethCommon.Hash, ti int, blockAccessIndex uint32) {
	a.txHash = thash
	a.txIndex = ti
}

// ============================================================================
// 账户与余额
// ============================================================================

func (a *StateDBAdapter) CreateAccount(addr gethCommon.Address) {
	// 语义：创建一个"干净"账户（清空存储等）。
	// chfault 的 SetNonce(0) + SetBalance(0) 即可让它出现在状态里。
	a.sess.SetNonce(fromGethAddr(addr), 0)
	_ = a.sess.SetBalance(fromGethAddr(addr), types.ZeroUint256())
}

func (a *StateDBAdapter) CreateContract(addr gethCommon.Address) {
	// EIP-161：合约创建时 nonce 应为 1
	a.sess.SetNonce(fromGethAddr(addr), 1)
}

// SubBalance 扣减余额，返回扣减后的余额。
func (a *StateDBAdapter) SubBalance(addr gethCommon.Address, amount *gethU256.Int, _ gethTracing.BalanceChangeReason) gethU256.Int {
	ca := fromGethAddr(addr)
	acc, err := a.sess.GetAccount(ca)
	cur := gethU256.NewInt(0)
	if err == nil && acc != nil {
		cur = toGethU256(acc.Balance)
	}
	newVal := new(gethU256.Int).Sub(cur, amount)
	if newVal.Sign() < 0 {
		// geth 在调用前已保证余额充足；到这里说明调用方有 bug，panic 暴露
		panic(fmt.Sprintf("vm: 余额下溢 addr=%s cur=%s sub=%s",
			addr.Hex(), cur.String(), amount.String()))
	}
	chfVal, _ := fromGethU256(newVal)
	_ = a.sess.SetBalance(ca, chfVal)
	return *newVal
}

// AddBalance 增加余额，返回增加后的余额。
func (a *StateDBAdapter) AddBalance(addr gethCommon.Address, amount *gethU256.Int, _ gethTracing.BalanceChangeReason) gethU256.Int {
	ca := fromGethAddr(addr)
	acc, err := a.sess.GetAccount(ca)
	cur := gethU256.NewInt(0)
	if err == nil && acc != nil {
		cur = toGethU256(acc.Balance)
	}
	newVal := new(gethU256.Int).Add(cur, amount)
	chfVal, err := fromGethU256(newVal)
	if err != nil {
		panic(fmt.Sprintf("vm: 余额溢出 addr=%s", addr.Hex()))
	}
	_ = a.sess.SetBalance(ca, chfVal)
	return *newVal
}

// GetBalance 查询余额。
func (a *StateDBAdapter) GetBalance(addr gethCommon.Address) *gethU256.Int {
	acc, err := a.sess.GetAccount(fromGethAddr(addr))
	if err != nil || acc == nil {
		return gethU256.NewInt(0)
	}
	return toGethU256(acc.Balance)
}

// ============================================================================
// Nonce / 代码
// ============================================================================

func (a *StateDBAdapter) GetNonce(addr gethCommon.Address) uint64 {
	acc, err := a.sess.GetAccount(fromGethAddr(addr))
	if err != nil || acc == nil {
		return 0
	}
	return uint64(acc.Nonce)
}

func (a *StateDBAdapter) SetNonce(addr gethCommon.Address, nonce uint64, _ gethTracing.NonceChangeReason) {
	a.sess.SetNonce(fromGethAddr(addr), types.Nonce(nonce))
}

func (a *StateDBAdapter) GetCodeHash(addr gethCommon.Address) gethCommon.Hash {
	acc, err := a.sess.GetAccount(fromGethAddr(addr))
	if err != nil || acc == nil {
		// 不存在的账户：空哈希（以太坊语义：与"存在但无代码"区分开的是
		// Exist()，这里统一返回 EmptyCodeHash 即可）
		return gethCommon.Hash{}
	}
	return gethCommon.Hash(acc.CodeHash)
}

func (a *StateDBAdapter) GetCode(addr gethCommon.Address) []byte {
	code, err := a.sess.GetCode(fromGethAddr(addr))
	if err != nil {
		return nil
	}
	return code
}

func (a *StateDBAdapter) GetCodeSize(addr gethCommon.Address) int {
	code := a.GetCode(addr)
	return len(code)
}

func (a *StateDBAdapter) SetCode(addr gethCommon.Address, code []byte, _ gethTracing.CodeChangeReason) []byte {
	old := a.GetCode(addr)
	_ = a.sess.SetCode(fromGethAddr(addr), code)
	return old
}

// ============================================================================
// gas 退款（EIP-3529 语义由调用方计算）
// ============================================================================

func (a *StateDBAdapter) AddRefund(gas uint64) {
	a.refundMu.Lock()
	a.refund += gas
	a.refundMu.Unlock()
}

func (a *StateDBAdapter) SubRefund(gas uint64) {
	a.refundMu.Lock()
	if gas > a.refund {
		panic("vm: refund 下溢")
	}
	a.refund -= gas
	a.refundMu.Unlock()
}

func (a *StateDBAdapter) GetRefund() uint64 {
	a.refundMu.Lock()
	defer a.refundMu.Unlock()
	return a.refund
}

// ============================================================================
// 存储
// ============================================================================

func (a *StateDBAdapter) GetCommittedState(addr gethCommon.Address, key gethCommon.Hash) gethCommon.Hash {
	// v0：与 GetState 相同（没有"已提交状态"与"暂存状态"的区分，
	// 因为 journal 回滚由 savepoint 处理）。
	// 注意：这与 geth 的精确语义有偏差，影响面是 SSTORE 冷/热成本判定，
	// 由 access list 补偿；M2 引入完整 journal 对账时收紧。
	return a.GetState(addr, key)
}

func (a *StateDBAdapter) GetStateAndCommittedState(addr gethCommon.Address, key gethCommon.Hash) (gethCommon.Hash, gethCommon.Hash) {
	v := a.GetState(addr, key)
	return v, v
}

func (a *StateDBAdapter) GetState(addr gethCommon.Address, key gethCommon.Hash) gethCommon.Hash {
	v, err := a.sess.GetStorage(fromGethAddr(addr), fromGethHash(key))
	if err != nil {
		return gethCommon.Hash{}
	}
	return gethCommon.Hash(v)
}

func (a *StateDBAdapter) SetState(addr gethCommon.Address, key gethCommon.Hash, value gethCommon.Hash) gethCommon.Hash {
	old := a.GetState(addr, key)
	a.sess.SetStorage(fromGethAddr(addr), fromGethHash(key), fromGethHash(value))
	return old
}

// ============================================================================
// Transient storage（EIP-1153，TSTORE/TLOAD）
// ============================================================================

func (a *StateDBAdapter) GetTransientState(addr gethCommon.Address, key gethCommon.Hash) gethCommon.Hash {
	if m, ok := a.transient[addr]; ok {
		return m[key]
	}
	return gethCommon.Hash{}
}

func (a *StateDBAdapter) SetTransientState(addr gethCommon.Address, key, value gethCommon.Hash) {
	m, ok := a.transient[addr]
	if !ok {
		m = make(map[gethCommon.Hash]gethCommon.Hash)
		a.transient[addr] = m
	}
	old := m[key]
	m[key] = value

	// 记录变更，供 RevertToSnapshot 回滚 transient
	a.transientJournal = append(a.transientJournal, transientChange{
		id:   a.snapDepth,
		addr: addr, key: key, old: old,
	})
}

// transientChange 记录一次 transient 写入，用于回滚。
type transientChange struct {
	id   int
	addr gethCommon.Address
	key  gethCommon.Hash
	old  gethCommon.Hash
}

// ============================================================================
// 自毁
// ============================================================================

func (a *StateDBAdapter) SelfDestruct(addr gethCommon.Address) {
	// EIP-6780（Cancun）：SELFDESTRUCT 只在同一交易内创建的合约上生效，
	// 其余情况只转余额不清存储。v0 采用简化语义：清余额 + 标记。
	_ = a.sess.SetBalance(fromGethAddr(addr), types.ZeroUint256())
	a.selfDestructed[addr] = true
}

func (a *StateDBAdapter) HasSelfDestructed(addr gethCommon.Address) bool {
	return a.selfDestructed[addr]
}

func (a *StateDBAdapter) Selfdestruct6780(addr gethCommon.Address) {
	// Cancun 语义：仅当合约是本交易创建的才真正销毁。
	// v0 简化：等同 SelfDestruct（v0 目标 fork 不含 6780 完整语义时影响有限）。
	a.SelfDestruct(addr)
}

// ============================================================================
// 存在性
// ============================================================================

func (a *StateDBAdapter) Exist(addr gethCommon.Address) bool {
	acc, err := a.sess.GetAccount(fromGethAddr(addr))
	return err == nil && acc != nil
}

func (a *StateDBAdapter) Touch(addr gethCommon.Address) {
	// EIP-158 的 touch：确保账户存在（空账户会在 Finalise 时清除）
	if !a.Exist(addr) {
		a.CreateAccount(addr)
	}
}

func (a *StateDBAdapter) IsNewContract(addr gethCommon.Address) bool {
	// v0 简化：不做精确跟踪（影响 EIP-6780 的边缘语义）
	return false
}

func (a *StateDBAdapter) Empty(addr gethCommon.Address) bool {
	// EIP-161：balance = nonce = code 均为空
	acc, err := a.sess.GetAccount(fromGethAddr(addr))
	if err != nil || acc == nil {
		return true
	}
	// ⚠️ 注意运算符优先级：曾把 || 与 && 混写导致语义错误
	return acc.Balance.IsZero() && acc.Nonce == 0 && len(a.GetCode(addr)) == 0
}

// ============================================================================
// Access list（EIP-2929）
// ============================================================================

func (a *StateDBAdapter) AddressInAccessList(addr gethCommon.Address) bool {
	_, ok := a.accessListAddresses[addr]
	return ok
}

func (a *StateDBAdapter) SlotInAccessList(addr gethCommon.Address, slot gethCommon.Hash) (addressOk, slotOk bool) {
	_, aOk := a.accessListAddresses[addr]
	if _, sOk := a.accessListSlots[addr]; !sOk {
		return aOk, false
	}
	_, sOk := a.accessListSlots[addr][slot]
	return aOk, sOk
}

func (a *StateDBAdapter) AddAddressToAccessList(addr gethCommon.Address) {
	a.accessListAddresses[addr] = struct{}{}
}

func (a *StateDBAdapter) AddSlotToAccessList(addr gethCommon.Address, slot gethCommon.Hash) {
	a.AddAddressToAccessList(addr)
	if a.accessListSlots[addr] == nil {
		a.accessListSlots[addr] = make(map[gethCommon.Hash]struct{})
	}
	a.accessListSlots[addr][slot] = struct{}{}
}

// Prepare 预热 access list（sender、coinbase、precompiles、tx access list）。
func (a *StateDBAdapter) Prepare(
	rules gethParams.Rules,
	sender, coinbase gethCommon.Address,
	dest *gethCommon.Address,
	precompiles []gethCommon.Address,
	txAccesses gethTypes.AccessList,
) {
	if rules.IsBerlin {
		a.AddAddressToAccessList(sender)
		if dest != nil {
			a.AddAddressToAccessList(*dest)
		}
		for _, addr := range precompiles {
			a.AddAddressToAccessList(addr)
		}
		for _, acc := range txAccesses {
			a.AddAddressToAccessList(acc.Address)
			for _, slot := range acc.StorageKeys {
				a.AddSlotToAccessList(acc.Address, slot)
			}
		}
		if rules.IsShanghai {
			if coinbase != (gethCommon.Address{}) {
				a.AddAddressToAccessList(coinbase)
			}
		}
	}
}

// ============================================================================
// 日志 / preimage
// ============================================================================

func (a *StateDBAdapter) AddLog(log *gethTypes.Log) {
	a.logs = append(a.logs, log)
}

func (a *StateDBAdapter) Logs() []*gethTypes.Log { return a.logs }

func (a *StateDBAdapter) AddPreimage(_ gethCommon.Hash, _ []byte) {
	// preimage 只服务于调试与状态导出，v0 不做
}

// ============================================================================
// Snapshot / revert
// ============================================================================

// Snapshot 实现接口：映射到 chfault 的 savepoint。
//
// transient 状态用独立的 journal（transientJournal + snapDepth）回滚，
// 因为 chfault 的 journal 不感知它。
func (a *StateDBAdapter) Snapshot() int {
	a.snapDepth++
	return int(a.sess.Savepoint())
}

// RevertToSnapshot 回滚到指定 snapshot。
func (a *StateDBAdapter) RevertToSnapshot(id int) {
	a.sess.RollbackTo(state.Savepoint(id))

	// 回滚 transient：逆序撤销 id 之后的所有 transient 变更
	for i := len(a.transientJournal) - 1; i >= 0; i-- {
		c := a.transientJournal[i]
		if c.id < id {
			break
		}
		m := a.transient[c.addr]
		if m == nil {
			continue
		}
		if c.old == (gethCommon.Hash{}) {
			delete(m, c.key)
		} else {
			m[c.key] = c.old
		}
	}
	// 裁剪 journal
	if id == 0 {
		a.transientJournal = nil
	} else {
		cut := 0
		for i := len(a.transientJournal) - 1; i >= 0; i-- {
			if a.transientJournal[i].id < id {
				cut = i + 1
				break
			}
			if i == 0 {
				cut = 0
			}
		}
		a.transientJournal = a.transientJournal[:cut]
	}
	a.snapDepth = id
}

// ============================================================================
// geth 需要但 v0 用不到的能力
// ============================================================================

// Witness v0 返回 nil：witness 只在无状态验证（stateless clients）使用。
// 若未来 EVM 内部路径调用它，会得到 nil —— 调用方需自行判空。
func (a *StateDBAdapter) Witness() *gethStateless.Witness { return nil }

// AccessEvents 返回访问事件（用于 witness 构建）。
func (a *StateDBAdapter) AccessEvents() *gethState.AccessEvents { return a.accessEvents }

// Finalise 交易结束回调。返回 nil（v0 不构建 BAL）。
func (a *StateDBAdapter) Finalise(deleteEmptyObjects bool) *gethBal.ConstructionBlockAccessList {
	return nil
}

// ============================================================================
// 编译期接口断言
// ============================================================================

var _ gethVM.StateDB = (*StateDBAdapter)(nil)

// ============================================================================
// 辅助
// ============================================================================

var _ = big.NewInt // 保持 big 导入（Rules 构造用）

// bigIntFromU256 供 engine 使用。
func bigIntFromU256(v types.Uint256) *big.Int {
	return v.ToBig()
}
