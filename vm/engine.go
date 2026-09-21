// Package vm — geth EVM 引擎的执行入口。
//
// 实现链：解码原始交易 → 恢复 sender → 构造 EVM → ApplyMessage → 收据。
// gas 计量与消息应用复用 geth 的 core.ApplyMessage（它实现了
// intrinsic gas、访问列表计费、value 转移、EVM 调用与退款的全套规则），
// 自研只会引入与以太坊语义的偏差。
//
// ⚠️ geth v1.17.5 的 API 与旧版本差异较大（实测记录）：
//   - NewEVM 不再接收 TxContext，改用 evm.SetTxContext(txCtx)
//   - GasPool 是 struct，用 core.NewGasPool(amount) 构造
//   - ChainConfig 的 ShanghaiTime/CancunTime 是 *uint64 而非 *big.Int
//   - CreateAddress 在 crypto 包（不在 core）
package vm

import (
	"errors"
	"fmt"
	"math/big"

	gethCommon "github.com/ethereum/go-ethereum/common"
	gethCore "github.com/ethereum/go-ethereum/core"
	gethTypes "github.com/ethereum/go-ethereum/core/types"
	gethVM "github.com/ethereum/go-ethereum/core/vm"
	gethCrypto "github.com/ethereum/go-ethereum/crypto"
	gethParams "github.com/ethereum/go-ethereum/params"
	gethU256 "github.com/holiman/uint256"

	"github.com/chfault/chfault/state"
	"github.com/chfault/chfault/types"
)

// u64Ptr 辅助：*uint64（fork 激活时间戳）。
func u64Ptr(v uint64) *uint64 { return &v }

// ChainConfigFor 返回 v0 的链配置。
//
// fork 全部在第 0 块/第 0 秒激活，止于 Cancun（v0 目标）。
// 这是**协议的一部分**：升级 fork = 硬分叉（ADR-006、docs/blueprint/05 §5.2），
// 必须按高度激活并全节点协调，不允许"悄悄跟上 geth 最新"。
func ChainConfig(chainID uint64) *gethParams.ChainConfig {
	id := new(big.Int).SetUint64(chainID)
	return &gethParams.ChainConfig{
		ChainID: id,
		// 共识引擎字段：chfault 自己做 BFT，不使用 geth 的引擎；
		// isMerge 传 true 时这些字段不参与判定
		HomesteadBlock:      big.NewInt(0),
		DAOForkBlock:        big.NewInt(0),
		DAOForkSupport:      false,
		EIP150Block:         big.NewInt(0),
		EIP155Block:         big.NewInt(0),
		EIP158Block:         big.NewInt(0),
		ByzantiumBlock:      big.NewInt(0),
		ConstantinopleBlock: big.NewInt(0),
		PetersburgBlock:     big.NewInt(0),
		IstanbulBlock:       big.NewInt(0),
		BerlinBlock:         big.NewInt(0),
		LondonBlock:         big.NewInt(0),
		ArrowGlacierBlock:   big.NewInt(0),
		GrayGlacierBlock:    big.NewInt(0),
		MergeNetsplitBlock:  big.NewInt(0),
		ShanghaiTime:        u64Ptr(0),
		CancunTime:          u64Ptr(0),
		// Prague 及之后：v0 不启用（不设置 PragueTime）
		TerminalTotalDifficulty: big.NewInt(0),
	}
}

// ExecutionContext 是执行一份交易所需的区块上下文。
type ExecutionContext struct {
	Height    types.Height
	Timestamp uint64
	Proposer  types.Address
	BaseFee   types.Uint256
	GasLimit  types.Gas
	ChainID   uint64
	PrevHash  types.Hash
}

// ExecutionResult 是交易执行结果（与以太坊语义对齐）。
type ExecutionResult struct {
	Success           bool
	GasUsed           types.Gas
	EffectiveGasPrice types.Uint256
	Logs              []*gethTypes.Log
	ReturnData        []byte
	ContractAddress   *types.Address
	VMError           string // 失败原因（revert 或异常），空 = 成功
}

// 错误。
var (
	// ErrDecodeTx 交易解码失败。
	ErrDecodeTx = errors.New("vm: 交易解码失败")
	// ErrBadSender sender 恢复失败。
	ErrBadSender = errors.New("vm: sender 恢复失败")
	// ErrInsufficientFunds 余额不足。
	ErrInsufficientFunds = errors.New("vm: 余额不足")
	// ErrNonceMismatch nonce 不匹配。
	ErrNonceMismatch = errors.New("vm: nonce 不匹配")
)

// Engine 用 geth 的 EVM 执行交易。
type Engine struct {
	chainConfig *gethParams.ChainConfig
}

// NewEngine 创建 EVM 引擎。
func NewEngine(chainID uint64) *Engine {
	return &Engine{chainConfig: ChainConfig(chainID)}
}

// ChainConfig 返回引擎使用的链配置。
func (e *Engine) ChainConfig() *gethParams.ChainConfig { return e.chainConfig }

// DecodeTx 解码原始交易字节（支持 legacy 与 typed，EIP-2718）。
//
// 直接用 geth 的解码 —— 交易格式与以太坊逐字节一致是硬要求，
// 自研解码器只会引入不兼容。
func (e *Engine) DecodeTx(data []byte) (*gethTypes.Transaction, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: 空数据", ErrDecodeTx)
	}
	if len(data) > types.MaxTxSize {
		return nil, fmt.Errorf("%w: 超过 %d 字节", types.ErrOversized, types.MaxTxSize)
	}

	var tx gethTypes.Transaction
	if err := tx.UnmarshalBinary(data); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecodeTx, err)
	}
	return &tx, nil
}

// RecoverSender 从交易恢复发送者（含 chainId 校验）。
func (e *Engine) RecoverSender(tx *gethTypes.Transaction) (types.Address, error) {
	signer := gethTypes.LatestSignerForChainID(e.chainConfig.ChainID)
	sender, err := gethTypes.Sender(signer, tx)
	if err != nil {
		return types.Address{}, fmt.Errorf("%w: %v", ErrBadSender, err)
	}
	return types.Address(sender), nil
}

// ValidateAgainstState 交易入池/执行前的状态校验（nonce、余额）。
func (e *Engine) ValidateAgainstState(sess state.ReadOnly, tx *gethTypes.Transaction, sender types.Address) error {
	acc, err := sess.GetAccount(sender)
	if err != nil {
		return fmt.Errorf("%w: 账户查询失败", ErrNonceMismatch)
	}
	if acc == nil {
		acc = &state.Account{}
	}

	if tx.Nonce() != uint64(acc.Nonce) {
		return fmt.Errorf("%w: 账户 %d，交易 %d", ErrNonceMismatch, acc.Nonce, tx.Nonce())
	}

	// 余额 >= gasLimit × maxFee + value（最坏情况）
	cost := tx.Cost() // *big.Int
	balance := toGethU256(acc.Balance)
	costU256, overflow := gethU256.FromBig(cost)
	if !overflow && balance.Cmp(costU256) < 0 {
		return fmt.Errorf("%w: 余额 %s < 需要 %s", ErrInsufficientFunds,
			balance.String(), cost.String())
	}
	return nil
}

// RunTx 执行一笔交易，返回结果。
//
// 失败的交易（revert）由调用方通过 savepoint 回滚状态，但 gas 仍然扣除 ——
// 这与以太坊语义一致，且是 chfault journal 设计的直接用途。
func (e *Engine) RunTx(
	sess state.Session,
	rawTx *gethTypes.Transaction,
	sender types.Address,
	ctx *ExecutionContext,
) (*ExecutionResult, error) {

	// ---- 区块上下文 ----
	prevHash := gethCommon.Hash(ctx.PrevHash)
	blockNumber := big.NewInt(int64(ctx.Height))

	blockCtx := gethVM.BlockContext{
		CanTransfer: gethCore.CanTransfer,
		Transfer:    gethCore.Transfer,
		GetHash: func(n uint64) gethCommon.Hash {
			// v0 只提供父哈希；完整历史回溯由链层在 M2 提供
			if n < uint64(ctx.Height) {
				return prevHash
			}
			return gethCommon.Hash{}
		},
		Coinbase:    gethCommon.Address(ctx.Proposer),
		BlockNumber: blockNumber,
		Time:        ctx.Timestamp,
		Difficulty:  big.NewInt(0), // PoS 后为 0
		BaseFee:     new(big.Int).SetBytes(ctx.BaseFee[:]),
		GasLimit:    uint64(ctx.GasLimit),
		Random:      nil,
	}

	// ---- 交易上下文（v1.17.5：通过 SetTxContext 设置，不再走 NewEVM 参数）----
	baseFeeBig := new(big.Int).SetBytes(ctx.BaseFee[:])
	gasPrice := txEffectiveGasPrice(rawTx, baseFeeBig)

	adapter := NewStateDBAdapter(sess)
	txCtx := gethVM.TxContext{
		Origin:       gethCommon.Address(sender),
		GasPrice:     gethU256.MustFromBig(gasPrice),
		BlobHashes:   nil,
		AccessEvents: adapter.accessEvents,
	}

	// ---- 构造 EVM（v1.17.5：NewEVM 无 txCtx 参数）----
	rules := e.chainConfig.Rules(blockNumber, true, ctx.Timestamp)
	evm := gethVM.NewEVM(blockCtx, adapter, e.chainConfig, gethVM.Config{})
	evm.SetTxContext(txCtx)

	// Berlin 之后预热 access list（sender/coinbase/precompiles/tx 自带列表）
	var dest *gethCommon.Address
	if msgTo := rawTx.To(); msgTo != nil {
		d := *msgTo
		dest = &d
	}
	adapter.Prepare(rules, gethCommon.Address(sender), blockCtx.Coinbase,
		dest, gethVM.PrecompiledAddressesCancun, nil)

	// ---- 构造 Message 并执行 ----
	signer := gethTypes.LatestSignerForChainID(e.chainConfig.ChainID)
	msg, err := gethCore.TransactionToMessage(rawTx, signer, baseFeeBig)
	if err != nil {
		return nil, fmt.Errorf("vm: 构造消息失败: %w", err)
	}

	gp := gethCore.NewGasPool(rawTx.Gas())
	result, err := gethCore.ApplyMessage(evm, msg, gp)
	if err != nil {
		return nil, fmt.Errorf("vm: 执行失败: %w", err)
	}
	defer evm.Release()

	// ---- 产出结果 ----
	out := &ExecutionResult{
		Success:           !result.Failed(),
		GasUsed:           types.Gas(result.UsedGas),
		EffectiveGasPrice: mustUint256(gasPrice),
		Logs:              adapter.Logs(),
		ReturnData:        result.Return(),
	}

	if result.Failed() {
		out.Success = false
		if result.Err != nil {
			out.VMError = result.Err.Error()
		}
	}

	// 合约创建：标准 CREATE 地址推导（keccak(rlp(sender, nonce))[12:]）
	if msg.To == nil {
		addr := gethCrypto.CreateAddress(gethCommon.Address(sender), rawTx.Nonce())
		out.ContractAddress = (*types.Address)(&addr)
	}

	return out, nil
}

// EffectiveGasPrice 计算 1559 的实际单价（导出供 RPC 与测试使用）。
//
//	effective = min(maxFee, baseFee + maxPriority)
//	legacy    = gasPrice
func EffectiveGasPrice(tx *gethTypes.Transaction, baseFee *big.Int) *big.Int {
	return txEffectiveGasPrice(tx, baseFee)
}

// txEffectiveGasPrice 计算 1559 的实际单价。
//
//	effective = min(maxFee, baseFee + maxPriority)
//	legacy    = gasPrice
func txEffectiveGasPrice(tx *gethTypes.Transaction, baseFee *big.Int) *big.Int {
	if tx.Type() == gethTypes.LegacyTxType {
		return tx.GasPrice()
	}
	headroom := new(big.Int).Sub(tx.GasFeeCap(), baseFee)
	if headroom.Sign() < 0 {
		headroom = big.NewInt(0)
	}
	tip := headroom
	if tx.GasTipCap().Cmp(tip) < 0 {
		tip = tx.GasTipCap()
	}
	return new(big.Int).Add(baseFee, tip)
}

// mustUint256 big.Int → Uint256（溢出即 panic：gas 价格不可能超过 256 位）。
func mustUint256(v *big.Int) types.Uint256 {
	out, err := types.Uint256FromBig(v)
	if err != nil {
		panic(fmt.Sprintf("vm: gas price 转换溢出: %v", err))
	}
	return out
}
