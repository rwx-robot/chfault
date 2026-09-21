package vm

import (
	"math/big"

	gethCommon "github.com/ethereum/go-ethereum/common"
	gethCore "github.com/ethereum/go-ethereum/core"
	gethState "github.com/ethereum/go-ethereum/core/state"
	gethVM "github.com/ethereum/go-ethereum/core/vm"
	gethU256 "github.com/holiman/uint256"

	"github.com/chfault/chfault/state"
	"github.com/chfault/chfault/types"
)

// RunCall 在指定状态根上执行一次**只读**消息调用（eth_call 语义）。
//
// 与 RunTx 的区别：
//   - 不修改任何状态（session Commit 的结果被丢弃）
//   - 不消耗 gas 费（value 转移也发生在临时会话中）
//   - gas 上限由调用者指定，仍受 EVM gas 计量约束
//
// 用途：eth_call、eth_estimateGas、链下预言机的模拟执行。
//
// **确定性**：给定 (状态根, 调用参数)，结果在任何节点都相同 ——
// 这是 RPC 查询可验证的前提。
func (e *Engine) RunCall(
	sess state.Session, // 调用方持有会话；本方法保证不提交
	caller types.Address,
	to types.Address,
	data []byte,
	gasLimit types.Gas,
	ctx *ExecutionContext,
) (*ExecutionResult, error) {

	blockCtx := gethVM.BlockContext{
		CanTransfer: gethCore.CanTransfer,
		Transfer:    gethCore.Transfer,
		GetHash:     func(uint64) gethCommon.Hash { return gethCommon.Hash(ctx.PrevHash) },
		Coinbase:    gethCommon.Address(ctx.Proposer),
		BlockNumber: bigNewInt(uint64(ctx.Height)),
		Time:        ctx.Timestamp,
		Difficulty:  bigNewInt(0),
		BaseFee:     bigNewInt(0), // eth_call 无 gas 费
		GasLimit:    uint64(ctx.GasLimit),
		Random:      nil,
	}

	txCtx := gethVM.TxContext{
		Origin:       gethCommon.Address(caller),
		GasPrice:     gethU256.NewInt(0), // eth_call 无 gas 价
		BlobHashes:   nil,
		AccessEvents: gethState.NewAccessEvents(),
	}

	adapter := NewStateDBAdapter(sess)
	evm := gethVM.NewEVM(blockCtx, adapter, e.chainConfig, gethVM.Config{})
	evm.SetTxContext(txCtx)
	defer evm.Release()

	// 预热 access list
	dest := gethCommon.Address(to)
	adapter.Prepare(
		e.chainConfig.Rules(bigNewInt(uint64(ctx.Height)), true, ctx.Timestamp),
		gethCommon.Address(caller), blockCtx.Coinbase, &dest,
		gethVM.PrecompiledAddressesCancun, nil,
	)

	// 直接调用目标合约（不经过签名与 gas 扣费）
	initial := gasBudgetOf(gasLimit)
	ret, leftover, err := evm.StaticCall(gethCommon.Address(caller), dest,
		data, initial)
	gasUsed := types.Gas(leftover.Used(initial))
	if err != nil {
		// 非 revert 的异常（如 OOG）
		return &ExecutionResult{
			Success: false,
			GasUsed: gasUsed,
			VMError: err.Error(),
		}, nil
	}

	return &ExecutionResult{
		Success:    true,
		GasUsed:    gasUsed,
		ReturnData: ret,
	}, nil
}

// EstGas 返回一段调用数据在指定状态下大约会消耗的 gas（eth_estimateGas 语义）。
//
// v0 用保守估计：intrinsic gas + 全额执行；有 revert 则返回失败原因。
// 精确的 estimateGas 语义（与真实执行差 1）在 M1 收尾时对齐。
func (e *Engine) EstGas(
	sess state.Session,
	from, to types.Address,
	data []byte,
	gasCap types.Gas,
	ctx *ExecutionContext,
) (types.Gas, string, error) {

	result, err := e.RunCall(sess, from, to, data, gasCap, ctx)
	if err != nil {
		return 0, "", err
	}
	if !result.Success {
		return 0, result.VMError, nil
	}
	return result.GasUsed, "", nil
}

// ============================================================================
// geth 类型薄封装（避免 import 泄漏到上层）
// ============================================================================

func bigNewInt(v uint64) *big.Int { return new(big.Int).SetUint64(v) }

// gasBudgetOf types.Gas → geth GasBudget（v0 无 state gas 储备，EIP-XXXX 未启用）。
func gasBudgetOf(g types.Gas) gethVM.GasBudget {
	return gethVM.NewGasBudget(uint64(g), 0)
}
