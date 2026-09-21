package vm_test

import (
	"crypto/ecdsa"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	gethCommon "github.com/ethereum/go-ethereum/common"
	gethCore "github.com/ethereum/go-ethereum/core"
	gethTypes "github.com/ethereum/go-ethereum/core/types"
	gethCrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/chfault/chfault/state"
	"github.com/chfault/chfault/types"
	"github.com/chfault/chfault/vm"
)

// ============================================================================
// 辅助
// ============================================================================

// mustWei 把十进制 wei 字符串转为 big.Int。
func mustWei(t *testing.T, s string) *big.Int {
	t.Helper()
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		t.Fatalf("wei 解析失败: %s", s)
	}
	return v
}

const (
	// hundredETH = 100 × 10^18 wei
	hundredETH = "100000000000000000000"
	// oneETH 与 1.5 ETH
	oneETH     = "1000000000000000000"
	oneETHU    = uint64(1_000_000_000_000_000_000)
	oneHalfETH = "1500000000000000000"
)

// mkAccount 生成测试账户（真实密钥对，确定性种子）。
func mkAccount(t *testing.T, seed byte) (*ecdsa.PrivateKey, types.Address) {
	t.Helper()
	key, err := gethCrypto.HexToECDSA(hexEncodeSeed(seed))
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	addr := gethCrypto.PubkeyToAddress(key.PublicKey)
	return key, types.Address(addr)
}

// hexEncodeSeed 生成确定性的测试私钥（仅测试用，不含真实资金）。
func hexEncodeSeed(seed byte) string {
	buf := make([]byte, 32)
	for i := range buf {
		buf[i] = seed
	}
	return hex.EncodeToString(buf)
}

// signDynamicFee 用 geth 签名一笔 EIP-1559 转账。
func signDynamicFee(t *testing.T, key *ecdsa.PrivateKey, chainID uint64, nonce uint64,
	to gethCommon.Address, wei *big.Int, tipGwei, maxFeeGwei, gas uint64,
) *gethTypes.Transaction {
	t.Helper()

	tx := gethTypes.NewTx(&gethTypes.DynamicFeeTx{
		ChainID:   new(big.Int).SetUint64(chainID),
		Nonce:     nonce,
		GasTipCap: big.NewInt(int64(tipGwei) * 1_000_000_000),
		GasFeeCap: big.NewInt(int64(maxFeeGwei) * 1_000_000_000),
		Gas:       gas,
		To:        &to,
		Value:     wei,
	})
	signer := gethTypes.LatestSignerForChainID(new(big.Int).SetUint64(chainID))
	signed, err := gethTypes.SignTx(tx, signer, key)
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	return signed
}

// rawBytes 序列化交易为原始字节。
func rawBytes(t *testing.T, tx *gethTypes.Transaction) []byte {
	t.Helper()
	raw, err := tx.MarshalBinary()
	if err != nil {
		t.Fatalf("序列化交易失败: %v", err)
	}
	return raw
}

// execCtx 构造执行上下文。
func execCtx(height types.Height) *vm.ExecutionContext {
	return &vm.ExecutionContext{
		Height:    height,
		Timestamp: 1700000000 + uint64(height),
		Proposer:  types.Address{0xAA},
		BaseFee:   types.Uint256FromUint64(1_000_000_000), // 1 gwei
		GasLimit:  30_000_000,
		ChainID:   10086,
	}
}

// ============================================================================
// 核心闭环测试
// ============================================================================

// TestEVM_TransferEndToEnd 是 M1 的核心验收：
// 真实签名 → EVM 执行 → 余额转移 → nonce 递增。
func TestEVM_TransferEndToEnd(t *testing.T) {
	engine := vm.NewEngine(10086)

	keyA, addrA := mkAccount(t, 0x11)
	_, addrB := mkAccount(t, 0x22)

	mgr := state.NewMemoryManager()
	sess, err := mgr.Begin(types.StateRoot{})
	if err != nil {
		t.Fatalf("打开会话失败: %v", err)
	}
	if err := sess.SetBalance(addrA, u256Big(t, hundredETH)); err != nil {
		t.Fatalf("设置余额失败: %v", err)
	}

	// A 转账 1.5 ETH 给 B（tip 2 gwei，maxFee 10 gwei）
	tx := signDynamicFee(t, keyA, 10086, 0,
		gethCommon.Address(addrB), mustWei(t, oneHalfETH), 2, 10, 21000)

	// 解码 + 恢复 sender
	decoded, err := engine.DecodeTx(rawBytes(t, tx))
	if err != nil {
		t.Fatalf("解码失败: %v", err)
	}
	sender, err := engine.RecoverSender(decoded)
	if err != nil {
		t.Fatalf("恢复 sender 失败: %v", err)
	}
	if sender != addrA {
		t.Fatalf("sender 应为 A:\n want %s\n got  %s", addrA.String(), sender.String())
	}

	if err := engine.ValidateAgainstState(sess, decoded, sender); err != nil {
		t.Fatalf("校验失败: %v", err)
	}
	result, err := engine.RunTx(sess, decoded, sender, execCtx(1))
	if err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	if !result.Success {
		t.Fatalf("交易应成功，VM 错误: %s", result.VMError)
	}
	if result.GasUsed != 21000 {
		t.Fatalf("纯转账应消耗 21000 gas，实际 %d", result.GasUsed)
	}

	// 验证余额与 nonce
	accA, _ := sess.GetAccount(addrA)
	accB, _ := sess.GetAccount(addrB)

	// gasPrice = baseFee(1) + tip(2) = 3 gwei（未触发 maxFee 上限）
	gasCost := new(big.Int).Mul(big.NewInt(21000), big.NewInt(3_000_000_000))
	wantA := new(big.Int).Sub(mustWei(t, hundredETH), mustWei(t, oneHalfETH))
	wantA.Sub(wantA, gasCost)

	if accA.Balance.ToBig().Cmp(wantA) != 0 {
		t.Fatalf("A 余额错误:\n want %s\n got  %s", wantA.String(), accA.Balance.ToBig().String())
	}
	if accB.Balance.ToBig().Cmp(mustWei(t, oneHalfETH)) != 0 {
		t.Fatalf("B 余额错误: %s", accB.Balance.ToBig().String())
	}
	if accA.Nonce != 1 {
		t.Fatalf("A 的 nonce 应为 1，实际 %d", accA.Nonce)
	}

	t.Logf("转账成功：A = %s wei，B = %s wei，gasUsed = %d",
		accA.Balance.ToBig().String(), accB.Balance.ToBig().String(), result.GasUsed)
}

// TestEVM_RevertRollsBackStateButChargesGas 验证：
// revert 的交易回滚状态但仍扣 gas —— 这是 journal 设计的直接用途。
func TestEVM_RevertRollsBackStateButChargesGas(t *testing.T) {
	engine := vm.NewEngine(10086)
	keyA, addrA := mkAccount(t, 0x11)

	mgr := state.NewMemoryManager()
	sess, _ := mgr.Begin(types.StateRoot{})
	tenETH := mustWei(t, "10000000000000000000")
	if err := sess.SetBalance(addrA, u256Big(t, tenETH.String())); err != nil {
		t.Fatal(err)
	}

	// 部署一个总是 revert 的合约：PUSH1 0x00 PUSH1 0x00 REVERT = 60006000fd
	revertCode := []byte{0x60, 0x00, 0x60, 0x00, 0xfd}
	contractAddr := gethCommon.Address{0xCC}
	_ = sess.SetCode(types.Address(contractAddr), revertCode)

	to := contractAddr
	tx := gethTypes.NewTx(&gethTypes.DynamicFeeTx{
		ChainID:   new(big.Int).SetUint64(10086),
		Nonce:     0,
		GasTipCap: big.NewInt(2_000_000_000),
		GasFeeCap: big.NewInt(10_000_000_000),
		Gas:       100_000,
		To:        &to,
		Value:     big.NewInt(0),
	})
	signer := gethTypes.LatestSignerForChainID(new(big.Int).SetUint64(10086))
	signed, err := gethTypes.SignTx(tx, signer, keyA)
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}

	sender, _ := engine.RecoverSender(signed)
	result, err := engine.RunTx(sess, signed, sender, execCtx(1))
	if err != nil {
		t.Fatalf("执行层错误（revert 不应产生执行层错误）: %v", err)
	}

	if result.Success {
		t.Fatal("revert 合约的交易应失败")
	}
	if result.VMError == "" {
		t.Fatal("应记录 VM 错误信息")
	}
	if result.GasUsed == 0 {
		t.Fatal("revert 仍应消耗 gas")
	}

	accA, _ := sess.GetAccount(addrA)
	if accA.Nonce != 1 {
		t.Fatalf("revert 后 nonce 应为 1，实际 %d", accA.Nonce)
	}
	if accA.Balance.ToBig().Cmp(tenETH) >= 0 {
		t.Fatal("revert 后余额应减少（gas 扣费）")
	}

	t.Logf("revert：gasUsed=%d，VMError=%q，A 余额=%s",
		result.GasUsed, result.VMError, accA.Balance.ToBig().String())
}

// TestEVM_NonceMismatchRejected 验证 nonce 不匹配被拒绝。
func TestEVM_NonceMismatchRejected(t *testing.T) {
	engine := vm.NewEngine(10086)
	keyA, addrA := mkAccount(t, 0x11)
	_, addrB := mkAccount(t, 0x22)

	mgr := state.NewMemoryManager()
	sess, _ := mgr.Begin(types.StateRoot{})
	_ = sess.SetBalance(addrA, types.Uint256FromUint64(oneETHU))
	sess.SetNonce(addrA, 5)

	tx := signDynamicFee(t, keyA, 10086, 0, gethCommon.Address(addrB),
		mustWei(t, oneETH), 2, 10, 21000)
	if err := engine.ValidateAgainstState(sess, tx, addrA); err == nil {
		t.Fatal("nonce 不匹配应被拒绝")
	} else if !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("错误信息应提及 nonce: %v", err)
	}
}

// TestEVM_InsufficientFundsRejected 验证余额不足被拒绝。
func TestEVM_InsufficientFundsRejected(t *testing.T) {
	engine := vm.NewEngine(10086)
	keyA, addrA := mkAccount(t, 0x11)
	_, addrB := mkAccount(t, 0x22)

	mgr := state.NewMemoryManager()
	sess, _ := mgr.Begin(types.StateRoot{})
	_ = sess.SetBalance(addrA, types.Uint256FromUint64(1000))

	tx := signDynamicFee(t, keyA, 10086, 0, gethCommon.Address(addrB),
		mustWei(t, oneETH), 2, 10, 21000)
	if err := engine.ValidateAgainstState(sess, tx, addrA); err == nil {
		t.Fatal("余额不足应被拒绝")
	}
}

// TestEVM_ChainIDMismatchRejected 验证跨链重放保护。
func TestEVM_ChainIDMismatchRejected(t *testing.T) {
	engine := vm.NewEngine(10086)
	keyA, _ := mkAccount(t, 0x11)
	to := gethCommon.Address{0x42}

	// 用 chainId 999 签名，引擎期望 10086
	tx := signDynamicFee(t, keyA, 999, 0, to, mustWei(t, oneETH), 2, 10, 21000)
	if _, err := engine.RecoverSender(tx); err == nil {
		t.Fatal("chainId 不匹配应导致 sender 恢复失败")
	}
}

// TestEVM_SmartContractStorage 验证合约部署 + SSTORE/SLOAD（完整 EVM 路径）。
func TestEVM_SmartContractStorage(t *testing.T) {
	engine := vm.NewEngine(10086)
	keyA, addrA := mkAccount(t, 0x11)

	mgr := state.NewMemoryManager()
	sess, _ := mgr.Begin(types.StateRoot{})
	if err := sess.SetBalance(addrA, u256Big(t, hundredETH)); err != nil {
		t.Fatal(err)
	}

	// 部署合约：PUSH1 42 PUSH1 0 SSTORE STOP（602a60005500）
	// 602a600055  SSTORE(0, 42)
	// 6001600053  MSTORE8(0, 1)
	// 60016000f3  RETURN(0, 1)  → runtime code = [0x01]（无 RETURN 则 SetCode 不会被调用）
	// 00          STOP
	deployCode := []byte{0x60, 0x2a, 0x60, 0x00, 0x55, 0x60, 0x01, 0x60, 0x00, 0x53, 0x60, 0x01, 0x60, 0x00, 0xf3, 0x00}
	deployTx := gethTypes.NewTx(&gethTypes.DynamicFeeTx{
		ChainID:   new(big.Int).SetUint64(10086),
		Nonce:     0,
		GasTipCap: big.NewInt(1_000_000_000),
		GasFeeCap: big.NewInt(10_000_000_000),
		Gas:       100_000,
		To:        nil,
		Value:     big.NewInt(0),
		Data:      deployCode,
	})
	signer := gethTypes.LatestSignerForChainID(new(big.Int).SetUint64(10086))
	signedDeploy, _ := gethTypes.SignTx(deployTx, signer, keyA)

	sender, _ := engine.RecoverSender(signedDeploy)
	result, err := engine.RunTx(sess, signedDeploy, sender, execCtx(1))
	if err != nil {
		t.Fatalf("部署失败: %v", err)
	}
	if !result.Success || result.ContractAddress == nil {
		t.Fatalf("部署失败: success=%v addr=%v err=%s",
			result.Success, result.ContractAddress, result.VMError)
	}

	// CREATE 地址推导
	want := gethCrypto.CreateAddress(gethCommon.Address(addrA), 0)
	if *result.ContractAddress != types.Address(want) {
		t.Fatalf("CREATE 地址错误:\n want %s\n got  %s",
			want.Hex(), result.ContractAddress.String())
	}

	// SSTORE：slot 0 = 42
	slot, _ := sess.GetStorage(*result.ContractAddress, types.Hash{})
	if slot[31] != 42 {
		t.Fatalf("SSTORE 未生效: slot0[31] = %d", slot[31])
	}

	// 代码已存储
	codeStored, err := sess.GetCode(*result.ContractAddress)
	if err != nil || len(codeStored) == 0 {
		t.Fatalf("合约代码未存储: %v", err)
	}

	t.Logf("合约部署于 %s，存储 42，gas=%d",
		result.ContractAddress.String(), result.GasUsed)
}

// TestEVM_DeterministicExecution 验证 EVM 执行的确定性。
//
// 同一笔交易在同样的初始状态下必须产生完全相同的结果 ——
// 这是多节点共识的前提。
func TestEVM_DeterministicExecution(t *testing.T) {
	run := func() (uint64, int, string) {
		engine := vm.NewEngine(10086)
		keyA, addrA := mkAccount(t, 0x11)
		_, addrB := mkAccount(t, 0x22)

		mgr := state.NewMemoryManager()
		sess, _ := mgr.Begin(types.StateRoot{})
		_ = sess.SetBalance(addrA, u256Big(t, hundredETH))

		tx := signDynamicFee(t, keyA, 10086, 0, gethCommon.Address(addrB),
			mustWei(t, oneHalfETH), 2, 10, 21000)
		sender, _ := engine.RecoverSender(tx)
		result, err := engine.RunTx(sess, tx, sender, execCtx(1))
		if err != nil {
			t.Fatalf("执行失败: %v", err)
		}
		return uint64(result.GasUsed), len(result.Logs), result.VMError
	}

	firstGas, firstLogs, firstErr := run()
	for i := 0; i < 10; i++ {
		gas, logs, vmErr := run()
		if gas != firstGas || logs != firstLogs || vmErr != firstErr {
			t.Fatalf("第 %d 次执行结果不一致: (%d,%d,%q) vs (%d,%d,%q)",
				i, gas, logs, vmErr, firstGas, firstLogs, firstErr)
		}
	}
}

// TestGasPrice_Calculation 验证 1559 的 effective gas price。
func TestGasPrice_Calculation(t *testing.T) {
	baseFee := big.NewInt(1_000_000_000)

	cases := []struct {
		name          string
		maxFeeGwei    uint64
		maxTipGwei    uint64
		wantPriceGwei uint64
	}{
		{"tip_limited", 100, 3, 4},     // baseFee(1) + tip(3) = 4 < maxFee
		{"headroom_limited", 2, 50, 2}, // maxFee 限制
		{"exact_match", 4, 3, 4},       // baseFee+tip == maxFee
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			to := gethCommon.Address{0x42}
			tx := gethTypes.NewTx(&gethTypes.DynamicFeeTx{
				ChainID:   new(big.Int).SetUint64(10086),
				Nonce:     0,
				GasTipCap: big.NewInt(int64(tc.maxTipGwei) * 1_000_000_000),
				GasFeeCap: big.NewInt(int64(tc.maxFeeGwei) * 1_000_000_000),
				Gas:       21000,
				To:        &to,
			})
			got := vm.EffectiveGasPrice(tx, baseFee)
			want := big.NewInt(int64(tc.wantPriceGwei) * 1_000_000_000)
			if got.Cmp(want) != 0 {
				t.Fatalf("effective gas price: want %s got %s", want, got)
			}
		})
	}
}

// TestChainConfig_ForksAtGenesis 验证 fork 配置（Cancun 全激活，无 Prague）。
func TestChainConfig_ForksAtGenesis(t *testing.T) {
	cfg := vm.ChainConfig(10086)
	if cfg.ChainID.Uint64() != 10086 {
		t.Fatal("chainId 错误")
	}

	rules := cfg.Rules(big.NewInt(1), true, 1)
	if !rules.IsBerlin || !rules.IsLondon || !rules.IsShanghai || !rules.IsCancun {
		t.Fatal("Berlin/London/Shanghai/Cancun 应在第 1 块激活")
	}
	if rules.IsPrague {
		t.Fatal("Prague 不应激活（v0 目标止于 Cancun）")
	}
}

// TestLegacyTxSupport 验证 legacy 交易兼容（旧客户端工具）。
func TestLegacyTxSupport(t *testing.T) {
	engine := vm.NewEngine(10086)
	keyA, addrA := mkAccount(t, 0x11)
	_, addrB := mkAccount(t, 0x22)

	mgr := state.NewMemoryManager()
	sess, _ := mgr.Begin(types.StateRoot{})
	_ = sess.SetBalance(addrA, u256Big(t, hundredETH))

	tx := gethTypes.NewTx(&gethTypes.LegacyTx{
		Nonce:    0,
		GasPrice: big.NewInt(3_000_000_000),
		Gas:      21000,
		To:       addrPtr(addrB),
		Value:    mustWei(t, oneETH),
	})
	signer := gethTypes.NewEIP155Signer(big.NewInt(10086))
	signed, err := gethTypes.SignTx(tx, signer, keyA)
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}

	sender, err := engine.RecoverSender(signed)
	if err != nil {
		t.Fatalf("legacy 交易的 sender 恢复失败: %v", err)
	}
	if sender != addrA {
		t.Fatal("sender 不匹配")
	}

	result, err := engine.RunTx(sess, signed, sender, execCtx(1))
	if err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	if !result.Success || result.GasUsed != 21000 {
		t.Fatalf("legacy 转账结果异常: success=%v gas=%d", result.Success, result.GasUsed)
	}

	// legacy 的 gasPrice 直接生效（3 gwei）
	wantBalance := new(big.Int).Sub(mustWei(t, hundredETH), mustWei(t, oneETH))
	gasCost := new(big.Int).Mul(big.NewInt(21000), big.NewInt(3_000_000_000))
	wantBalance.Sub(wantBalance, gasCost)
	accA, _ := sess.GetAccount(addrA)
	if accA.Balance.ToBig().Cmp(wantBalance) != 0 {
		t.Fatalf("legacy 余额计算错误:\n want %s\n got  %s",
			wantBalance.String(), accA.Balance.ToBig().String())
	}
}

// TestApplyMessageRejectsInsufficientTransfer 验证 geth 的 CanTransfer
// 通过 StateDBAdapter 正确读取 chfault 状态（适配器完整性验证）。
func TestApplyMessageRejectsInsufficientTransfer(t *testing.T) {
	engine := vm.NewEngine(10086)
	keyA, addrA := mkAccount(t, 0x11)
	_, addrB := mkAccount(t, 0x22)

	// A 余额刚好只够 gas（无转账空间）
	mgr := state.NewMemoryManager()
	sess, _ := mgr.Begin(types.StateRoot{})
	justGas := new(big.Int).Mul(big.NewInt(21000), big.NewInt(3_000_000_000))
	if err := sess.SetBalance(addrA, u256Big(t, justGas.String())); err != nil {
		t.Fatal(err)
	}

	// 转账 1 wei → 余额不足，ApplyMessage 拒绝
	tx := signDynamicFee(t, keyA, 10086, 0, gethCommon.Address(addrB),
		big.NewInt(1), 2, 10, 21000)
	sender, _ := engine.RecoverSender(tx)
	_, err := engine.RunTx(sess, tx, sender, execCtx(1))
	if err == nil {
		t.Fatal("余额不足的交易应被 ApplyMessage 拒绝")
	}
}

// ============================================================================
// 辅助
// ============================================================================

func addrPtr(a types.Address) *gethCommon.Address {
	ga := gethCommon.Address(a)
	return &ga
}

// 编译期引用检查
var _ = gethCore.CanTransfer

// u256Big 从十进制字符串构造 Uint256（测试辅助，Uint256FromBig 是双返回值）。
func u256Big(t *testing.T, s string) types.Uint256 {
	t.Helper()
	v, err := types.Uint256FromBig(mustWei(t, s))
	if err != nil {
		t.Fatalf("Uint256 构造失败: %v", err)
	}
	return v
}
