package node_test

import (
	"encoding/hex"
	"math/big"
	"os"
	"strings"
	"testing"

	gethCommon "github.com/ethereum/go-ethereum/common"
	gethTypes "github.com/ethereum/go-ethereum/core/types"

	"github.com/chfault/chfault/crypto"
	"github.com/chfault/chfault/types"
)

// ============================================================================
// ERC20 真实合约端到端 —— M1 DoD 的最后一块拼图
//
// 合约：solc 0.8.37 编译的 SimpleToken（testdata/simple_token.bin，
// 源码见 testdata/Token.sol —— transfer / balanceOf / Transfer 事件）。
//
// 链路：部署（CREATE）→ balanceOf（eth_call 语义）→ transfer（状态变更）
// → 余额断言。全部走真实 EVM 执行 + 共识出块。
// ============================================================================

const (
	// tokenSupply 初始供应量：1000 * 10^18。
	tokenSupply = "1000000000000000000000"
	// transferAmount 转账量：100 * 10^18。
	transferAmount = "100000000000000000000"
)

// loadTokenBytecode 读取编译产物。
func loadTokenBytecode(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/simple_token.bin")
	if err != nil {
		t.Fatalf("读取字节码失败: %v", err)
	}
	bin, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("hex 解码失败: %v", err)
	}
	return bin
}

// selector 计算函数选择器（keccak[:4]）。
func selector(sig string) []byte {
	h := crypto.Keccak256([]byte(sig))
	return h[:4]
}

// padRight20 地址左填充到 32 字节（ABI 编码）。
func padAddr(a types.Address) []byte {
	out := make([]byte, 32)
	copy(out[12:], a[:])
	return out
}

// padUint uint256 大端 32 字节。
func padUint(s string) []byte {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("bad uint")
	}
	out := make([]byte, 32)
	v.FillBytes(out)
	return out
}

// encodeCall 组装 calldata：selector + ABI 参数。
func encodeCall(sig string, args ...[]byte) []byte {
	out := selector(sig)
	for _, a := range args {
		out = append(out, a...)
	}
	return out
}

// readBalance 通过 eth_call 语义查询 balanceOf（只读，不产生区块）。
func readBalance(t *testing.T, n interface {
	Call(from, to types.Address, data []byte, gas uint64) ([]byte, uint64, string, error)
}, token, who types.Address) *big.Int {
	t.Helper()
	data := encodeCall("balanceOf(address)", padAddr(who))
	ret, _, vmErr, err := n.Call(types.Address{}, token, data, 1_000_000)
	if err != nil {
		t.Fatalf("balanceOf 调用失败: %v", err)
	}
	if vmErr != "" {
		t.Fatalf("balanceOf VM 错误: %s", vmErr)
	}
	if len(ret) != 32 {
		t.Fatalf("balanceOf 返回应为 32 字节，实际 %d", len(ret))
	}
	return new(big.Int).SetBytes(ret)
}

// TestNode_ERC20Lifecycle 是 M1 的完整验收：
// 部署代币 → 铸造余额 → 转账 → 余额断言 → Transfer 事件入收据。
func TestNode_ERC20Lifecycle(t *testing.T) {
	n := newTestNode(t)

	from := mkFundedAddr(t, 0x11)
	to := mkFundedAddr(t, 0x12)

	// ---- 1. 部署：bytecode + constructor(supply) ----
	bytecode := loadTokenBytecode(t)
	deployData := append(append([]byte{}, bytecode...), padUint(tokenSupply)...)
	deployRaw := signContractCall(t, 0x11, 0, nil, deployData, 3_000_000)

	deployHash, err := n.SubmitRawTx(deployRaw)
	if err != nil {
		t.Fatalf("部署交易提交失败: %v", err)
	}

	n.ProduceBlockOnce()

	head := n.Chain().Head()
	if head.Height != 1 {
		t.Fatalf("部署后高度应为 1，实际 %d", head.Height)
	}

	// 收据 → 合约地址
	receipt, err := n.Chain().GetReceipt(1, 0)
	if err != nil {
		t.Fatalf("读取部署收据失败: %v", err)
	}
	if receipt.Status != 1 {
		t.Fatalf("部署应成功，收据状态 %d", receipt.Status)
	}
	if receipt.ContractAddress.IsZero() {
		t.Fatal("收据应包含合约地址")
	}
	token := *receipt.ContractAddress
	_ = deployHash

	t.Logf("合约已部署: %s", token.String())

	// ---- 1.5 totalSupply 诊断（slot 0：区分"存储丢失"与"mapping 键错"）----
	tsData := encodeCall("totalSupply()")
	tsRet, _, tsVMErr, tsErr := n.Call(types.Address{}, token, tsData, 1_000_000)
	if tsErr != nil || tsVMErr != "" {
		t.Fatalf("totalSupply 失败: err=%v vmErr=%s", tsErr, tsVMErr)
	}
	t.Logf("totalSupply=%s (retLen=%d)", new(big.Int).SetBytes(tsRet).String(), len(tsRet))

	// ---- 2. balanceOf(0x11) == supply ----
	got := readBalance(t, n, token, from)
	want, _ := new(big.Int).SetString(tokenSupply, 10)
	if got.Cmp(want) != 0 {
		t.Fatalf("部署后余额错误:\n want %s\n got  %s", want.String(), got.String())
	}

	// ---- 3. transfer(0x12, 100e18) ----
	callData := encodeCall("transfer(address,uint256)", padAddr(to), padUint(transferAmount))
	transferRaw := signContractCall(t, 0x11, 1, &token, callData, 1_000_000)
	if _, err := n.SubmitRawTx(transferRaw); err != nil {
		t.Fatalf("转账提交失败: %v", err)
	}

	n.ProduceBlockOnce()

	// ---- 4. 余额断言 ----
	gotFrom := readBalance(t, n, token, from)
	gotTo := readBalance(t, n, token, to)
	amount, _ := new(big.Int).SetString(transferAmount, 10)

	wantFrom := new(big.Int).Sub(want, amount)
	if gotFrom.Cmp(wantFrom) != 0 {
		t.Fatalf("发送方余额错误:\n want %s\n got  %s", wantFrom.String(), gotFrom.String())
	}
	if gotTo.Cmp(amount) != 0 {
		t.Fatalf("接收方余额错误:\n want %s\n got  %s", amount.String(), gotTo.String())
	}

	// ---- 5. Transfer 事件入收据 ----
	r, err := n.Chain().GetReceipt(2, 0)
	if err != nil {
		t.Fatalf("读取转账收据失败: %v", err)
	}
	if r.Status != 1 {
		t.Fatal("转账应成功")
	}
	if len(r.Logs) == 0 {
		t.Fatal("转账应产生 Transfer 事件日志")
	}

	// 事件签名：keccak("Transfer(address,address,uint256)")[:4]
	wantTopic := crypto.Keccak256([]byte("Transfer(address,address,uint256)"))
	if len(r.Logs[0].Topics) < 1 {
		t.Fatal("应有事件 topics")
	}
	t0 := r.Logs[0].Topics[0]
	if t0[0] != wantTopic[0] || t0[1] != wantTopic[1] || t0[2] != wantTopic[2] || t0[3] != wantTopic[3] {
		t.Fatalf("应为 Transfer 事件，实际 topic0=%s", t0.String())
	}

	t.Logf("ERC20 全链路：部署 → 查询 → 转账 → 事件，余额 from=%s to=%s",
		gotFrom.String(), gotTo.String())
}

// TestNode_ERC20TransferInsufficient 余额不足 → EVM revert → 收据失败。
func TestNode_ERC20TransferInsufficient(t *testing.T) {
	n := newTestNode(t)
	outsider := mkFundedAddr(t, 0x13) // 无代币
	to := mkFundedAddr(t, 0x12)

	// 部署
	bytecode := loadTokenBytecode(t)
	deployRaw := signContractCall(t, 0x11, 0, nil,
		append(append([]byte{}, bytecode...), padUint(tokenSupply)...), 3_000_000)
	if _, err := n.SubmitRawTx(deployRaw); err != nil {
		t.Fatal(err)
	}
	n.ProduceBlockOnce()

	receipt, err := n.Chain().GetReceipt(1, 0)
	if err != nil || receipt.Status != 1 {
		t.Fatalf("部署失败: %v", err)
	}
	token := *receipt.ContractAddress

	// outsider 转账（余额为 0 → require 失败 → revert）
	callData := encodeCall("transfer(address,uint256)", padAddr(to), padUint(transferAmount))
	txRaw := signContractCall(t, 0x13, 0, &token, callData, 1_000_000)
	if _, err := n.SubmitRawTx(txRaw); err != nil {
		t.Fatalf("提交失败（revert 交易应可入池）: %v", err)
	}
	n.ProduceBlockOnce()

	// 收据状态 = 0（失败），但 gas 已扣（EVM 语义）
	r, err := n.Chain().GetReceipt(2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != 0 {
		t.Fatal("余额不足的转账应失败（revert）")
	}
	if r.GasUsed == 0 {
		t.Fatal("revert 交易 gas 仍应被消耗")
	}

	// 状态未变：outsider 余额仍 0，接收方仍 0
	if b := readBalance(t, n, token, outsider); b.Sign() != 0 {
		t.Fatalf("失败交易不应改变状态，outsider=%s", b.String())
	}
	if b := readBalance(t, n, token, to); b.Sign() != 0 {
		t.Fatalf("失败交易不应改变状态，to=%s", b.String())
	}

	t.Log("revert 语义验证：状态未变，gas 已扣")
}

// signContractCall 构造并签名一笔合约调用（to 可 nil = CREATE）。
func signContractCall(t *testing.T, seed byte, nonce uint64, to *types.Address,
	data []byte, gas uint64) []byte {
	t.Helper()

	key := loadDevKey(t, seed)
	var toG *gethCommon.Address
	if to != nil {
		g := gethCommon.Address(*to)
		toG = &g
	}
	tx := gethTypes.NewTx(&gethTypes.DynamicFeeTx{
		ChainID:   big.NewInt(testChainID),
		Nonce:     nonce,
		GasTipCap: big.NewInt(2 * 1_000_000_000),
		GasFeeCap: big.NewInt(10 * 1_000_000_000),
		Gas:       gas,
		To:        toG,
		Value:     big.NewInt(0),
		Data:      data,
	})
	return marshalTx(t, signTxWithKey(t, tx, big.NewInt(testChainID), key))
}
