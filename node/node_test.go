package node_test

import (
	"context"
	"math/big"
	"testing"
	"time"

	gethCommon "github.com/ethereum/go-ethereum/common"
	gethTypes "github.com/ethereum/go-ethereum/core/types"
	gethCrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/chfault/chfault/node"
	"github.com/chfault/chfault/types"
)

const testChainID = 10086

// ============================================================================
// 测试辅助
// ============================================================================

// mkFundedAddr 返回种子对应的账户地址。
func mkFundedAddr(t *testing.T, seed byte) types.Address {
	t.Helper()
	key, err := gethCrypto.HexToECDSA(hexStr(seedBytes(seed)))
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	return types.Address(gethCrypto.PubkeyToAddress(key.PublicKey))
}

func seedBytes(seed byte) []byte {
	buf := make([]byte, 32)
	for i := range buf {
		buf[i] = seed
	}
	return buf
}

func hexStr(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = digits[v>>4]
		out[i*2+1] = digits[v&0x0f]
	}
	return string(out)
}

// signTransfer 签名一笔 1559 转账，返回原始字节。
func signTransfer(t *testing.T, seed byte, nonce uint64, to types.Address,
	valueWei *big.Int, tipGwei, maxFeeGwei, gas uint64) []byte {
	t.Helper()
	key, err := gethCrypto.HexToECDSA(hexStr(seedBytes(seed)))
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	toG := gethCommon.Address(to)
	tx := gethTypes.NewTx(&gethTypes.DynamicFeeTx{
		ChainID:   big.NewInt(testChainID),
		Nonce:     nonce,
		GasTipCap: big.NewInt(int64(tipGwei) * 1_000_000_000),
		GasFeeCap: big.NewInt(int64(maxFeeGwei) * 1_000_000_000),
		Gas:       gas,
		To:        &toG,
		Value:     valueWei,
	})
	signer := gethTypes.LatestSignerForChainID(big.NewInt(testChainID))
	signed, err := gethTypes.SignTx(tx, signer, key)
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	raw, err := signed.MarshalBinary()
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	return raw
}

// newTestNode 创建并启动测试节点（内存存储，3 个账户各注资 100 ETH）。
func newTestNode(t *testing.T) *node.Node {
	t.Helper()

	cfg := node.DefaultConfig()
	cfg.Storage.Backend = "memory"
	cfg.RPC.HTTP.Enabled = false

	alloc := map[string]node.AllocAccount{}
	for seed := 0x11; seed <= 0x13; seed++ {
		addr := mkFundedAddr(t, byte(seed))
		alloc[addr.String()] = node.AllocAccount{Balance: "100000000000000000000"}
	}

	dir := t.TempDir()
	if err := node.WriteGenesis(dir+"/genesis.json", testChainID, alloc, 4); err != nil {
		t.Fatalf("写创世失败: %v", err)
	}
	cfg.Chain.ChainID = "10086"
	cfg.Chain.Genesis = dir + "/genesis.json"

	n, err := node.New(cfg, nil)
	if err != nil {
		t.Fatalf("创建节点失败: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := n.Start(ctx); err != nil {
		t.Fatalf("启动节点失败: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer stopCancel()
		_ = n.Stop(stopCtx)
	})
	return n
}

// ============================================================================
// 端到端测试
// ============================================================================

// TestNode_SubmitAndBlockInclusion 是 M1 的完整闭环验收：
// 创世 → 提交真实签名交易 → 打包出块 → 余额转移生效 → 交易可查询。
func TestNode_SubmitAndBlockInclusion(t *testing.T) {
	n := newTestNode(t)

	if head := n.Chain().Head(); head.Height != 0 {
		t.Fatalf("初始高度应为 0，实际 %d", head.Height)
	}

	// 0x11 转账 1.5 ETH 给 0x12
	from := mkFundedAddr(t, 0x11)
	to := mkFundedAddr(t, 0x12)
	raw := signTransfer(t, 0x11, 0, to,
		big.NewInt(1_500_000_000_000_000_000), 2, 10, 21000)

	hash, err := n.SubmitRawTx(raw)
	if err != nil {
		t.Fatalf("提交交易失败: %v", err)
	}

	// 出块
	n.ProduceBlockOnce()

	head := n.Chain().Head()
	if head.Height != 1 {
		t.Fatalf("出块后高度应为 1，实际 %d", head.Height)
	}

	// 交易可查询
	loc, err := n.Chain().FindTx(hash)
	if err != nil {
		t.Fatalf("交易应可查询: %v", err)
	}
	if loc.Height != 1 {
		t.Fatalf("交易应在高度 1，实际 %d", loc.Height)
	}

	// 余额验证
	ro, err := n.Chain().State().View(head.StateRoot)
	if err != nil {
		t.Fatalf("打开状态失败: %v", err)
	}
	accA, _ := ro.GetAccount(from)
	accB, _ := ro.GetAccount(to)
	if accA == nil || accB == nil {
		t.Fatal("余额查询失败")
	}

	// gasPrice = baseFee(1) + tip(2) = 3 gwei
	gasCost := new(big.Int).Mul(big.NewInt(21000), big.NewInt(3_000_000_000))
	wantA, _ := new(big.Int).SetString("100000000000000000000", 10)
	wantA.Sub(wantA, big.NewInt(1_500_000_000_000_000_000))
	wantA.Sub(wantA, gasCost)

	if accA.Balance.ToBig().Cmp(wantA) != 0 {
		t.Fatalf("A 余额错误:\n want %s\n got  %s", wantA.String(), accA.Balance.ToBig().String())
	}
	// B 创世注资 100 ETH + 收到 1.5 ETH = 101.5 ETH
	wantB, _ := new(big.Int).SetString("101500000000000000000", 10)
	if accB.Balance.ToBig().Cmp(wantB) != 0 {
		t.Fatalf("B 余额错误: want %s got %s", wantB.String(), accB.Balance.ToBig().String())
	}

	// 收据
	r, err := n.Chain().GetReceipt(1, 0)
	if err != nil {
		t.Fatalf("读取收据失败: %v", err)
	}
	if r.Status != 1 {
		t.Fatalf("收据状态应为 1，实际 %d", r.Status)
	}

	t.Logf("闭环成功：高度 1，gas 21000")
}

// TestNode_MultipleBlocksAndNonces 验证多块连续出块与 nonce 推进。
func TestNode_MultipleBlocksAndNonces(t *testing.T) {
	n := newTestNode(t)
	to := mkFundedAddr(t, 0x12)

	for nonce := 0; nonce < 3; nonce++ {
		raw := signTransfer(t, 0x11, uint64(nonce), to,
			big.NewInt(1_000_000_000_000_000_000), 2, 10, 21000)
		if _, err := n.SubmitRawTx(raw); err != nil {
			t.Fatalf("第 %d 笔提交失败: %v", nonce, err)
		}
		n.ProduceBlockOnce()
	}

	if head := n.Chain().Head(); head.Height != 3 {
		t.Fatalf("应出到高度 3，实际 %d", head.Height)
	}

	ro, _ := n.Chain().State().View(n.Chain().Head().StateRoot)
	accA, _ := ro.GetAccount(mkFundedAddr(t, 0x11))
	if accA.Nonce != 3 {
		t.Fatalf("A 的 nonce 应为 3，实际 %d", accA.Nonce)
	}

	wantA, _ := new(big.Int).SetString("100000000000000000000", 10)
	wantA.Sub(wantA, big.NewInt(3_000_000_000_000_000_000))
	gasTotal := new(big.Int).Mul(big.NewInt(3*21000), big.NewInt(3_000_000_000))
	wantA.Sub(wantA, gasTotal)
	if accA.Balance.ToBig().Cmp(wantA) != 0 {
		t.Fatalf("A 余额错误:\n want %s\n got  %s", wantA.String(), accA.Balance.ToBig().String())
	}
}

// TestNode_EmptyBlockNotAppended 验证空块不追加。
func TestNode_EmptyBlockNotAppended(t *testing.T) {
	n := newTestNode(t)
	n.ProduceBlockOnce()
	n.ProduceBlockOnce()

	if head := n.Chain().Head(); head.Height != 0 {
		t.Fatalf("无交易时不应出块，实际高度 %d", head.Height)
	}
}

// TestNode_SignatureRejection 验证被篡改的交易被拒绝。
func TestNode_SignatureRejection(t *testing.T) {
	n := newTestNode(t)
	to := mkFundedAddr(t, 0x12)
	raw := signTransfer(t, 0x11, 0, to,
		big.NewInt(1_500_000_000_000_000_000), 2, 10, 21000)

	corrupted := append([]byte{}, raw...)
	corrupted[len(corrupted)-1] ^= 0xff

	if _, err := n.SubmitRawTx(corrupted); err == nil {
		t.Fatal("被篡改的交易应被拒绝")
	}
}

// TestNode_ChainIDDeterminism 验证同一创世在不同节点产生相同哈希。
func TestNode_ChainIDDeterminism(t *testing.T) {
	n1 := newTestNode(t)
	n2 := newTestNode(t)

	h1 := n1.Chain().Head().Hash
	h2 := n2.Chain().Head().Hash
	if h1 != h2 {
		t.Fatalf("两次初始化的创世哈希不同（节点无法组网）:\n %s\n %s",
			h1.String(), h2.String())
	}
}

// TestNode_ConsensusDrivenBlocks 验证 M2 接线：
// 出块由共识状态机驱动（而非定时器），提交经过完整三阶段。
func TestNode_ConsensusDrivenBlocks(t *testing.T) {
	n := newTestNode(t)

	// 提交一笔交易
	to := mkFundedAddr(t, 0x12)
	raw := signTransfer(t, 0x11, 0, to,
		big.NewInt(1_000_000_000_000_000_000), 2, 10, 21000)
	if _, err := n.SubmitRawTx(raw); err != nil {
		t.Fatalf("提交失败: %v", err)
	}

	// 手动触发一轮共识（StartNewHeight 内含提议→投票→提交）
	if err := n.AdvanceConsensus(); err != nil {
		t.Fatalf("共识推进失败: %v", err)
	}

	head := n.Chain().Head()
	if head.Height != 1 {
		t.Fatalf("共识驱动应出块到高度 1，实际 %d", head.Height)
	}
	if !n.Consensus().IsCommitted(1) {
		t.Fatal("共识应已提交高度 1")
	}
}
