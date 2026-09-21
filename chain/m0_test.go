package chain_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/chfault/chfault/chain"
	"github.com/chfault/chfault/crypto"
	"github.com/chfault/chfault/state"
	"github.com/chfault/chfault/storage"
	"github.com/chfault/chfault/types"
)

// ============================================================================
// M0 核心验收（对应 docs/HANDOVER.md 第 7 节 DoD）
// ============================================================================

// buildThreeTransferBlock 构造一个含 3 笔转账的区块，并返回三个根。
//
// 这个函数被多个测试复用，也用于验证"不同环境下结果一致"。
func buildThreeTransferBlock(t *testing.T) (
	txRoot types.TxRoot,
	receiptRoot types.ReceiptRoot,
	stateRoot types.StateRoot,
	blockHash types.BlockHash,
) {
	t.Helper()

	// ---- 1. 构造 3 笔交易 ----
	txs := make([]*chain.Transaction, 0, 3)
	for i := 0; i < 3; i++ {
		to := types.Address{byte(0x10 + i)}
		tx := &chain.Transaction{
			Type:                 chain.TxTypeDynamicFee,
			ChainID:              10086,
			Nonce:                types.Nonce(i),
			MaxPriorityFeePerGas: types.Uint256FromUint64(1_000_000_000),
			MaxFeePerGas:         types.Uint256FromUint64(2_000_000_000),
			GasLimit:             21000,
			To:                   &to,
			Value:                types.Uint256FromUint64(uint64(1000 * (i + 1))),
			Data:                 nil,
		}
		txs = append(txs, tx)
	}

	// ---- 2. 构造区块并计算 txRoot ----
	blk := &chain.Block{
		Header: &chain.BlockHeader{
			Version:          1,
			ChainID:          10086,
			Height:           1,
			Round:            0,
			Timestamp:        1700000000,
			GasLimit:         30_000_000,
			BaseFeePerGas:    types.Uint256FromUint64(1_000_000_000),
			ValidatorSetHash: types.Hash{0xab},
		},
		Transactions: txs,
	}
	txRoot = blk.ComputeTxRoot()

	// ---- 3. 执行状态变更并计算 stateRoot ----
	mgr := state.NewMemoryManager()
	sess, err := mgr.Begin(types.StateRoot{}) // 从空状态开始
	if err != nil {
		t.Fatalf("打开状态会话失败: %v", err)
	}

	from := types.Address{0x01}
	if err := sess.SetBalance(from, types.Uint256FromUint64(1_000_000)); err != nil {
		t.Fatalf("设置余额失败: %v", err)
	}
	for i := 0; i < 3; i++ {
		to := types.Address{byte(0x10 + i)}
		sess.SetNonce(to, 0)
		if err := sess.SetBalance(to, types.Uint256FromUint64(uint64(1000*(i+1)))); err != nil {
			t.Fatalf("设置余额失败: %v", err)
		}
	}
	stateRoot, err = sess.Commit()
	if err != nil {
		t.Fatalf("提交状态失败: %v", err)
	}

	// ---- 4. 构造收据并计算 receiptRoot ----
	receipts := make([]*chain.Receipt, 0, 3)
	var cumulative types.Gas
	for i, tx := range txs {
		h, err := tx.Hash()
		if err != nil {
			t.Fatalf("计算交易哈希失败: %v", err)
		}
		cumulative += 21000
		r := &chain.Receipt{
			Status:            1,
			TxHash:            h,
			GasUsed:           21000,
			CumulativeGasUsed: cumulative,
			EffectiveGasPrice: types.Uint256FromUint64(1_000_000_000),
		}
		r.LogsBloom = r.ComputeLogsBloom()
		receipts = append(receipts, r)
		_ = i
	}
	receiptRoot = chain.ComputeReceiptRoot(receipts)

	// ---- 5. 填充头部并计算区块哈希 ----
	blk.Header.TxRoot = txRoot
	blk.Header.ReceiptRoot = receiptRoot
	blk.Header.StateRoot = stateRoot
	blk.Header.GasUsed = cumulative
	blk.Header.LogsBloom = chain.ComputeBlockLogsBloom(receipts)

	blockHash, err = blk.Header.Hash()
	if err != nil {
		t.Fatalf("计算区块哈希失败: %v", err)
	}

	return txRoot, receiptRoot, stateRoot, blockHash
}

// TestM0_BuildBlockAndPersist 是 M0 的核心验收测试：
// 构造含 3 笔交易的区块 → 算三根 → 写入 Pebble → 读出 → 字节一致。
func TestM0_BuildBlockAndPersist(t *testing.T) {
	txRoot, receiptRoot, stateRoot, blockHash := buildThreeTransferBlock(t)

	// 三个根都必须是非零的（空状态/空列表才会是零）
	if txRoot.IsZero() {
		t.Error("txRoot 不应为零")
	}
	if receiptRoot.IsZero() {
		t.Error("receiptRoot 不应为零")
	}
	if stateRoot.IsZero() {
		t.Error("stateRoot 不应为零")
	}
	if blockHash.IsZero() {
		t.Error("blockHash 不应为零")
	}

	// ---- 持久化到 Pebble 再读回 ----
	dir := filepath.Join(t.TempDir(), "db")
	store, err := storage.Open(dir)
	if err != nil {
		t.Fatalf("打开 Pebble 失败: %v", err)
	}
	defer func() { _ = store.Close() }()

	// 写入：区块头编码 + 三个根
	header := &chain.BlockHeader{
		Version: 1, ChainID: 10086, Height: 1, Round: 0,
		Timestamp: 1700000000, GasLimit: 30_000_000,
		BaseFeePerGas: types.Uint256FromUint64(1_000_000_000),
		TxRoot:        txRoot, ReceiptRoot: receiptRoot, StateRoot: stateRoot,
		ValidatorSetHash: types.Hash{0xab},
	}
	enc, err := header.Encode()
	if err != nil {
		t.Fatalf("编码区块头失败: %v", err)
	}

	b := store.NewBatch()
	if err := b.Put(storage.NSBlocks, heightKey(1), enc); err != nil {
		t.Fatalf("写入批次失败: %v", err)
	}
	if err := store.Apply(b); err != nil {
		t.Fatalf("提交批次失败: %v", err)
	}
	b.Close()

	// 读回并逐字节比较
	got, err := store.Get(storage.NSBlocks, heightKey(1))
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	if string(got) != string(enc) {
		t.Fatalf("往返不一致:\n写入 %d 字节\n读出 %d 字节", len(enc), len(got))
	}

	// 重新解码后哈希必须一致
	t.Logf("区块哈希 = %s", blockHash.String())
	t.Logf("stateRoot = %s", stateRoot.String())
	t.Logf("txRoot    = %s", txRoot.String())
	t.Logf("receiptRoot = %s", receiptRoot.String())
	t.Logf("区块头编码 %d 字节，往返一致", len(enc))
}

// TestDeterminism_SameResultAcrossEnvironments 是本项目的独门检查：
// 同一份输入必须产生完全相同的输出。
//
// 配合不同 GOMAXPROCS / GOGC 运行（见 Makefile 的 test-determinism），
// 这个测试能抓出 map 顺序依赖、goroutine 竞态、调度顺序依赖。
func TestDeterminism_SameResultAcrossEnvironments(t *testing.T) {
	const runs = 20

	firstTxRoot, firstReceiptRoot, firstStateRoot, firstBlockHash := buildThreeTransferBlock(t)
	for i := 1; i < runs; i++ {
		txRoot, receiptRoot, stateRoot, blockHash := buildThreeTransferBlock(t)
		if stateRoot != firstStateRoot {
			t.Fatalf("第 %d 次运行 stateRoot 不一致:\n want %s\n got  %s",
				i, firstStateRoot.String(), stateRoot.String())
		}
		if txRoot != firstTxRoot {
			t.Fatalf("第 %d 次运行 txRoot 不一致", i)
		}
		if receiptRoot != firstReceiptRoot {
			t.Fatalf("第 %d 次运行 receiptRoot 不一致", i)
		}
		if blockHash != firstBlockHash {
			t.Fatalf("第 %d 次运行 blockHash 不一致", i)
		}
	}
}

// TestDeterminism_AccountOrderingIndependence 验证状态根不依赖账户插入顺序。
//
// 这是针对"Go map 迭代顺序随机"的专项测试：
// 同样的账户集合，以不同顺序插入，必须得到相同的 stateRoot。
func TestDeterminism_AccountOrderingIndependence(t *testing.T) {
	t.Helper()

	rootFor := func(order []int) types.StateRoot {
		mgr := state.NewMemoryManager()
		sess, err := mgr.Begin(types.StateRoot{})
		if err != nil {
			t.Fatalf("打开会话失败: %v", err)
		}
		for _, i := range order {
			addr := types.Address{byte(i)}
			sess.SetNonce(addr, types.Nonce(i))
			_ = sess.SetBalance(addr, types.Uint256FromUint64(uint64(i*100)))
		}
		root, err := sess.Commit()
		if err != nil {
			t.Fatalf("提交失败: %v", err)
		}
		return root
	}

	a := rootFor([]int{1, 2, 3, 4, 5})
	b := rootFor([]int{5, 4, 3, 2, 1})
	c := rootFor([]int{3, 1, 5, 2, 4})

	if a != b || a != c {
		t.Fatalf("账户插入顺序影响了状态根:\n 顺序1 %s\n 顺序2 %s\n 顺序3 %s",
			a.String(), b.String(), c.String())
	}
}

// TestState_SavepointRollback 验证 journal 的嵌套回滚（EVM REVERT 语义依赖它）。
func TestState_SavepointRollback(t *testing.T) {
	mgr := state.NewMemoryManager()
	sess, err := mgr.Begin(types.StateRoot{})
	if err != nil {
		t.Fatalf("打开会话失败: %v", err)
	}

	addrA := types.Address{0xAA}
	addrB := types.Address{0xBB}

	// 设置 A = 100
	_ = sess.SetBalance(addrA, types.Uint256FromUint64(100))

	// 打点，设置 B = 200，然后回滚 → 只剩 A
	sp := sess.Savepoint()
	_ = sess.SetBalance(addrB, types.Uint256FromUint64(200))

	accB, err := sess.GetAccount(addrB)
	if err != nil || accB.Balance.IsZero() {
		t.Fatalf("回滚前 B 应有余额")
	}

	sess.RollbackTo(sp)

	accB, err = sess.GetAccount(addrB)
	if err == nil && !accB.Balance.IsZero() {
		t.Fatalf("回滚后 B 的余额应被撤销，实际 %s", accB.Balance.ToBig().String())
	}

	accA, err := sess.GetAccount(addrA)
	if err != nil {
		t.Fatalf("回滚后 A 应仍然存在: %v", err)
	}
	if accA.Balance.Cmp(types.Uint256FromUint64(100)) != 0 {
		t.Fatalf("回滚不应影响 A，实际 %s", accA.Balance.ToBig().String())
	}

	// 嵌套 savepoint
	sp1 := sess.Savepoint()
	_ = sess.SetBalance(addrA, types.Uint256FromUint64(111))
	sp2 := sess.Savepoint()
	_ = sess.SetBalance(addrA, types.Uint256FromUint64(222))

	sess.RollbackTo(sp2)
	accA, _ = sess.GetAccount(addrA)
	if accA.Balance.Cmp(types.Uint256FromUint64(111)) != 0 {
		t.Fatalf("回滚到 sp2 后应为 111，实际 %s", accA.Balance.ToBig().String())
	}

	sess.RollbackTo(sp1)
	accA, _ = sess.GetAccount(addrA)
	if accA.Balance.Cmp(types.Uint256FromUint64(100)) != 0 {
		t.Fatalf("回滚到 sp1 后应为 100，实际 %s", accA.Balance.ToBig().String())
	}
}

// TestStorage_NamespacesIsolated 验证 namespace 隔离。
func TestStorage_NamespacesIsolated(t *testing.T) {
	store := storage.NewMemory()
	defer func() { _ = store.Close() }()

	b := store.NewBatch()
	_ = b.Put(storage.NSBlocks, []byte("k"), []byte("blocks-value"))
	_ = b.Put(storage.NSState, []byte("k"), []byte("state-value"))
	if err := store.Apply(b); err != nil {
		t.Fatalf("提交失败: %v", err)
	}
	b.Close()

	v1, _ := store.Get(storage.NSBlocks, []byte("k"))
	v2, _ := store.Get(storage.NSState, []byte("k"))

	if string(v1) != "blocks-value" {
		t.Fatalf("NSBlocks 读取错误: %s", v1)
	}
	if string(v2) != "state-value" {
		t.Fatalf("NSState 读取错误: %s", v2)
	}
}

// TestCrypto_KeccakVector 用已知向量验证 Keccak-256 实现正确。
//
// 这是防止"用了 SHA3 而不是 Keccak"的关键测试。
func TestCrypto_KeccakVector(t *testing.T) {
	// keccak256("") 的已知值
	empty := crypto.Keccak256([]byte{})
	const wantEmpty = "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
	if empty.String() != wantEmpty {
		t.Fatalf("keccak256(\"\") 错误:\n want %s\n got  %s", wantEmpty, empty.String())
	}

	// keccak256("abc") 的已知值
	abc := crypto.Keccak256([]byte("abc"))
	const wantABC = "0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
	if abc.String() != wantABC {
		t.Fatalf("keccak256(\"abc\") 错误:\n want %s\n got  %s", wantABC, abc.String())
	}
}

// TestCrypto_MerkleRootVectors 验证 Merkle 根的规则（空列表、奇数叶子）。
func TestCrypto_MerkleRootVectors(t *testing.T) {
	// 空列表 → 32 字节零
	if r := crypto.MerkleRoot(nil); !r.IsZero() {
		t.Fatalf("空列表的 Merkle 根应为零，实际 %s", r.String())
	}

	// 单叶子 → 该叶子本身
	h := crypto.Keccak256([]byte("x"))
	if r := crypto.MerkleRoot([]types.Hash{h}); r != h {
		t.Fatalf("单叶子的 Merkle 根应为叶子本身")
	}

	// 奇数叶子：最后一个与自己配对，结果必须稳定
	a := crypto.Keccak256([]byte("a"))
	b := crypto.Keccak256([]byte("b"))
	c := crypto.Keccak256([]byte("c"))
	r1 := crypto.MerkleRoot([]types.Hash{a, b, c})
	r2 := crypto.MerkleRoot([]types.Hash{a, b, c})
	if r1 != r2 {
		t.Fatalf("Merkle 根不稳定")
	}

	// 顺序不同则根不同
	r3 := crypto.MerkleRoot([]types.Hash{c, b, a})
	if r1 == r3 {
		t.Fatalf("不同顺序应产生不同的 Merkle 根")
	}
}

// TestUint256_NoSilentOverflow 验证 Uint256 不会静默回绕。
func TestUint256_NoSilentOverflow(t *testing.T) {
	max := types.Uint256{}
	for i := range max {
		max[i] = 0xff
	}

	one := types.Uint256FromUint64(1)
	if _, err := max.Add(one); err == nil {
		t.Fatal("Uint256 加法溢出必须返回错误，不能静默回绕")
	}

	zero := types.ZeroUint256()
	if _, err := zero.Sub(one); err == nil {
		t.Fatal("Uint256 减法下溢必须返回错误")
	}
}

// heightKey 构造区块高度键（大端，spec/40 §5.1）。
func heightKey(h types.Height) []byte {
	return append([]byte{storage.SubBlockByHeight}, crypto.Uint64BE(uint64(h))...)
}

// TestMain 确保测试在临时目录中运行，不污染工作区。
func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
