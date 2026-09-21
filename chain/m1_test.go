package chain_test

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/chfault/chfault/chain"
	"github.com/chfault/chfault/crypto"
	"github.com/chfault/chfault/storage"
	"github.com/chfault/chfault/types"
)

// testGenesis 返回一个固定的测试创世配置。
func testGenesis() *chain.Genesis {
	return &chain.Genesis{
		ChainID:        "10086",
		Timestamp:      "1700000000",
		GasLimit:       "30000000",
		InitialBaseFee: "1000000000",
		Version:        "1",
		Alloc: map[string]chain.AllocAccount{
			"0x0000000000000000000000000000000000000001": {Balance: "1000000000000000000000"},
			"0x0000000000000000000000000000000000000002": {Balance: "500000000000000000000"},
			"0x0000000000000000000000000000000000000003": {Balance: "0"},
		},
		Validators: []chain.GenesisValidator{
			{
				Address: "0x0000000000000000000000000000000000000001",
				PubKey:  "0x02" + strings.Repeat("ab", 32),
				Power:   "1",
				Moniker: "v1",
			},
			{
				Address: "0x0000000000000000000000000000000000000002",
				PubKey:  "0x03" + strings.Repeat("cd", 32),
				Power:   "1",
				Moniker: "v2",
			},
		},
	}
}

// ============================================================================
// Genesis 确定性
// ============================================================================

// TestGenesis_DeterministicHash 验证创世哈希与分配顺序无关。
//
// 这是多节点组网的硬要求：任何一个字节差异都会导致节点无法握手。
func TestGenesis_DeterministicHash(t *testing.T) {
	g1 := testGenesis()

	// 用不同的插入顺序构造同样的 alloc（模拟 JSON 解析顺序不同）
	g2 := testGenesis()
	g2.Alloc = map[string]chain.AllocAccount{
		"0x0000000000000000000000000000000000000003": {Balance: "0"},
		"0x0000000000000000000000000000000000000002": {Balance: "500000000000000000000"},
		"0x0000000000000000000000000000000000000001": {Balance: "1000000000000000000000"},
	}

	h1, err := g1.Hash()
	if err != nil {
		t.Fatalf("计算创世哈希失败: %v", err)
	}
	h2, err := g2.Hash()
	if err != nil {
		t.Fatalf("计算创世哈希失败: %v", err)
	}

	if h1 != h2 {
		t.Fatalf("创世哈希依赖 alloc 插入顺序（会导致节点无法组网）:\n %s\n %s",
			h1.String(), h2.String())
	}

	// 多次计算必须稳定
	for i := 0; i < 20; i++ {
		h, _ := g1.Hash()
		if h != h1 {
			t.Fatal("创世哈希不稳定")
		}
	}

	t.Logf("创世哈希 = %s", h1.String())
}

// TestGenesis_ValidatorSetHashOrderIndependent 验证验证者集哈希与数组顺序无关。
func TestGenesis_ValidatorSetHashOrderIndependent(t *testing.T) {
	g1 := testGenesis()

	// 反转验证者顺序
	g2 := testGenesis()
	g2.Validators = []chain.GenesisValidator{g2.Validators[1], g2.Validators[0]}

	h1, err := g1.ValidatorSetHash()
	if err != nil {
		t.Fatalf("计算验证者集哈希失败: %v", err)
	}
	h2, err := g2.ValidatorSetHash()
	if err != nil {
		t.Fatalf("计算验证者集哈希失败: %v", err)
	}

	if h1 != h2 {
		t.Fatalf("验证者集哈希依赖数组顺序:\n %s\n %s", h1.String(), h2.String())
	}
}

// TestGenesis_DifferentConfigsDifferentHashes 验证不同配置产生不同哈希。
func TestGenesis_DifferentConfigsDifferentHashes(t *testing.T) {
	base, _ := testGenesis().Hash()

	// 改余额
	g2 := testGenesis()
	g2.Alloc["0x0000000000000000000000000000000000000001"] = chain.AllocAccount{
		Balance: "9999999999999999999999",
	}
	h2, _ := g2.Hash()
	if base == h2 {
		t.Fatal("余额不同但创世哈希相同")
	}

	// 改 chainId
	g3 := testGenesis()
	g3.ChainID = "10087"
	h3, _ := g3.Hash()
	if base == h3 {
		t.Fatal("chainId 不同但创世哈希相同")
	}

	// 改时间戳
	g4 := testGenesis()
	g4.Timestamp = "1700000001"
	h4, _ := g4.Hash()
	if base == h4 {
		t.Fatal("时间戳不同但创世哈希相同")
	}
}

// TestGenesis_Validation 验证创世配置的校验。
func TestGenesis_Validation(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*chain.Genesis)
		wantErr bool
	}{
		{"valid", func(*chain.Genesis) {}, false},
		{"missing_chain_id", func(g *chain.Genesis) { g.ChainID = "" }, true},
		{"bad_chain_id", func(g *chain.Genesis) { g.ChainID = "abc" }, true},
		{"missing_timestamp", func(g *chain.Genesis) { g.Timestamp = "" }, true},
		{"bad_address", func(g *chain.Genesis) {
			g.Alloc = map[string]chain.AllocAccount{"0xnothex": {Balance: "1"}}
		}, true},
		{"short_address", func(g *chain.Genesis) {
			g.Alloc = map[string]chain.AllocAccount{"0x1234": {Balance: "1"}}
		}, true},
		{"missing_balance", func(g *chain.Genesis) {
			g.Alloc = map[string]chain.AllocAccount{
				"0x0000000000000000000000000000000000000001": {},
			}
		}, true},
		{"zero_validator_power", func(g *chain.Genesis) {
			g.Validators[0].Power = "0"
		}, true},
		{"missing_validator_pubkey", func(g *chain.Genesis) {
			g.Validators[0].PubKey = ""
		}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := testGenesis()
			tc.mutate(g)
			err := g.Validate()
			if tc.wantErr && err == nil {
				t.Fatal("应报错但通过了")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("不应报错: %v", err)
			}
		})
	}
}

// ============================================================================
// 链状态机
// ============================================================================

// TestChain_InitAndAppend 端到端：初始化创世 → 追加区块 → 读回。
func TestChain_InitAndAppend(t *testing.T) {
	store := storage.NewMemory()
	defer func() { _ = store.Close() }()

	c, err := chain.New(store, chain.Config{ChainID: 10086})
	if err != nil {
		t.Fatalf("打开链失败: %v", err)
	}

	if c.HasGenesis() {
		t.Fatal("新链不应有创世")
	}

	// ---- 初始化创世 ----
	g := testGenesis()
	if err := c.InitGenesis(g); err != nil {
		t.Fatalf("初始化创世失败: %v", err)
	}
	if !c.HasGenesis() {
		t.Fatal("初始化后应有创世")
	}

	head := c.Head()
	if head.Height != 0 {
		t.Fatalf("创世高度应为 0，实际 %d", head.Height)
	}

	genesisHash, _ := g.Hash()
	if head.Hash != genesisHash {
		t.Fatal("链头哈希与创世哈希不一致")
	}

	// 幂等：重复初始化应成功且不改变状态
	if err := c.InitGenesis(g); err != nil {
		t.Fatalf("重复初始化应幂等: %v", err)
	}

	// ---- 构造并追加重区块 ----
	blk := buildChildBlock(t, c.Head(), 1)

	if err := c.AppendBlock(blk, nil); err != nil {
		t.Fatalf("追加区块失败: %v", err)
	}

	newHead := c.Head()
	if newHead.Height != 1 {
		t.Fatalf("链头高度应为 1，实际 %d", newHead.Height)
	}

	// ---- 读回 ----
	got, err := c.GetBlock(1)
	if err != nil {
		t.Fatalf("读取区块失败: %v", err)
	}
	if len(got.Transactions) != len(blk.Transactions) {
		t.Fatalf("交易数量不一致: %d vs %d", len(got.Transactions), len(blk.Transactions))
	}

	gotHash, _ := got.Header.Hash()
	wantHash, _ := blk.Header.Hash()
	if gotHash != wantHash {
		t.Fatalf("读回的区块哈希不一致:\n want %s\n got  %s",
			wantHash.String(), gotHash.String())
	}

	// 按哈希读取
	byHash, err := c.GetBlockByHash(gotHash)
	if err != nil {
		t.Fatalf("按哈希读取失败: %v", err)
	}
	byHashHash, _ := byHash.Header.Hash()
	if byHashHash != gotHash {
		t.Fatal("按哈希读取的结果不一致")
	}

	// 交易定位
	txHash, _ := got.Transactions[0].Hash()
	loc, err := c.FindTx(txHash)
	if err != nil {
		t.Fatalf("定位交易失败: %v", err)
	}
	if loc.Height != 1 || loc.Index != 0 {
		t.Fatalf("交易位置错误: 高度 %d 索引 %d", loc.Height, loc.Index)
	}

	t.Logf("创世 %s → 区块 1 %s", genesisHash.String()[:18], gotHash.String()[:18])
}

// TestChain_RejectsBadBlocks 验证链状态机拒绝非法区块。
func TestChain_RejectsBadBlocks(t *testing.T) {
	store := storage.NewMemory()
	defer func() { _ = store.Close() }()

	c, _ := chain.New(store, chain.Config{ChainID: 10086})
	if err := c.InitGenesis(testGenesis()); err != nil {
		t.Fatalf("初始化失败: %v", err)
	}

	t.Run("wrong_height", func(t *testing.T) {
		blk := buildChildBlock(t, c.Head(), 1)
		blk.Header.Height = 5 // 跳高度
		if err := c.AppendBlock(blk, nil); err == nil {
			t.Fatal("应拒绝高度跳跃")
		}
	})

	t.Run("wrong_prev_hash", func(t *testing.T) {
		blk := buildChildBlock(t, c.Head(), 1)
		blk.Header.PrevHash = types.BlockHash{0xde, 0xad}
		if err := c.AppendBlock(blk, nil); err == nil {
			t.Fatal("应拒绝错误的父哈希")
		}
	})

	t.Run("wrong_chain_id", func(t *testing.T) {
		blk := buildChildBlock(t, c.Head(), 1)
		blk.Header.ChainID = 999
		if err := c.AppendBlock(blk, nil); err == nil {
			t.Fatal("应拒绝错误的 chainId")
		}
	})

	t.Run("tx_root_mismatch", func(t *testing.T) {
		blk := buildChildBlock(t, c.Head(), 1)
		blk.Header.TxRoot = types.TxRoot{0xff} // 与区块体不匹配
		if err := c.AppendBlock(blk, nil); err == nil {
			t.Fatal("应拒绝 tx_root 与区块体不一致")
		}
	})

	t.Run("nil_block", func(t *testing.T) {
		if err := c.AppendBlock(nil, nil); err == nil {
			t.Fatal("应拒绝 nil 区块")
		}
	})
}

// TestChain_GenesisMismatchDetected 验证"数据目录挂错"的检测。
//
// 这是生产事故的常见来源：把 A 链的数据目录用于 B 链。
func TestChain_GenesisMismatchDetected(t *testing.T) {
	store := storage.NewMemory()
	defer func() { _ = store.Close() }()

	c, _ := chain.New(store, chain.Config{ChainID: 10086})
	if err := c.InitGenesis(testGenesis()); err != nil {
		t.Fatalf("初始化失败: %v", err)
	}

	// 换一个不同的创世配置重开
	other := testGenesis()
	other.ChainID = "10087"

	c2, _ := chain.New(store, chain.Config{ChainID: 10087})
	err := c2.InitGenesis(other)
	if err == nil {
		t.Fatal("应检测到创世不匹配并拒绝启动")
	}
	if !strings.Contains(err.Error(), "创世哈希不匹配") {
		t.Fatalf("错误信息应说明原因，实际: %v", err)
	}
}

// TestChain_ConcurrentReadsAreSafe 验证并发读取安全（链状态机需支持多 RPC 并发读）。
func TestChain_ConcurrentReadsAreSafe(t *testing.T) {
	store := storage.NewMemory()
	defer func() { _ = store.Close() }()

	c, _ := chain.New(store, chain.Config{ChainID: 10086})
	if err := c.InitGenesis(testGenesis()); err != nil {
		t.Fatalf("初始化失败: %v", err)
	}
	if err := c.AppendBlock(buildChildBlock(t, c.Head(), 1), nil); err != nil {
		t.Fatalf("追加失败: %v", err)
	}

	done := make(chan bool, 20)
	for i := 0; i < 20; i++ {
		go func() {
			defer func() { done <- true }()
			if _, err := c.GetBlock(1); err != nil {
				t.Errorf("并发读取失败: %v", err)
			}
			_ = c.Head()
		}()
	}
	for i := 0; i < 20; i++ {
		<-done
	}
}

// ============================================================================
// 编解码
// ============================================================================

// TestCodec_BlockRoundTrip 验证区块编解码往返。
func TestCodec_BlockRoundTrip(t *testing.T) {
	store := storage.NewMemory()
	defer func() { _ = store.Close() }()

	c, _ := chain.New(store, chain.Config{ChainID: 10086})
	if err := c.InitGenesis(testGenesis()); err != nil {
		t.Fatalf("初始化失败: %v", err)
	}

	blk := buildChildBlock(t, c.Head(), 1)

	enc, err := blk.Encode()
	if err != nil {
		t.Fatalf("编码失败: %v", err)
	}

	dec, err := chain.DecodeBlock(enc)
	if err != nil {
		t.Fatalf("解码失败: %v", err)
	}

	// 编码必须稳定
	enc2, _ := dec.Encode()
	if hex.EncodeToString(enc) != hex.EncodeToString(enc2) {
		t.Fatalf("编解码往返后编码不一致（长度 %d vs %d）", len(enc), len(enc2))
	}

	h1, _ := blk.Header.Hash()
	h2, _ := dec.Header.Hash()
	if h1 != h2 {
		t.Fatal("往返后区块哈希不一致")
	}

	t.Logf("区块 %d 字节，%d 笔交易，往返一致",
		len(enc), len(blk.Transactions))
}

// TestCodec_RejectsTruncated 验证编解码的防御性。
func TestCodec_RejectsTruncated(t *testing.T) {
	store := storage.NewMemory()
	defer func() { _ = store.Close() }()

	c, _ := chain.New(store, chain.Config{ChainID: 10086})
	_ = c.InitGenesis(testGenesis())

	blk := buildChildBlock(t, c.Head(), 1)
	enc, _ := blk.Encode()

	// 逐长度截断，都必须被拒绝（不能 panic，不能静默接受）
	for n := 0; n < len(enc); n++ {
		if _, err := chain.DecodeBlock(enc[:n]); err == nil {
			t.Fatalf("截断到 %d 字节时应报错", n)
		}
	}

	// 追加垃圾字节
	if _, err := chain.DecodeBlock(append(append([]byte{}, enc...), 0xff)); err == nil {
		t.Fatal("有 trailing bytes 时应报错")
	}
}

// TestCodec_ReceiptRoundTrip 验证收据编解码往返。
func TestCodec_ReceiptRoundTrip(t *testing.T) {
	addr := types.Address{0xAA}
	topic := crypto.Keccak256([]byte("Transfer(address,address,uint256)"))

	r := &chain.Receipt{
		Status:            1,
		TxHash:            types.TxHash(crypto.Keccak256([]byte("tx"))),
		GasUsed:           52000,
		CumulativeGasUsed: 52000,
		Logs: []*chain.Log{{
			Address: addr,
			Topics:  []types.Hash{topic, {0x01}, {0x02}},
			Data:    []byte{0xde, 0xad, 0xbe, 0xef},
		}},
		EffectiveGasPrice: types.Uint256FromUint64(2000000000),
	}
	r.LogsBloom = r.ComputeLogsBloom()

	enc, err := r.Encode()
	if err != nil {
		t.Fatalf("编码失败: %v", err)
	}

	dec, err := chain.DecodeReceipt(enc)
	if err != nil {
		t.Fatalf("解码失败: %v", err)
	}

	if dec.Status != r.Status || dec.GasUsed != r.GasUsed {
		t.Fatal("基本字段不一致")
	}
	if len(dec.Logs) != 1 || len(dec.Logs[0].Topics) != 3 {
		t.Fatalf("日志未正确往返: %d 条", len(dec.Logs))
	}
	if dec.Logs[0].Topics[0] != topic {
		t.Fatal("topic 不一致")
	}
	if dec.LogsBloom != r.LogsBloom {
		t.Fatal("bloom 不一致")
	}

	// 逐字节比较
	enc2, _ := dec.Encode()
	if hex.EncodeToString(enc) != hex.EncodeToString(enc2) {
		t.Fatal("收据往返后编码不一致")
	}
}

// TestCodec_ReceiptRejectsBadStatus 验证收据 status 的取值约束。
func TestCodec_ReceiptRejectsBadStatus(t *testing.T) {
	r := &chain.Receipt{Status: 2, EffectiveGasPrice: types.ZeroUint256()}
	if _, err := r.Encode(); err == nil {
		t.Fatal("status=2 应被拒绝（spec/30：只能是 0 或 1）")
	}
}

// ============================================================================
// RLP 与交易
// ============================================================================

// TestTx_EncodeDeterministic 验证交易编码的确定性。
func TestTx_EncodeDeterministic(t *testing.T) {
	to := types.Address{0xAA}
	tx := &chain.Transaction{
		Type:                 chain.TxTypeDynamicFee,
		ChainID:              10086,
		Nonce:                7,
		MaxPriorityFeePerGas: types.Uint256FromUint64(1000000000),
		MaxFeePerGas:         types.Uint256FromUint64(2000000000),
		GasLimit:             21000,
		To:                   &to,
		Value:                types.Uint256FromUint64(12345),
	}

	first, err := tx.Encode()
	if err != nil {
		t.Fatalf("编码失败: %v", err)
	}
	for i := 0; i < 50; i++ {
		// 每次用新对象，确保没有隐藏的缓存掩盖不确定性
		tx2 := &chain.Transaction{
			Type:                 chain.TxTypeDynamicFee,
			ChainID:              10086,
			Nonce:                7,
			MaxPriorityFeePerGas: types.Uint256FromUint64(1000000000),
			MaxFeePerGas:         types.Uint256FromUint64(2000000000),
			GasLimit:             21000,
			To:                   &to,
			Value:                types.Uint256FromUint64(12345),
		}
		got, _ := tx2.Encode()
		if hex.EncodeToString(got) != hex.EncodeToString(first) {
			t.Fatal("交易编码不确定")
		}
	}

	// 交易哈希必须稳定
	h1, _ := tx.Hash()
	tx3 := *tx
	hashNil := tx3
	hashNil.Hash_ = nil
	h2, _ := hashNil.Hash()
	if h1 != h2 {
		t.Fatal("交易哈希不稳定")
	}
}

// TestTx_EffectivePriorityFee 验证有效小费计算（mempool 排序依据）。
func TestTx_EffectivePriorityFee(t *testing.T) {
	baseFee := types.Uint256FromUint64(100)

	cases := []struct {
		name    string
		maxFee  uint64
		maxTip  uint64
		wantTip uint64
	}{
		{"tip_limited", 1000, 5, 5},         // maxTip < headroom
		{"headroom_limited", 110, 1000, 10}, // headroom = 110-100 = 10 < maxTip
		{"exact", 105, 5, 5},
		{"maxfee_below_basefee", 50, 5, 0}, // maxFee < baseFee → 0（这类交易应被准入拒绝）
		{"maxfee_equals_basefee", 100, 5, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tx := &chain.Transaction{
				Type:                 chain.TxTypeDynamicFee,
				MaxFeePerGas:         types.Uint256FromUint64(tc.maxFee),
				MaxPriorityFeePerGas: types.Uint256FromUint64(tc.maxTip),
			}
			got := tx.EffectivePriorityFee(baseFee)
			if got.Cmp(types.Uint256FromUint64(tc.wantTip)) != 0 {
				t.Fatalf("有效小费错误: want %d, got %s",
					tc.wantTip, got.ToBig().String())
			}
		})
	}
}

// ============================================================================
// 辅助
// ============================================================================

// buildChildBlock 基于当前链头构造一个合法的子区块。
func buildChildBlock(t *testing.T, parent chain.Head, height types.Height) *chain.Block {
	t.Helper()

	txs := make([]*chain.Transaction, 0, 2)
	for i := 0; i < 2; i++ {
		to := types.Address{byte(0x30 + i)}
		txs = append(txs, &chain.Transaction{
			Type:                 chain.TxTypeDynamicFee,
			ChainID:              10086,
			Nonce:                types.Nonce(i),
			MaxPriorityFeePerGas: types.Uint256FromUint64(1000000000),
			MaxFeePerGas:         types.Uint256FromUint64(2000000000),
			GasLimit:             21000,
			To:                   &to,
			Value:                types.Uint256FromUint64(uint64(100 * (i + 1))),
		})
	}

	blk := &chain.Block{
		Header: &chain.BlockHeader{
			Version:          1,
			ChainID:          10086,
			Height:           height,
			Round:            0,
			Timestamp:        1700000000 + uint64(height),
			PrevHash:         parent.Hash,
			Proposer:         types.Address{0x01},
			StateRoot:        parent.StateRoot,
			GasLimit:         30000000,
			BaseFeePerGas:    types.Uint256FromUint64(1000000000),
			ValidatorSetHash: types.Hash{0xab},
		},
		Transactions: txs,
	}

	// txRoot 必须与区块体一致（AppendBlock 会校验）
	blk.Header.TxRoot = blk.ComputeTxRoot()

	// receiptRoot 由空收据列表推导（M1 尚无执行层）
	blk.Header.ReceiptRoot = chain.ComputeReceiptRoot(nil)

	return blk
}
