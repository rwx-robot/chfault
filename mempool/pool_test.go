package mempool_test

import (
	"math/big"
	"testing"

	gethCommon "github.com/ethereum/go-ethereum/common"
	gethTypes "github.com/ethereum/go-ethereum/core/types"
	gethCrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/chfault/chfault/mempool"
	"github.com/chfault/chfault/types"
)

// ============================================================================
// 辅助
// ============================================================================

// mkTx 构造一笔**真实签名**的 geth 交易。
//
// 交易哈希由签名决定（不同私钥 → 不同哈希），天然唯一。
// 返回 sender 供 pool.Add 使用（geth Transaction 无公开 From setter，
// sender 是提交时签名恢复的派生信息，由提交者显式传入池）。
func mkTx(t *testing.T, seed byte, nonce uint64, tipGwei uint64, gas uint64) (*gethTypes.Transaction, types.Address) {
	t.Helper()
	key, err := gethCrypto.HexToECDSA(hexSeed(seed))
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	addr := types.Address(gethCrypto.PubkeyToAddress(key.PublicKey))
	to := gethCommon.Address{0xee}

	tx := gethTypes.NewTx(&gethTypes.DynamicFeeTx{
		ChainID:   new(big.Int).SetUint64(10086),
		Nonce:     nonce,
		GasTipCap: big.NewInt(int64(tipGwei) * 1_000_000_000),
		GasFeeCap: big.NewInt(100 * 1_000_000_000),
		Gas:       gas,
		To:        &to,
		Value:     big.NewInt(1000),
	})
	signer := gethTypes.LatestSignerForChainID(new(big.Int).SetUint64(10086))
	signed, err := gethTypes.SignTx(tx, signer, key)
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	return signed, addr
}

// hexSeed 生成确定性测试私钥（仅测试用）。
func hexSeed(seed byte) string {
	buf := make([]byte, 32)
	for i := range buf {
		buf[i] = seed
	}
	const hexDigits = "0123456789abcdef"
	out := make([]byte, len(buf)*2)
	for i, v := range buf {
		out[i*2] = hexDigits[v>>4]
		out[i*2+1] = hexDigits[v&0x0f]
	}
	return string(out)
}

func newPool() *mempool.Pool {
	return mempool.New(mempool.DefaultConfig())
}

// addTx 便捷封装：签名并入池。
func addTx(t *testing.T, p *mempool.Pool, seed byte, nonce uint64, tipGwei uint64, gas uint64) {
	t.Helper()
	tx, sender := mkTx(t, seed, nonce, tipGwei, gas)
	if err := p.Add(tx, sender, 0); err != nil {
		t.Fatalf("加入交易失败: %v", err)
	}
}

// selectedHashes 把 Select 的结果转为哈希字符串列表（便于比较）。
func selectedHashes(t *testing.T, txs []mempool.SelectedTx) []string {
	t.Helper()
	out := make([]string, len(txs))
	for i, st := range txs {
		out[i] = st.Tx.Hash().String()
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// shuffled 返回 [0,n) 的确定性伪随机排列（LCG，不用 math/rand）。
func shuffled(n, seed int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = i
	}
	state := uint64(seed)*2654435761 + 12345
	next := func() uint64 {
		state = state*6364136223846793005 + 1442695040888963407
		return state >> 33
	}
	for i := n - 1; i > 0; i-- {
		j := int(next() % uint64(i+1))
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// ============================================================================
// 确定性 —— 本项目最关键的一类测试
// ============================================================================

// TestSelect_IsDeterministicAcrossRuns 验证：
// 相同的交易集合（以不同顺序加入）必须选出完全相同的交易序列。
//
// 这是防止分叉的核心测试：排序规则必须构成全序，
// 否则不同节点会打包不同的交易集，stateRoot 必然不一致。
func TestSelect_IsDeterministicAcrossRuns(t *testing.T) {
	const senders = 8
	const txPerSender = 4

	type txSpec struct {
		seed  byte
		nonce uint64
		tip   uint64
	}
	var specs []txSpec
	for s := 0; s < senders; s++ {
		for n := 0; n < txPerSender; n++ {
			specs = append(specs, txSpec{
				seed:  byte(s + 1),
				nonce: uint64(n),
				tip:   uint64((s*7+n*3)%5) + 1, // 混合小费制造排序压力
			})
		}
	}

	selectWith := func(order []int) []string {
		p := newPool()
		for _, idx := range order {
			sp := specs[idx]
			addTx(t, p, sp.seed, sp.nonce, sp.tip, 21000)
		}
		return selectedHashes(t, p.Select(30_000_000))
	}

	forward := make([]int, len(specs))
	for i := range forward {
		forward[i] = i
	}
	baseline := selectWith(forward)
	if len(baseline) == 0 {
		t.Fatal("应选出交易")
	}

	// 反序
	backward := make([]int, len(specs))
	for i := range backward {
		backward[i] = len(specs) - 1 - i
	}
	if got := selectWith(backward); !equalStrings(got, baseline) {
		t.Fatalf("反序加入导致选取结果不同（会分叉）:\n 基线 %d 笔\n 反序 %d 笔",
			len(baseline), len(got))
	}

	// 20 组伪随机顺序
	for seed := 0; seed < 20; seed++ {
		got := selectWith(shuffled(len(specs), seed))
		if !equalStrings(got, baseline) {
			t.Fatalf("随机顺序（seed=%d）导致选取结果不同（会分叉）", seed)
		}
	}

	t.Logf("选取 %d 笔交易，22 种加入顺序下结果一致", len(baseline))
}

// TestSelect_SameSenderNonceOrder 验证同一发送者的交易按 nonce 递增打包。
func TestSelect_SameSenderNonceOrder(t *testing.T) {
	p := newPool()
	for n := 0; n < 5; n++ {
		addTx(t, p, 0x01, uint64(n), 1, 21000)
	}

	selected := p.Select(1_000_000)
	if len(selected) != 5 {
		t.Fatalf("应选出 5 笔，实际 %d", len(selected))
	}
	for i := 1; i < len(selected); i++ {
		if selected[i].Tx.Nonce() <= selected[i-1].Tx.Nonce() {
			t.Fatalf("同一发送者的 nonce 应递增：%d 然后 %d",
				selected[i-1].Tx.Nonce(), selected[i].Tx.Nonce())
		}
	}

	// 重复选取一致
	again := p.Select(1_000_000)
	if !equalStrings(selectedHashes(t, selected), selectedHashes(t, again)) {
		t.Fatal("重复选取结果不同")
	}
}

// TestSelect_RespectsNonceContinuity 验证 nonce 间隙的交易不被打包。
func TestSelect_RespectsNonceContinuity(t *testing.T) {
	p := newPool()
	// 只加入 nonce 2、3（缺 0、1）
	addTx(t, p, 0x01, 2, 1, 21000)
	addTx(t, p, 0x01, 3, 1, 21000)

	if got := p.Select(1_000_000); len(got) != 0 {
		t.Fatalf("nonce 不连续的交易不应被选中，实际 %d 笔", len(got))
	}

	// 补上 nonce 0、1 后全部可执行
	addTx(t, p, 0x01, 0, 1, 21000)
	addTx(t, p, 0x01, 1, 1, 21000)
	if got := p.Select(1_000_000); len(got) != 4 {
		t.Fatalf("补齐后应选中 4 笔，实际 %d", len(got))
	}
}

// TestSelect_RespectsGasLimit 验证 gas 上限约束。
func TestSelect_RespectsGasLimit(t *testing.T) {
	p := newPool()
	for s := 1; s <= 10; s++ {
		addTx(t, p, byte(s), 0, 1, 30000)
	}

	selected := p.Select(90000)
	if len(selected) != 3 {
		t.Fatalf("gas 上限 90000 应选中 3 笔，实际 %d", len(selected))
	}
	var used uint64
	for _, sel := range selected {
		used += sel.Tx.Gas()
	}
	if used > 90000 {
		t.Fatalf("总 gas 超限: %d", used)
	}
}

// TestSelect_DeterministicAcrossEnvironments 独门检查的 mempool 版。
func TestSelect_DeterministicAcrossEnvironments(t *testing.T) {
	build := func() []string {
		p := newPool()
		for s := 1; s <= 12; s++ {
			for n := 0; n < 3; n++ {
				addTx(t, p, byte(s), uint64(n), uint64((s+n)%4)+1, 21000)
			}
		}
		return selectedHashes(t, p.Select(10_000_000))
	}

	baseline := build()
	if len(baseline) == 0 {
		t.Fatal("应选出交易")
	}
	for i := 0; i < 30; i++ {
		if got := build(); !equalStrings(got, baseline) {
			t.Fatalf("第 %d 次构建的选取结果与基线不同（会分叉）", i)
		}
	}
}

// ============================================================================
// 准入与替换
// ============================================================================

func TestAdd_RejectsDuplicate(t *testing.T) {
	p := newPool()
	tx, sender := mkTx(t, 0x01, 0, 1, 21000)

	if err := p.Add(tx, sender, 0); err != nil {
		t.Fatalf("首次加入应成功: %v", err)
	}
	if err := p.Add(tx, sender, 0); err != mempool.ErrDuplicate {
		t.Fatalf("应返回 ErrDuplicate，实际 %v", err)
	}
}

func TestAdd_RejectsNonceTooLow(t *testing.T) {
	p := newPool()
	tx, sender := mkTx(t, 0x01, 5, 1, 21000)
	if err := p.Add(tx, sender, 10); err != mempool.ErrNonceTooLow {
		t.Fatalf("应返回 ErrNonceTooLow，实际 %v", err)
	}
}

func TestAdd_RejectsFeeBelowBaseFee(t *testing.T) {
	cfg := mempool.DefaultConfig()
	cfg.BaseFee = types.Uint256FromUint64(10_000_000_000)
	p := mempool.New(cfg)

	tx, sender := mkTx(t, 0x01, 0, 1, 21000)
	// mkTx 的 maxFee 是 100 gwei > 10 gwei，需要单独压低
	tx2, sender2 := mkTx(t, 0x01, 0, 1, 21000)
	_ = tx
	// 直接构造低 maxFee 交易
	lowFee := gethTypes.NewTx(&gethTypes.DynamicFeeTx{
		ChainID:   new(big.Int).SetUint64(10086),
		Nonce:     0,
		GasTipCap: big.NewInt(1_000_000_000),
		GasFeeCap: big.NewInt(5_000_000_000), // 5 gwei < baseFee 10 gwei
		Gas:       21000,
		To:        &gethCommon.Address{0xee},
		Value:     big.NewInt(1000),
	})
	signer := gethTypes.LatestSignerForChainID(new(big.Int).SetUint64(10086))
	key, _ := gethCrypto.HexToECDSA(hexSeed(0x01))
	signed, err := gethTypes.SignTx(lowFee, signer, key)
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	_ = tx2
	_ = sender2
	if err := p.Add(signed, sender, 0); err != mempool.ErrFeeTooLow {
		t.Fatalf("应返回 ErrFeeTooLow，实际 %v", err)
	}
}

func TestAdd_RejectsOversizedGasLimit(t *testing.T) {
	cfg := mempool.DefaultConfig()
	cfg.BlockGasLimit = 30_000_000
	p := mempool.New(cfg)

	tx, sender := mkTx(t, 0x01, 0, 1, 100_000_000)
	if err := p.Add(tx, sender, 0); err != mempool.ErrGasLimitTooHigh {
		t.Fatalf("应返回 ErrGasLimitTooHigh，实际 %v", err)
	}
}

// TestReplace_RequiresPriceBump 验证替换交易的 10% 加价要求。
//
// ⚠️ 历史教训：曾把 11000 bps 写成 1100（=11%），
// 导致替换门槛形同虚设 —— 本测试就是为防回归而存在。
func TestReplace_RequiresPriceBump(t *testing.T) {
	p := newPool()

	orig, origSender := mkTx(t, 0x01, 0, 1, 21000)
	if err := p.Add(orig, origSender, 0); err != nil {
		t.Fatalf("加入原交易失败: %v", err)
	}

	// 同一发送者、同 nonce、tip 加 5%（不足 10%）→ 拒绝
	cheap, cheapSender := mkTxWithTip(t, 0x01, 0, 1_050_000_000, 100_000_000_000)
	if err := p.Add(cheap, cheapSender, 0); err != mempool.ErrReplaceTooCheap {
		t.Fatalf("加价 5%% 应被拒绝，实际 %v", err)
	}

	// tip 与 maxFee 都加 20% → 接受
	good, goodSender := mkTxWithTip(t, 0x01, 0, 1_200_000_000, 120_000_000_000)
	if err := p.Add(good, goodSender, 0); err != nil {
		t.Fatalf("加价 20%% 应被接受，实际 %v", err)
	}

	if n := p.Count(); n != 1 {
		t.Fatalf("替换后池内应有 1 笔，实际 %d", n)
	}
}

// mkTxWithTip 同 mkTx，但 tip 与 maxFee 精确指定（替换测试用）。
func mkTxWithTip(t *testing.T, seed byte, nonce uint64, tipWei uint64, maxFeeWei uint64) (*gethTypes.Transaction, types.Address) {
	t.Helper()
	key, err := gethCrypto.HexToECDSA(hexSeed(seed))
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	addr := types.Address(gethCrypto.PubkeyToAddress(key.PublicKey))
	to := gethCommon.Address{0xee}

	tx := gethTypes.NewTx(&gethTypes.DynamicFeeTx{
		ChainID:   new(big.Int).SetUint64(10086),
		Nonce:     nonce,
		GasTipCap: big.NewInt(int64(tipWei)),
		GasFeeCap: big.NewInt(int64(maxFeeWei)),
		Gas:       21000,
		To:        &to,
		Value:     big.NewInt(1000),
	})
	signer := gethTypes.LatestSignerForChainID(new(big.Int).SetUint64(10086))
	signed, err := gethTypes.SignTx(tx, signer, key)
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	return signed, addr
}

func TestAdd_RespectsPerAccountLimit(t *testing.T) {
	cfg := mempool.DefaultConfig()
	cfg.MaxPerAccount = 3
	p := mempool.New(cfg)

	for n := 0; n < 3; n++ {
		addTx(t, p, 0x01, uint64(n), 1, 21000)
	}
	tx, sender := mkTx(t, 0x01, 3, 1, 21000)
	if err := p.Add(tx, sender, 0); err != mempool.ErrAccountQueueFull {
		t.Fatalf("超过账户上限应被拒绝，实际 %v", err)
	}

	// 其他账户不受影响
	addTx(t, p, 0x02, 0, 1, 21000)
	if p.Count() != 4 {
		t.Fatalf("应有 4 笔，实际 %d", p.Count())
	}
}

func TestAdd_EvictsLowestWhenFull(t *testing.T) {
	cfg := mempool.DefaultConfig()
	cfg.MaxTxs = 3
	p := mempool.New(cfg)

	for s := 1; s <= 3; s++ {
		addTx(t, p, byte(s), 0, 1, 21000)
	}
	if p.Count() != 3 {
		t.Fatalf("应有 3 笔，实际 %d", p.Count())
	}

	// 高优先级（tip 100 gwei）→ 驱逐一个低优先级
	addTx(t, p, 0x09, 0, 100, 21000)
	if p.Count() != 3 {
		t.Fatalf("驱逐后仍应有 3 笔，实际 %d", p.Count())
	}

	// 高优先级交易必须被选中
	wantSender := mkSender(0x09)
	found := false
	for _, sel := range p.Select(1_000_000) {
		if sel.Sender == wantSender {
			found = true
		}
	}
	if !found {
		t.Fatal("高优先级交易应被选中")
	}
}

// ============================================================================
// 移除
// ============================================================================

func TestRemove(t *testing.T) {
	p := newPool()
	tx, sender := mkTx(t, 0x01, 0, 1, 21000)
	if err := p.Add(tx, sender, 0); err != nil {
		t.Fatal(err)
	}

	if !p.Remove(types.TxHash(tx.Hash())) {
		t.Fatal("移除应成功")
	}
	if p.Remove(types.TxHash(tx.Hash())) {
		t.Fatal("重复移除应返回 false")
	}
	if p.Count() != 0 {
		t.Fatalf("移除后应为空，实际 %d", p.Count())
	}
}

func TestRemoveBySender(t *testing.T) {
	p := newPool()
	for n := 0; n < 4; n++ {
		addTx(t, p, 0x01, uint64(n), 1, 21000)
	}
	addTx(t, p, 0x02, 0, 1, 21000)

	if n := p.RemoveBySender(mkSender(0x01)); n != 4 {
		t.Fatalf("应移除 4 笔，实际 %d", n)
	}
	if p.Count() != 1 {
		t.Fatalf("应剩 1 笔，实际 %d", p.Count())
	}
}

func mkSender(seed byte) types.Address {
	key, _ := gethCrypto.HexToECDSA(hexSeed(seed))
	return types.Address(gethCrypto.PubkeyToAddress(key.PublicKey))
}

// ============================================================================
// 并发安全（配合 -race 运行）
// ============================================================================

func TestConcurrentAccess(t *testing.T) {
	p := newPool()
	done := make(chan bool, 40)

	for s := 1; s <= 20; s++ {
		go func(seed byte) {
			defer func() { done <- true }()
			for n := 0; n < 5; n++ {
				tx, sender := mkTx(t, seed, uint64(n), 1, 21000)
				_ = p.Add(tx, sender, 0) // 重复加入预期会被拒绝
			}
		}(byte(s))
	}

	for i := 0; i < 20; i++ {
		go func() {
			defer func() { done <- true }()
			_ = p.Select(1_000_000)
			_ = p.Count()
			_ = p.Stats()
			_ = p.PendingHashes()
		}()
	}

	for i := 0; i < 40; i++ {
		<-done
	}

	if len(p.Select(100_000_000)) == 0 {
		t.Fatal("并发写入后应能选出交易")
	}
}

// TestShuffledSanity 确保测试辅助函数本身工作正常。
func TestShuffledSanity(t *testing.T) {
	for seed := 0; seed < 10; seed++ {
		got := shuffled(10, seed)
		seen := make(map[int]bool)
		for _, v := range got {
			if v < 0 || v >= 10 {
				t.Fatalf("排列元素越界: %d", v)
			}
			if seen[v] {
				t.Fatalf("排列有重复元素: %d", v)
			}
			seen[v] = true
		}
	}
	s0 := fmtShuffled(10, 0)
	allSame := true
	for seed := 1; seed < 10; seed++ {
		if fmtShuffled(10, seed) == s0 {
			continue
		}
		allSame = false
		break
	}
	if allSame {
		t.Fatal("不同种子产生相同排列，测试失去意义")
	}
}

func fmtShuffled(n, seed int) string {
	out := shuffled(n, seed)
	s := ""
	for _, v := range out {
		s += string(rune('0' + v%10))
	}
	return s
}
