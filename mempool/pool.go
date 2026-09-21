// Package mempool 实现交易池。
//
// 核心确定性要求：**打包选取必须是确定性的** ——
// 给定同一份池子快照与 gas 上限，所有节点必须选出完全相同的交易集合与顺序。
// 否则不同节点会执行不同的交易集 → stateRoot 不一致 → 分叉。
//
// 排序规则：effectivePriorityFee 降序，同值用 txHash 升序做 tie-break。
// 禁止依赖 map 迭代顺序（determinism linter 会拦截）。
//
// 一个区块可以包含同一发送者的**多笔连续 nonce** 交易。
// 因此"可执行"的定义不是 `nonce == accountNonce`，而是
// **从 accountNonce 开始的一段连续 nonce 链**。
package mempool

import (
	"container/heap"
	"errors"
	"maps"
	"math/big"
	"slices"
	"sync"

	gethTypes "github.com/ethereum/go-ethereum/core/types"

	"github.com/chfault/chfault/types"
)

// 默认配置。
const (
	// DefaultMaxTxs 池内交易总数上限。
	DefaultMaxTxs = 8192
	// DefaultMaxPerAccount 单账户队列上限（防单账户灌爆）。
	DefaultMaxPerAccount = 64
	// ReplacePriceBumpBps 替换交易的加价要求。
	//
	// 基点语义：11000 bps = 11000/10000 = 1.10 倍（即 +10%）。
	// ⚠️ 常见错误：写成 1100 表示"110%" —— 那实际是 11%，会让替换门槛形同虚设。
	ReplacePriceBumpBps = 11000
	// BasisPoints 基点分母。
	BasisPoints = 10000
)

// Config 是交易池配置。
type Config struct {
	// MaxTxs 池内交易总数上限。
	MaxTxs int
	// MaxPerAccount 单账户入队上限。
	MaxPerAccount int
	// BaseFee 当前基础费（用于计算有效小费）。
	BaseFee types.Uint256
	// BlockGasLimit 单区块 gas 上限。
	BlockGasLimit types.Gas
}

// DefaultConfig 返回默认配置。
func DefaultConfig() Config {
	return Config{
		MaxTxs:        DefaultMaxTxs,
		MaxPerAccount: DefaultMaxPerAccount,
		BaseFee:       types.Uint256FromUint64(1_000_000_000),
		BlockGasLimit: 30_000_000,
	}
}

// entry 是池内的一个条目。
//
// tx 是 **geth 的已签名交易**：交易格式与以太坊逐字节兼容（spec/10），
// 池内、执行层、区块体全程使用同一类型，消除双向桥接。
// sender 是提交时签名恢复的结果（geth Transaction 无公开 From setter）。
type entry struct {
	tx       *gethTypes.Transaction
	sender   types.Address
	hash     types.TxHash
	priority types.Uint256 // effective priority fee
}

// Pool 是交易池。
type Pool struct {
	mu     sync.Mutex
	cfg    Config
	byHash map[types.TxHash]*entry
	// bySender[sender][nonce] = entry，用于 nonce 序列管理。
	bySender map[types.Address]map[types.Nonce]*entry
	// accountNonce 是各账户当前已确认的 nonce（由外部在执行后更新）。
	accountNonce map[types.Address]types.Nonce
	stats        Stats
}

// Stats 是池的统计。
type Stats struct {
	// Pending 可执行交易数（nonce 连续的链上的交易）。
	Pending int
	// Queued 因 nonce 间隙而暂时不可执行的交易数。
	Queued int
	// Total 池内交易总数。
	Total int
	// Rejected 按原因统计的拒绝次数。
	Rejected map[string]uint64
}

// 错误。
var (
	// ErrDuplicate 交易已存在。
	ErrDuplicate = errors.New("mempool: 交易已存在")
	// ErrPoolFull 池已满且新交易优先级不够。
	ErrPoolFull = errors.New("mempool: 交易池已满")
	// ErrAccountQueueFull 该账户队列已满。
	ErrAccountQueueFull = errors.New("mempool: 该账户队列已满")
	// ErrNonceTooLow nonce 低于账户当前值。
	ErrNonceTooLow = errors.New("mempool: nonce 过低")
	// ErrReplaceTooCheap 替换交易的加价不足。
	ErrReplaceTooCheap = errors.New("mempool: 替换交易加价不足（需 10%）")
	// ErrFeeTooLow 费用低于基础费。
	ErrFeeTooLow = errors.New("mempool: 费用低于基础费")
	// ErrGasLimitTooHigh gas 上限超区块上限。
	ErrGasLimitTooHigh = errors.New("mempool: gas 上限超过区块上限")
)

// ============================================================================
// 构造
// ============================================================================

// New 创建交易池。
func New(cfg Config) *Pool {
	if cfg.MaxTxs <= 0 {
		cfg.MaxTxs = DefaultMaxTxs
	}
	if cfg.MaxPerAccount <= 0 {
		cfg.MaxPerAccount = DefaultMaxPerAccount
	}
	if cfg.BlockGasLimit == 0 {
		cfg.BlockGasLimit = 30_000_000
	}
	return &Pool{
		cfg:          cfg,
		byHash:       make(map[types.TxHash]*entry),
		bySender:     make(map[types.Address]map[types.Nonce]*entry),
		accountNonce: make(map[types.Address]types.Nonce),
		stats:        Stats{Rejected: make(map[string]uint64)},
	}
}

// SetBaseFee 更新基础费（每次出块后应调用）。
func (p *Pool) SetBaseFee(v types.Uint256) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cfg.BaseFee = v
}

// BaseFee 返回当前基础费。
func (p *Pool) BaseFee() types.Uint256 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cfg.BaseFee
}

// SetAccountNonce 更新某账户的当前 nonce（交易被确认后调用）。
//
// 更新后，原先因 nonce 间隙而"排队"的交易会自动变为可执行。
func (p *Pool) SetAccountNonce(sender types.Address, nonce types.Nonce) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.accountNonce[sender] = nonce
	p.pruneBelowNonceLocked(sender, nonce)
	p.refreshStatsLocked()
}

// pruneBelowNonceLocked 移除某账户 nonce 低于给定值的交易（已被确认或已失效）。
func (p *Pool) pruneBelowNonceLocked(sender types.Address, nonce types.Nonce) {
	txs := p.bySender[sender]
	if txs == nil {
		return
	}
	// 用排序后的 nonce 列表遍历，保证确定性
	stale := make([]types.Nonce, 0, len(txs))
	for _, n := range slices.Sorted(maps.Keys(txs)) {
		if n < nonce {
			stale = append(stale, n)
		}
	}
	for _, n := range stale {
		if e, ok := txs[n]; ok {
			p.removeLocked(e)
		}
	}
}

// ============================================================================
// 入池
// ============================================================================

// Add 把交易加入池中。
//
// 静态校验（大小、gas 上限、费用）在池内完成；
// **依赖状态的校验（余额）由调用方在传入前完成** ——
// 池不理解状态，只做池级策略（去重、替换、容量、排序）。
//
// accountNonce 是该发送者当前的账户 nonce，用于判断交易是否可立即执行。
func (p *Pool) Add(tx *gethTypes.Transaction, sender types.Address, accountNonce types.Nonce) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	hash := types.TxHash(tx.Hash())

	// ---- 静态校验 ----
	if types.Gas(tx.Gas()) > p.cfg.BlockGasLimit {
		return p.rejectLocked("gas_limit", ErrGasLimitTooHigh)
	}
	if tx.Type() == gethTypes.DynamicFeeTxType {
		if toU256(tx.GasFeeCap()).Cmp(p.cfg.BaseFee) < 0 {
			return p.rejectLocked("fee_too_low", ErrFeeTooLow)
		}
		if toU256(tx.GasFeeCap()).Cmp(toU256(tx.GasTipCap())) < 0 {
			return p.rejectLocked("fee_too_low", ErrFeeTooLow)
		}
	}

	// 记录账户当前 nonce（取较大值，避免回退）
	if cur, ok := p.accountNonce[sender]; !ok || accountNonce > cur {
		p.accountNonce[sender] = accountNonce
	}
	base := p.accountNonce[sender]

	if types.Nonce(tx.Nonce()) < base {
		return p.rejectLocked("nonce_too_low", ErrNonceTooLow)
	}

	// ---- 去重 / 替换 ----
	if _, ok := p.byHash[hash]; ok {
		return p.rejectLocked("duplicate", ErrDuplicate)
	}

	senderTxs := p.bySender[sender]
	if senderTxs != nil {
		if old, ok := senderTxs[types.Nonce(tx.Nonce())]; ok {
			if !canReplace(old.tx, tx) {
				return p.rejectLocked("replace_too_cheap", ErrReplaceTooCheap)
			}
			p.removeLocked(old)
		}
	}

	// ---- 容量 ----
	if senderTxs != nil && len(senderTxs) >= p.cfg.MaxPerAccount {
		return p.rejectLocked("account_queue_full", ErrAccountQueueFull)
	}
	if len(p.byHash) >= p.cfg.MaxTxs {
		if !p.evictLowestIfWorseThanLocked(tx) {
			return p.rejectLocked("pool_full", ErrPoolFull)
		}
	}

	// ---- 入池 ----
	e := &entry{
		tx:       tx,
		hash:     hash,
		sender:   sender,
		priority: tipToU256(tx, p.cfg.BaseFee),
	}
	p.byHash[hash] = e
	if p.bySender[sender] == nil {
		p.bySender[sender] = make(map[types.Nonce]*entry)
	}
	p.bySender[sender][types.Nonce(tx.Nonce())] = e

	p.refreshStatsLocked()
	return nil
}

// canReplace 判断新交易是否满足替换要求（两个费用字段都要 +10%）。
func canReplace(oldTx, newTx *gethTypes.Transaction) bool {
	if !priceBumpedU(oldTx.GasFeeCap(), newTx.GasFeeCap()) {
		return false
	}
	return priceBumpedU(oldTx.GasTipCap(), newTx.GasTipCap())
}

// toU256 big.Int → chfault Uint256（失败返回零值）。
func toU256(v *big.Int) types.Uint256 {
	out, err := types.Uint256FromBig(v)
	if err != nil {
		return types.ZeroUint256()
	}
	return out
}

// u256Of 同 toU256（EffectiveGasTip 双返回值场景的薄封装）。
func u256Of(v *big.Int) types.Uint256 { return toU256(v) }

// tipToU256 计算 effective tip 并转 Uint256。
//
// EffectiveGasTip 在 maxFee < baseFee 时返回错误 —— 但那种交易
// 在准入阶段（Add 的静态校验）就被拒绝了，这里防御性返回 0。
func tipToU256(tx *gethTypes.Transaction, baseFee types.Uint256) types.Uint256 {
	tip, err := tx.EffectiveGasTip(baseFee.ToBig())
	if err != nil || tip == nil {
		return types.ZeroUint256()
	}
	return toU256(tip)
}

// priceBumped 判断 newV 是否 >= oldV × 110%。
//
// 用整数基点运算，禁止浮点（确定性契约 C5）。
func priceBumpedU(oldV, newV *big.Int) bool {
	return priceBumped(toU256(oldV), toU256(newV))
}

func priceBumped(oldV, newV types.Uint256) bool {
	if oldV.IsZero() {
		return true // 旧值为 0，任何新值都算加价
	}
	product, err := oldV.Mul(types.Uint256FromUint64(ReplacePriceBumpBps))
	if err != nil {
		// 溢出说明 oldV 极大，保守地要求新值更大
		return newV.Cmp(oldV) > 0
	}
	required := divBySmall(product, types.Uint256FromUint64(BasisPoints))
	return newV.Cmp(required) >= 0
}

// divBySmall 对 Uint256 做小整数除法。
func divBySmall(v, d types.Uint256) types.Uint256 {
	den := d.ToBig()
	if den.Sign() == 0 {
		return types.ZeroUint256()
	}
	out, err := types.Uint256FromBig(new(big.Int).Div(v.ToBig(), den))
	if err != nil {
		return types.ZeroUint256()
	}
	return out
}

// ============================================================================
// 可执行交易集合
// ============================================================================

// executableLocked 返回**所有可执行**的交易。
//
// 定义：对每个发送者，从 accountNonce 开始、nonce 连续的那一段。
// 一个区块可以包含同一发送者的多笔连续 nonce 交易，所以不能只看
// `nonce == accountNonce` 那一笔。
//
// 调用方必须已持有锁。
func (p *Pool) executableLocked() []*entry {
	var out []*entry

	// 遍历排序后的发送者列表，保证结果顺序可复现
	// （Address 是 [20]byte，不满足 cmp.Ordered，用 SortedFunc + Compare）
	for _, sender := range slices.SortedFunc(maps.Keys(p.bySender),
		func(a, b types.Address) int { return a.Compare(b) }) {
		txs := p.bySender[sender]
		start := p.accountNonce[sender]
		for n := start; ; n++ {
			e, ok := txs[n]
			if !ok {
				break // nonce 链在此断开
			}
			out = append(out, e)
		}
	}
	return out
}

// ============================================================================
// 打包选取
// ============================================================================

// Select 选取一个区块的交易集合。
//
// **确定性关键**：给定同一份池子快照与 gas 上限，
// 所有节点必须选出完全相同的集合与顺序。
//
// 算法（sender 链 + 优先级堆，这是 mempool 打包的标准做法）：
//
//  1. 对每个发送者，取出从 accountNonce 开始的**连续 nonce 链**
//     （一个区块可以包含同一发送者的多笔交易，所以不能只看第一笔）
//  2. 把每个发送者链的**队首**放入优先级堆（堆序：priority desc, hash asc）
//  3. 循环弹出堆顶：
//     - gas 不够 → 丢弃该发送者的后续（nonce 必须连续，跳过一笔则后面都不能选）
//     - 否则选中，并把该发送者链的下一笔放入堆
//
// ⚠️ 曾经写错的两个版本（都已废弃）：
//   - 只把 `nonce == accountNonce` 的交易放进候选 → 同一发送者的后续永远选不出来
//   - 单次按优先级遍历 + "期望 nonce"过滤 → 当同一发送者的高 nonce 交易
//     优先级更高时会先被遇到并跳过，之后再无机会回头，导致大量漏选
//
// SelectedTx 是选中交易及其发送者（执行时恢复 From 需要）。
type SelectedTx struct {
	Tx     *gethTypes.Transaction
	Sender types.Address
}

func (p *Pool) Select(gasLimit types.Gas) []SelectedTx {
	p.mu.Lock()
	defer p.mu.Unlock()

	// 1. 为每个发送者构建连续 nonce 链
	type senderChain struct {
		txs  []*entry
		next int
	}

	chains := make([]*senderChain, 0, 8)
	index := make(map[types.Address]*senderChain)

	for _, sender := range slices.SortedFunc(maps.Keys(p.bySender),
		func(a, b types.Address) int { return a.Compare(b) }) {

		txs := p.bySender[sender]
		var chainTxs []*entry
		for n := p.accountNonce[sender]; ; n++ {
			e, ok := txs[n]
			if !ok {
				break // nonce 链在此断开
			}
			chainTxs = append(chainTxs, e)
		}
		if len(chainTxs) == 0 {
			continue // 该发送者的交易全部不可执行
		}
		st := &senderChain{txs: chainTxs}
		chains = append(chains, st)
		index[sender] = st
	}

	// 2. 初始化堆：每个发送者链的队首
	h := make(entryHeap, 0, len(chains))
	for _, st := range chains {
		h = append(h, st.txs[0])
	}
	heapInit(&h)

	// 3. 按优先级弹出
	var (
		used   types.Gas
		picked []SelectedTx
	)

	for len(h) > 0 {
		e := heapPop(&h)

		if used+types.Gas(e.tx.Gas()) > gasLimit {
			// gas 不足以容纳这一笔。由于同一发送者的 nonce 必须连续，
			// 该发送者的后续交易也一并放弃（不再入堆）。
			continue
		}

		picked = append(picked, SelectedTx{Tx: e.tx, Sender: e.sender})
		used += types.Gas(e.tx.Gas())

		// 暴露该发送者链的下一笔
		st := index[e.sender]
		st.next++
		if st.next < len(st.txs) {
			heapPush(&h, st.txs[st.next])
		}
	}

	return picked
}

// sortEntriesDeterministic 按 (priority desc, hash asc) 排序。
//
// hash 升序是关键：没有它，同优先级的交易顺序不确定 → 分叉。
func sortEntriesDeterministic(entries []*entry) {
	slices.SortFunc(entries, func(a, b *entry) int {
		c := b.priority.Cmp(a.priority) // 优先级降序
		if c != 0 {
			return c
		}
		return compareHash(a.hash, b.hash) // 同优先级按哈希升序
	})
}

// compareHash 按字节序比较两个哈希。
func compareHash(a, b types.TxHash) int {
	for i := range a {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

// ============================================================================
// 优先级堆（container/heap）
// ============================================================================

// entryHeap 是确定性优先队列。
//
// 比较规则必须构成**全序** —— 否则堆的内部顺序会因插入顺序而异，
// 导致同样的交易集合在不同节点产生不同的弹出顺序。
// 这里用 (priority desc, hash asc) 保证全序。
type entryHeap []*entry

func (h entryHeap) Len() int { return len(h) }

func (h entryHeap) Less(i, j int) bool {
	c := h[i].priority.Cmp(h[j].priority)
	if c != 0 {
		return c > 0 // 优先级高的先
	}
	return compareHash(h[i].hash, h[j].hash) < 0 // 同优先级按哈希升序
}

func (h entryHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }

func (h *entryHeap) Push(x any) {
	e, ok := x.(*entry)
	if !ok {
		panic("mempool: 堆元素类型错误")
	}
	*h = append(*h, e)
}

func (h *entryHeap) Pop() any {
	old := *h
	n := len(old)
	if n == 0 {
		return nil
	}
	e := old[n-1]
	old[n-1] = nil
	*h = old[:n-1]
	return e
}

// 薄封装，避免调用方每次写 heap. 前缀。
func heapInit(h *entryHeap)           { heap.Init(h) }
func heapPush(h *entryHeap, e *entry) { heap.Push(h, e) }
func heapPop(h *entryHeap) *entry     { return heap.Pop(h).(*entry) }

// ============================================================================
// 移除
// ============================================================================

// removeLocked 从池中移除一个条目（调用方必须已持有锁）。
func (p *Pool) removeLocked(e *entry) {
	delete(p.byHash, e.hash)
	if s := p.bySender[e.sender]; s != nil {
		delete(s, types.Nonce(e.tx.Nonce()))
		if len(s) == 0 {
			delete(p.bySender, e.sender)
		}
	}
}

// Remove 按哈希移除交易（例如已被其他节点打包）。
func (p *Pool) Remove(hash types.TxHash) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.byHash[hash]
	if !ok {
		return false
	}
	p.removeLocked(e)
	p.refreshStatsLocked()
	return true
}

// RemoveAll 移除给定的交易集合（区块被打包后清理池子）。
func (p *Pool) RemoveAll(txs []*gethTypes.Transaction) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, tx := range txs {
		h := types.TxHash(tx.Hash())
		if e, ok := p.byHash[h]; ok {
			p.removeLocked(e)
			n++
		}
	}
	p.refreshStatsLocked()
	return n
}

// RemoveBySender 移除某发送者的所有交易。
func (p *Pool) RemoveBySender(sender types.Address) int {
	p.mu.Lock()
	defer p.mu.Unlock()

	s := p.bySender[sender]
	if s == nil {
		return 0
	}
	// 用排序后的 nonce 列表，保证遍历顺序可复现
	n := 0
	for _, nonce := range slices.Sorted(maps.Keys(s)) {
		if e, ok := s[nonce]; ok {
			p.removeLocked(e)
			n++
		}
	}
	p.refreshStatsLocked()
	return n
}

// ============================================================================
// 查询
// ============================================================================

// Get 按哈希查询。
func (p *Pool) Get(hash types.TxHash) (*gethTypes.Transaction, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.byHash[hash]
	if !ok {
		return nil, false
	}
	return e.tx, true
}

// Has 判断交易是否在池中。
func (p *Pool) Has(hash types.TxHash) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.byHash[hash]
	return ok
}

// Count 返回池内交易总数。
func (p *Pool) Count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.byHash)
}

// Stats 返回统计。
func (p *Pool) Stats() Stats {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.stats
	// 用 maps.Clone 而非 range map —— 尊重 determinism 约束
	s.Rejected = maps.Clone(p.stats.Rejected)
	return s
}

// PendingHashes 返回所有可执行交易的哈希（**已按优先级排序**）。
func (p *Pool) PendingHashes() []types.TxHash {
	p.mu.Lock()
	defer p.mu.Unlock()

	entries := p.executableLocked()
	sortEntriesDeterministic(entries)

	out := make([]types.TxHash, len(entries))
	for i, e := range entries {
		out[i] = e.hash
	}
	return out
}

// ============================================================================
// 内部
// ============================================================================

// refreshStatsLocked 更新统计（调用方必须已持有锁）。
func (p *Pool) refreshStatsLocked() {
	pending := len(p.executableLocked())
	p.stats.Pending = pending
	p.stats.Total = len(p.byHash)
	p.stats.Queued = len(p.byHash) - pending
	if p.stats.Queued < 0 {
		p.stats.Queued = 0
	}
}

// rejectLocked 记录拒绝原因并返回错误。
func (p *Pool) rejectLocked(reason string, err error) error {
	p.stats.Rejected[reason]++
	return err
}

// evictLowestIfWorseThanLocked 在池满时尝试驱逐最低优先级交易。
//
// 返回 true 表示成功腾出位置。
func (p *Pool) evictLowestIfWorseThanLocked(tx *gethTypes.Transaction) bool {
	candidates := p.executableLocked()
	if len(candidates) == 0 {
		// 没有可执行交易（全是 queued）：退化为驱逐任意一个 queued 交易
		return p.evictAnyQueuedLocked()
	}

	// 找最低优先级（优先级相同则哈希最大者）
	lowest := candidates[0]
	for _, e := range candidates {
		c := e.priority.Cmp(lowest.priority)
		if c < 0 || (c == 0 && compareHash(e.hash, lowest.hash) > 0) {
			lowest = e
		}
	}

	newPriority := tipToU256(tx, p.cfg.BaseFee)
	if newPriority.Cmp(lowest.priority) <= 0 {
		return false // 新交易不更优，不驱逐
	}

	p.removeLocked(lowest)
	return true
}

// evictAnyQueuedLocked 驱逐一个 queued 交易（确定性：取哈希最小者）。
func (p *Pool) evictAnyQueuedLocked() bool {
	var victim *entry
	// 用排序后的哈希列表遍历（不 range map）
	hashes := slices.SortedFunc(maps.Keys(p.byHash), compareHash)
	for _, h := range hashes {
		e := p.byHash[h]
		if p.isExecutableLocked(e) {
			continue // 只驱逐 queued
		}
		if victim == nil {
			victim = e
		}
	}
	if victim == nil {
		return false
	}
	p.removeLocked(victim)
	return true
}

// isExecutableLocked 判断某条目是否在可执行链上。
func (p *Pool) isExecutableLocked(e *entry) bool {
	txs := p.bySender[e.sender]
	if txs == nil {
		return false
	}
	start := p.accountNonce[e.sender]
	for n := start; ; n++ {
		cur, ok := txs[n]
		if !ok {
			return false
		}
		if cur == e {
			return true
		}
	}
}
