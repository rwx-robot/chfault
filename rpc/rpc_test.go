package rpc_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/chfault/chfault/chain"
	"github.com/chfault/chfault/rpc"
	"github.com/chfault/chfault/storage"
	"github.com/chfault/chfault/types"
)

// ============================================================================
// 测试夹具
// ============================================================================

// testEnv 是测试用的链 + RPC 服务。
type testEnv struct {
	chain      *chain.Chain
	registry   *rpc.Registry
	dispatcher *rpc.Dispatcher
	server     *rpc.Server
	baseURL    string
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })

	ch, err := chain.New(store, chain.Config{ChainID: 10086})
	if err != nil {
		t.Fatalf("创建链失败: %v", err)
	}

	g := &chain.Genesis{
		ChainID:        "10086",
		Timestamp:      "1700000000",
		GasLimit:       "30000000",
		InitialBaseFee: "1000000000",
		Version:        "1",
		Alloc: map[string]chain.AllocAccount{
			"0x0000000000000000000000000000000000000001": {Balance: "1000000000000000000000"},
		},
		Validators: []chain.GenesisValidator{{
			Address: "0x0000000000000000000000000000000000000001",
			PubKey:  "0x02" + strings.Repeat("ab", 32),
			Power:   "1",
		}},
	}
	if err := ch.InitGenesis(g); err != nil {
		t.Fatalf("初始化创世失败: %v", err)
	}

	// 追加一个区块，让 RPC 有内容可查
	if err := ch.AppendBlock(makeBlock(t, ch.Head(), 1), nil); err != nil {
		t.Fatalf("追加区块失败: %v", err)
	}

	reg := rpc.NewRegistry()
	rpc.RegisterChainMethods(reg, ch, ch.HasGenesis, nil)
	disp := rpc.NewDispatcher(reg)
	disp.ReadyFunc = ch.HasGenesis

	cfg := rpc.DefaultServerConfig()
	cfg.HTTPPort = 0 // 让系统分配端口，避免测试间冲突
	cfg.PerIPRateLimit = 0

	srv := rpc.NewServer(cfg, reg, disp)
	if err := srv.StartAsync(); err != nil {
		t.Fatalf("启动 RPC 服务失败: %v", err)
	}

	// 等待服务真正就绪。
	// StartAsync 里 net.Listen 成功后即返回，但偶发情况下（尤其 -race 下）
	// 紧接着的第一次请求会被 reset —— 轮询 /health 消除这个竞态。
	ready := false
	for i := 0; i < 40; i++ {
		resp, err := http.Get("http://" + srv.Addr() + "/health")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				ready = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		t.Fatalf("RPC 服务 2 秒内未就绪")
	}

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Stop(ctx)
	})

	return &testEnv{
		chain:      ch,
		registry:   reg,
		dispatcher: disp,
		server:     srv,
		baseURL:    "http://" + srv.Addr(),
	}
}

func makeBlock(t *testing.T, parent chain.Head, height types.Height) *chain.Block {
	t.Helper()
	to := types.Address{0x42}
	tx := &chain.Transaction{
		Type:                 chain.TxTypeDynamicFee,
		ChainID:              10086,
		Nonce:                0,
		MaxPriorityFeePerGas: types.Uint256FromUint64(1_000_000_000),
		MaxFeePerGas:         types.Uint256FromUint64(2_000_000_000),
		GasLimit:             21000,
		To:                   &to,
		Value:                types.Uint256FromUint64(12345),
		From:                 types.Address{0x01},
	}
	blk := &chain.Block{
		Header: &chain.BlockHeader{
			Version: 1, ChainID: 10086, Height: height, Timestamp: 1700000001,
			PrevHash: parent.Hash, Proposer: types.Address{0x01},
			StateRoot: parent.StateRoot, GasLimit: 30_000_000,
			BaseFeePerGas:    types.Uint256FromUint64(1_000_000_000),
			ValidatorSetHash: types.Hash{0xab},
		},
		Transactions: []*chain.Transaction{tx},
	}
	blk.Header.TxRoot = blk.ComputeTxRoot()
	blk.Header.ReceiptRoot = chain.ComputeReceiptRoot(nil)
	return blk
}

// call 发起一个 RPC 调用并返回原始响应 JSON。
func (e *testEnv) call(t *testing.T, method string, params ...any) map[string]any {
	t.Helper()

	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
		"id":      1,
	}
	raw, _ := json.Marshal(reqBody)

	resp, err := http.Post(e.baseURL, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("HTTP 请求失败: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("解析响应失败: %v\n响应: %s", err, string(body))
	}
	return out
}

// ============================================================================
// 协议层
// ============================================================================

// TestEncodeUint64 验证 quantity 编码。
func TestEncodeUint64(t *testing.T) {
	cases := []struct {
		v    uint64
		want string
	}{
		{0, "0x0"},
		{1, "0x1"},
		{15, "0xf"},
		{16, "0x10"},
		{1024, "0x400"},
		{10086, "0x2766"},
		{1<<63 + 1, "0x8000000000000001"},
	}
	for _, tc := range cases {
		if got := rpc.EncodeUint64(tc.v); got != tc.want {
			t.Errorf("EncodeUint64(%d) = %s, want %s", tc.v, got, tc.want)
		}
	}
}

// TestEncodeUint256 验证 256 位整数的 quantity 编码（去前导零）。
func TestEncodeUint256(t *testing.T) {
	// 0
	if got := rpc.EncodeUint256(types.ZeroUint256()); got != "0x0" {
		t.Errorf("零应编码为 0x0，实际 %s", got)
	}
	// 1
	if got := rpc.EncodeUint256(types.Uint256FromUint64(1)); got != "0x1" {
		t.Errorf("1 应编码为 0x1，实际 %s", got)
	}
	// 1 ETH = 10^18
	oneETH := types.Uint256FromUint64(1_000_000_000_000_000_000)
	if got := rpc.EncodeUint256(oneETH); got != "0xde0b6b3a7640000" {
		t.Errorf("1 ETH 编码错误: %s", got)
	}
}

// TestEncodeDecodeRoundTrip 验证编解码往返。
func TestEncodeDecodeRoundTrip(t *testing.T) {
	for _, v := range []uint64{0, 1, 255, 65536, 1 << 40, 1<<64 - 1} {
		enc := rpc.EncodeUint64(v)
		raw, _ := json.Marshal(enc)
		got, err := rpc.DecodeUint64(raw)
		if err != nil {
			t.Fatalf("解码 %s 失败: %v", enc, err)
		}
		if got != v {
			t.Errorf("往返不一致: %d → %s → %d", v, enc, got)
		}
	}
}

// TestDecodeUint64_AcceptsMultipleForms 验证参数的宽容解析。
func TestDecodeUint64_AcceptsMultipleForms(t *testing.T) {
	cases := []struct {
		input string
		want  uint64
	}{
		{`"0x0"`, 0},
		{`"0x1"`, 1},
		{`"0x2766"`, 10086},
		{`"10086"`, 10086},
		{`10086`, 10086},
		{`0`, 0},
	}
	for _, tc := range cases {
		got, err := rpc.DecodeUint64(json.RawMessage(tc.input))
		if err != nil {
			t.Errorf("解析 %s 失败: %v", tc.input, err)
			continue
		}
		if got != tc.want {
			t.Errorf("解析 %s = %d, want %d", tc.input, got, tc.want)
		}
	}
}

// TestParseParams 验证位置参数与命名参数。
func TestParseParams(t *testing.T) {
	// 位置参数
	got, err := rpc.ParseParams(json.RawMessage(`["0x1","latest"]`))
	if err != nil || len(got) != 2 {
		t.Fatalf("解析位置参数失败: %v, %d 个", err, len(got))
	}

	// 命名参数（按 key 排序）
	got, err = rpc.ParseParams(json.RawMessage(`{"b":"2","a":"1"}`))
	if err != nil || len(got) != 2 {
		t.Fatalf("解析命名参数失败: %v", err)
	}

	// null
	got, err = rpc.ParseParams(json.RawMessage(`null`))
	if err != nil || got != nil {
		t.Fatalf("null 应解析为 nil: %v", err)
	}
}

// ============================================================================
// 方法调用
// ============================================================================

// TestEthChainId 验证 eth_chainId。
func TestEthChainId(t *testing.T) {
	env := newTestEnv(t)
	resp := env.call(t, "eth_chainId")

	if resp["error"] != nil {
		t.Fatalf("调用失败: %v", resp["error"])
	}
	if resp["result"] != "0x2766" { // 10086
		t.Fatalf("chainId 应为 0x2766，实际 %v", resp["result"])
	}
}

// TestEthBlockNumber 验证 eth_blockNumber。
func TestEthBlockNumber(t *testing.T) {
	env := newTestEnv(t)
	resp := env.call(t, "eth_blockNumber")

	if resp["result"] != "0x1" {
		t.Fatalf("区块高度应为 0x1，实际 %v", resp["result"])
	}
}

// TestEthGetBlockByNumber 验证区块查询与字段完整性。
func TestEthGetBlockByNumber(t *testing.T) {
	env := newTestEnv(t)

	t.Run("by_number", func(t *testing.T) {
		resp := env.call(t, "eth_getBlockByNumber", "0x1", false)
		if resp["error"] != nil {
			t.Fatalf("调用失败: %v", resp["error"])
		}
		blk, ok := resp["result"].(map[string]any)
		if !ok {
			t.Fatalf("结果应为对象，实际 %T", resp["result"])
		}

		// 以太坊兼容字段必须存在
		for _, field := range []string{
			"number", "hash", "parentHash", "stateRoot", "transactionsRoot",
			"receiptsRoot", "logsBloom", "gasLimit", "gasUsed", "timestamp",
			"miner", "transactions", "baseFeePerGas",
		} {
			if _, ok := blk[field]; !ok {
				t.Errorf("缺少以太坊兼容字段: %s", field)
			}
		}

		// 默认返回交易哈希列表
		txs, ok := blk["transactions"].([]any)
		if !ok || len(txs) != 1 {
			t.Fatalf("应有 1 笔交易，实际 %v", blk["transactions"])
		}
		if _, isString := txs[0].(string); !isString {
			t.Errorf("false 参数时应返回交易哈希字符串，实际 %T", txs[0])
		}
	})

	t.Run("latest_tag", func(t *testing.T) {
		resp := env.call(t, "eth_getBlockByNumber", "latest", false)
		blk := resp["result"].(map[string]any)
		if blk["number"] != "0x1" {
			t.Fatalf("latest 应返回高度 1，实际 %v", blk["number"])
		}
	})

	t.Run("full_transactions", func(t *testing.T) {
		resp := env.call(t, "eth_getBlockByNumber", "0x1", true)
		blk := resp["result"].(map[string]any)
		txs := blk["transactions"].([]any)
		tx, ok := txs[0].(map[string]any)
		if !ok {
			t.Fatalf("true 参数时应返回完整交易对象，实际 %T", txs[0])
		}
		for _, field := range []string{
			"hash", "nonce", "from", "to", "value", "gas",
			"maxFeePerGas", "maxPriorityFeePerGas", "v", "r", "s",
		} {
			if _, ok := tx[field]; !ok {
				t.Errorf("交易缺少字段: %s", field)
			}
		}
	})
}

// TestAllQuantitiesAreStrings 验证所有数值字段都是十六进制字符串。
//
// ⚠️ 这是关键的兼容性测试：如果返回 JSON number，
// JavaScript 客户端（所有主流 Web3 工具）在数值 > 2^53 时会丢精度。
func TestAllQuantitiesAreStrings(t *testing.T) {
	env := newTestEnv(t)
	resp := env.call(t, "eth_getBlockByNumber", "0x1", true)
	blk := resp["result"].(map[string]any)

	// 这些必须是字符串
	stringFields := []string{
		"number", "gasLimit", "gasUsed", "timestamp",
		"baseFeePerGas", "difficulty", "chainId", "round",
	}
	for _, f := range stringFields {
		if _, ok := blk[f].(string); !ok {
			t.Errorf("字段 %s 必须是字符串，实际 %T (%v)", f, blk[f], blk[f])
		}
	}

	// 交易中的数值字段
	txs := blk["transactions"].([]any)
	tx := txs[0].(map[string]any)
	for _, f := range []string{"nonce", "value", "gas", "maxFeePerGas", "chainId"} {
		if _, ok := tx[f].(string); !ok {
			t.Errorf("交易字段 %s 必须是字符串，实际 %T", f, tx[f])
		}
	}
}

// TestEthGetBlockByHash 验证按哈希查询。
func TestEthGetBlockByHash(t *testing.T) {
	env := newTestEnv(t)

	// 先拿到区块哈希
	resp := env.call(t, "eth_getBlockByNumber", "0x1", false)
	blk := resp["result"].(map[string]any)
	blockHash := blk["hash"].(string)

	// 按哈希查
	resp = env.call(t, "eth_getBlockByHash", blockHash, false)
	if resp["error"] != nil {
		t.Fatalf("调用失败: %v", resp["error"])
	}
	got := resp["result"].(map[string]any)
	if got["hash"] != blockHash {
		t.Fatalf("哈希不匹配: %v vs %v", got["hash"], blockHash)
	}

	// 不存在的哈希 → null（不是错误）
	resp = env.call(t, "eth_getBlockByHash",
		"0x0000000000000000000000000000000000000000000000000000000000000099", false)
	if resp["error"] != nil {
		t.Fatalf("不存在的区块不应报错: %v", resp["error"])
	}
	if resp["result"] != nil {
		t.Fatalf("不存在的区块应返回 null，实际 %v", resp["result"])
	}
}

// TestEthGetTransactionByHash 验证交易查询。
func TestEthGetTransactionByHash(t *testing.T) {
	env := newTestEnv(t)

	// 从区块里取一笔交易的哈希
	resp := env.call(t, "eth_getBlockByNumber", "0x1", true)
	blk := resp["result"].(map[string]any)
	txHash := blk["transactions"].([]any)[0].(map[string]any)["hash"].(string)

	// 查询
	resp = env.call(t, "eth_getTransactionByHash", txHash)
	if resp["error"] != nil {
		t.Fatalf("调用失败: %v", resp["error"])
	}
	tx, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("应返回交易对象，实际 %v", resp["result"])
	}
	if tx["hash"] != txHash {
		t.Fatalf("哈希不匹配")
	}
	if tx["blockNumber"] != "0x1" {
		t.Fatalf("blockNumber 应为 0x1，实际 %v", tx["blockNumber"])
	}
}

// TestNetAndWeb3 验证辅助命名空间。
func TestNetAndWeb3(t *testing.T) {
	env := newTestEnv(t)

	resp := env.call(t, "net_version")
	if resp["result"] != "10086" {
		t.Errorf("net_version 应为 10086，实际 %v", resp["result"])
	}

	resp = env.call(t, "web3_clientVersion")
	if !strings.HasPrefix(resp["result"].(string), "chfault/") {
		t.Errorf("clientVersion 格式错误: %v", resp["result"])
	}
}

// TestChfaultStatus 验证链特有方法。
func TestChfaultStatus(t *testing.T) {
	env := newTestEnv(t)
	resp := env.call(t, "chfault_status")

	if resp["error"] != nil {
		t.Fatalf("调用失败: %v", resp["error"])
	}
	st := resp["result"].(map[string]any)
	for _, f := range []string{"chainId", "height", "blockHash", "stateRoot", "clientVersion"} {
		if _, ok := st[f]; !ok {
			t.Errorf("chfault_status 缺少字段: %s", f)
		}
	}
	if st["initialized"] != true {
		t.Errorf("initialized 应为 true")
	}
}

// ============================================================================
// 错误处理
// ============================================================================

// TestMethodNotFound 验证未知方法返回 -32601。
func TestMethodNotFound(t *testing.T) {
	env := newTestEnv(t)
	resp := env.call(t, "eth_thisDoesNotExist")

	errObj, ok := resp["error"].(map[string]any)
	if !ok {
		t.Fatalf("应返回错误对象，实际 %v", resp)
	}
	code := int(errObj["code"].(float64))
	if code != rpc.CodeMethodNotFound {
		t.Fatalf("错误码应为 %d，实际 %d", rpc.CodeMethodNotFound, code)
	}
}

// TestInvalidParams 验证参数错误返回 -32602。
func TestInvalidParams(t *testing.T) {
	env := newTestEnv(t)

	// 缺少必需参数
	resp := env.call(t, "eth_getTransactionByHash")
	errObj, ok := resp["error"].(map[string]any)
	if !ok {
		t.Fatalf("应返回错误，实际 %v", resp)
	}
	if int(errObj["code"].(float64)) != rpc.CodeInvalidParams {
		t.Fatalf("错误码应为 %d，实际 %v", rpc.CodeInvalidParams, errObj["code"])
	}
}

// TestTooManyParams 验证参数过多被拒绝。
func TestTooManyParams(t *testing.T) {
	env := newTestEnv(t)
	resp := env.call(t, "eth_chainId", "extra1", "extra2", "extra3")

	if _, ok := resp["error"].(map[string]any); !ok {
		t.Fatalf("参数过多应报错，实际 %v", resp)
	}
}

// TestParseError 验证非法 JSON 返回 -32700。
func TestParseError(t *testing.T) {
	env := newTestEnv(t)

	resp, err := http.Post(env.baseURL, "application/json", strings.NewReader("{invalid json"))
	if err != nil {
		t.Fatalf("HTTP 请求失败: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("响应不是合法 JSON: %s", string(body))
	}
	errObj, ok := out["error"].(map[string]any)
	if !ok {
		t.Fatalf("应返回错误对象: %v", out)
	}
	if int(errObj["code"].(float64)) != rpc.CodeParseError {
		t.Fatalf("错误码应为 %d，实际 %v", rpc.CodeParseError, errObj["code"])
	}
}

// ============================================================================
// 批处理与 HTTP
// ============================================================================

// TestBatchRequest 验证批量请求。
func TestBatchRequest(t *testing.T) {
	env := newTestEnv(t)

	batch := `[
		{"jsonrpc":"2.0","method":"eth_chainId","id":1},
		{"jsonrpc":"2.0","method":"eth_blockNumber","id":2},
		{"jsonrpc":"2.0","method":"web3_clientVersion","id":3}
	]`

	resp, err := http.Post(env.baseURL, "application/json", strings.NewReader(batch))
	if err != nil {
		t.Fatalf("HTTP 请求失败: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	var out []map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("解析批量响应失败: %s", string(body))
	}
	if len(out) != 3 {
		t.Fatalf("应有 3 个响应，实际 %d", len(out))
	}

	// id 必须正确对应
	seen := map[float64]bool{}
	for _, r := range out {
		seen[r["id"].(float64)] = true
	}
	for _, id := range []float64{1, 2, 3} {
		if !seen[id] {
			t.Errorf("缺少 id=%v 的响应", id)
		}
	}
}

// TestBatchTooLarge 验证批量上限。
func TestBatchTooLarge(t *testing.T) {
	env := newTestEnv(t)

	var sb strings.Builder
	sb.WriteString("[")
	for i := 0; i < 20; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, `{"jsonrpc":"2.0","method":"eth_chainId","id":%d}`, i)
	}
	sb.WriteString("]")

	resp, err := http.Post(env.baseURL, "application/json", strings.NewReader(sb.String()))
	if err != nil {
		t.Fatalf("HTTP 请求失败: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "limit") && !strings.Contains(string(body), "上限") {
		t.Fatalf("超批量上限应被拒绝，实际: %s", string(body))
	}
}

// TestHealthEndpoint 验证健康检查。
func TestHealthEndpoint(t *testing.T) {
	env := newTestEnv(t)

	resp, err := http.Get(env.baseURL + "/health")
	if err != nil {
		t.Fatalf("HTTP 请求失败: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(body, &out)
	if out["status"] != "ok" {
		t.Fatalf("健康检查应返回 ok: %s", string(body))
	}
	if n, ok := out["methods"].(float64); !ok || n < 8 {
		t.Errorf("应注册至少 8 个方法，实际 %v", out["methods"])
	}
}

// TestGetMethodNotAllowed 验证 GET 请求被拒绝。
func TestGetMethodNotAllowed(t *testing.T) {
	env := newTestEnv(t)
	resp, err := http.Get(env.baseURL + "/")
	if err != nil {
		t.Fatalf("HTTP 请求失败: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("应返回 405，实际 %d", resp.StatusCode)
	}
}

// ============================================================================
// 注册表
// ============================================================================

// TestRegistry 验证方法注册表。
func TestRegistry(t *testing.T) {
	reg := rpc.NewRegistry()
	reg.Register(&rpc.MethodSpec{
		Name: "eth_test", MaxParams: 0,
		Handler: func(_ context.Context, _ []json.RawMessage) (any, *rpc.Error) {
			return "ok", nil
		},
	})

	if _, ok := reg.Lookup("eth_test"); !ok {
		t.Fatal("应能查到已注册的方法")
	}
	if _, ok := reg.Lookup("eth_missing"); ok {
		t.Fatal("不应查到未注册的方法")
	}
	if reg.Count() != 1 {
		t.Fatalf("应有 1 个方法，实际 %d", reg.Count())
	}
	if ns := reg.MethodsIn("eth"); len(ns) != 1 || ns[0] != "eth_test" {
		t.Fatalf("命名空间查询错误: %v", ns)
	}
}

// TestRegistryRejectsBadNames 验证非法方法名在注册时即失败。
//
// 配置错误应该在启动时暴露，而不是等请求打进来。
func TestRegistryRejectsBadNames(t *testing.T) {
	cases := []struct {
		name string
		spec *rpc.MethodSpec
	}{
		{"无下划线", &rpc.MethodSpec{Name: "nodash", Handler: noopHandler}},
		{"空名", &rpc.MethodSpec{Name: "", Handler: noopHandler}},
		{"无处理器", &rpc.MethodSpec{Name: "eth_nohandler"}},
		{"下划线开头", &rpc.MethodSpec{Name: "_bad", Handler: noopHandler}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("应在注册时 panic")
				}
			}()
			rpc.NewRegistry().Register(tc.spec)
		})
	}
}

func noopHandler(_ context.Context, _ []json.RawMessage) (any, *rpc.Error) {
	return nil, nil
}

// TestRegistryRejectsDuplicate 验证重复注册被拒绝。
func TestRegistryRejectsDuplicate(t *testing.T) {
	reg := rpc.NewRegistry()
	spec := func() *rpc.MethodSpec {
		return &rpc.MethodSpec{Name: "eth_dup", Handler: noopHandler}
	}
	reg.Register(spec())

	defer func() {
		if recover() == nil {
			t.Fatal("重复注册应 panic")
		}
	}()
	reg.Register(spec())
}
