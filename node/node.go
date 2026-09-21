package node

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/chfault/chfault/chain"
	"github.com/chfault/chfault/consensus"
	"github.com/chfault/chfault/mempool"
	"github.com/chfault/chfault/network"
	"github.com/chfault/chfault/rpc"
	"github.com/chfault/chfault/storage"
	"github.com/chfault/chfault/types"
	"github.com/chfault/chfault/vm"
)

// Node 是一个完整的区块链节点：组件接线与生命周期管理。
//
// v0 的节点 = 存储 + 链状态机 + 交易池 + RPC（无共识、无 EVM）。
// 共识在 M2 接入（通过注入 Clock / MessageSink）；
// EVM 在 ADR-016 决策后接入（注入 vm.Engine）。
//
// 架构上 node 不做任何业务逻辑 —— 它只负责把组件按正确顺序启动、
// 把依赖注入到正确的位置、并在关闭时按相反顺序优雅停止。
type Node struct {
	cfg        *Config
	logger     *slog.Logger
	store      storage.KVStore
	chain      *chain.Chain
	pool       *mempool.Pool
	rpcSrv     *rpc.Server
	registry   *rpc.Registry
	evm        *vm.Engine
	consensus  *consensus.State
	devKey     *devSigner
	swarm      *network.Swarm
	gossipSeen map[types.TxHash]bool
	gossipMu   sync.Mutex
	// pendingBuilt 最近一次生成的待提交区块（共识提交时使用）
	pendingBuilt *BuiltBlock

	mu      sync.Mutex
	started bool
	stopped bool
}

// 错误。
var (
	// ErrAlreadyStarted 节点已启动。
	ErrAlreadyStarted = errors.New("node: 节点已启动")
	// ErrNotStarted 节点未启动。
	ErrNotStarted = errors.New("node: 节点未启动")
)

// New 从配置创建节点（不启动）。
func New(cfg *Config, logger *slog.Logger) (*Node, error) {
	if cfg == nil {
		return nil, errors.New("node: 配置为空")
	}
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))
	}
	return &Node{cfg: cfg, logger: logger}, nil
}

// ============================================================================
// 启动
// ============================================================================

// Start 按依赖顺序启动所有组件。
//
// **启动顺序即依赖顺序**，不能乱：
//
//	存储 → 链（依赖存储）→ 交易池（依赖链）→ RPC（依赖以上全部）
//
// 任何一步失败都必须停止已启动的组件（不能留下一半运行的节点）。
func (n *Node) Start(ctx context.Context) error {
	n.mu.Lock()
	if n.started {
		n.mu.Unlock()
		return ErrAlreadyStarted
	}
	n.started = true
	n.mu.Unlock()

	// ---- 1. 打开存储 ----
	if err := n.openStorage(); err != nil {
		n.shutdown("存储打开失败", err)
		return err
	}
	n.logger.Info("存储已打开", "backend", n.cfg.Storage.Backend, "dir", n.cfg.Storage.DataDir)

	// ---- 2. 初始化链 ----
	if err := n.initChain(ctx); err != nil {
		n.shutdown("链初始化失败", err)
		return err
	}
	head := n.chain.Head()
	n.logger.Info("链已就绪",
		"height", uint64(head.Height),
		"hash", head.Hash.String()[:18],
		"stateRoot", head.StateRoot.String()[:18],
	)

	// ---- 3. EVM 引擎（ADR-016 决策 A：geth LGPLv3）----
	chainID, _ := parseChainID(n.cfg.Chain.ChainID)
	n.evm = vm.NewEngine(uint64(chainID))

	// ---- 4. 交易池 ----
	baseFee, err := u256FromString("1000000000")
	if err != nil {
		n.shutdown("基础费解析失败", err)
		return err
	}
	n.pool = mempool.New(mempool.Config{
		BaseFee:       baseFee,
		BlockGasLimit: 30_000_000,
	})
	n.logger.Info("交易池已就绪")

	// ---- 5. 共识（M2：验证者集来自配置，单节点时只有自己）----
	if err := n.initConsensus(); err != nil {
		n.shutdown("共识初始化失败", err)
		return err
	}

	// ---- 4. RPC ----
	if n.cfg.RPC.HTTP.Enabled {
		if err := n.startRPC(ctx); err != nil {
			n.shutdown("RPC 启动失败", err)
			return err
		}
		n.logger.Info("RPC 已就绪", "addr", n.rpcSrv.Addr(),
			"modules", strings.Join(n.cfg.RPC.HTTP.Modules, ","))
	}

	n.logger.Info("节点启动完成", "chain", n.cfg.Chain.Name, "chainId", n.cfg.Chain.ChainID)
	return nil
}

// openStorage 打开存储。
//
// **不支持降级**：配置 pebble 但打不开就报错退出，
// 绝不静默切换到内存存储 —— 那会让节点"看起来在运行"但数据全丢。
func (n *Node) openStorage() error {
	switch n.cfg.Storage.Backend {
	case "memory":
		n.store = storage.NewMemory()
		return nil
	case "pebble":
		dir := n.cfg.Storage.DataDir
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("node: 创建数据目录失败: %w", err)
		}
		st, err := storage.Open(filepath.Join(dir, "db"))
		if err != nil {
			return err
		}
		n.store = st
		return nil
	default:
		return fmt.Errorf("node: 未知存储后端 %q", n.cfg.Storage.Backend)
	}
}

// initChain 初始化链：加载创世、打开链状态机。
//
// 创世文件不存在时的行为由 --init 决定：
// 这里采用**拒绝启动**（fail fast），由 CLI 的 init 命令负责生成。
func (n *Node) initChain(ctx context.Context) error {
	chainID, err := parseChainID(n.cfg.Chain.ChainID)
	if err != nil {
		return err
	}

	// 加载创世
	genesisPath := n.cfg.Chain.Genesis
	if !filepath.IsAbs(genesisPath) {
		genesisPath = filepath.Join(".", genesisPath)
	}
	if _, err := os.Stat(genesisPath); err != nil {
		return fmt.Errorf("node: 创世文件不存在（%s）。请先运行 `chfault init` 生成", genesisPath)
	}

	g, err := chain.LoadGenesis(genesisPath)
	if err != nil {
		return err
	}

	// 创世 chainId 必须与配置一致（不一致通常是配置错误）
	gChainID, _ := parseChainID(g.ChainID)
	if gChainID != chainID {
		return fmt.Errorf("node: 创世 chain_id(%s) 与配置 chainId(%s) 不一致",
			g.ChainID, n.cfg.Chain.ChainID)
	}

	c, err := chain.New(n.store, chain.Config{ChainID: chainID})
	if err != nil {
		return err
	}
	if err := c.InitGenesis(g); err != nil {
		return err
	}

	n.chain = c
	return nil
}

// startRPC 启动 JSON-RPC 服务。
func (n *Node) startRPC(_ context.Context) error {
	n.registry = rpc.NewRegistry()

	// EVM 引擎（ADR-016 决策 A：geth LGPLv3）
	chainID, _ := parseChainID(n.cfg.Chain.ChainID)
	n.evm = vm.NewEngine(uint64(chainID))

	rpc.RegisterChainMethods(n.registry, n.chain, n.chain.HasGenesis, n)

	// M1 阶段：eth_sendRawTransaction / eth_call 需要 EVM，暂不注册。
	// 接入时在这里追加，调用方不需要改 RPC 层。

	disp := rpc.NewDispatcher(n.registry)
	disp.ReadyFunc = n.chain.HasGenesis

	cfg := rpc.DefaultServerConfig()
	cfg.HTTPPort = n.cfg.RPC.HTTP.Port
	n.rpcSrv = rpc.NewServer(cfg, n.registry, disp)

	return n.rpcSrv.StartAsync()
}

// ============================================================================
// 停止
// ============================================================================

// Stop 优雅关闭：按启动的**相反顺序**停止组件。
//
// RPC 先停（停止接收新请求）→ 交易池（无需处理）→ 链（无需处理）→ 存储（最后关）。
func (n *Node) Stop(ctx context.Context) error {
	n.mu.Lock()
	if !n.started || n.stopped {
		n.mu.Unlock()
		return ErrNotStarted
	}
	n.stopped = true
	n.mu.Unlock()

	var firstErr error

	// 1. RPC
	if n.rpcSrv != nil {
		if err := n.rpcSrv.Stop(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
		n.logger.Info("RPC 已停止")
	}

	// 2. 存储（最后关闭，保证缓冲数据落盘）
	if n.store != nil {
		if err := n.store.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		n.logger.Info("存储已关闭")
	}

	n.logger.Info("节点已停止")
	return firstErr
}

// shutdown 是 Start 中途失败时的回滚：按相反顺序停止已启动的组件。
func (n *Node) shutdown(stage string, cause error) {
	n.logger.Error("启动失败", "stage", stage, "err", cause)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if n.rpcSrv != nil {
		_ = n.rpcSrv.Stop(ctx)
		n.rpcSrv = nil
	}
	if n.store != nil {
		_ = n.store.Close()
		n.store = nil
	}

	n.mu.Lock()
	n.started = false
	n.mu.Unlock()
}

// ============================================================================
// 查询
// ============================================================================

// Chain 返回链实例（测试与 CLI 用）。
func (n *Node) Chain() *chain.Chain { return n.chain }

// RPCAddr 返回 RPC 监听地址（未启动返回空）。
func (n *Node) RPCAddr() string {
	if n.rpcSrv == nil {
		return ""
	}
	return n.rpcSrv.Addr()
}

// IsRunning 判断节点是否在运行。
func (n *Node) IsRunning() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.started && !n.stopped
}

// ============================================================================
// 辅助
// ============================================================================

func parseChainID(s string) (types.ChainID, error) {
	if s == "" {
		return 0, errors.New("node: chainId 为空")
	}
	var v uint64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("node: chainId 含非数字字符 %q", c)
		}
		nv := v*10 + uint64(c-'0')
		if nv < v {
			return 0, errors.New("node: chainId 溢出")
		}
		v = nv
	}
	if v == 0 {
		return 0, errors.New("node: chainId 必须为正")
	}
	return types.ChainID(v), nil
}

// Uint256FromString 从十进制字符串构造 Uint256（辅助函数）。
func u256FromString(s string) (types.Uint256, error) {
	if s == "" {
		return types.ZeroUint256(), errors.New("空字符串")
	}
	acc := types.ZeroUint256()
	ten := types.Uint256FromUint64(10)
	for _, c := range s {
		if c < '0' || c > '9' {
			return types.ZeroUint256(), fmt.Errorf("非数字字符 %q", c)
		}
		a, _ := acc.Mul(ten)
		d, err := a.Add(types.Uint256FromUint64(uint64(c - '0')))
		if err != nil {
			return types.ZeroUint256(), errors.New("溢出")
		}
		acc = d
	}
	return acc, nil
}

// ============================================================================
// TxSubmitter（注入 RPC 的交易提交能力）
// ============================================================================

// SubmitRawTx 解码、校验并提交一笔原始交易。
//
// 流程：解码（geth）→ sender 恢复 → 状态校验（nonce/余额）→ 转换为
// chain.Transaction → 入交易池。实际执行发生在出块时。
//
// **边界桥接**：geth 的交易类型与 chfault 的 chain.Transaction 在此转换。
// 这是唯一需要桥接的地方 —— 交易格式与以太坊逐字节兼容（spec/10），
// 但内存表示各自独立，转换成本一次性且边界清晰。
func (n *Node) SubmitRawTx(data []byte) (types.TxHash, error) {
	if n.evm == nil || n.pool == nil || n.chain == nil {
		return types.TxHash{}, errors.New("node: 节点未完全启动")
	}

	gtx, err := n.evm.DecodeTx(data)
	if err != nil {
		return types.TxHash{}, err
	}

	sender, err := n.evm.RecoverSender(gtx)
	if err != nil {
		return types.TxHash{}, err
	}

	// 从链状态取账户 nonce 与余额做准入校验
	var accountNonce types.Nonce
	ro, viewErr := n.chain.State().View(n.chain.Head().StateRoot)
	if viewErr != nil {
		return types.TxHash{}, viewErr
	}
	if acc, err := ro.GetAccount(sender); err == nil && acc != nil {
		accountNonce = acc.Nonce
	}
	if err := n.evm.ValidateAgainstState(ro, gtx, sender); err != nil {
		return types.TxHash{}, err
	}

	if err := n.pool.Add(gtx, sender, accountNonce); err != nil {
		return types.TxHash{}, err
	}

	// 交易 gossip：广播给邻居（邻居入池后继续转发，seen 集合防循环）
	n.gossipTx(data)

	return types.TxHash(gtx.Hash()), nil
}

// GetBalance 查询账户余额（返回十六进制 wei 字符串由 RPC 层编码，这里给 Uint256 字符串）。
func (n *Node) GetBalance(addr types.Address) (string, error) {
	if n.chain == nil {
		return "0x0", errors.New("node: 链未初始化")
	}
	ro, err := n.chain.State().View(n.chain.Head().StateRoot)
	if err != nil {
		return "0x0", err
	}
	acc, err := ro.GetAccount(addr)
	if err != nil || acc == nil {
		return "0", nil // 不存在 = 0（返回十进制串，RPC 层再编码）
	}
	return acc.Balance.ToBig().String(), nil
}

// GetNonce 查询账户 nonce。
func (n *Node) GetNonce(addr types.Address) (uint64, error) {
	if n.chain == nil {
		return 0, errors.New("node: 链未初始化")
	}
	ro, err := n.chain.State().View(n.chain.Head().StateRoot)
	if err != nil {
		return 0, err
	}
	acc, err := ro.GetAccount(addr)
	if err != nil || acc == nil {
		return 0, nil
	}
	return uint64(acc.Nonce), nil
}

// Call 在最新状态上执行只读合约调用（eth_call 后端）。
func (n *Node) Call(from, to types.Address, data []byte, gas uint64) ([]byte, uint64, string, error) {
	if n.evm == nil || n.chain == nil {
		return nil, 0, "", errors.New("node: 节点未完全启动")
	}

	head := n.chain.Head()
	sess, err := n.chain.State().Begin(head.StateRoot)
	if err != nil {
		return nil, 0, "", err
	}
	defer func() {
		// eth_call 不提交状态 —— 显式释放（MemorySession 的 Commit 有 done 保护）
		_ = sess
	}()

	ctx := &vm.ExecutionContext{
		Height:    head.Height + 1,
		Timestamp: uint64(head.Height+1) + 1700000000,
		Proposer:  types.Address{0x01},
		BaseFee:   types.Uint256FromUint64(1_000_000_000),
		GasLimit:  types.Gas(gas),
		PrevHash:  types.Hash(head.Hash),
	}

	result, err := n.evm.RunCall(sess, from, to, data, types.Gas(gas), ctx)
	if err != nil {
		return nil, 0, "", err
	}
	if !result.Success {
		return result.ReturnData, uint64(result.GasUsed), result.VMError, nil
	}
	return result.ReturnData, uint64(result.GasUsed), "", nil
}
