// Command chfault 是 chfault 的命令行入口。
//
// 当前支持的命令（M1 范围，完整命令集见 docs/blueprint/06 §6.5）：
//
//	chfault init     生成默认配置与创世文件
//	chfault start    启动节点
//	chfault version  显示版本
//
// 参数解析用标准库 flag 实现（子命令模式）；
// 后续迁移到 cobra 只替换这一层，不影响功能与命令语义。
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/chfault/chfault/chain"
	"github.com/chfault/chfault/node"
)

// Version 是客户端版本。
const Version = "0.1.0-m1"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit(os.Args[2:])
	case "start":
		err = cmdStart(os.Args[2:])
	case "snapshot":
		err = cmdSnapshot(os.Args[2:])
	case "codegen":
		err = cmdCodegen(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Printf("chfault %s\n", Version)
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "未知命令: %s\n\n", os.Args[1])
		usage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`chfault — 用 Go 写的区块链框架

用法:
  chfault <command> [flags]

命令:
  init      生成默认配置与创世文件
  start     启动节点
  snapshot  创建 / 恢复链数据快照
  codegen   生成 OpenRPC 文档
  version   显示版本

示例:
  chfault init --dir ./my-chain --chain-id 10086 --validators 4
  chfault start --config ./my-chain/chfault.config.yaml
  chfault snapshot create --data ./my-chain/data --out ./snap
  chfault codegen openrpc --out openrpc.json
`)
}

// ============================================================================
// init
// ============================================================================

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dir := fs.String("dir", "./my-chain", "输出目录")
	chainID := fs.String("chain-id", "10086", "链 ID")
	name := fs.String("name", "", "链名（默认取目录名）")
	validators := fs.Int("validators", 4, "验证者数量")
	funded := fs.String("funded", "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf", "获得初始资金的地址（Hardhat 第一个账户）")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *name == "" {
		*name = filepath.Base(*dir)
	}
	if *validators < 1 || *validators > 25 {
		return fmt.Errorf("验证者数量必须在 1–25 之间")
	}
	if _, err := chain.ParseAddress(*funded); err != nil {
		return fmt.Errorf("--funded 地址非法: %w", err)
	}

	// 创建目录
	if err := os.MkdirAll(*dir, 0o750); err != nil {
		return fmt.Errorf("创建目录失败: %w", err)
	}

	// 不覆盖已有文件（防止误操作毁掉现有链）
	cfgPath := filepath.Join(*dir, "chfault.config.yaml")
	genPath := filepath.Join(*dir, "genesis.json")
	for _, p := range []string{cfgPath, genPath} {
		if _, err := os.Stat(p); err == nil {
			return fmt.Errorf("%s 已存在，拒绝覆盖（如需重新初始化请先删除）", p)
		}
	}

	// ---- 生成创世 ----
	genesis := map[string]any{
		"chain_id":         *chainID,
		"timestamp":        fmt.Sprintf("%d", time.Now().Unix()),
		"gas_limit":        "30000000",
		"initial_base_fee": "1000000000",
		"version":          "1",
		"extra_data":       "0x",
		"alloc": map[string]any{
			// 初始资金给指定地址（1 亿 CHFT，18 位小数）
			strings.ToLower(*funded): map[string]string{
				"balance": "100000000000000000000000000",
			},
		},
		"validators": genValidators(*validators),
	}

	genBytes, err := json.MarshalIndent(genesis, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化创世失败: %w", err)
	}
	if err := os.WriteFile(genPath, genBytes, 0o600); err != nil {
		return fmt.Errorf("写入创世失败: %w", err)
	}

	// ---- 生成配置 ----
	cfg := node.DefaultConfig()
	cfg.Chain.Name = *name
	cfg.Chain.ChainID = *chainID
	cfg.Chain.Genesis = "genesis.json"
	cfg.Storage.DataDir = "./data"

	cfgBytes, err := yamlMarshal(cfg)
	if err != nil {
		return fmt.Errorf("序列化配置失败: %w", err)
	}
	if err := os.WriteFile(cfgPath, cfgBytes, 0o600); err != nil {
		return fmt.Errorf("写入配置失败: %w", err)
	}

	// ---- 验证创世可推导（fail fast：初始化时就发现问题）----
	g, err := chain.LoadGenesis(genPath)
	if err != nil {
		return fmt.Errorf("生成的创世文件校验失败: %w", err)
	}
	gHash, err := g.Hash()
	if err != nil {
		return fmt.Errorf("计算创世哈希失败: %w", err)
	}

	fmt.Printf("✅ 链已初始化\n")
	fmt.Printf("   目录:       %s\n", *dir)
	fmt.Printf("   链名:       %s\n", *name)
	fmt.Printf("   链 ID:      %s\n", *chainID)
	fmt.Printf("   验证者:     %d 个\n", *validators)
	fmt.Printf("   创世哈希:   %s\n", gHash.String())
	fmt.Printf("\n启动:\n   chfault start --config %s\n", cfgPath)
	return nil
}

// genValidators 生成 N 个占位验证者。
//
// ⚠️ 这些是开发用占位数据（地址 0x01..0xNN，公钥为重复字节）。
// 生产环境必须用真实密钥对的公钥 —— `chfault account create`（M1 后续）会提供。
func genValidators(n int) []map[string]string {
	out := make([]map[string]string, 0, n)
	for i := 0; i < n; i++ {
		addr := fmt.Sprintf("0x%040x", i+1)
		pk := fmt.Sprintf("0x02%s", repeatHex(byte(i+1), 32))
		out = append(out, map[string]string{
			"address": addr,
			"pubkey":  pk,
			"power":   "1",
			"moniker": fmt.Sprintf("validator-%d", i+1),
		})
	}
	return out
}

func repeatHex(b byte, n int) string {
	s := ""
	for i := 0; i < n; i++ {
		s += fmt.Sprintf("%02x", b)
	}
	return s
}

// ============================================================================
// start
// ============================================================================

func cmdStart(args []string) error {
	fs := flag.NewFlagSet("start", flag.ExitOnError)
	cfgPath := fs.String("config", "chfault.config.yaml", "配置文件路径")
	if err := fs.Parse(args); err != nil {
		return err
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	cfg, err := node.LoadConfig(*cfgPath)
	if err != nil {
		return err
	}

	n, err := node.New(cfg, logger)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := n.Start(ctx); err != nil {
		return err
	}

	if addr := n.RPCAddr(); addr != "" {
		fmt.Printf("✅ 节点运行中\n   RPC: http://%s\n   按 Ctrl+C 停止\n", addr)
	}

	// 等待中断信号
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	fmt.Println("\n正在停止...")
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer stopCancel()
	return n.Stop(stopCtx)
}

// ============================================================================
// 辅助
// ============================================================================

// yamlMarshal 序列化为 YAML。
//
// 独立函数是为了集中管理序列化选项（缩进、字段顺序等）。
func yamlMarshal(v any) ([]byte, error) {
	// 用 JSON→map→YAML 的方式保证字段顺序稳定：
	// yaml.Marshal 对 struct 按字段声明顺序输出，已经足够稳定。
	return yamlMarshalImpl(v)
}
