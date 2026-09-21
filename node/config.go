// Package node 把 chain / mempool / rpc 等组件组装成一个可运行的节点。
//
// 职责边界：
//   - node 负责**接线与生命周期**（启动顺序、依赖注入、优雅关闭）
//   - 各组件只暴露自己的能力，不感知其他组件的存在
//
// 启动流程（docs/blueprint/02 §2.8）：
//
//	加载配置 → 打开存储 → 初始化链 → 启动 RPC → 就绪
package node

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config 是节点的完整配置（对应 chfault.config.yaml）。
//
// 全部字段都有默认值：最小配置只需 chain.name。
// "零配置启动 = 提供合理默认值，不是没有配置"（docs/blueprint/02 §2.6）。
type Config struct {
	Chain     ChainConfig     `yaml:"chain"`
	Consensus ConsensusConfig `yaml:"consensus"`
	Execution ExecutionConfig `yaml:"execution"`
	Storage   StorageConfig   `yaml:"storage"`
	Network   NetworkConfig   `yaml:"network"`
	RPC       RPCConfig       `yaml:"rpc"`
}

// ChainConfig 链配置。
type ChainConfig struct {
	// Name 链名（用于数据目录与日志）。
	Name string `yaml:"name"`
	// ChainID 链标识。
	ChainID string `yaml:"chainId"`
	// NetworkType consortium | private（v2 增加 public）。
	NetworkType string `yaml:"networkType"`
	// Genesis 创世文件路径。
	Genesis string `yaml:"genesis"`
}

// ConsensusConfig 共识配置。
type ConsensusConfig struct {
	// Protocol 目前只有 tendermint-bft。
	Protocol string `yaml:"protocol"`
	// ValidatorSet poa | pos（v2）。这是公链切换点（ADR-015 预留点 1）。
	ValidatorSet string `yaml:"validatorSet"`
	// BlockTimeMs 目标出块间隔。
	BlockTimeMs int `yaml:"blockTimeMs"`
	// TimeoutProposeMs 等待提议的超时。
	TimeoutProposeMs int `yaml:"timeoutProposeMs"`
	// TimeoutPrevoteMs / TimeoutPrecommitMs 投票阶段的等待余量。
	TimeoutPrevoteMs   int `yaml:"timeoutPrevoteMs"`
	TimeoutPrecommitMs int `yaml:"timeoutPrecommitMs"`
	// DeltaIncrementMs 每轮递增。
	DeltaIncrementMs int `yaml:"deltaIncrementMs"`
	// EpochLength 验证者集变更周期（区块数）。
	EpochLength int `yaml:"epochLength"`
	// MaxValidators 验证者数量上限（v2 pos 模式放宽）。
	MaxValidators int `yaml:"maxValidators"`
	// Validators 验证者地址列表（0x 前缀）。
	// 空 = 单节点模式（验证者集只有自己）。
	// 多节点时**所有节点的这份列表必须完全一致** —— 与创世哈希同等对待。
	Validators []string `yaml:"validators"`
	// KeySeed 开发密钥种子（0-255）。
	// ⚠️ dev-only：生产节点必须用 keystore（M3），绝不能部署带种子的配置。
	KeySeed int `yaml:"keySeed"`
}

// ExecutionConfig 执行配置。
type ExecutionConfig struct {
	// Engine evm | wasm（M4）。
	Engine string `yaml:"engine"`
	// BlockGasLimit 单区块 gas 上限。
	BlockGasLimit string `yaml:"blockGasLimit"`
}

// StorageConfig 存储配置。
type StorageConfig struct {
	// DataDir 数据目录。
	DataDir string `yaml:"dataDir"`
	// Backend pebble | memory（测试用）。
	Backend string `yaml:"backend"`
}

// NetworkConfig 网络配置。
type NetworkConfig struct {
	Listen            []string `yaml:"listen"`
	Bootstrap         []string `yaml:"bootstrap"`
	PrivateNetworkPSK string   `yaml:"privateNetworkPSK"`
	MaxPeers          int      `yaml:"maxPeers"`
	// EnableDHT 无许可发现（v2 公链路径的开关，v0 固定 false）。
	EnableDHT bool `yaml:"enableDHT"`
}

// RPCConfig RPC 服务配置。
type RPCConfig struct {
	HTTP struct {
		Enabled bool     `yaml:"enabled"`
		Port    int      `yaml:"port"`
		Modules []string `yaml:"modules"`
	} `yaml:"http"`
	Metrics struct {
		Enabled bool `yaml:"enabled"`
		Port    int  `yaml:"port"`
	} `yaml:"metrics"`
}

// ============================================================================
// 默认值
// ============================================================================

// DefaultConfig 返回默认配置。
func DefaultConfig() *Config {
	c := &Config{}
	c.Chain.Name = "chfault-dev"
	c.Chain.ChainID = "10086"
	c.Chain.NetworkType = "consortium"
	c.Chain.Genesis = "genesis.json"

	c.Consensus.Protocol = "tendermint-bft"
	c.Consensus.ValidatorSet = "poa"
	c.Consensus.BlockTimeMs = 1000
	c.Consensus.TimeoutProposeMs = 800
	c.Consensus.TimeoutPrevoteMs = 400
	c.Consensus.TimeoutPrecommitMs = 400
	c.Consensus.DeltaIncrementMs = 200
	c.Consensus.EpochLength = 1000
	c.Consensus.MaxValidators = 25
	c.Consensus.KeySeed = 7

	c.Execution.Engine = "evm"
	c.Execution.BlockGasLimit = "30000000"

	c.Storage.DataDir = "./data"
	c.Storage.Backend = "pebble"

	c.Network.MaxPeers = 50
	c.Network.EnableDHT = false

	c.RPC.HTTP.Enabled = true
	c.RPC.HTTP.Port = 8545
	c.RPC.HTTP.Modules = []string{"eth", "net", "web3", "chfault"}

	return c
}

// ============================================================================
// 加载与校验
// ============================================================================

// LoadConfig 从 YAML 文件加载配置，缺失字段用默认值补齐。
//
// **fail fast 原则**：非法配置必须启动时失败并给出精确错误，
// 不允许"带着错配置跑起来"—— 那会产生分叉。
func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("node: 配置文件不存在: %s", path)
		}
		return nil, fmt.Errorf("node: 读取配置失败: %w", err)
	}

	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true) // 拼错的字段名应该报错，而不是被静默忽略
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("node: 解析配置失败: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Validate 校验配置。
func (c *Config) Validate() error {
	if c.Chain.Name == "" {
		return fmt.Errorf("node: chain.name 不能为空")
	}
	if c.Chain.ChainID == "" {
		return fmt.Errorf("node: chain.chainId 不能为空")
	}
	if _, err := parsePositiveInt(c.Chain.ChainID); err != nil {
		return fmt.Errorf("node: chain.chainId 非法: %w", err)
	}

	switch c.Chain.NetworkType {
	case "consortium", "private":
	default:
		return fmt.Errorf("node: chain.networkType 必须是 consortium 或 private（v0 不支持 %q）",
			c.Chain.NetworkType)
	}

	if c.Chain.Genesis == "" {
		return fmt.Errorf("node: chain.genesis 不能为空")
	}

	switch c.Consensus.Protocol {
	case "tendermint-bft":
	default:
		return fmt.Errorf("node: consensus.protocol 只支持 tendermint-bft（v0 不支持 %q）",
			c.Consensus.Protocol)
	}

	switch c.Consensus.ValidatorSet {
	case "poa":
	case "pos":
		return fmt.Errorf("node: consensus.validatorSet=pos 属于 v2 公链路径，v0 尚未实现")
	default:
		return fmt.Errorf("node: consensus.validatorSet 必须是 poa（v0），实际 %q",
			c.Consensus.ValidatorSet)
	}

	for i, v := range c.Consensus.Validators {
		if len(v) != 42 || v[:2] != "0x" {
			return fmt.Errorf("node: consensus.validators[%d] 必须是 0x 前缀的 20 字节地址，实际 %q",
				i, v)
		}
	}
	if c.Consensus.KeySeed < 0 || c.Consensus.KeySeed > 255 {
		return fmt.Errorf("node: consensus.keySeed 必须在 0-255 之间")
	}

	if c.Consensus.BlockTimeMs <= 0 {
		return fmt.Errorf("node: consensus.blockTimeMs 必须为正")
	}
	if c.Consensus.TimeoutProposeMs <= 0 {
		return fmt.Errorf("node: consensus.timeoutProposeMs 必须为正")
	}
	// 超时参数 sanity check：propose 超时应小于出块时间
	if c.Consensus.TimeoutProposeMs >= c.Consensus.BlockTimeMs {
		return fmt.Errorf("node: consensus.timeoutProposeMs(%d) 应小于 blockTimeMs(%d)",
			c.Consensus.TimeoutProposeMs, c.Consensus.BlockTimeMs)
	}

	switch c.Execution.Engine {
	case "evm":
	case "wasm":
		return fmt.Errorf("node: execution.engine=wasm 属于 M4，v0 尚未实现")
	default:
		return fmt.Errorf("node: execution.engine 只支持 evm（v0），实际 %q", c.Execution.Engine)
	}

	switch c.Storage.Backend {
	case "pebble", "memory":
	default:
		return fmt.Errorf("node: storage.backend 必须是 pebble 或 memory，实际 %q",
			c.Storage.Backend)
	}
	if c.Storage.DataDir == "" {
		return fmt.Errorf("node: storage.dataDir 不能为空")
	}

	if c.RPC.HTTP.Enabled && c.RPC.HTTP.Port == 0 {
		return fmt.Errorf("node: rpc.http.port 不能为 0")
	}

	return nil
}

// GenesisPath 返回创世文件的绝对路径（相对配置文件所在目录）。
func (c *Config) GenesisPath(configDir string) string {
	if filepath.IsAbs(c.Chain.Genesis) {
		return c.Chain.Genesis
	}
	return filepath.Join(configDir, c.Chain.Genesis)
}

// DataDirPath 返回数据目录的绝对路径。
func (c *Config) DataDirPath(configDir string) string {
	if filepath.IsAbs(c.Storage.DataDir) {
		return c.Storage.DataDir
	}
	return filepath.Join(configDir, c.Storage.DataDir)
}

func parsePositiveInt(s string) (uint64, error) {
	if s == "" {
		return 0, fmt.Errorf("空字符串")
	}
	var v uint64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("非数字字符 %q", c)
		}
		nv := v*10 + uint64(c-'0')
		if nv < v {
			return 0, fmt.Errorf("溢出")
		}
		v = nv
	}
	if v == 0 {
		return 0, fmt.Errorf("必须为正")
	}
	return v, nil
}

// WriteDefault 写出一份默认配置（`chfault init` 用）。
func WriteDefault(path string) error {
	cfg := DefaultConfig()
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("node: 序列化配置失败: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("node: 写入配置失败: %w", err)
	}
	return nil
}

// ============================================================================
// 创世相关（WriteGenesis 用）
// ============================================================================

// AllocAccount 是创世分配中的账户。
type AllocAccount struct {
	// Balance 十进制 wei 字符串。
	Balance string `json:"balance"`
	// Nonce 十进制字符串（可选）。
	Nonce string `json:"nonce,omitempty"`
	// Code 0x 前缀十六进制合约代码（可选）。
	Code string `json:"code,omitempty"`
}
