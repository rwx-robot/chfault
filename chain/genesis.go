package chain

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/chfault/chfault/crypto"
	"github.com/chfault/chfault/state"
	"github.com/chfault/chfault/types"
)

// Genesis 是链的创世配置。
//
// 关键要求（spec/20 §6）：**相同输入必须产生相同的 genesis_hash**。
// 这是多节点能组网的前提 —— 任何一个字节的差异都会导致节点间无法握手。
//
// 实现上通过"所有集合先排序再序列化"来保证：
// JSON 对象的键顺序在 Go 里不保证，但排序后遍历就与输入顺序无关。
type Genesis struct {
	// ChainID 链标识。
	ChainID string `json:"chain_id"`
	// Timestamp 创世时间戳（秒）。
	Timestamp string `json:"timestamp"`
	// GasLimit 创世区块 gas 上限。
	GasLimit string `json:"gas_limit"`
	// InitialBaseFee EIP-1559 初始基础费。
	InitialBaseFee string `json:"initial_base_fee"`
	// Alloc 初始分配：地址 → 账户。
	Alloc map[string]AllocAccount `json:"alloc"`
	// Validators 初始验证者集。
	Validators []GenesisValidator `json:"validators"`
	// ExtraData 运营方自定义数据。
	ExtraData string `json:"extra_data"`
	// Version 协议版本。
	Version string `json:"version"`
}

// AllocAccount 是初始分配中的账户。
type AllocAccount struct {
	Balance string `json:"balance"`
	Nonce   string `json:"nonce,omitempty"`
	Code    string `json:"code,omitempty"`
}

// GenesisValidator 是初始验证者。
type GenesisValidator struct {
	Address string `json:"address"`
	PubKey  string `json:"pubkey"`
	Power   string `json:"power"`
	Moniker string `json:"moniker,omitempty"`
}

// ============================================================================
// 加载与校验
// ============================================================================

// LoadGenesis 从文件加载创世配置。
func LoadGenesis(path string) (*Genesis, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("chain: 读取创世文件失败: %w", err)
	}

	var g Genesis
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields() // 拼错的字段名应该报错，而不是被静默忽略
	if err := dec.Decode(&g); err != nil {
		return nil, fmt.Errorf("chain: 解析创世文件失败: %w", err)
	}

	if err := g.Validate(); err != nil {
		return nil, err
	}
	return &g, nil
}

// Validate 校验创世配置的合法性与内部一致性。
//
// 必须尽早失败：带着错误的创世配置启动节点，代价（分叉）远大于启动失败。
func (g *Genesis) Validate() error {
	if g.ChainID == "" {
		return fmt.Errorf("chain: 创世缺少 chain_id")
	}
	if _, err := parseUint64(g.ChainID); err != nil {
		return fmt.Errorf("chain: chain_id 非法: %w", err)
	}
	if g.Timestamp == "" {
		return fmt.Errorf("chain: 创世缺少 timestamp")
	}
	if _, err := parseUint64(g.Timestamp); err != nil {
		return fmt.Errorf("chain: timestamp 非法: %w", err)
	}
	if g.GasLimit == "" {
		return fmt.Errorf("chain: 创世缺少 gas_limit")
	}
	if g.InitialBaseFee == "" {
		g.InitialBaseFee = "1000000000" // 默认 1 gwei
	}

	// 校验地址格式
	// 用 slices.Sorted(maps.Keys(...)) 而非直接 range map ——
	// 见 spec/01 §8 与 internal/lint/determinism。
	for _, addrStr := range slices.Sorted(maps.Keys(g.Alloc)) {
		acc := g.Alloc[addrStr]
		if _, err := ParseAddress(addrStr); err != nil {
			return fmt.Errorf("chain: alloc 中的地址 %q 非法: %w", addrStr, err)
		}
		if acc.Balance == "" {
			return fmt.Errorf("chain: alloc[%s] 缺少 balance", addrStr)
		}
		if _, err := parseUint256(acc.Balance); err != nil {
			return fmt.Errorf("chain: alloc[%s].balance 非法: %w", addrStr, err)
		}
	}

	for i, v := range g.Validators {
		if _, err := ParseAddress(v.Address); err != nil {
			return fmt.Errorf("chain: validators[%d].address 非法: %w", i, err)
		}
		if v.PubKey == "" {
			return fmt.Errorf("chain: validators[%d] 缺少 pubkey", i)
		}
		if v.Power == "" {
			return fmt.Errorf("chain: validators[%d] 缺少 power", i)
		}
		p, err := parseUint64(v.Power)
		if err != nil || p == 0 {
			return fmt.Errorf("chain: validators[%d].power 必须为正整数", i)
		}
	}

	return nil
}

// ============================================================================
// 推导
// ============================================================================

// BuildState 依据创世配置构建初始状态并返回状态根。
//
// **确定性关键**：alloc 是 map，遍历顺序随机。
// 必须显式排序后处理，否则相同创世在不同节点会产生不同的 state_root。
func (g *Genesis) BuildState() (types.StateRoot, error) {
	mgr := state.NewMemoryManager()
	sess, err := mgr.Begin(types.StateRoot{})
	if err != nil {
		return types.StateRoot{}, err
	}
	if err := g.applyToSession(sess); err != nil {
		return types.StateRoot{}, err
	}
	return sess.Commit()
}

// applyToSession 把创世分配写入会话（排序后处理，顺序无关）。
func (g *Genesis) applyToSession(sess state.Session) error {
	// 排序地址，保证与输入顺序无关
	addrs := slices.Sorted(maps.Keys(g.Alloc))

	for _, addrStr := range addrs {
		acc := g.Alloc[addrStr]

		addr, err := ParseAddress(addrStr)
		if err != nil {
			return err
		}

		if acc.Nonce != "" {
			n, err := parseUint64(acc.Nonce)
			if err != nil {
				return fmt.Errorf("chain: alloc[%s].nonce 非法: %w", addrStr, err)
			}
			sess.SetNonce(addr, types.Nonce(n))
		}

		bal, err := parseUint256(acc.Balance)
		if err != nil {
			return fmt.Errorf("chain: alloc[%s].balance 非法: %w", addrStr, err)
		}
		if err := sess.SetBalance(addr, bal); err != nil {
			return err
		}

		if acc.Code != "" {
			code, err := decodeHex(acc.Code)
			if err != nil {
				return fmt.Errorf("chain: alloc[%s].code 非法: %w", addrStr, err)
			}
			if err := sess.SetCode(addr, code); err != nil {
				return err
			}
		}
	}
	return nil
}

// BuildBlock 构建创世区块。
func (g *Genesis) BuildBlock() (*Block, error) {
	blk, _, err := g.BuildBlockWithManager()
	return blk, err
}

// BuildBlockWithManager 构建创世区块并返回其状态管理器
// （供链持有，后续交易执行从这里打开 Session）。
func (g *Genesis) BuildBlockWithManager() (*Block, state.Manager, error) {
	mgr := state.NewMemoryManager()
	sess, err := mgr.Begin(types.StateRoot{})
	if err != nil {
		return nil, nil, err
	}
	if err := g.applyToSession(sess); err != nil {
		return nil, nil, err
	}
	stateRoot, err := sess.Commit()
	if err != nil {
		return nil, nil, err
	}

	ts, _ := parseUint64(g.Timestamp)
	gasLimit, _ := parseUint64(g.GasLimit)
	baseFee, _ := parseUint256(g.InitialBaseFee)
	chainID, _ := parseUint64(g.ChainID)
	version := uint64(1)
	if g.Version != "" {
		version, _ = parseUint64(g.Version)
	}

	var extraData []byte
	if g.ExtraData != "" {
		extraData, err = decodeHex(g.ExtraData)
		if err != nil {
			return nil, nil, fmt.Errorf("chain: extra_data 非法: %w", err)
		}
		if len(extraData) > types.MaxExtraData {
			return nil, nil, fmt.Errorf("chain: extra_data 超过 %d 字节", types.MaxExtraData)
		}
	}

	vsHash, err := g.ValidatorSetHash()
	if err != nil {
		return nil, nil, err
	}

	header := &BlockHeader{
		Version:          types.Version(version),
		ChainID:          types.ChainID(chainID),
		Height:           0,
		Round:            0,
		Timestamp:        ts,
		PrevHash:         types.BlockHash{}, // 创世无父块
		Proposer:         types.Address{},   // 创世无提议者
		TxRoot:           types.TxRoot(crypto.MerkleRoot(nil)),
		ReceiptRoot:      types.ReceiptRoot(crypto.MerkleRoot(nil)),
		StateRoot:        stateRoot,
		LogsBloom:        types.Bloom{},
		GasUsed:          0,
		GasLimit:         types.Gas(gasLimit),
		BaseFeePerGas:    baseFee,
		ValidatorSetHash: vsHash,
		ExtraData:        extraData,
	}

	return &Block{Header: header, Transactions: nil}, mgr, nil
}

// Hash 计算创世区块哈希。
//
// 这是节点握手时校验的第一件事。两个节点如果算出的 genesis_hash 不同，
// 说明它们的创世配置不一致，必须拒绝连接。
func (g *Genesis) Hash() (types.BlockHash, error) {
	blk, err := g.BuildBlock()
	if err != nil {
		return types.BlockHash{}, err
	}
	return blk.Header.Hash()
}

// ValidatorSetHash 计算初始验证者集的哈希。
//
// **确定性关键**：验证者必须先按地址排序，否则验证者顺序不同
// （JSON 数组顺序、或以后的 map 遍历）会导致哈希不同。
func (g *Genesis) ValidatorSetHash() (types.Hash, error) {
	type entry struct {
		addr   types.Address
		pubkey string
		power  uint64
	}

	entries := make([]entry, 0, len(g.Validators))
	for _, v := range g.Validators {
		addr, err := ParseAddress(v.Address)
		if err != nil {
			return types.Hash{}, err
		}
		power, err := parseUint64(v.Power)
		if err != nil {
			return types.Hash{}, err
		}
		entries = append(entries, entry{addr: addr, pubkey: v.PubKey, power: power})
	}

	// 按地址字节序排序 —— 这是规范要求的确定性顺序（spec/01 §8）
	slices.SortFunc(entries, func(a, b entry) int { return a.addr.Compare(b.addr) })

	buf := make([]byte, 0, len(entries)*80)
	for _, e := range entries {
		buf = append(buf, e.addr.Bytes()...)
		pk, err := decodeHex(e.pubkey)
		if err != nil {
			return types.Hash{}, fmt.Errorf("chain: 验证者公钥非法: %w", err)
		}
		buf = append(buf, crypto.Uint64BE(uint64(len(pk)))...)
		buf = append(buf, pk...)
		buf = append(buf, crypto.Uint64BE(e.power)...)
	}

	return crypto.Keccak256(buf), nil
}

// ============================================================================
// 辅助
// ============================================================================

// ParseAddress 解析 0x 前缀的十六进制地址。
func ParseAddress(s string) (types.Address, error) {
	var addr types.Address
	b, err := decodeHex(s)
	if err != nil {
		return addr, err
	}
	if len(b) != types.AddressLen {
		return addr, fmt.Errorf("chain: 地址需要 %d 字节，实际 %d", types.AddressLen, len(b))
	}
	copy(addr[:], b)
	return addr, nil
}

// FormatAddress 把地址格式化为 0x 前缀十六进制。
func FormatAddress(a types.Address) string { return a.String() }

func decodeHex(s string) ([]byte, error) {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	if s == "" {
		return nil, nil
	}
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("chain: 十六进制长度必须是偶数，实际 %d", len(s))
	}
	return hex.DecodeString(s)
}

func parseUint64(s string) (uint64, error) {
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
			return 0, fmt.Errorf("数值溢出")
		}
		v = nv
	}
	return v, nil
}

func parseUint256(s string) (types.Uint256, error) {
	if s == "" {
		return types.ZeroUint256(), fmt.Errorf("空字符串")
	}
	// 支持 0x 前缀
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		b, err := decodeHex(s)
		if err != nil {
			return types.ZeroUint256(), err
		}
		var u types.Uint256
		if err := u.SetBytes(b); err != nil {
			return types.ZeroUint256(), err
		}
		return u, nil
	}
	// 十进制：逐位累加，检测溢出
	acc := types.ZeroUint256()
	ten := types.Uint256FromUint64(10)
	for _, c := range s {
		if c < '0' || c > '9' {
			return types.ZeroUint256(), fmt.Errorf("非数字字符 %q", c)
		}
		acc, _ = acc.Mul(ten)
		digit := types.Uint256FromUint64(uint64(c - '0'))
		next, err := acc.Add(digit)
		if err != nil {
			return types.ZeroUint256(), fmt.Errorf("数值溢出 256 位")
		}
		acc = next
	}
	return acc, nil
}
