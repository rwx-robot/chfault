package chain

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/chfault/chfault/crypto"
	"github.com/chfault/chfault/state"
	"github.com/chfault/chfault/storage"
	"github.com/chfault/chfault/types"
)

// Chain 是链状态机：管理链头、区块的持久化与读取、区块追加校验。
//
// **不含共识**（依赖方向规则 1：chain 不得 import consensus）。
// 共识负责决定"哪个区块该被追加"，Chain 只负责"追加它的后果"。
type Chain struct {
	store  storage.KVStore
	config Config
	head   Head
	// mgr 是状态管理器（InitGenesis 时创建）。
	// 交易执行的 nonce/余额校验、EVM 执行都从这里打开 Session。
	mgr state.Manager
}

// Config 是链级配置。
type Config struct {
	// ChainID 链标识，启动时与创世文件校验。
	ChainID types.ChainID
	// MaxExtraData 区块头附加数据上限。
	MaxExtraData int
}

// Head 是链头指针。
type Head struct {
	Height    types.Height
	Hash      types.BlockHash
	StateRoot types.StateRoot
}

// 错误。
var (
	// ErrNotFound 区块不存在。
	ErrNotFound = errors.New("chain: 区块不存在")
	// ErrNoGenesis 链尚未初始化。
	ErrNoGenesis = errors.New("chain: 链未初始化（缺少创世）")
	// ErrAlreadyInit 链已初始化。
	ErrAlreadyInit = errors.New("chain: 链已初始化")
	// ErrBadParent 父区块不匹配。
	ErrBadParent = errors.New("chain: 父区块不匹配")
	// ErrBadHeight 高度不连续。
	ErrBadHeight = errors.New("chain: 高度不连续")
	// ErrBadChainID 链 ID 不匹配。
	ErrBadChainID = errors.New("chain: chainId 不匹配")
	// ErrGenesisMismatch 创世哈希与已存储的不一致（数据目录挂错）。
	ErrGenesisMismatch = errors.New("chain: 创世哈希不匹配")
	// ErrSchemaMismatch 数据格式版本不兼容。
	ErrSchemaMismatch = errors.New("chain: 数据格式版本不兼容")
)

// ============================================================================
// 打开
// ============================================================================

// New 打开（或初始化）一条链。
//
// 启动流程（spec/20、docs/blueprint/02 §2.8）：
//  1. 校验数据格式版本（不兼容即拒绝启动，绝不静默迁移）
//  2. 读取链头
//  3. 已初始化则校验创世哈希一致（防止挂错数据目录）
func New(store storage.KVStore, cfg Config) (*Chain, error) {
	c := &Chain{store: store, config: cfg}

	// 1. 数据格式版本
	v, err := store.Get(storage.NSMeta, storage.KeySchemaVersion)
	if err != nil {
		return nil, err
	}
	if v != nil {
		got := binary.BigEndian.Uint32(v)
		if got != storage.SchemaVersion {
			return nil, fmt.Errorf("%w: 数据目录版本 %d，程序期望 %d（需要迁移工具）",
				ErrSchemaMismatch, got, storage.SchemaVersion)
		}
	}

	// 2. 链头
	head, err := c.loadHead()
	if err != nil {
		return nil, err
	}
	if head != nil {
		c.head = *head
	}

	return c, nil
}

// ============================================================================
// 初始化
// ============================================================================

// InitGenesis 用创世配置初始化链。
//
// 幂等性：若链已存在，校验创世哈希一致后返回 nil（允许重复调用启动）；
// 不一致则报错 —— 这是"把 A 链的数据目录用于 B 链"的检测点。
func (c *Chain) InitGenesis(g *Genesis) error {
	if err := g.Validate(); err != nil {
		return err
	}

	gHash, err := g.Hash()
	if err != nil {
		return err
	}

	// 已有数据：校验一致性
	if stored, err := c.store.Get(storage.NSMeta, storage.KeyGenesisHash); err != nil {
		return err
	} else if stored != nil {
		if len(stored) != types.HashLen {
			return fmt.Errorf("%w: 存储的创世哈希长度异常", ErrGenesisMismatch)
		}
		var want types.BlockHash
		copy(want[:], stored)
		if want != gHash {
			return fmt.Errorf("%w:\n 已存储 %s\n 配置为 %s\n"+
				"这通常意味着数据目录与创世文件不匹配 —— 拒绝启动，避免产生分叉",
				ErrGenesisMismatch, want.String(), gHash.String())
		}
		return nil // 已初始化且一致
	}

	// 首次初始化
	blk, mgr, err := g.BuildBlockWithManager()
	if err != nil {
		return err
	}
	c.mgr = mgr
	if blk.Header.ChainID != c.config.ChainID && c.config.ChainID != 0 {
		return fmt.Errorf("%w: 创世 chain_id %d，配置 %d",
			ErrBadChainID, blk.Header.ChainID, c.config.ChainID)
	}

	batch := c.store.NewBatch()
	defer batch.Close()

	// 原子写入：创世区块 + 索引 + 链头 + 元数据
	if err := c.writeBlockToBatch(batch, blk); err != nil {
		return err
	}
	if err := batch.Put(storage.NSMeta, storage.KeyGenesisHash, gHash[:]); err != nil {
		return err
	}
	verBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(verBytes, storage.SchemaVersion)
	if err := batch.Put(storage.NSMeta, storage.KeySchemaVersion, verBytes); err != nil {
		return err
	}
	if err := c.writeHeadToBatch(batch, Head{
		Height:    0,
		Hash:      gHash,
		StateRoot: blk.Header.StateRoot,
	}); err != nil {
		return err
	}

	if err := c.store.Apply(batch); err != nil {
		return err
	}
	c.head = Head{Height: 0, Hash: gHash, StateRoot: blk.Header.StateRoot}
	return nil
}

// ============================================================================
// 查询
// ============================================================================

// Head 返回当前链头。
func (c *Chain) Head() Head { return c.head }

// ChainID 返回链标识。
func (c *Chain) ChainID() types.ChainID { return c.config.ChainID }

// State 返回状态管理器（交易执行与查询的入口）。
// 链未初始化时返回 nil。
func (c *Chain) State() state.Manager { return c.mgr }

// HasGenesis 判断链是否已初始化。
func (c *Chain) HasGenesis() bool {
	v, err := c.store.Get(storage.NSMeta, storage.KeyGenesisHash)
	return err == nil && v != nil
}

// GetBlock 按高度读取区块。
func (c *Chain) GetBlock(height types.Height) (*Block, error) {
	if !c.HasGenesis() {
		return nil, ErrNoGenesis
	}
	data, err := c.store.Get(storage.NSBlocks, blockKeyByHeight(height))
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, fmt.Errorf("%w: 高度 %d", ErrNotFound, height)
	}
	return DecodeBlock(data)
}

// GetBlockByHash 按哈希读取区块。
func (c *Chain) GetBlockByHash(hash types.BlockHash) (*Block, error) {
	h, err := c.HeightOf(hash)
	if err != nil {
		return nil, err
	}
	return c.GetBlock(h)
}

// GetHeader 按高度读取区块头（比读完整区块更省）。
func (c *Chain) GetHeader(height types.Height) (*BlockHeader, error) {
	blk, err := c.GetBlock(height)
	if err != nil {
		return nil, err
	}
	return blk.Header, nil
}

// HeightOf 通过哈希索引查询高度。
func (c *Chain) HeightOf(hash types.BlockHash) (types.Height, error) {
	data, err := c.store.Get(storage.NSBlocks, blockKeyByHash(hash))
	if err != nil {
		return 0, err
	}
	if data == nil {
		return 0, fmt.Errorf("%w: 哈希 %s", ErrNotFound, hash.String())
	}
	if len(data) != 8 {
		return 0, fmt.Errorf("chain: 高度索引长度异常: %d", len(data))
	}
	return types.Height(binary.BigEndian.Uint64(data)), nil
}

// GetReceipts 读取指定高度的全部收据。
func (c *Chain) GetReceipts(height types.Height) ([]*Receipt, error) {
	blk, err := c.GetBlock(height)
	if err != nil {
		return nil, err
	}
	out := make([]*Receipt, 0, len(blk.Transactions))
	for i := range blk.Transactions {
		r, err := c.GetReceipt(height, uint32(i))
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// GetReceipt 读取单条收据。
func (c *Chain) GetReceipt(height types.Height, index uint32) (*Receipt, error) {
	data, err := c.store.Get(storage.NSReceipts, receiptKey(height, index))
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, fmt.Errorf("%w: 高度 %d 索引 %d", ErrNotFound, height, index)
	}
	return DecodeReceipt(data)
}

// TxLocation 是交易在链上的位置。
type TxLocation struct {
	Height types.Height
	Index  uint32
}

// FindTx 按交易哈希定位。
func (c *Chain) FindTx(hash types.TxHash) (*TxLocation, error) {
	data, err := c.store.Get(storage.NSTxIndex, hash[:])
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, fmt.Errorf("%w: 交易 %s", ErrNotFound, hash.String())
	}
	if len(data) != 12 {
		return nil, fmt.Errorf("chain: 交易索引长度异常: %d", len(data))
	}
	return &TxLocation{
		Height: types.Height(binary.BigEndian.Uint64(data[:8])),
		Index:  binary.BigEndian.Uint32(data[8:]),
	}, nil
}

// ============================================================================
// 追加
// ============================================================================

// AppendBlock 校验并持久化一个区块。
//
// 校验内容（spec/20 §7 的链级部分）：
//   - chainId 匹配
//   - 高度 = 父高度 + 1
//   - prev_hash = 父哈希
//   - tx_root 与区块体一致
//
// **不做**：执行交易、验证 stateRoot、验证共识证明。
// 那些由上层（执行层、共识层）负责 —— 本函数只保证"结构与链接正确"。
// receipts 会随区块一起持久化（收据是执行的产物，与区块同生命周期）。
func (c *Chain) AppendBlock(blk *Block, receipts []*Receipt) error {
	if blk == nil || blk.Header == nil {
		return fmt.Errorf("%w: 区块为空", ErrCodec)
	}
	if !c.HasGenesis() {
		return ErrNoGenesis
	}
	if c.config.ChainID != 0 && blk.Header.ChainID != c.config.ChainID {
		return fmt.Errorf("%w: 区块 %d，配置 %d",
			ErrBadChainID, blk.Header.ChainID, c.config.ChainID)
	}

	h := blk.Header

	// 高度必须连续
	if h.Height != c.head.Height+1 {
		return fmt.Errorf("%w: 期望 %d，实际 %d",
			ErrBadHeight, c.head.Height+1, h.Height)
	}

	// 父链校验
	if h.PrevHash != c.head.Hash {
		return fmt.Errorf("%w:\n 期望 %s\n 实际 %s",
			ErrBadParent, c.head.Hash.String(), h.PrevHash.String())
	}

	// tx_root 必须与区块体一致（防止头部与体不匹配的构造攻击）
	computed := blk.ComputeTxRoot()
	if computed != h.TxRoot {
		return fmt.Errorf("%w: tx_root 与区块体不一致\n 头部 %s\n 计算 %s",
			ErrCodec, h.TxRoot.String(), computed.String())
	}

	// 幂等：已存在同高度区块
	if existing, err := c.GetBlock(h.Height); err == nil {
		existingHash, _ := existing.Header.Hash()
		newHash, _ := h.Hash()
		if existingHash != newHash {
			return fmt.Errorf("chain: 高度 %d 已存在不同区块（分叉），拒绝覆盖", h.Height)
		}
		return nil // 已存在且相同
	}

	hash, err := h.Hash()
	if err != nil {
		return err
	}

	batch := c.store.NewBatch()
	defer batch.Close()

	if err := c.writeBlockToBatch(batch, blk); err != nil {
		return err
	}
	// 收据与区块同批持久化
	for i, r := range receipts {
		renc, rerr := r.Encode()
		if rerr != nil {
			return rerr
		}
		if err := batch.Put(storage.NSReceipts, receiptKey(h.Height, uint32(i)), renc); err != nil {
			return err
		}
	}
	// 原子写入链头 —— 与区块在同一批次，避免"有区块无链头"的不一致
	if err := c.writeHeadToBatch(batch, Head{
		Height:    h.Height,
		Hash:      hash,
		StateRoot: h.StateRoot,
	}); err != nil {
		return err
	}

	if err := c.store.Apply(batch); err != nil {
		return err
	}

	c.head = Head{Height: h.Height, Hash: hash, StateRoot: h.StateRoot}
	return nil
}

// ============================================================================
// 内部：持久化
// ============================================================================

func (c *Chain) writeBlockToBatch(batch storage.Batch, blk *Block) error {
	h := blk.Header

	enc, err := blk.Encode()
	if err != nil {
		return err
	}

	hash, err := h.Hash()
	if err != nil {
		return err
	}

	if err := batch.Put(storage.NSBlocks, blockKeyByHeight(h.Height), enc); err != nil {
		return err
	}
	if err := batch.Put(storage.NSBlocks, blockKeyByHash(hash),
		crypto.Uint64BE(uint64(h.Height))); err != nil {
		return err
	}

	// 交易索引
	for i, tx := range blk.Transactions {
		txHash, err := tx.Hash()
		if err != nil {
			return err
		}
		loc := make([]byte, 12)
		binary.BigEndian.PutUint64(loc[:8], uint64(h.Height))
		binary.BigEndian.PutUint32(loc[8:], uint32(i))
		if err := batch.Put(storage.NSTxIndex, txHash[:], loc); err != nil {
			return err
		}
	}
	return nil
}

func (c *Chain) writeHeadToBatch(batch storage.Batch, head Head) error {
	buf := make([]byte, 0, 8+32+32)
	buf = append(buf, crypto.Uint64BE(uint64(head.Height))...)
	buf = append(buf, head.Hash[:]...)
	buf = append(buf, head.StateRoot[:]...)
	return batch.Put(storage.NSMeta, storage.KeyChainTip, buf)
}

func (c *Chain) loadHead() (*Head, error) {
	data, err := c.store.Get(storage.NSMeta, storage.KeyChainTip)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, nil
	}
	if len(data) != 8+32+32 {
		return nil, fmt.Errorf("chain: 链头数据长度异常: %d", len(data))
	}
	h := &Head{Height: types.Height(binary.BigEndian.Uint64(data[:8]))}
	copy(h.Hash[:], data[8:40])
	copy(h.StateRoot[:], data[40:72])
	return h, nil
}

// ============================================================================
// Key 构造（spec/40 §5.1：整数一律大端）
// ============================================================================

func blockKeyByHeight(h types.Height) []byte {
	return append([]byte{storage.SubBlockByHeight}, crypto.Uint64BE(uint64(h))...)
}

func blockKeyByHash(hash types.BlockHash) []byte {
	return append([]byte{storage.SubBlockByHash}, hash[:]...)
}

func receiptKey(h types.Height, index uint32) []byte {
	key := make([]byte, 0, 12)
	key = append(key, crypto.Uint64BE(uint64(h))...)
	key = append(key, crypto.Uint32BE(index)...)
	return key
}
