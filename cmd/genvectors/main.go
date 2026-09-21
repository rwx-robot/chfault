// Command genvectors 生成 spec 的回归基线测试向量。
//
// 与 crypto.json 的区别：
//   - crypto.json 是**权威向量**（来自以太坊规范，人工整理，不可自动生成）
//   - regression.json 是**回归基线**（由本工具生成后冻结，用于检测重构导致的行为变化）
//
// 回归基线的价值：如果某次重构意外改变了 stateRoot 或 blockHash 的计算方式，
// 测试会立刻失败。它不能证明"与以太坊兼容"，但能证明"实现没变"。
//
// 用法：
//
//	go run ./cmd/genvectors            # 生成/更新 spec/vectors/regression.json
//	go run ./cmd/genvectors --check    # 只校验，不写入（CI 用）
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/chfault/chfault/chain"
	"github.com/chfault/chfault/crypto"
	"github.com/chfault/chfault/state"
	"github.com/chfault/chfault/types"
)

// Vector 是一条回归向量。
type Vector struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Expected    map[string]string `json:"expected"`
}

// File 是整个回归基线文件。
type File struct {
	Comment     string   `json:"_comment"`
	Spec        string   `json:"_spec"`
	GeneratedBy string   `json:"_generated_by"`
	Vectors     []Vector `json:"vectors"`
}

func main() {
	check := flag.Bool("check", false, "只校验不写入")
	out := flag.String("out", filepath.Join("spec", "vectors", "regression.json"), "输出路径")
	flag.Parse()

	f := build()

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(f); err != nil {
		fail("编码失败: %v", err)
	}
	// json.Encoder 会加末尾换行，保持
	generated := buf.Bytes()

	if *check {
		existing, err := os.ReadFile(*out)
		if err != nil {
			fail("读取现有基线失败（先跑 go run ./cmd/genvectors 生成）: %v", err)
		}
		if !bytes.Equal(bytes.TrimSpace(existing), bytes.TrimSpace(generated)) {
			fail("❌ 回归基线不一致 —— 说明实现行为已改变。\n" +
				"   若这是有意的变更：同步更新 spec 与 ADR，然后重新生成基线。\n" +
				"   若这不是有意的：说明有 bug。")
		}
		fmt.Println("✅ 回归基线与实现一致")
		return
	}

	if err := os.WriteFile(*out, generated, 0o644); err != nil {
		fail("写入失败: %v", err)
	}
	fmt.Printf("✅ 已生成 %s（%d 条向量）\n", *out, len(f.Vectors))
}

func build() File {
	return File{
		Comment: "回归基线向量。由 cmd/genvectors 生成后冻结，用于检测重构导致的行为变化。" +
			"这些值不是权威值（不证明与以太坊兼容），只证明『实现没变』。权威向量见 crypto.json。",
		Spec:        "spec/01-编码原语.md, spec/20-区块头与区块体.md, spec/40-状态与账户.md",
		GeneratedBy: "go run ./cmd/genvectors",
		Vectors: []Vector{
			merkleEmpty(),
			merkleSingle(),
			merkleThree(),
			merkleOddFive(),
			accountSingle(),
			accountTwo(),
			emptyState(),
			blockHeaderGenesis(),
			blockThreeTransfers(),
		},
	}
}

func merkleEmpty() Vector {
	return Vector{
		Name:        "merkle_empty",
		Description: "空列表的 Merkle 根必须是 32 字节零（spec/01 §7）",
		Expected: map[string]string{
			"merkle_root": crypto.MerkleRoot(nil).String(),
		},
	}
}

func merkleSingle() Vector {
	h := crypto.Keccak256([]byte("single-leaf"))
	return Vector{
		Name:        "merkle_single",
		Description: "单叶子的 Merkle 根等于该叶子本身",
		Expected: map[string]string{
			"leaf":        h.String(),
			"merkle_root": crypto.MerkleRoot([]types.Hash{h}).String(),
		},
	}
}

func merkleThree() Vector {
	leaves := []types.Hash{
		crypto.Keccak256([]byte("a")),
		crypto.Keccak256([]byte("b")),
		crypto.Keccak256([]byte("c")),
	}
	return Vector{
		Name:        "merkle_three_odd",
		Description: "3 个叶子（奇数）：最后一个与自己配对，h = keccak(x ‖ x)",
		Expected: map[string]string{
			"leaf_a":      leaves[0].String(),
			"leaf_b":      leaves[1].String(),
			"leaf_c":      leaves[2].String(),
			"merkle_root": crypto.MerkleRoot(leaves).String(),
		},
	}
}

func merkleOddFive() Vector {
	leaves := make([]types.Hash, 5)
	for i := range leaves {
		leaves[i] = crypto.Keccak256([]byte{byte(i + 1)})
	}
	return Vector{
		Name:        "merkle_five_odd",
		Description: "5 个叶子（奇数，跨两层补位）",
		Expected: map[string]string{
			"merkle_root": crypto.MerkleRoot(leaves).String(),
		},
	}
}

func emptyState() Vector {
	mgr := state.NewMemoryManager()
	sess, _ := mgr.Begin(types.StateRoot{})
	root, _ := sess.Commit()
	return Vector{
		Name:        "state_empty",
		Description: "空状态的根（所有账户为空，EIP-158 全部跳过）",
		Expected: map[string]string{
			"state_root": root.String(),
		},
	}
}

func accountSingle() Vector {
	mgr := state.NewMemoryManager()
	sess, _ := mgr.Begin(types.StateRoot{})
	addr := types.Address{0x01}
	_ = sess.SetBalance(addr, types.Uint256FromUint64(1000000000000000000))
	root, _ := sess.Commit()
	return Vector{
		Name:        "state_single_account",
		Description: "单个账户，余额 1 ETH",
		Expected: map[string]string{
			"account":    addr.String(),
			"balance":    "1000000000000000000",
			"state_root": root.String(),
		},
	}
}

func accountTwo() Vector {
	mgr := state.NewMemoryManager()
	sess, _ := mgr.Begin(types.StateRoot{})
	a := types.Address{0x01}
	b := types.Address{0x02}
	_ = sess.SetBalance(a, types.Uint256FromUint64(1000))
	sess.SetNonce(b, 5)
	_ = sess.SetBalance(b, types.Uint256FromUint64(2000))
	root, _ := sess.Commit()
	return Vector{
		Name:        "state_two_accounts",
		Description: "两个账户，含 nonce。验证排序后序列化的确定性",
		Expected: map[string]string{
			"state_root": root.String(),
		},
	}
}

func blockHeaderGenesis() Vector {
	h := &chain.BlockHeader{
		Version:          1,
		ChainID:          10086,
		Height:           0,
		Round:            0,
		Timestamp:        1700000000,
		PrevHash:         types.BlockHash{},
		Proposer:         types.Address{},
		TxRoot:           types.TxRoot(crypto.MerkleRoot(nil)),
		ReceiptRoot:      types.ReceiptRoot(crypto.MerkleRoot(nil)),
		StateRoot:        types.StateRoot(crypto.MerkleRoot(nil)),
		GasUsed:          0,
		GasLimit:         30000000,
		BaseFeePerGas:    types.Uint256FromUint64(1000000000),
		ValidatorSetHash: types.Hash{},
		ExtraData:        nil,
	}
	enc, _ := h.Encode()
	hash, _ := h.Hash()
	return Vector{
		Name:        "block_header_genesis",
		Description: "创世区块头的编码与哈希",
		Expected: map[string]string{
			"encoding_len": fmt.Sprintf("%d", len(enc)),
			"block_hash":   hash.String(),
		},
	}
}

func blockThreeTransfers() Vector {
	txs := make([]*chain.Transaction, 0, 3)
	for i := 0; i < 3; i++ {
		to := types.Address{byte(0x10 + i)}
		tx := &chain.Transaction{
			Type:                 chain.TxTypeDynamicFee,
			ChainID:              10086,
			Nonce:                types.Nonce(i),
			MaxPriorityFeePerGas: types.Uint256FromUint64(1000000000),
			MaxFeePerGas:         types.Uint256FromUint64(2000000000),
			GasLimit:             21000,
			To:                   &to,
			Value:                types.Uint256FromUint64(uint64(1000 * (i + 1))),
		}
		txs = append(txs, tx)
	}

	blk := &chain.Block{Transactions: txs}
	txRoot := blk.ComputeTxRoot()

	receipts := make([]*chain.Receipt, 0, 3)
	var cumulative types.Gas
	for _, tx := range txs {
		h, _ := tx.Hash()
		cumulative += 21000
		r := &chain.Receipt{
			Status:            1,
			TxHash:            h,
			GasUsed:           21000,
			CumulativeGasUsed: cumulative,
			EffectiveGasPrice: types.Uint256FromUint64(1000000000),
		}
		receipts = append(receipts, r)
	}
	receiptRoot := chain.ComputeReceiptRoot(receipts)

	// 逐个交易哈希，便于定位
	exp := map[string]string{
		"tx_root":      txRoot.String(),
		"receipt_root": receiptRoot.String(),
	}
	for i, tx := range txs {
		h, _ := tx.Hash()
		exp[fmt.Sprintf("tx_%d_hash", i)] = h.String()
	}

	return Vector{
		Name:        "block_three_transfers",
		Description: "含 3 笔 EIP-1559 转账的区块：txRoot 与 receiptRoot",
		Expected:    exp,
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
