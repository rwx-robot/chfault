package rpc

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/chfault/chfault/chain"
	"github.com/chfault/chfault/types"
)

// ChainAPI 暴露 RPC 所需的链能力。
//
// 用接口而非直接依赖 *chain.Chain，便于测试与分层。
type ChainAPI interface {
	HasGenesis() bool
	Head() chain.Head
	ChainID() types.ChainID
	GetBlock(height types.Height) (*chain.Block, error)
	GetBlockByHash(hash types.BlockHash) (*chain.Block, error)
	HeightOf(hash types.BlockHash) (types.Height, error)
	FindTx(hash types.TxHash) (*chain.TxLocation, error)
	GetReceipt(height types.Height, index uint32) (*chain.Receipt, error)
	GetHeader(height types.Height) (*chain.BlockHeader, error)
}

// ClientVersion 是 web3_clientVersion 的返回值。
const ClientVersion = "chfault/v0.1.0-m1"

// TxSubmitter 是交易提交能力（由 node 实现，注入 RPC）。
//
// 依赖 EVM 的方法（sendRawTransaction / getBalance）通过本接口接入，
// EVM 未接入时传 nil，相关方法自动返回明确错误而非静默假数据。
type TxSubmitter interface {
	// SubmitRawTx 解码、验证并提交一笔原始交易，返回交易哈希。
	SubmitRawTx(data []byte) (types.TxHash, error)
	// GetBalance 查询账户余额（十六进制 wei 字符串形式由调用方编码）。
	GetBalance(addr types.Address) (string, error)
	// GetNonce 查询账户 nonce。
	GetNonce(addr types.Address) (uint64, error)
	// Call 在最新状态上执行只读合约调用（eth_call）。
	// 返回 (返回数据, gasUsed, VM错误信息, error)。
	Call(from, to types.Address, data []byte, gas uint64) ([]byte, uint64, string, error)
}

// RegisterChainMethods 注册所有链查询方法。
// txAPI 为 nil 时，依赖 EVM 的方法返回明确错误。
func RegisterChainMethods(reg *Registry, api ChainAPI, live func() bool, txAPI TxSubmitter) {
	// ---- eth 命名空间 ----

	reg.Register(&MethodSpec{
		Name: "eth_chainId", Params: nil,
		Handler: func(_ context.Context, _ []json.RawMessage) (any, *Error) {
			return EncodeUint64(uint64(api.ChainID())), nil
		},
	})

	reg.Register(&MethodSpec{
		Name: "eth_blockNumber", Params: nil, RequireLive: true,
		Handler: func(_ context.Context, _ []json.RawMessage) (any, *Error) {
			return EncodeUint64(uint64(api.Head().Height)), nil
		},
	})

	reg.Register(&MethodSpec{
		Name:      "eth_getBlockByNumber",
		Params:    []string{"blockNumber", "fullTransactions"},
		MaxParams: 2, RequireLive: true,
		Handler: func(ctx context.Context, params []json.RawMessage) (any, *Error) {
			h, rpcErr := resolveBlockNumber(api, params, 0)
			if rpcErr != nil {
				return nil, rpcErr
			}
			full := false
			if raw := OptionalParam(params, 1); raw != nil {
				_ = json.Unmarshal(raw, &full)
			}
			return blockToRPC(api, h, full)
		},
	})

	reg.Register(&MethodSpec{
		Name:      "eth_getBlockByHash",
		Params:    []string{"blockHash", "fullTransactions"},
		MaxParams: 2, RequireLive: true,
		Handler: func(ctx context.Context, params []json.RawMessage) (any, *Error) {
			hash, rpcErr := decodeHashParam(params, 0, "blockHash")
			if rpcErr != nil {
				return nil, rpcErr
			}
			h, err := api.HeightOf(types.BlockHash(hash))
			if err != nil {
				return nil, nil // 未找到返回 null（JSON-RPC 惯例）
			}
			full := false
			if raw := OptionalParam(params, 1); raw != nil {
				_ = json.Unmarshal(raw, &full)
			}
			return blockToRPC(api, h, full)
		},
	})

	reg.Register(&MethodSpec{
		Name: "eth_getTransactionByHash", Params: []string{"txHash"},
		RequireLive: true,
		Handler: func(ctx context.Context, params []json.RawMessage) (any, *Error) {
			hash, rpcErr := decodeHashParam(params, 0, "txHash")
			if rpcErr != nil {
				return nil, rpcErr
			}
			loc, err := api.FindTx(types.TxHash(hash))
			if err != nil {
				return nil, nil
			}
			blk, err := api.GetBlock(loc.Height)
			if err != nil || int(loc.Index) >= len(blk.Transactions) {
				return nil, nil
			}
			return transactionToRPC(blk, loc.Index), nil
		},
	})

	reg.Register(&MethodSpec{
		Name: "eth_getTransactionReceipt", Params: []string{"txHash"},
		RequireLive: true,
		Handler: func(ctx context.Context, params []json.RawMessage) (any, *Error) {
			hash, rpcErr := decodeHashParam(params, 0, "txHash")
			if rpcErr != nil {
				return nil, rpcErr
			}
			loc, err := api.FindTx(types.TxHash(hash))
			if err != nil {
				return nil, nil
			}
			r, err := api.GetReceipt(loc.Height, loc.Index)
			if err != nil {
				return nil, nil
			}
			return receiptToRPC(r, loc.Height, loc.Index), nil
		},
	})

	reg.Register(&MethodSpec{
		Name: "eth_getCode", Params: []string{"address", "blockNumber"},
		MaxParams: 2, RequireLive: true,
		Handler: func(ctx context.Context, params []json.RawMessage) (any, *Error) {
			// 合约代码存储需要 state 层（M1 后续接入）
			return "0x", nil
		},
	})

	// ---- 依赖 EVM 的方法 ----

	ethDisabled := func() *Error {
		return NewError(CodeServerError, "EVM 未接入（交易执行尚未启用）")
	}

	reg.Register(&MethodSpec{
		Name: "eth_sendRawTransaction", Params: []string{"signedTx"},
		MaxParams: 1, RequireLive: true,
		Handler: func(ctx context.Context, params []json.RawMessage) (any, *Error) {
			if txAPI == nil {
				return nil, ethDisabled()
			}
			raw, err := ParamBytes(params, 0, "signedTx")
			if err != nil {
				return nil, err
			}
			hash, submitErr := txAPI.SubmitRawTx(raw)
			if submitErr != nil {
				return nil, NewError(CodeTxRejected, submitErr.Error())
			}
			return EncodeHash(types.Hash(hash)), nil
		},
	})

	reg.Register(&MethodSpec{
		Name: "eth_getBalance", Params: []string{"address", "blockNumber"},
		MaxParams: 2, RequireLive: true,
		Handler: func(ctx context.Context, params []json.RawMessage) (any, *Error) {
			if txAPI == nil {
				return nil, ethDisabled()
			}
			addr, rpcErr := ParamAddress(params, 0, "address")
			if rpcErr != nil {
				return nil, rpcErr
			}
			bal, err := txAPI.GetBalance(addr)
			if err != nil {
				return nil, NewError(CodeInternalError, err.Error())
			}
			return bal, nil
		},
	})

	reg.Register(&MethodSpec{
		Name: "eth_getTransactionCount", Params: []string{"address", "blockNumber"},
		MaxParams: 2, RequireLive: true,
		Handler: func(ctx context.Context, params []json.RawMessage) (any, *Error) {
			if txAPI == nil {
				return nil, ethDisabled()
			}
			addr, rpcErr := ParamAddress(params, 0, "address")
			if rpcErr != nil {
				return nil, rpcErr
			}
			nonce, err := txAPI.GetNonce(addr)
			if err != nil {
				return nil, NewError(CodeInternalError, err.Error())
			}
			return EncodeUint64(nonce), nil
		},
	})

	reg.Register(&MethodSpec{
		Name:      "eth_call",
		Params:    []string{"txObject", "blockNumber"},
		MaxParams: 2, RequireLive: true,
		Handler: func(ctx context.Context, params []json.RawMessage) (any, *Error) {
			if txAPI == nil {
				return nil, ethDisabled()
			}
			raw, err := Param(params, 0, "txObject")
			if err != nil {
				return nil, err
			}
			// 解析 {to, data, from, gas}
			var obj struct {
				To   string `json:"to"`
				Data string `json:"data"`
				From string `json:"from"`
			}
			if uerr := json.Unmarshal(raw, &obj); uerr != nil {
				return nil, NewError(CodeInvalidParams, "txObject 非法: "+uerr.Error())
			}
			to, aerr := ParseAddressStr(obj.To)
			if aerr != nil {
				return nil, NewError(CodeInvalidParams, "to 非法")
			}
			from := types.Address{}
			if obj.From != "" {
				from, _ = ParseAddressStr(obj.From)
			}
			data, derr := DecodeBytes(json.RawMessage(strconv.Quote(obj.Data)))
			if derr != nil {
				return nil, NewError(CodeInvalidParams, "data 非法")
			}
			result, _, vmErr, callErr := txAPI.Call(from, to, data, 50_000_000)
			if callErr != nil {
				return nil, NewError(CodeInternalError, callErr.Error())
			}
			if vmErr != "" {
				return nil, NewError(CodeTxRejected, "VM 错误: "+vmErr)
			}
			return EncodeBytes(result), nil
		},
	})

	// ---- net / web3 ----

	reg.Register(&MethodSpec{
		Name: "net_version", Params: nil,
		Handler: func(_ context.Context, _ []json.RawMessage) (any, *Error) {
			return fmt.Sprintf("%d", api.ChainID()), nil
		},
	})

	reg.Register(&MethodSpec{
		Name: "net_listening", Params: nil,
		Handler: func(_ context.Context, _ []json.RawMessage) (any, *Error) {
			return true, nil
		},
	})

	reg.Register(&MethodSpec{
		Name: "web3_clientVersion", Params: nil,
		Handler: func(_ context.Context, _ []json.RawMessage) (any, *Error) {
			return ClientVersion, nil
		},
	})

	// ---- chfault 命名空间 ----

	reg.Register(&MethodSpec{
		Name: "chfault_status", Params: nil, RequireLive: true,
		Handler: func(_ context.Context, _ []json.RawMessage) (any, *Error) {
			head := api.Head()
			return map[string]any{
				"chainId":       EncodeUint64(uint64(api.ChainID())),
				"height":        EncodeUint64(uint64(head.Height)),
				"blockHash":     EncodeHash(types.Hash(head.Hash)),
				"stateRoot":     EncodeHash(types.Hash(head.StateRoot)),
				"clientVersion": ClientVersion,
				"initialized":   api.HasGenesis(),
			}, nil
		},
	})
}

// ============================================================================
// 参数解析
// ============================================================================

// resolveBlockNumber 解析区块号参数，支持 "latest" / "earliest" / 十六进制高度。
func resolveBlockNumber(api ChainAPI, params []json.RawMessage, i int) (types.Height, *Error) {
	raw := OptionalParam(params, i)
	if raw == nil {
		return 0, NewError(CodeInvalidParams, "缺少区块号参数")
	}

	// 字符串形式："latest" / "earliest" / "pending" / "0x..."
	s := string(raw)
	if len(s) > 0 && s[0] == '"' {
		var tag string
		if err := json.Unmarshal(raw, &tag); err == nil {
			switch tag {
			case "latest", "pending", "safe", "finalized":
				return api.Head().Height, nil
			case "earliest":
				return 0, nil
			}
		}
	}

	v, err := DecodeUint64(raw)
	if err != nil {
		return 0, NewError(CodeInvalidParams, fmt.Sprintf("区块号非法: %v", err))
	}
	return types.Height(v), nil
}

func decodeHashParam(params []json.RawMessage, i int, name string) (types.Hash, *Error) {
	raw, err := Param(params, i, name)
	if err != nil {
		return types.Hash{}, err
	}
	h, perr := DecodeHash(raw)
	if perr != nil {
		return types.Hash{}, NewError(CodeInvalidParams,
			fmt.Sprintf("参数 %s 非法: %v", name, perr))
	}
	return h, nil
}

// ============================================================================
// 输出编码
// ============================================================================

// blockToRPC 把区块转为 JSON-RPC 的区块表示（对齐以太坊字段名）。
func blockToRPC(api ChainAPI, h types.Height, fullTx bool) (any, *Error) {
	blk, err := api.GetBlock(h)
	if err != nil {
		return nil, nil // 未找到返回 null
	}
	header := blk.Header

	blockHash, err := header.Hash()
	if err != nil {
		return nil, NewError(CodeInternalError, "计算区块哈希失败", err.Error())
	}

	txs := make([]any, 0, len(blk.Transactions))
	for i := range blk.Transactions {
		if fullTx {
			txs = append(txs, transactionToRPC(blk, uint32(i)))
		} else {
			txHash, _ := blk.Transactions[i].Hash()
			txs = append(txs, EncodeHash(types.Hash(txHash)))
		}
	}

	out := map[string]any{
		"number":           EncodeUint64(uint64(header.Height)),
		"hash":             EncodeHash(types.Hash(blockHash)),
		"parentHash":       EncodeHash(types.Hash(header.PrevHash)),
		"nonce":            "0x0000000000000000", // 兼容字段（非 PoW 链）
		"sha3Uncles":       EncodeHash(types.Hash{}),
		"logsBloom":        EncodeBytes(header.LogsBloom[:]),
		"transactionsRoot": EncodeHash(types.Hash(header.TxRoot)),
		"stateRoot":        EncodeHash(types.Hash(header.StateRoot)),
		"receiptsRoot":     EncodeHash(types.Hash(header.ReceiptRoot)),
		"miner":            EncodeAddress(header.Proposer),
		"difficulty":       "0x0",
		"totalDifficulty":  "0x0",
		"extraData":        EncodeBytes(header.ExtraData),
		"size":             EncodeUint64(0),
		"gasLimit":         EncodeUint64(uint64(header.GasLimit)),
		"gasUsed":          EncodeUint64(uint64(header.GasUsed)),
		"timestamp":        EncodeUint64(header.Timestamp),
		"transactions":     txs,
		"uncles":           []any{},
		"baseFeePerGas":    EncodeUint256(header.BaseFeePerGas),
		// chfault 扩展
		"chainId":          EncodeUint64(uint64(header.ChainID)),
		"round":            EncodeUint64(uint64(header.Round)),
		"validatorSetHash": EncodeHash(header.ValidatorSetHash),
		"transactionCount": EncodeUint64(uint64(len(blk.Transactions))),
	}
	return out, nil
}

// transactionToRPC 把交易转为 JSON-RPC 表示（对齐 EIP-1559 字段名）。
func transactionToRPC(blk *chain.Block, index uint32) any {
	tx := blk.Transactions[index]
	hash, _ := tx.Hash()
	blockHash, _ := blk.Header.Hash()

	var to any
	if tx.To != nil {
		to = EncodeAddress(*tx.To)
	}

	return map[string]any{
		"hash":                 EncodeHash(types.Hash(hash)),
		"nonce":                EncodeUint64(uint64(tx.Nonce)),
		"blockHash":            EncodeHash(types.Hash(blockHash)),
		"blockNumber":          EncodeUint64(uint64(blk.Header.Height)),
		"transactionIndex":     EncodeUint64(uint64(index)),
		"from":                 EncodeAddress(tx.From),
		"to":                   to,
		"value":                EncodeUint256(tx.Value),
		"gas":                  EncodeUint64(uint64(tx.GasLimit)),
		"input":                EncodeBytes(tx.Data),
		"type":                 EncodeUint64(uint64(tx.Type)),
		"chainId":              EncodeUint64(uint64(tx.ChainID)),
		"maxFeePerGas":         EncodeUint256(tx.MaxFeePerGas),
		"maxPriorityFeePerGas": EncodeUint256(tx.MaxPriorityFeePerGas),
		"gasPrice":             EncodeUint256(tx.MaxFeePerGas),
		"accessList":           []any{},
		"v":                    EncodeUint64(uint64(tx.Signature[64])),
		"r":                    EncodeHash(types.Hash(tx.Signature[0:32])),
		"s":                    EncodeHash(types.Hash(tx.Signature[32:64])),
	}
}

// receiptToRPC 把收据转为 JSON-RPC 表示。
func receiptToRPC(r *chain.Receipt, height types.Height, index uint32) any {
	logs := make([]any, 0, len(r.Logs))
	for i, lg := range r.Logs {
		topics := make([]string, 0, len(lg.Topics))
		for _, t := range lg.Topics {
			topics = append(topics, EncodeHash(t))
		}
		logs = append(logs, map[string]any{
			"address":          EncodeAddress(lg.Address),
			"topics":           topics,
			"data":             EncodeBytes(lg.Data),
			"blockNumber":      EncodeUint64(uint64(height)),
			"transactionIndex": EncodeUint64(uint64(index)),
			"logIndex":         EncodeUint64(uint64(i)),
			"removed":          false,
		})
	}

	var contractAddr any
	if r.ContractAddress != nil {
		contractAddr = EncodeAddress(*r.ContractAddress)
	}

	var status string
	if r.Status == 1 {
		status = "0x1"
	} else {
		status = "0x0"
	}

	return map[string]any{
		"transactionHash":   EncodeHash(types.Hash(r.TxHash)),
		"transactionIndex":  EncodeUint64(uint64(index)),
		"blockNumber":       EncodeUint64(uint64(height)),
		"cumulativeGasUsed": EncodeUint64(uint64(r.CumulativeGasUsed)),
		"gasUsed":           EncodeUint64(uint64(r.GasUsed)),
		"logs":              logs,
		"logsBloom":         EncodeBytes(r.LogsBloom[:]),
		"status":            status,
		"effectiveGasPrice": EncodeUint256(r.EffectiveGasPrice),
		"contractAddress":   contractAddr,
		"type":              "0x2",
	}
}

// ParseAddressStr 解析 0x 前缀地址字符串（eth_call 参数用）。
func ParseAddressStr(s string) (types.Address, error) {
	var addr types.Address
	raw, err := decodeHexString(json.RawMessage("\"" + s + "\""))
	if err != nil {
		return addr, err
	}
	if len(raw) != types.AddressLen {
		return addr, fmt.Errorf("地址需要 20 字节，实际 %d", len(raw))
	}
	copy(addr[:], raw)
	return addr, nil
}
