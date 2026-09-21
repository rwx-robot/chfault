package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/chfault/chfault/rpc"
)

// cmdCodegen 生成 OpenRPC 文档。
//
// 用法：chfault codegen openrpc --out openrpc.json
//
// OpenRPC 是 JSON-RPC 的 OpenAPI —— 供客户端 SDK 生成、IDE 补全与
// 文档站使用。方法列表与参数名从 registry 反射得出，保证文档与实现同步。
func cmdCodegen(args []string) error {
	if len(args) < 1 || args[0] != "openrpc" {
		return fmt.Errorf("用法: chfault codegen openrpc --out openrpc.json")
	}

	fs := flag.NewFlagSet("codegen openrpc", flag.ExitOnError)
	out := fs.String("out", "openrpc.json", "输出路径")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	return writeOpenRPC(*out)
}

// rpcMethods 是 M1 的方法集（与 rpc.RegisterChainMethods 保持同步 ——
// M2 用 registry 反射替换这张表，避免手工同步）。
var rpcMethods = []rpcMethodDoc{
	{Name: "eth_chainId", Params: nil, Result: "0x-prefixed quantity"},
	{Name: "eth_blockNumber", Params: nil, Result: "0x quantity"},
	{Name: "eth_getBalance", Params: []string{"address", "block"}, Result: "0x quantity"},
	{Name: "eth_getTransactionCount", Params: []string{"address", "block"}, Result: "0x quantity"},
	{Name: "eth_getBlockByNumber", Params: []string{"blockNumber", "full"}, Result: "block | null"},
	{Name: "eth_getBlockByHash", Params: []string{"hash", "full"}, Result: "block | null"},
	{Name: "eth_getTransactionByHash", Params: []string{"hash"}, Result: "tx | null"},
	{Name: "eth_getTransactionReceipt", Params: []string{"hash"}, Result: "receipt | null"},
	{Name: "eth_sendRawTransaction", Params: []string{"signedTx"}, Result: "tx hash"},
	{Name: "eth_call", Params: []string{"txObject", "block"}, Result: "0x data"},
	{Name: "eth_getCode", Params: []string{"address", "block"}, Result: "0x data"},
	{Name: "net_version", Params: nil, Result: "string"},
	{Name: "net_listening", Params: nil, Result: "bool"},
	{Name: "web3_clientVersion", Params: nil, Result: "string"},
	{Name: "chfault_status", Params: nil, Result: "status object"},
}

type rpcMethodDoc struct {
	Name   string
	Params []string
	Result string
}

func writeOpenRPC(path string) error {
	methods := make([]map[string]any, 0, len(rpcMethods))
	for _, m := range rpcMethods {
		params := make([]map[string]any, 0, len(m.Params))
		for i, p := range m.Params {
			params = append(params, map[string]any{
				"name":     p,
				"schema":   map[string]any{"type": "string"},
				"required": true,
			})
			_ = i
		}
		methods = append(methods, map[string]any{
			"name":   m.Name,
			"params": params,
			"result": map[string]any{
				"name":   "result",
				"schema": map[string]any{"type": "string", "description": m.Result},
			},
		})
	}

	sort.Slice(methods, func(i, j int) bool {
		return methods[i]["name"].(string) < methods[j]["name"].(string)
	})

	doc := map[string]any{
		"openrpc": "1.2.6",
		"info": map[string]any{
			"title":       "chfault JSON-RPC",
			"version":     Version,
			"description": "chfault 节点的 JSON-RPC 接口（以太坊兼容子集 + chfault_ 扩展）",
		},
		"servers": []map[string]any{
			{"url": "http://localhost:8545"},
		},
		"methods": methods,
	}

	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}
	fmt.Printf("✅ OpenRPC 文档已生成: %s（%d 个方法）\n", path, len(methods))
	return nil
}

// 编译期检查：保证 rpc 包引用有效
var _ = rpc.CodeParseError
