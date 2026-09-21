// Package rpc 实现 JSON-RPC 2.0 接口层。
//
// 设计原则（docs/blueprint/06 §6.3）：
//  1. **eth 兼容子集优先** —— 名字与语义完全对齐以太坊，生态工具零改动接入
//  2. **链特有功能用 chfault_ 前缀** —— 不污染 eth 命名空间
//  3. **大整数一律走十六进制字符串** —— 绝不返回 JSON number（会丢精度）
//
// 本包是边界层：把链的内部表示转换为 JSON-RPC 的线格式。
package rpc

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/chfault/chfault/types"
)

// ============================================================================
// JSON-RPC 2.0 协议
// ============================================================================

// 标准错误码（JSON-RPC 2.0 规范）。
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603

	// 自定义错误码（-32000 ~ -32099 为服务端保留区）
	CodeServerError   = -32000
	CodeTxRejected    = -32001
	CodeNotFound      = -32002
	CodeLimitExceeded = -32003
)

// Request 是一个 JSON-RPC 请求。
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	ID      json.RawMessage `json:"id,omitempty"`
}

// Response 是一个 JSON-RPC 响应。
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  any             `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
	ID      json.RawMessage `json:"id,omitempty"`
}

// Error 是 JSON-RPC 错误对象。
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("rpc 错误 %d: %s", e.Code, e.Message)
}

// NewError 构造错误对象。
func NewError(code int, msg string, data ...any) *Error {
	e := &Error{Code: code, Message: msg}
	if len(data) > 0 {
		e.Data = data[0]
	}
	return e
}

// IsNotification 判断是否为通知（无 id，不需要响应）。
func (r *Request) IsNotification() bool {
	return len(r.ID) == 0 || string(r.ID) == "null"
}

// ============================================================================
// 十六进制数量编码（spec/01 §5）
// ============================================================================

// EncodeUint64 把整数编码为 JSON-RPC 的 quantity 形式（0x 前缀，最短表示）。
//
// 例：0 → "0x0"，1024 → "0x400"，10086 → "0x2766"
//
// ⚠️ 绝不返回 JSON number：uint64 超过 2^53 时 JavaScript 会丢精度，
// 而所有主流 Web3 客户端都是 JS。
func EncodeUint64(v uint64) string {
	return "0x" + strconv.FormatUint(v, 16)
}

// EncodeUint256 把 Uint256 编码为 quantity 形式。
//
// quantity 要求**最短表示**：既不能有前导零字节，也不能有前导零 nibble。
// 例：0 → "0x0"，1 → "0x1"（不是 "0x01"），1 ETH → "0xde0b6b3a7640000"。
func EncodeUint256(v types.Uint256) string {
	b := v[:]

	// 先去掉前导零**字节**
	i := 0
	for i < len(b) && b[i] == 0 {
		i++
	}
	if i == len(b) {
		return "0x0"
	}

	// 再去掉第一个字节可能的前导零 **nibble**
	s := strings.TrimLeft(hex.EncodeToString(b[i:]), "0")
	if s == "" {
		return "0x0"
	}
	return "0x" + s
}

// EncodeBytes 把字节编码为 0x 前缀小写十六进制（data 形式，保留全部字节）。
func EncodeBytes(b []byte) string {
	return "0x" + hex.EncodeToString(b)
}

// EncodeHash 把哈希编码为 data 形式（总是 32 字节，前导零保留）。
func EncodeHash(h types.Hash) string { return "0x" + hex.EncodeToString(h[:]) }

// EncodeAddress 把地址编码为 data 形式（总是 20 字节）。
//
// 注意：这里用小写形式。EIP-55 校验和属于显示层，
// 主流客户端（viem/ethers）都能接受小写地址。
func EncodeAddress(a types.Address) string { return "0x" + hex.EncodeToString(a[:]) }

// DecodeUint64 解析 quantity 或 number 形式的整数。
//
// 兼容三种输入："0x400"、"1024"、1024（JSON number）。
// 兼容性是必要的：不同客户端对 quantity 的理解不一致。
func DecodeUint64(raw json.RawMessage) (uint64, error) {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" {
		return 0, fmt.Errorf("缺少数值")
	}

	// JSON number
	if s[0] != '"' {
		return strconv.ParseUint(s, 10, 64)
	}

	// 字符串形式
	unquoted, err := strconv.Unquote(s)
	if err != nil {
		return 0, fmt.Errorf("非法字符串: %w", err)
	}
	if unquoted == "" {
		return 0, fmt.Errorf("空字符串")
	}
	if strings.HasPrefix(unquoted, "0x") || strings.HasPrefix(unquoted, "0X") {
		return strconv.ParseUint(unquoted[2:], 16, 64)
	}
	return strconv.ParseUint(unquoted, 10, 64)
}

// DecodeAddress 解析地址参数。
func DecodeAddress(raw json.RawMessage) (types.Address, error) {
	var addr types.Address
	s, err := decodeHexString(raw)
	if err != nil {
		return addr, err
	}
	if len(s) != types.AddressLen {
		return addr, fmt.Errorf("地址需要 %d 字节，实际 %d", types.AddressLen, len(s))
	}
	copy(addr[:], s)
	return addr, nil
}

// DecodeHash 解析 32 字节哈希参数。
func DecodeHash(raw json.RawMessage) (types.Hash, error) {
	var h types.Hash
	s, err := decodeHexString(raw)
	if err != nil {
		return h, err
	}
	if len(s) != types.HashLen {
		return h, fmt.Errorf("哈希需要 %d 字节，实际 %d", types.HashLen, len(s))
	}
	copy(h[:], s)
	return h, nil
}

// DecodeBytes 解析 0x 前缀的字节参数。
func DecodeBytes(raw json.RawMessage) ([]byte, error) {
	return decodeHexString(raw)
}

func decodeHexString(raw json.RawMessage) ([]byte, error) {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" {
		return nil, fmt.Errorf("缺少参数")
	}
	if s[0] == '"' {
		unq, err := strconv.Unquote(s)
		if err != nil {
			return nil, fmt.Errorf("非法字符串: %w", err)
		}
		s = unq
	}
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	if s == "" {
		return nil, nil
	}
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("十六进制长度必须是偶数，实际 %d", len(s))
	}
	return hex.DecodeString(s)
}

// ParseParams 把 params 解析为 []json.RawMessage。
//
// 同时支持位置参数（数组）与命名参数（对象）—— 后者转为按 key 排序的数组。
func ParseParams(raw json.RawMessage) ([]json.RawMessage, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}

	trimmed := strings.TrimSpace(string(raw))
	if len(trimmed) == 0 {
		return nil, nil
	}

	switch trimmed[0] {
	case '[':
		var arr []json.RawMessage
		if err := json.Unmarshal(raw, &arr); err != nil {
			return nil, fmt.Errorf("解析位置参数失败: %w", err)
		}
		return arr, nil
	case '{':
		// 命名参数：按 key 字典序展开。
		// 用 map 取出所有 key 后排序 —— 避免依赖 Go map 的迭代顺序。
		var m map[string]json.RawMessage
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, fmt.Errorf("解析命名参数失败: %w", err)
		}
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sortStrings(keys)
		out := make([]json.RawMessage, len(keys))
		for i, k := range keys {
			out[i] = m[k]
		}
		return out, nil
	default:
		return nil, fmt.Errorf("params 必须是数组或对象")
	}
}

// ============================================================================
// 小块工具
// ============================================================================

func sortStrings(s []string) {
	// 简单的插入排序足够（参数数量通常 < 10），
	// 且避免为这个小函数引入额外依赖
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
