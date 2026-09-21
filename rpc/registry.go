package rpc

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/chfault/chfault/types"
)

// Handler 是 RPC 方法处理器。
//
// 参数以原始 JSON 形式传入，由各方法自己解析 ——
// 这样既支持位置参数也支持命名参数，且避免了为每个方法写反射样板。
type Handler func(ctx context.Context, params []json.RawMessage) (any, *Error)

// MethodSpec 是方法的元信息，用于生成文档与自检。
type MethodSpec struct {
	// Name 方法名（如 "eth_getBlockByNumber"）。
	Name string
	// Namespace 命名空间（eth / net / web3 / chfault）。
	Namespace string
	// Params 参数名列表（用于命名参数映射与文档）。
	Params []string
	// MaxParams 允许的最大参数个数。
	MaxParams int
	// Handler 处理器。
	Handler Handler
	// RequireLive 是否需要链已初始化（genesis 存在）。
	RequireLive bool
}

// Registry 是方法注册表。
type Registry struct {
	mu       sync.RWMutex
	methods  map[string]*MethodSpec
	byNS     map[string][]string // namespace → 方法名（已排序）
	registry *Registry           // 预留：插件式扩展
}

// NewRegistry 创建方法注册表。
func NewRegistry() *Registry {
	return &Registry{
		methods: make(map[string]*MethodSpec),
		byNS:    make(map[string][]string),
	}
}

// Register 注册一个方法。
//
// 重复注册或命名不合法会在**启动时** panic —— 配置错误应该在启动时暴露，
// 而不是等某个请求打进来才发现。
func (r *Registry) Register(spec *MethodSpec) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if spec.Name == "" {
		panic("rpc: 方法名不能为空")
	}
	if spec.Handler == nil {
		panic(fmt.Sprintf("rpc: 方法 %s 缺少处理器", spec.Name))
	}

	// 命名空间校验
	idx := strings.Index(spec.Name, "_")
	if idx <= 0 {
		panic(fmt.Sprintf("rpc: 方法名 %q 必须形如 namespace_method", spec.Name))
	}
	if spec.Namespace == "" {
		spec.Namespace = spec.Name[:idx]
	}

	if _, exists := r.methods[spec.Name]; exists {
		panic(fmt.Sprintf("rpc: 方法 %s 重复注册", spec.Name))
	}

	if spec.MaxParams == 0 {
		spec.MaxParams = len(spec.Params)
	}

	r.methods[spec.Name] = spec
	r.byNS[spec.Namespace] = append(r.byNS[spec.Namespace], spec.Name)
	sort.Strings(r.byNS[spec.Namespace])
}

// MustRegister 是 Register 的链式形式。
func (r *Registry) MustRegister(specs ...*MethodSpec) *Registry {
	for _, s := range specs {
		r.Register(s)
	}
	return r
}

// Lookup 查找方法。
func (r *Registry) Lookup(name string) (*MethodSpec, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	m, ok := r.methods[name]
	return m, ok
}

// Methods 返回所有已注册的方法名（已排序）。
func (r *Registry) Methods() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.methods))
	for name := range r.methods {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// MethodsIn 返回指定命名空间的方法名（已排序）。
func (r *Registry) MethodsIn(ns string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	src := r.byNS[ns]
	out := make([]string, len(src))
	copy(out, src)
	return out
}

// Count 返回已注册方法数量。
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.methods)
}

// ============================================================================
// 分发
// ============================================================================

// Dispatcher 把 JSON-RPC 请求分发到注册的方法。
type Dispatcher struct {
	registry *Registry
	// ReadyFunc 判断链是否已初始化（用于 RequireLive 的方法）。
	ReadyFunc func() bool
	// MaxBatchSize 批量请求上限（防放大攻击）。
	MaxBatchSize int
}

// NewDispatcher 创建分发器。
func NewDispatcher(reg *Registry) *Dispatcher {
	return &Dispatcher{
		registry:     reg,
		MaxBatchSize: 10,
	}
}

// Handle 处理单个请求，返回响应（通知返回 nil）。
func (d *Dispatcher) Handle(ctx context.Context, raw []byte) *Response {
	var req Request
	if err := json.Unmarshal(raw, &req); err != nil {
		return &Response{
			JSONRPC: "2.0",
			Error:   NewError(CodeParseError, "JSON 解析失败", err.Error()),
		}
	}

	resp := d.handleOne(ctx, &req)
	if req.IsNotification() {
		return nil
	}
	if resp != nil {
		resp.ID = req.ID
	}
	return resp
}

// HandleBatch 处理批量请求。
func (d *Dispatcher) HandleBatch(ctx context.Context, raw []byte) []*Response {
	trimmed := strings.TrimSpace(string(raw))
	if len(trimmed) == 0 || trimmed[0] != '[' {
		// 不是数组：按单请求处理
		r := d.Handle(ctx, raw)
		if r == nil {
			return nil
		}
		return []*Response{r}
	}

	var reqs []Request
	if err := json.Unmarshal(raw, &reqs); err != nil {
		return []*Response{{
			JSONRPC: "2.0",
			Error:   NewError(CodeParseError, "批量请求解析失败", err.Error()),
		}}
	}

	// 空数组是非法的
	if len(reqs) == 0 {
		return []*Response{{
			JSONRPC: "2.0",
			Error:   NewError(CodeInvalidRequest, "批量请求不能为空"),
		}}
	}

	// 防放大：限制批量大小
	if len(reqs) > d.MaxBatchSize {
		return []*Response{{
			JSONRPC: "2.0",
			Error: NewError(CodeLimitExceeded,
				fmt.Sprintf("批量请求上限 %d，实际 %d", d.MaxBatchSize, len(reqs))),
		}}
	}

	out := make([]*Response, 0, len(reqs))
	for i := range reqs {
		if resp := d.handleOne(ctx, &reqs[i]); resp != nil {
			resp.ID = reqs[i].ID
			out = append(out, resp)
		}
	}
	if len(out) == 0 {
		return nil // 全是通知
	}
	return out
}

// handleOne 处理单个请求。
func (d *Dispatcher) handleOne(ctx context.Context, req *Request) *Response {
	// 校验 jsonrpc 版本。允许缺省（部分老客户端不发送）。
	if req.JSONRPC != "" && req.JSONRPC != "2.0" {
		return &Response{
			JSONRPC: "2.0",
			Error:   NewError(CodeInvalidRequest, "jsonrpc 必须为 \"2.0\""),
		}
	}
	if req.Method == "" {
		return &Response{
			JSONRPC: "2.0",
			Error:   NewError(CodeInvalidRequest, "缺少 method"),
		}
	}

	spec, ok := d.registry.Lookup(req.Method)
	if !ok {
		return &Response{
			JSONRPC: "2.0",
			Error: NewError(CodeMethodNotFound,
				fmt.Sprintf("方法 %s 不存在", req.Method)),
		}
	}

	// 链未初始化时的行为：明确报错，而不是返回空数据
	if spec.RequireLive && d.ReadyFunc != nil && !d.ReadyFunc() {
		return &Response{
			JSONRPC: "2.0",
			Error:   NewError(CodeServerError, "链尚未初始化"),
		}
	}

	params, err := ParseParams(req.Params)
	if err != nil {
		return &Response{
			JSONRPC: "2.0",
			Error:   NewError(CodeInvalidParams, "参数解析失败", err.Error()),
		}
	}
	if len(params) > spec.MaxParams {
		return &Response{
			JSONRPC: "2.0",
			Error: NewError(CodeInvalidParams,
				fmt.Sprintf("方法 %s 最多接受 %d 个参数，实际 %d",
					req.Method, spec.MaxParams, len(params))),
		}
	}

	result, rpcErr := spec.Handler(ctx, params)
	if rpcErr != nil {
		return &Response{JSONRPC: "2.0", Error: rpcErr}
	}
	return &Response{JSONRPC: "2.0", Result: result}
}

// ============================================================================
// 参数辅助
// ============================================================================

// Param 按索引取参数，缺失返回错误。
func Param(params []json.RawMessage, i int, name string) (json.RawMessage, *Error) {
	if i >= len(params) {
		return nil, NewError(CodeInvalidParams,
			fmt.Sprintf("缺少参数 %d（%s）", i, name))
	}
	return params[i], nil
}

// OptionalParam 按索引取可选参数，缺失返回 nil。
func OptionalParam(params []json.RawMessage, i int) json.RawMessage {
	if i >= len(params) {
		return nil
	}
	return params[i]
}

// ParamUint64 按索引取整数参数。
func ParamUint64(params []json.RawMessage, i int, name string) (uint64, *Error) {
	raw, err := Param(params, i, name)
	if err != nil {
		return 0, err
	}
	v, perr := DecodeUint64(raw)
	if perr != nil {
		return 0, NewError(CodeInvalidParams,
			fmt.Sprintf("参数 %s 非法: %v", name, perr))
	}
	return v, nil
}

// ParamBytes 按索引取字节参数。
func ParamBytes(params []json.RawMessage, i int, name string) ([]byte, *Error) {
	raw, err := Param(params, i, name)
	if err != nil {
		return nil, err
	}
	v, perr := DecodeBytes(raw)
	if perr != nil {
		return nil, NewError(CodeInvalidParams,
			fmt.Sprintf("参数 %s 非法: %v", name, perr))
	}
	return v, nil
}

// ParamAddress 按索引取地址参数。
func ParamAddress(params []json.RawMessage, i int, name string) (types.Address, *Error) {
	raw, err := Param(params, i, name)
	if err != nil {
		return types.Address{}, err
	}
	v, perr := DecodeAddress(raw)
	if perr != nil {
		return types.Address{}, NewError(CodeInvalidParams,
			fmt.Sprintf("参数 %s 非法: %v", name, perr))
	}
	return v, nil
}
