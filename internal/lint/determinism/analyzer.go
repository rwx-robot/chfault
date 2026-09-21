// Package determinism 提供一个静态分析器，用于拦截会导致区块链状态分叉的确定性违规。
//
// 背景：Go 从 1.0 起就故意随机化 map 的迭代顺序（Go 1.12 后随机化更彻底）。
// 任何用 map 遍历决定顺序的代码（打包交易、序列化、遍历验证者）在不同节点上
// 会产生不同结果，导致状态根分叉。
//
// 更危险的是：这类错误在单元测试中不会暴露 —— 单跑一次是"某个随机顺序"，
// 测试照样通过。只有多节点运行才会炸，且极难定位。
//
// 本分析器是 chfault 最重要的一道防线。它必须在写任何业务代码之前就位。
package determinism

import (
	"go/ast"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

// Analyzer 是 determinism 分析器的入口。
var Analyzer = &analysis.Analyzer{
	Name:     "determinism",
	Doc:      "禁止在共识/状态路径上遍历 map（Go 的 map 迭代顺序是随机的，会导致链分叉）",
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      run,
}

// ProtectedPackages 是受保护的包路径片段。
// 这些包中的任何 map 遍历都会被视为违规。
var ProtectedPackages = []string{
	"/types",
	"/crypto",
	"/storage",
	"/state",
	"/chain",
	"/vm",
	"/consensus",
	"/mempool",
}

// ForbiddenIdents 是在受保护包中禁止直接使用的标识符。
// key 是 import 路径，value 是禁用的选择器集合。
var ForbiddenIdents = map[string][]string{
	"time": {"Now", "Since", "Tick", "After"},
	"math/rand": {
		"Int", "Intn", "Float64", "Float32", "Perm", "Shuffle",
		"Read", "New", "NewSource", "Uint32", "Uint64", "Int31", "Int63",
	},
}

// run 执行分析。
func run(pass *analysis.Pass) (any, error) {
	pkgPath := pass.Pkg.Path()
	if !isProtected(pkgPath) {
		return nil, nil
	}

	insp := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)

	nodeFilter := []ast.Node{
		(*ast.RangeStmt)(nil),
		(*ast.SelectorExpr)(nil),
	}

	insp.Preorder(nodeFilter, func(n ast.Node) {
		switch stmt := n.(type) {
		case *ast.RangeStmt:
			checkRangeMap(pass, stmt)
		case *ast.SelectorExpr:
			checkForbiddenIdent(pass, pkgPath, stmt)
		}
	})

	return nil, nil
}

// checkRangeMap 检查 `for ... range <map>`。
func checkRangeMap(pass *analysis.Pass, stmt *ast.RangeStmt) {
	if stmt.X == nil {
		return
	}

	tv, ok := pass.TypesInfo.Types[stmt.X]
	if !ok {
		return
	}

	if _, isMap := tv.Type.Underlying().(*types.Map); isMap {
		pass.Reportf(stmt.Pos(),
			"确定性违规：禁止 range 遍历 map（Go 的 map 迭代顺序是随机的，会导致链分叉）。\n"+
				"\t改用显式排序，例如：\n"+
				"\t\tkeys := slices.Sorted(maps.Keys(m))\n"+
				"\t\tfor _, k := range keys { ... }\n"+
				"\tmap 可以用于查找（m[k]），但不得用于决定顺序。")
	}
}

// checkForbiddenIdent 检查 time.Now() / rand.Intn() 等不确定性调用。
func checkForbiddenIdent(pass *analysis.Pass, pkgPath string, sel *ast.SelectorExpr) {
	// 只处理 pkg.Ident 形式（x 是包名）
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return
	}

	// 找到这个标识符对应的 import 路径
	importPath := resolveImportPath(pass, ident.Name)
	if importPath == "" {
		return
	}

	forbidden, ok := ForbiddenIdents[importPath]
	if !ok {
		return
	}

	for _, name := range forbidden {
		if sel.Sel.Name == name {
			pass.Reportf(sel.Pos(),
				"确定性违规：%s.%s 在受保护包中被禁止（%s）。\n"+
					"\t时间应使用注入的 Clock 或区块头的 timestamp；\n"+
					"\t随机应使用确定性派生（如 keccak256(prevHash ‖ height)）。",
				ident.Name, sel.Sel.Name, pkgPath)
			return
		}
	}
}

// resolveImportPath 根据包名找到 import 路径。
func resolveImportPath(pass *analysis.Pass, pkgName string) string {
	for _, imp := range pass.Pkg.Imports() {
		if imp.Name() == pkgName {
			return removeVersionSuffix(imp.Path())
		}
	}
	return ""
}

// removeVersionSuffix 去掉 /v4 之类的版本后缀，便于匹配。
func removeVersionSuffix(path string) string {
	// 例如 github.com/foo/bar/v4 → github.com/foo/bar
	parts := strings.Split(path, "/")
	if len(parts) > 1 {
		last := parts[len(parts)-1]
		if len(last) > 1 && last[0] == 'v' && isNumeric(last[1:]) {
			return strings.Join(parts[:len(parts)-1], "/")
		}
	}
	return path
}

func isNumeric(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) > 0
}

// isProtected 判断包路径是否受保护。
func isProtected(pkgPath string) bool {
	for _, p := range ProtectedPackages {
		if strings.HasSuffix(pkgPath, p) || strings.Contains(pkgPath, p+"/") {
			return true
		}
	}
	return false
}
