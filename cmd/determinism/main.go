// Command determinism 是 determinism 分析器的独立入口。
//
// 用法：
//
//	go run ./cmd/determinism ./...
//
// 也可以集成进 golangci-lint（作为 plugin）。独立入口的价值是：
// 不依赖 golangci-lint 也能跑，CI 里多一道保险。
package main

import (
	"golang.org/x/tools/go/analysis/singlechecker"

	"github.com/chfault/chfault/internal/lint/determinism"
)

func main() {
	// singlechecker.Main 内部会调用 os.Exit，不返回值。
	singlechecker.Main(determinism.Analyzer)
}
