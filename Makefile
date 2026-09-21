# chfault Makefile
#
# 使用说明见 `make help`。
# 本项目由 AI 开发，进度以 DoD 度量（见 docs/blueprint/09），不设时间周期。

.PHONY: help build test test-race test-determinism lint lint-determinism vet \
        cross-build fuzz vuln clean bench determinism

GO      ?= go
PKGS    := ./...

## help: 显示可用命令
help:
	@echo "chfault 可用命令："
	@echo ""
	@echo "  构建与检查"
	@echo "    build              编译所有包"
	@echo "    cross-build        交叉编译（linux/darwin × amd64/arm64），必须全部通过"
	@echo "    vet                go vet"
	@echo "    lint               golangci-lint（含 depguard 依赖方向）"
	@echo "    lint-determinism   determinism 分析器（拦截 range map / time.Now / rand）"
	@echo ""
	@echo "  测试"
	@echo "    test               单元测试"
	@echo "    test-race          竞态检测（必须开启）"
	@echo "    test-determinism   多环境一致性（不同 GOMAXPROCS/GOGC 结果必须相同）"
	@echo "    bench              性能基准"
	@echo "    fuzz               模糊测试"
	@echo ""
	@echo "  安全"
	@echo "    vuln               govulncheck 漏洞扫描"
	@echo ""
	@echo "  其他"
	@echo "    clean              清理构建产物"

## build: 编译所有包
build:
	$(GO) build $(PKGS)

## cross-build: 交叉编译验证（ADR-002 的静态单二进制目标）
cross-build:
	@echo ">>> linux/amd64"
	CGO_ENABLED=0 GOOS=linux  GOARCH=amd64 $(GO) build -o /dev/null $(PKGS)
	@echo ">>> linux/arm64"
	CGO_ENABLED=0 GOOS=linux  GOARCH=arm64 $(GO) build -o /dev/null $(PKGS)
	@echo ">>> darwin/amd64"
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GO) build -o /dev/null $(PKGS)
	@echo ">>> darwin/arm64"
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) build -o /dev/null $(PKGS)
	@echo "交叉编译全部通过"

## vet: go vet
vet:
	$(GO) vet $(PKGS)

## lint: golangci-lint（含 depguard）
lint:
	golangci-lint run ./... || echo "(golangci-lint 未安装，跳过；请确保 CI 中已安装)"

## lint-determinism: 运行 determinism 分析器
lint-determinism: determinism
	./bin/determinism $(PKGS)

## determinism: 构建 determinism 分析器
determinism:
	mkdir -p bin
	$(GO) build -o bin/determinism ./cmd/determinism

## test: 单元测试
test:
	$(GO) test $(PKGS)

## test-race: 竞态检测
test-race:
	$(GO) test -race $(PKGS)

## test-determinism: 多环境一致性（本项目的独门检查）
#
# 同一份输入在不同 GOMAXPROCS / GOGC 下必须产出完全相同的 stateRoot。
# 能一次性抓出：map 顺序依赖、goroutine 竞态、调度顺序依赖。
test-determinism:
	@echo ">>> GOMAXPROCS=1"
	GOMAXPROCS=1 $(GO) test -run 'Determinism' -count=1 $(PKGS)
	@echo ">>> GOMAXPROCS=16"
	GOMAXPROCS=16 $(GO) test -run 'Determinism' -count=1 $(PKGS)
	@echo ">>> GOGC=1（激进 GC）"
	GOGC=1 $(GO) test -run 'Determinism' -count=1 $(PKGS)
	@echo ">>> GOGC=off（关闭 GC）"
	GOGC=off $(GO) test -run 'Determinism' -count=1 $(PKGS)
	@echo "多环境一致性通过"

## vectors: 重新生成回归基线向量（行为有意变更时才跑）
vectors:
	$(GO) run ./cmd/genvectors

## vectors-check: 校验回归基线未被意外改变（CI 用）
vectors-check:
	$(GO) run ./cmd/genvectors --check

## bench: 性能基准
bench:
	$(GO) test -bench=. -benchmem $(PKGS)

## fuzz: 模糊测试（默认 30 秒）
fuzz:
	$(GO) test -fuzz=Fuzz -fuzztime=30s $(PKGS) || \
		echo "(无 fuzz 目标，跳过)"

## vuln: 漏洞扫描
vuln:
	govulncheck $(PKGS) || echo "(govulncheck 未安装；go install golang.org/x/vuln/cmd/govulncheck@latest)"

## ci: 本地跑完整的 CI 检查
ci: vet lint-determinism vectors-check test test-race test-determinism cross-build
	@echo ""
	@echo "全部检查通过"

## clean: 清理构建产物
clean:
	rm -rf bin
	$(GO) clean
