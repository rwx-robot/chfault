# chfault

> 用 Go 写的区块链框架。v0 交付联盟链 / 应用链，架构预留无许可公链能力。

**状态：M0（规范与骨架）** —— 代码量很少，但地基已就位。

---

## 这是什么

一个**可插拔的区块链框架**，不是一条具体的链：

- **联盟链 / 私链 / 应用链** 优先：许可验证者集、企业可运维
- **EVM 兼容**：Solidity、Hardhat、Foundry 零改动接入
- **100% Go**：静态单二进制，无运行时依赖
- **预留公链路径**：联盟链与公链的差异被收敛为 6 个可替换接口（见 `docs/blueprint/10`）

## 文档在哪

**所有设计文档在 `../docs/`**，代码仓库内只保留 `spec/`（字节级规范，必须与实现同版本）。

| 想做什么 | 读什么 |
|---------|--------|
| 快速了解 | [`../docs/HANDOVER.md`](../docs/HANDOVER.md) —— 交接文档，15 分钟可开工 |
| 看施工图 | [`../docs/blueprint/`](../docs/blueprint/) —— 10 章 |
| 知道为什么这么定 | [`../docs/adr/README.md`](../docs/adr/README.md) —— 19 条决策 |
| 写实现代码 | `spec/` —— 字节级规范，**实现与规范冲突时改实现** |

---

## 目录结构

```
chfault/
├── spec/              字节级规范（唯一真相来源）
├── types/             领域类型（具名类型，非裸 []byte）
├── crypto/            keccak256、签名、大端编码、Merkle、Bloom
├── storage/           KVStore 抽象 + Pebble 实现 + 内存实现
├── state/             状态管理 + journal 回滚 + 账户模型
├── chain/             区块、交易、收据、链级计算
├── vm/                EVM 适配（M1）
├── consensus/         共识（M2）
├── mempool/           交易池（M1）
├── network/           libp2p（M2）
├── rpc/               JSON-RPC（M1）
├── internal/lint/     determinism 分析器 ★
├── cmd/               CLI 与工具入口
├── test/              仿真、集成、混沌、基准
└── deploy/            Docker / Helm / Grafana
```

**依赖方向（CI 强制）**：

```
types ← crypto ← storage ← state ← chain ← vm
                                    ↑
                              consensus ← network
                                    ↑
                                 mempool ← rpc
```

四条硬规则（见 `.golangci.yml`）：
1. `chain` 不得 import `consensus`
2. `consensus` / `vm` 不得 import `network`
3. `types` 是叶子包
4. 核心包不得用 `time` / `math/rand`（用注入的 Clock 与确定性派生）

---

## ⚠️ 三条必须知道的规矩

### 1. 核心包禁止 `for range map`

Go 的 map 迭代顺序是**随机化的**（语言故意如此）。用它决定顺序会导致链分叉，
而且**单元测试永远测不出来** —— 每次是"某个随机顺序"，测试照样通过。

正确写法：

```go
import ("maps"; "slices")

for _, k := range slices.Sorted(maps.Keys(m)) { ... }
```

`internal/lint/determinism` 会在 CI 拦截违规。

### 2. 禁止 `time.Now()` / `math/rand` / 浮点进入状态路径

时间只能用注入的 Clock 或区块头的 timestamp；
随机只能用 `crypto.DeriveRandomness(prevHash, height)`；
比率用**基点整数**（`6667` 而非 `0.6667`）。

### 3. 不得修改 `spec/` 与 `../docs/adr/`

规范与决策是人类决策。**发现问题请报告，不要自己改。**

---

## 开发

```bash
make help              # 看所有命令

make build             # 编译
make test              # 单元测试
make test-race         # 竞态检测
make test-determinism  # ★ 多环境一致性（不同 GOMAXPROCS/GOGC 结果必须相同）
make lint-determinism  # ★ 确定性分析器
make cross-build       # 四平台交叉编译
make ci                # 本地跑完整检查
```

**提交前至少跑 `make ci`。**

---

## 当前进度

| 里程碑 | 内容 | 状态 |
|--------|------|------|
| **M0** | 规范与骨架 | 🚧 进行中 |
| M1 | 单节点链（EVM + RPC + CLI） | ⏳ 阻塞于 M0 |
| M2 | 多节点共识（BFT + 同步 + 仿真） | ⏳ 阻塞于 M1 |
| M3 | 可用产品（SDK + 监控 + 部署） | ⏳ 阻塞于 M2 |
| M4 | 公链能力验证（PoS + WASM） | ⏳ 阻塞于 M3 |

进度以 **DoD 勾选数**度量（共 32 项），不设时间周期。
进度看板见 [`../docs/blueprint/09`](../docs/blueprint/09-里程碑·验收·测试.md) 末节。

---

## 许可

**待定** —— geth 的 `core/vm` 与 `trie` 是 **LGPLv3**（已实测，v1.17.5 全库零 MIT 文件）。
需要决定是接受 LGPLv3 并开源，还是换 `evmone`（引入 cgo）。见 `../docs/adr/README.md` ADR-016。

**注意**：M0 不依赖 geth，所以这个决定不阻塞当前工作。
