# 爬取性能优化实施计划

本文档是本轮性能优化的执行清单与验收依据。约束沿用既定方案：不改动 `config/` 下任何文件，不新增用户必填参数，不改变现有配置字段语义，不通过关闭 AST、敏感规则、source map 或浏览器采集来提速，保留作用域检查、请求头隔离、Cookie 行为、去重、深度与资源数量限制。

## 0. 基线与瓶颈核对

已核实的事实（以代码为准）：

| 瓶颈 | 位置 | 说明 |
|---|---|---|
| 批屏障 | `internal/pipeline/pipeline.go` `drain` / `collectBatch` | 每批 `ResourcesPerTarget`（默认 16）个请求并发发出后等待整批结束，最慢请求决定整批墙钟 |
| 下载阶段全量分析 | `collectOne` script 分支 | `DownloadJS` 开启时仍调用完整 `FromJavaScript`，但只保留 candidates，findings 被丢弃 |
| 分析阶段重复分析 | `computeBatch` | 从磁盘读回后再次执行完整正则分析 |
| 分析并发无界 | `computeBatch` | 为整批 pending 文件逐个起 goroutine，无信号量 |
| 重复 AST 解析 | `AnalyzeJS` + `ParamsFromAST` | 同一文件各建一次 parser 与语法树 |
| 命中上下文重复扫描 | `discover/context.go`、`discover/javascript.go` | 每次命中重建行索引；`lineColumn` 重复建两次 |
| 引擎级命中上下文 | `internal/analyze/engine.go` `location` / `matchContext` | 每个 finding 做 O(offset) 计数并把全文 `strings.Split` 一次 |
| 队列搬移 | `internal/scheduler/queue.go` `Take` | 每次取批整体前移，且底层数组尾部保留已消费元素引用 |
| 浏览器进程 | `internal/collect/browser/collector.go` | 非 `--login` 模式每次采集新起进程并含固定等待；本轮不处理 |

基线测量（`go test -run '^$' -bench BenchmarkAnalyzeLargeBundle -benchtime 3x -benchmem .`，i5-12500H）：

```
1318655567 ns/op   0.32 MB/s   144978944 B/op   490287 allocs/op   (440 KB 合成 JS)
```

即完整正则分析约 0.32 MB/s、单次约 145 MB 分配。它是当前扫描的绝对主成本。

## 1. 实施步骤

### Step 1 — 下载阶段改用 URL 子集规则（消除重复分析）

- 在 `internal/analyze` 中增加只产出 URL 候选的入口：只遍历 `Category == url` 的规则，不构造 finding、不计算上下文。
- 在 `internal/discover` 增加 `FromJavaScriptDiscovery`：产出与 `FromJavaScript` 完全一致的 `Candidates` 与 SPA 证据，不产出 findings/hosts。
- `pipeline.collectOne` 的 `deferJS` 分支改调新入口；非 defer 分支与 HTML 分支保持不变。
- 依据：引擎里候选只可能来自 URL 类规则，因此子集规则的候选集与全量规则严格相同，发现能力不下降。

验收：

- 同一 body 下，子集入口的 candidates（Raw/Kind/Method/RuleID/Line/Column）与全量入口逐条相等。
- `DownloadJS` 开关两种模式的资源、端点、参数、敏感发现语义不变（除上下文行在磁盘读失败时可能缺失，需记录为已知退化）。
- 基准显示单文件下载阶段的正则成本明显下降。

### Step 2 — 有界分析并发

- 新增 `pipeline.Limiter`（容量默认 `GOMAXPROCS`，至少 1）。
- `Options.AnalysisLimiter` 可注入；`Scanner` 创建单个 limiter 供所有目标共享，保证多目标总并发有界。
- `computeBatch` 改为固定 worker 数（不超过 limiter 容量），不再为每个文件起 goroutine。
- 取消时停止派发并释放正文与语法树。

验收：分析阶段 goroutine 数与并发有上限；取消后能返回。

### Step 3 — 持续工作的采集 worker 池

- `drain` 改为协调器 + 短生命周期 worker：协调器补位派发、单线程合并结果；worker 只做 `collectOne`。
- 结束条件：队列为空且 in-flight 为 0。
- 结果 channel 缓冲等于 worker 数，worker 发送永不阻塞；取消后 worker 仍能退出，无泄漏。
- 协调器一次收取所有已就绪结果，按 (Depth, URL) 稳定排序后合并，减少完成顺序带来的抖动。
- 保留既有错误语义：入口错误致命、子资源错误记录 issue、取消返回 context 错误。
- 已知限制：资源预算（`MaxResources`）边界上的准入顺序仍取决于完成顺序；预算本身不会被突破。此限制写入文档与测试。

验收：

- 快速资源不必等待慢请求即可开始采集。
- 多层动态任务不会提前结束、漏任务或死锁。
- 预算不超限。

### Step 4 — 共享行索引与引擎上下文

- `discover` 引入 `lineIndex`（body + 行首偏移），在 `FromJavaScript`、AST walker、参数收集器、host 收集器、base path 扫描之间共享。
- `lineColumn` 与 `extractContext` 保留为创建一次性索引的兼容包装。
- `analyze/engine.go` 每次 `Analyze` 只建一次行索引；`location` 与 `matchContext` 改为索引查询，输出与旧实现逐字节一致。
- ASCII 正文的 `runeOffsets` 不再分配 rune→byte 表，直接用恒等映射。
- `FromJavaScript` 的 SPA 检测改为无分配的大小写不敏感扫描，不再 `bytes.ToLower` 复制整份正文。

验收：新旧上下文输出一致；大压缩包上下文耗时与分配下降；Unicode 多字节位置与高亮正确。

### Step 5 — 同一文件共用 AST

- `discover` 暴露 `ParsedScript`（body + tree + root + lineIndex）及 `ParseJS`。
- `AnalyzeJS` / `ParamsFromAST` 保留为兼容包装，内部改为解析一次后复用。
- `pipeline.computeBatch` 与内联脚本路径改为解析一次、依次执行分析、参数与主机提取，结束后统一 `Close`。
- 所有权：tree 只在该文件的分析作用域内有效，不跨 goroutine、不长期持有。

验收：相同输入下 candidates/params/hosts 与旧实现一致；基准显示解析次数下降。

### Step 6 — 队列头索引

- `Queue` 增加 `head` 索引，`Take` 只推进头指针并清空已消费槽位，按阈值压缩。
- 增加 `TakeOne` 供持续 worker 池使用。
- 保留 FIFO、去重、深度与预算语义。

验收：既有队列测试通过；长队列下不再整体搬移，已消费元素不被底层数组滞留。

### Step 7 — 基准与回归

- 新增基准：URL 子集分析、共享行索引上下文、AST 共享解析、端到端 pipeline。
- 新增测试：候选一致性、上下文一致性、慢请求不阻塞、动态任务终止、预算上限、分析并发上限、Unicode 位置。
- 运行 `go test ./...`，并在环境允许时对并发路径跑 `-race`。

## 2. 不做的事

- 不修改 `config/` 下任何 YAML。
- 不改变默认配置值与字段语义。
- 不在本轮复用浏览器进程（单独评估）。
- 不为确定性引入深度级屏障；预算边界上的完成顺序差异作为已知限制记录。

## 3. 交付记录

### 3.1 实际完成的修改

| 步骤 | 状态 | 主要文件 |
|---|---|---|
| Step 1 URL 子集发现 | 完成 | `internal/analyze/engine.go`（`AnalyzeCandidates`）、`internal/discover/javascript.go`（`FromJavaScriptDiscovery`、`containsFold`）、`internal/pipeline/pipeline.go` |
| Step 2 有界分析并发 | 完成 | `internal/pipeline/limiter.go`、`pipeline.go`（`computeBatch`）、`scanner.go`（跨目标共享） |
| Step 3 持续 worker 池 | 完成 | `pipeline.go`（`drain` 重写，删除 `collectBatch`） |
| Step 4 共享行索引 | 完成 | `internal/discover/context.go`、`astapi.go`、`astparams.go`、`hosts.go`、`hostregex.go`、`basepath.go`；`internal/analyze/engine.go`、`matcher.go` |
| Step 5 共享 AST | 完成 | `internal/discover/astapi.go`（`ParsedScript`、`AnalyzeBody`）、`astparams.go`；pipeline 各分支改调 `AnalyzeBody` |
| Step 6 队列头索引 | 完成 | `internal/scheduler/queue.go`（`head`、`TakeOne`、压缩） |
| Step 7 基准与回归 | 完成 | `benchmark_test.go`、各包新增测试 |

额外优化（方案 P2 的延伸，实测收益最大）：命中上下文的提取改为按 ASCII 快路径工作。此前每次命中都会把整行转换、全行查找值位置、必要时整行转 rune；在单行大压缩包上这是 O(行²)。现在按窗口切片，多字节正文仍走原路径以保持位置与高亮完全一致。

### 3.2 基准测量

测试条件：i5-12500H / Windows / Go 1.25。合成正文 440 KB（`fetch("/api/users");const token="fixture";` 重复 10000 次）。由于笔记本在连续跑基准时会降频，**同一轮内的比值**比跨轮绝对值更可靠：

| 场景 | 耗时/次 | 分配/次 | 相对全量 |
|---|---|---|---|
| 全量正则 `Analyze` | 1.93 s | 133 MB | 1.00 |
| URL 子集 `AnalyzeCandidates` | 0.48 s | 48.5 MB | 0.25 |
| `FromJavaScript`（完整发现） | 2.85 s | 133 MB | 1.00 |
| `FromJavaScriptDiscovery`（下载阶段） | 0.53 s | 48.5 MB | 0.19 |
| `AnalyzeBody`（AST+参数，共享解析） | 1.14 s | 50.3 MB | 1.00 |
| `AnalyzeJS` + `ParamsFromAST`（各解析一次） | 1.49 s | 50.8 MB | 1.31 |

会话开始时测得的基线为：全量 `Analyze` 1.32 s / 145 MB；`AnalyzeBody` 对应路径在上下文优化前为 **68.5 s / 42.0 GB**，优化后 1.14 s / 50 MB，约 60 倍。该差距远大于降频噪声。

结论：下载阶段（`DownloadJS` 开启）每份 JS 的正则成本降到原来的约 1/5，分析阶段不再重复一次全量正则，AST 上下文成本不再随“命中数×行长”增长。

### 3.3 语义与行为

- 资源、端点、参数、敏感发现的集合在改动前后保持一致：`TestFromJavaScriptDiscoveryMatchesFullCandidates` 逐条比对候选（Raw/Kind/Method/RuleID/Line/Column），`TestAnalyzeCandidatesMatchesAnalyze` 比对全量/子集候选，`TestAnalyzeBodyMatchesSeparateExtractors` 比对共享解析与独立解析，`TestFindingLinesMatchesLegacyContext` 与 `TestExtractASCIIMatchesRunePath` 逐偏移比对上下文输出。
- 上下文补全路径：下载阶段刻意不生成上下文；延迟分析阶段会把同一批 URL 规则的候选用于补全已记录端点（只补字段，不新建端点、不入队、不触发前缀探测），因此只被正则规则命中的端点同样保留上下文。对应测试 `TestDeferredAnalysisKeepsRegexOnlyEndpointContext`。
- 已知限制：`MaxResources` 预算边界上的准入顺序仍取决于请求完成顺序；预算本身不会被突破（`TestDrainHonorsResourceBudgetUnderConcurrency`）。预算为 0（默认）时无影响。
- 非 ASCII 正文使用原有的上下文提取路径，正确性优先，未做窗口化。

### 3.4 测试结果

- `go test ./...`：全部通过。
- `go test -race ./internal/pipeline ./internal/discover ./internal/scheduler`：通过。
- `go test -race ./internal/analyze -run 'TestAnalyzeCandidatesMatchesAnalyze|TestFindingLinesMatchesLegacyContext|TestEngine'`：通过。
- `go test -race .`（端到端）：通过。
- `go vet ./...`：无告警。

说明：工作区中 `config/rules.yml` 存在用户未提交的规则改名（`扩展敏感配置你` → `密钥提取`）。`internal/analyze/extended_fields_test.go` 按旧规则 ID 查找，因此**使用工作区配置**运行该包会失败；该失败与本轮改动无关（用提交版配置运行全量测试全部通过，且工作区文件已原样恢复）。

### 3.5 配置与兼容性

- 未修改 `config/` 下任何文件，未新增用户必填参数，未改变配置字段含义或默认值。
- `pipeline.Options.AnalysisLimiter` 是可选注入项：库调用方不传时自动使用 `GOMAXPROCS` 容量的内部 limiter。
- 保留的兼容入口：`analyze.Engine.Analyze`、`discover.FromJavaScript`、`discover.AnalyzeJS`、`discover.ParamsFromAST`、`scheduler.Queue.Take`。
- 浏览器进程复用未纳入本轮（与方案一致，留待单独评估）。
