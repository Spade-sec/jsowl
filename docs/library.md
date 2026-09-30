# Go 库与 MCP Server

JsOwl 既是一个 CLI 工具，也是一个可复用的 Go 库（`github.com/youmulijiang/jsowl`），并通过独立的 `jsowl-mcp` 二进制对外提供 MCP 服务。

## 作为 Go 库使用

```bash
go get github.com/youmulijiang/jsowl
```

单目标扫描：

```go
cfg := jsowl.DefaultConfig()
scanner, err := jsowl.New(cfg)
result, err := scanner.Scan(ctx, jsowl.Target{URL: "https://example.com"})
```

批量扫描使用固定目标 worker 池，完成一个目标就流式返回：

```go
for item := range scanner.ScanBatch(ctx, targets) {
    if item.Err != nil {
        continue
    }
    fmt.Println(item.Result.Statistics)
}
```

实时进度：`scanner.SetProbeSink(ch)` 注册一个 channel，每个 API 探测完成即推送一个 `ProbeEvent`（状态码、方法、URL、证据来源），适合构建进度 UI。

报告输出与工具函数：

- `jsowl.WriteJSONReport(path, result)` — 写 JSON 报告
- `jsowl.WriteHTMLReport(path, result)` — 写自包含 HTML 报告
- `jsowl.WriteSplitReports(dir, result)` — 写分项 HTML/文本报告
- `jsowl.CheckBrowser(ctx, config.Browser)` — 检查本地浏览器可用性

完整可编译示例见 [examples/library/main.go](../examples/library/main.go)。

## MCP Server（`jsowl-mcp`）

JsOwl 还提供一个公开子包 `github.com/youmulijiang/jsowl/mcpserver`，通过 [Model Context Protocol](https://modelcontextprotocol.io)（stdio）把扫描能力暴露给任意 LLM 客户端。扫描在进程内运行，结果保存在内存中，同时报告文件落盘备查。

独立二进制 `cmd/jsowl-mcp` 是最简单的使用方式：

```bash
go build -o jsowl-mcp ./cmd/jsowl-mcp
```

在 MCP 客户端中配置（`-config` 可选，用于注入代理、浏览器路径、作用域、规则等基础配置）：

```json
{
  "mcpServers": {
    "jsowl": {
      "command": "/path/to/jsowl-mcp",
      "args": ["-dir", "/path/to/jsowl-reports", "-config", "/path/to/config.yml"]
    }
  }
}
```

可用工具：

| 工具 | 说明 |
|---|---|
| `jsowl_scan` | 扫描一个目标（支持 `mode: auto/direct/browser`、`base_url`、`headers`、`timeout_seconds`），返回 `scan_id` 与计数摘要，含浏览器是否降级（`browser_degraded`）及原因 |
| `jsowl_endpoints` | 列出某次扫描发现的 API 端点（方法、证据级别、源码位置与上下文） |
| `jsowl_sensitive` | 列出敏感信息发现（密钥、Token、凭证等） |
| `jsowl_parameters` | 查询端点参数细节 |

### 在 Go 项目中内嵌 MCP Server

`mcpserver` 是公开包，可以直接在自己的进程里起一个 MCP server：

```go
base, err := jsowl.LoadConfig("config.yml") // 或 nil 使用内置默认值
store := mcpserver.NewStore(reportDir, base)
go store.Run(ctx) // stdio 方式服务 LLM 客户端
```
