# JsOwl

JsOwl 是一个使用 Go 编写的高性能 Web 安全信息收集工具和可复用库。它收集目标页面、JavaScript、Webpack/RequireJS chunk 与 SPA 运行时资源，通过 RE2 兼容规则提取 URL、API 路径和敏感信息，并生成 JSON 与自包含 HTML 报告。

> 仅可用于已获得明确授权的安全测试环境。报告会保留完整敏感值，请严格限制访问并妥善清理。

## 功能

- `direct`：使用 [enetx/surf](https://github.com/enetx/surf) 并发执行有界 GET 请求。
- `browser`：使用 Rod 和本地 Chrome/Chromium 渲染页面，在网络空闲后继续等待异步 JavaScript。
- `auto`：默认先运行快速 direct 扫描；检测到 SPA、动态 import、History 路由等信号后再启动 Rod。浏览器不可用时保留 direct 结果并记录降级原因。
- 从 HTML、内联脚本、普通 bundle、Webpack 3/4/5 runtime 和 RequireJS 配置中递归发现脚本、chunk、路由与 API。
- 同源或显式 allowlist 的 API 仅使用 GET 获取并继续执行正则匹配；不会提交表单或发送 POST/PUT/PATCH/DELETE。
- 页面明确引用的跨域脚本默认允许下载分析；跨域 API 默认不会探测。
- 未配置 User-Agent 时，每个目标随机选择一个现代桌面 UA，并在该目标的 Surf、Rod、chunk 和 API 请求中保持一致。
- 可选保存 JS/chunk；API 响应正文永不保存。

## 构建

需要 Go 1.25 或兼容版本。

```bash
go build -o jsowl ./cmd/jsowl
go test ./...
```

## CLI

CLI 没有子命令，常用示例：

```bash
jsowl -u https://example.com
jsowl -u https://a.example -u https://b.example
jsowl -l targets.txt
jsowl -u https://example.com -c config.yml
jsowl -u https://example.com -o reports
jsowl -u https://example.com -m direct
jsowl -u https://example.com -t 32
jsowl -u https://example.com -H "Authorization: Bearer token"
jsowl --check -c config.yml
jsowl -v
jsowl -h
```

参数：

| 参数 | 作用 |
|---|---|
| `-u, --url` | 目标 URL，可重复 |
| `-l, --list` | 目标文件，忽略空行和 `#` 注释 |
| `-c, --config` | YAML 配置文件 |
| `-o, --output` | 覆盖报告目录 |
| `-m, --mode` | `auto`、`direct` 或 `browser` |
| `-H, --header` | `Name: value` 请求头，可重复 |
| `-t, --threads` | 覆盖单目标资源并发数 |
| `-v, --version` | 显示版本 |
| `--check` | 检查配置、规则、输出目录、本地浏览器、CDP、JS 与注入快照 |

CLI 显式值优先于 YAML，YAML 优先于内置默认值。若未传 `-c`，当前目录存在 `config.yml` 时会自动加载；不存在则直接使用默认配置。

## 配置

完整模板见 [config.example.yml](config.example.yml)。关键默认值如下：

```yaml
mode: auto
request:
  timeout: 15s
  target_timeout: 5m
  retry: 1
  user_agent: ""
browser:
  path: ""
  wait: 3s
  idle: 800ms
  timeout: 45s
  headless: true
  collector_script: ""
concurrency:
  targets: 4
  resources_per_target: 16
limits:
  max_depth: 5
  max_resources: 2000
  max_body_size: 10MiB
scope:
  allow_domains: []
  fetch_external_scripts: true
  probe_external_endpoints: false
output:
  directory: ./jsowl-report
  json: true
  html: true
  download_js: false
  js_directory: js
```

Rod 的路径、等待、网络空闲、超时、窗口模式和注入脚本只通过 YAML 配置。`wait` 默认 `3s`，表示页面加载并达到网络空闲后，继续等待异步 JS 的时间。`headless: false` 可显示浏览器窗口，等待时间仍受 `browser.timeout` 限制。

JsOwl 始终显式解析本地浏览器路径，并禁用了 Rod 的自动下载路径。找不到 Chrome/Chromium 时，`browser` 模式返回错误，`auto` 模式降级到 Surf。

若需要使用外部收集器：

```yaml
browser:
  collector_script: 'D:\project\exercise\reverse\转子女神\grok\assets\collect_resource_urls.js'
```

内置收集器是该脚本的增强版，会在页面脚本之前注入，并合并 fetch、XHR、MutationObserver、DOM、Performance API 与 CDP 网络响应。

## 输出

```text
jsowl-report/
└── example.com/
    ├── report.json
    ├── report.html
    └── js/
        ├── app.<hash>.js
        └── chunks/
            └── users.<hash>.js
```

`output.download_js` 默认为 `false`。开启后只保存普通 JS 和 chunk，文件名会清理 Windows 非法字符并使用稳定哈希避免 query/重名覆盖。超过正文上限的脚本不会保存，并在结果中记录 Issue。

JSON 完整序列化 `Result`；HTML 是无需外部资源的交互报告。两者都会保留完整敏感值，不做脱敏。

## Go 库

单目标：

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

可使用 `jsowl.WriteJSONReport`、`jsowl.WriteHTMLReport` 输出报告，使用 `jsowl.CheckBrowser` 检查本地浏览器。完整可编译示例见 [examples/library/main.go](examples/library/main.go)。

## 自定义规则

自定义规则使用 Go RE2 语法：

```yaml
rules:
  disabled: [secret.account]
  custom:
    - id: secret.internal-token
      name: Internal token
      category: sensitive
      severity: high
      pattern: '(?i)internal[_-]?token\s*[:=]\s*["'']([^"'']+)'
      group: 1
      description: Internal test token
      enabled: true
```

无效正则、捕获组、模式、时间、并发和资源边界会在扫描前拒绝。
