# JsOwl — JavaScript 信息收集与敏感信息扫描器

[![Go](https://img.shields.io/badge/Go-1.25%2B-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![Engine](https://img.shields.io/badge/Engine-Regex%20%2B%20Tree--sitter%20AST-4479A1)](docs/development.md)
[![Report](https://img.shields.io/badge/Report-JSON%20%7C%20HTML-ff6f00)](docs/output.md)
[![Rules](https://img.shields.io/badge/Rules-HaE%20Compatible-8A2BE2)](docs/rules.md)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)](docs/development.md)
[![MCP](https://img.shields.io/badge/MCP-Server-20c997)](docs/library.md)

**JsOwl** 是一个使用 Go 编写的高性能 JavaScript 信息收集与安全分析工具，同时也是一个可复用的 Go 库。它自动收集目标站点的页面、JavaScript、Webpack/RequireJS chunk 与 SPA 运行时资源，通过正则与 AST（Tree-sitter）提取 API 端点、参数、路由和敏感信息（密钥、Token、身份证、内网 IP 等），并生成 JSON 与自包含的交互式 HTML 报告——是 Web 安全测试、渗透测试信息收集阶段和攻击面梳理的自动化利器。

> **免责声明**：仅可用于已获得明确授权的安全测试环境。报告会保留完整敏感值，请严格限制访问并妥善清理。

## 核心能力

| 能力 | 说明 |
|---|---|
| **三种采集模式** | `direct`（高速 HTTP）/ `browser`（Rod 驱动本地 Chrome 渲染）/ `auto`（默认，先 direct 后按 SPA 信号自动升级浏览器） |
| **深度资源发现** | 递归发现脚本、Webpack chunk、RequireJS 配置、框架路由与 API，支持 source map 还原原始源码 |
| **敏感信息提取** | 兼容 [HaE](https://github.com/gh0stkey/HaE) 规则格式，正则 + AST 双引擎，内置密钥/凭证/指纹规则集 |
| **运行时交互** | 自动填表提交、事件点击、SPA 路由爬取，捕获页面真实发出的 API 请求（可选，默认关闭） |
| **登录态扫描** | `--login` 打开可见浏览器手动登录后，携带会话 Cookie 完成整批扫描（可带 `-u`，也可不带 `-u` 在浏览器里自行导航） |
| **AI 辅助分析** | `-ai` 接入大模型做参数完整性与敏感发现评级（可选，需配置 API Key） |
| **MCP Server** | 通过 [Model Context Protocol](https://modelcontextprotocol.io) 把扫描能力暴露给任意 LLM 客户端 |
| **多格式报告** | JSON + 自包含交互式 HTML 总览与分项报告（API / URL / 敏感信息 / 参数 / 路由 / 资源）+ 纯文本清单 |

## 快速开始

需要 Go 1.25+ 与 C 编译器（JavaScript AST 使用 Tree-sitter，必须启用 CGO）：

```bash
git clone https://github.com/youmulijiang/jsowl.git
cd jsowl
go build -o jsowl ./cmd/jsowl
```

扫描一个目标：

```bash
jsowl -u https://example.com                  # 基础扫描
jsowl -u https://example.com -m browser       # 强制浏览器渲染模式
jsowl -u https://example.com --login          # 手动登录后带会话扫描
jsowl --login                                 # 不指定 URL：打开浏览器自行导航，登录后扫描当前页
jsowl -u https://example.com --aff            # 开启运行时自动填表与交互
jsowl -l targets.txt -o reports               # 批量目标 + 自定义输出目录
jsowl --check                                 # 检查配置、规则与本地浏览器
```

扫描完成后在 `jsowl-report/example.com/` 下生成 `report.html`（交互式总览入口）、`report.json` 与分项报告。

## 示例输出

```text
https://example.com/ [18240] [200] [text/html; charset=utf-8]
[200] GET https://api.example.com/v2/user/info [runtime]
```

```text
jsowl-report/
└── example.com/
    ├── report.html          # 交互式总览 + 分项报告导航
    ├── report.json          # 完整 JSON 结果
    ├── API报告.html / url.txt / 敏感信息.txt ...
    └── js/                  # 下载保存的脚本与 chunk
```

## 文档

| 文档 | 内容 |
|---|---|
| [CLI 用法](docs/cli.md) | 全部命令行参数、目标配置、登录扫描、AI 分析 |
| [配置指南](docs/configuration.md) | 配置分层加载、浏览器选项、作用域控制、代理与请求头 |
| [自定义规则](docs/rules.md) | HaE 兼容规则与 JsOwl 原生规则格式、规则加载优先级 |
| [报告输出](docs/output.md) | 报告目录结构、各分项报告说明、下载保存策略 |
| [Go 库与 MCP](docs/library.md) | 作为库集成、批量扫描、MCP Server 接入 |
| [开发与构建](docs/development.md) | 构建要求、测试、架构与运行时流程 |

## 生态

- [HaE](https://github.com/gh0stkey/HaE) — 规则格式来源，直接复用其规则库文件
- [Rod](https://github.com/go-rod/rod) — 浏览器自动化
- [Tree-sitter](https://tree-sitter.github.io/tree-sitter/) — JavaScript AST 解析
- 自动填表算法适配自 [projectdiscovery/katana](https://github.com/projectdiscovery/katana)（MIT）
