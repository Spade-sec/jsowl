# 开发与构建

## 构建要求

- Go 1.25 或兼容版本
- 可用的 C 编译器：JavaScript AST 使用 Tree-sitter，构建时必须启用 CGO
- 交叉编译时还需要目标平台对应的 C 交叉编译器

```bash
go build -o jsowl ./cmd/jsowl
go build -o jsowl-mcp ./cmd/jsowl-mcp
go test ./...
```

## 仓库结构

```text
├── cmd/jsowl          # CLI 入口（Cobra）
├── cmd/jsowl-mcp      # MCP Server 入口（stdio）
├── mcpserver/         # 公开的 MCP Server 子包（可被其他项目内嵌）
├── internal/
│   ├── analyze/       # 正则 + Tree-sitter AST 提取引擎
│   ├── aiclient/      # 可选的 AI 辅助分析客户端
│   ├── collect/       # direct（Surf HTTP）与 browser（Rod/CDP）采集器
│   ├── discover/      # 脚本/chunk/路由/API 发现（Webpack、RequireJS、source map）
│   ├── model/         # 配置与结果模型
│   ├── pipeline/      # 采集 → 分析 → 报告流水线
│   ├── report/        # JSON/HTML/文本报告生成
│   ├── scheduler/     # 目标 worker 池与并发控制
│   ├── scope/         # 作用域过滤与库 bundle 判定
│   ├── storage/       # JS/chunk 下载保存
│   └── ua/            # 现代 UA 池
├── config/            # config.example.yml、rules.yml（规则唯一来源）
├── examples/          # 库使用示例
└── docs/              # 文档
```

## 运行时流程

运行时流程图见 [jsowl-runtime-flow.drawio](jsowl-runtime-flow.drawio)。核心流水线：

1. **目标调度** — 固定 worker 池按 `concurrency.targets` 并发处理目标；
2. **采集** — `auto` 模式先 direct 快扫，检测到 SPA 信号后升级为 Rod 渲染；浏览器阶段捕获运行时网络请求并可选执行交互；
3. **发现** — 对 HTML/JS/chunk 做正则与 AST 解析，递归入队新发现的脚本、chunk 与 API；
4. **提取** — 规则引擎（regexp2）跑敏感信息匹配，AST 提取路径、参数与路由；
5. **报告** — 流式写出 JSON、HTML 与文本报告。

## 测试

```bash
go test ./...          # 全部单元测试
go test -run E2E ./... # 端到端测试
go vet ./...
```

## 规则与配置

- 规则只维护 [config/rules.yml](../config/rules.yml) 一个文件，格式见[自定义规则](rules.md)；
- 新增配置项时同步更新 [config/config.example.yml](../config/config.example.yml) 与[配置指南](configuration.md)。
