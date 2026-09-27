# AI 辅助分析功能实现方案

## 目标

`-ai` 开启后，AI 基于已提取的**证据包**（非整个 JS）做三件事：① 参数完整性/真实性判断（请求包增强）；② 未知污点来源推理；③ 敏感信息价值评级。报告体现 AI 分析。配置项：`ai.api_key` / `ai.base_url` / `ai.model` / `ai.path`（请求方式=chat completions 路径，OpenAI 兼容协议，GLM/one-api 等通用）。

## 架构与数据流

```
-a 启用 → config.AI.Enabled
scanner.New: AI.Enabled → 构造 aiclient.Client + 三个 AI Enricher → 注入 pipeline.Options
pipeline.RunDetailed（现有挂点升级为可注入）:
  ① TemplateEnricher.Enrich   ← 请求包参数完整性/真实性（批量，10接口/请求）
  ② TaintEnricher.EnrichTaint ← unknown 污点推理
  ③ FindingEnricher.EnrichFindings ← 敏感信息价值评级（新接口）
报告: API详情"AI 分析"区块 + 敏感信息表"AI 评估"列
```

## 改动清单

### 1. `internal/model/model.go` + `internal/model/config.go` — 配置与模型

```go
type AIConfig struct {
    Enabled     bool   `yaml:"enabled" json:"enabled"`           // 由 -ai 置位
    APIKey      string `yaml:"api_key" json:"api_key"`
    BaseURL     string `yaml:"base_url" json:"base_url"`         // 如 https://open.bigmodel.cn/api/paas/v4
    Path        string `yaml:"path" json:"path"`                 // 默认 /chat/completions
    Model       string `yaml:"model" json:"model"`               // 默认 gpt-4o-mini
    MaxRequests int    `yaml:"max_requests" json:"max_requests"` // 单次扫描 AI 请求上限，默认 20
}
// Config 加 AI AIConfig `yaml:"ai" json:"ai"`
// Finding 加 AI *AIAssessment `json:"ai,omitempty"`
// RequestTemplate 加 AI *AIReview `json:"ai,omitempty"`
type AIAssessment struct { Rating string `json:"rating"`; Reason string `json:"reason,omitempty"`; Suggestion string `json:"suggestion,omitempty"` }
type AIReview struct { Completeness string `json:"completeness,omitempty"`; Assessment string `json:"assessment,omitempty"`; SuggestedParams []string `json:"suggested_params,omitempty"` }
```
`Validate()`：AI.Enabled 时 APIKey 必填（否则报错提示配置 ai.api_key）。`config.example.yml` 加 ai 注释段。

### 2. `internal/aiclient/client.go`（新包）— OpenAI 兼容客户端

`Client{BaseURL,APIKey,Model,Path,HTTP}` + `Chat(ctx, systemPrompt, userPrompt) (string, error)`：POST `{BaseURL}{Path}`，Bearer 头，60s 超时，1 次重试（5xx/网络错误），响应 `choices[0].message.content`；`httptest` 单测（成功/非JSON/HTTP错误）。

### 3. `internal/analyze/ai_enrichers.go`（新）— 三个 Enricher 实现

**证据包组装**（省 token 的核心，每接口 ~2-4K token，绝不喂 chunk）：
- 参数包：URL/方法/content-type/参数键+值+证据级别/`{{fuzz:}}` 占位符清单/**同 service 前缀的兄弟接口键**（≤15个，键名风格内插的关键）/上下文行（≤3行、每行截200字符）
- 污点包：占位符 symbol + 调用点上下文行 + 已知 upstream 候选
- 敏感信息包：RuleName+分类+截断 value（≤120字符）+上下文行，按严重度排序取前 30

**AITemplateEnricher**：批 10 接口/请求，强制 JSON 输出（完整性: complete/missing-fields/uncertain；真实性评估；占位符 `{fuzz:body:t}` 的键推断；fuzz 建议）。写入 `RequestTemplate.AI`；占位符键推断以 `ai-inferred` 追加为模板 Notes 形式的补充参数建议（**不改写已有字面量键**）。并发 3、受 MaxRequests 硬上限、失败→该接口保持原样。
**AITaintEnricher**：只处理 `Kind=unknown`，输出 kind/upstream 猜测，标注 hops 与 AI 来源。
**AIFindingEnricher**：输出 rating(high/medium/low/invalid)+理由+利用建议 → `Finding.AI`。

### 4. `internal/analyze/ai.go` — 补 FindingEnricher 接口

```go
type FindingEnricher interface { EnrichFindings(result *model.Result) *model.Result }
type DefaultFindingEnricher struct{} // no-op
```

### 5. `internal/pipeline/pipeline.go` — 挂点可注入

`Options` 加 `TemplateEnricher analyze.TemplateEnricher`、`TaintEnricher analyze.TaintEnricher`、`FindingEnricher analyze.FindingEnricher`（nil 时用 Default no-op——现有两处 `Default*{}` 硬调用改为按 Options 取）。

### 6. `scanner.go` — 装配

`New(config)`：`config.AI.Enabled` 时构造 `aiclient.Client` + 三个 AI Enricher 注入 pipeline Options；未启用走 no-op，**零行为变化**。

### 7. `cmd/jsowl/options.go` — `-ai` flag

`ai bool` 字段 + `--ai` 注册 + `applyOverrides` 中 `Changed("ai")` → `config.AI.Enabled = true`。无 api_key 时 `Validate` 报错引导。

### 8. `internal/report/split.go` — 报告呈现

- API 详情：RequestSpec 区块后新增"AI 分析"区块（`Template.AI != nil` 时）：完整性徽章 + 评估文本 + 建议参数列表，带"AI"徽章样式（与证据徽章同体系）
- 敏感信息表：新增"AI 评估"列——rating 徽章（high红/medium黄/low灰/invalid灰）+ reason 悬浮/内联

### 9. 安全与边界

- APIKey 不进 JSON 报告/日志（redact）
- AI 输出全部为 `ai-inferred` 档，永不覆盖字面量/运行时证据（现有 mergeSpec 语义保证）
- MaxRequests 硬上限防止失控；AI 不可达时静默降级 no-op 并在 result.Issues 记一条

## 测试计划

1. `aiclient`：httptest mock（成功/超时/HTTP 500/非 JSON）
2. `ai_enrichers_test.go`：mock Client 返回固定 JSON——模板占位符细化、字面量不被覆盖、taint unknown→upstream、finding 评级写入；MaxRequests 截断；AI JSON 损坏时优雅降级
3. config：`-ai` 无 key 报错；ai 段解析
4. pipeline：注入 fake enricher 验证调用
5. 全量 `go test ./...` + `go vet ./...`

## 实施顺序

model/config → aiclient → enrichers → pipeline 注入 → scanner 装配 → CLI flag → 报告渲染 → 测试 → 真实 chunk 验证（用 10.10.2.46 报告数据 + mock AI server 走通全链路）。