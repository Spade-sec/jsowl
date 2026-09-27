# 请求包复原功能实施（分支 feature/request-template）

已确认决策：输出仅 API报告.html 详情面板；参数值字面量保真 + 智能 fuzz 占位。

## 步骤

1. **建分支**：`git checkout -b feature/request-template`（基于当前 dev）
2. **model**：`internal/model/model.go` 新增 `RequestTemplate{Method,URL,Headers,Body,Notes}`、`HeaderTpl{Key,Value,Evidence}`；`Endpoint` 加 `Template *RequestTemplate`；`OutputConfig` 加 `RequestTemplate bool` 开关（默认 true）
3. **构造器**：新增 `internal/analyze/packet.go` `BuildTemplate(ep)` 纯函数——URL/Method/Content-Type 行、body 按 json/form 序列化、字面量保真、键名启发式 `{{fuzz:}}` 占位、form 格式提示 XSRF 隐式头、password 类键出 Notes 提示；`packet_test.go` 覆盖五类请求形态
4. **管线挂载**：`pipeline.RunDetailed` 在 probeRoutes 后、finalize 前遍历 api 类型 Endpoints 生成 Template（开关控制）
5. **报告渲染**：`report/split.go` `renderAPIDetail` 的 RequestSpec 区块后新增"请求包复原" `<pre>` 区块——占位符/方法行/注释行分色高亮 + 一键复制
6. **配置**：`config.example.yml` output 区块加 `request_template` 注释条目
7. **验证**：全量 `go test ./...` + `go vet ./...`；用真实 chunk（app.6b63242c.js 的 /applet/login、FeedbackOrAuditSubmit）端到端验证输出格式与目标一致

## 明确边界

只产出报文模板不发送；`{{transform:}}` 语法预留但本期不做加密检测（password 只出提示 Notes）；跨模块占位符照旧 `{t}` 形态。