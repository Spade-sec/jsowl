# 配置指南

完整模板见 [config/config.example.yml](../config/config.example.yml)。本文说明关键配置项及其默认值。

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
  idle_max: 5s
  timeout: 45s
  headless: true
  # 发现框架路由后逐个渲染，采集每个视图自己的请求、相对路径与敏感信息。
  # 默认开启：成倍放大请求量，且可能触发目标自身的写操作。
  crawl_routes: true
  # 运行时自动填表并提交（算法适配自 projectdiscovery/katana，MIT），
  # 提交产生的请求由 CDP 捕获，其真实参数以 runtime 置信度回填报告。
  auto_form: false
  # 运行时点击按钮与内联事件元素，触发 SPA 隐藏的 API 调用。
  trigger_events: false
  # 两种交互单次页面渲染的总次数上限。
  max_interactions: 20
  max_routes: 30
  crawl_timeout: 60s
  # 仅在受限容器/靶场中 Chrome 沙箱无法启动时开启。
  no_sandbox: false
  collector_script: ""
concurrency:
  targets: 4
  resources_per_target: 16
limits:
  max_depth: 5
  max_resources: 0
  max_body_size: 10MiB
scope:
  allow_domains: []
  restrict_domains: []
  probe_source_maps: true
  skip_library_bundles: true
  source_map_blacklist: [chunk-vendors, chunk-libs, node_modules, axios, lodash]
  suffix_blacklist: [.png, .jpg, .svg, .css, .woff2, .mp4, .zip]
  fetch_external_scripts: true
  probe_external_endpoints: false
output:
  directory: ./jsowl-report
  json: true
  html: true
  download_js: true
  js_directory: js
```

## 采集模式

- `direct`：使用 [enetx/surf](https://github.com/enetx/surf) 并发执行有界 GET 请求。
- `browser`：使用 Rod 和本地 Chrome/Chromium 渲染页面，在网络空闲后继续等待异步 JavaScript。
- `auto`：默认先运行快速 direct 扫描；检测到 SPA、动态 import、History 路由等信号后再启动 Rod。浏览器不可用时保留 direct 结果并记录降级原因（stderr 提示 `browser degraded`，原因记录在报告的 `browser_status` 中）。

同源或显式 allowlist 的 API 仅使用 GET 获取并继续执行正则匹配；不会提交表单或发送 POST/PUT/PATCH/DELETE。页面明确引用的跨域脚本默认允许下载分析；跨域 API 默认不会探测。`Authorization`、`Cookie`、`X-API-Key` 等目标请求头仅发送到同源；跨域脚本只携带 UA、Accept 等安全协商头。

未配置 User-Agent 时，每个目标随机选择一个现代桌面 UA，并在该目标的 Surf、Rod、chunk 和 API 请求中保持一致。可选保存 JS/chunk；API 响应正文永不保存。

上述 GET 限制针对 JsOwl 主动发起的 API 探测。Rod 会按站点原生行为执行页面 JavaScript，不改写或阻断页面自身的请求方法，因此目标脚本本身可能发出 POST 等请求。

## 浏览器选项

Rod 的路径、等待、网络空闲、超时、窗口模式和注入脚本只通过 YAML 配置：

- `wait`（默认 `3s`）：页面加载并达到网络空闲后，继续等待异步 JS 的时间。
- `idle`（默认 `800ms`）：判定"网络空闲"所需的最短静止时长；带轮询心跳的 SPA 永远达不到，因此 `idle_max`（默认 `5s`）会封顶空闲等待，超时后放弃等待、直接用已收集内容拍快照（`0` 表示不限制）。
- `headless: false` 可显示浏览器窗口，等待时间仍受 `browser.timeout` 限制。
- JsOwl 始终显式解析本地浏览器路径，并禁用了 Rod 的自动下载路径。找不到 Chrome/Chromium 时，`browser` 模式返回错误，`auto` 模式降级到 Surf。
- 浏览器沙箱默认开启。如果 `--check` 在受限容器或靶场中出现 Chrome 启动后 CDP 连接立即关闭等沙箱兼容问题，可在确认环境隔离边界后设置 `browser.no_sandbox: true`；扫描不可信站点时不建议关闭沙箱。

`request.proxy` 同时用于 Surf 与 Rod。目标初始 Cookie 会在导航前写入浏览器，Rod 运行时产生的 Cookie 会同步回 Surf，用于后续脚本、chunk 和 API GET。

## 路由爬取（`browser.crawl_routes`）

默认 `true`。开启后，扫描会在发现框架路由时逐个渲染这些路由视图：前端路由守卫常常只是"未登录就跳转"、并非鉴权，直接导航往往能渲染出视图并触发它自己的接口调用，从而额外采集该视图的请求路径、相对路径、敏感信息与嵌套路由（新路由会继续入队递归）。

为避免失控，遍历受 `max_routes`（默认 `30`）与 `crawl_timeout`（默认 `60s`）双重约束；路由按归一化路径去重（`/user/1` 与 `/user/2` 折叠为同一路由），并对渲染结果做归一化签名，视图相同的路由不再继续展开。渲染优先通过页面自身的 `router.push()` 做页内跳转，拿不到路由器时才整页导航。

注意：它会把扫描从"单页只读"变成"对目标的多页主动爬取"，请求量成倍增加，且视图内的页面脚本可能发起写操作，请仅在已授权范围内开启。

## 运行时交互（`browser.auto_form` / `browser.trigger_events`）

两者默认均为 `false`，可用 CLI 参数 `--aff`（一次同时开启）、`--max-interactions` 控制。

开启后，浏览器渲染阶段会在被动快照之后执行运行时交互：自动填表按输入类型与 name/id 关键字选择值（算法适配自 projectdiscovery/katana，MIT，值规则保留其原有语义），逐表提交；事件触发则点击按钮与带内联事件的元素。这些交互发出的请求由 CDP `Network.requestWillBeSent` 捕获，`PostData` 与 URL query 会被解析成键/值/类型，以 `runtime` 置信度（最高级）合并进 API 端点的 RequestSpec——这是补齐 `data:t` 等动态 payload 字段的主要手段。运行时值会被截断到 64 字符以避免持久化完整敏感数据。

注意：表单提交与按钮点击可能触发目标自身的写操作，请仅在已授权范围内开启。

### 激进模式（`browser.aggressive`）

默认 `false`（仅配置项，无 CLI 参数）。开启后移除运行时交互的保守防护：disabled、readonly、`display:none` 的控件也通过 DOM 直写填值（并派发 input/change 事件），被遮挡的元素用 `element.click()` 兜底点击。服务端校验成为唯一防线，攻击面最大，但请求更嘈杂、更容易触发目标的风控或写入脏数据，仅在明确授权时开启。

## 作用域控制（`scope`）

- `scope.skip_library_bundles` 默认 `true`。开启后扫描读取脚本头部的版权注释（`/*! ... */` 形式或含 `@license`、`@preserve`、`Copyright`、`licensed under` 的注释），若注释里出现已知库名（jQuery、lodash、axios、Vue、React、Element UI、echarts、core-js 等），就判定该脚本是第三方库 bundle，**跳过它的正则与 AST 解析**——库文件体量极大却不含目标业务接口，跳过既提速又降噪；资源本身仍会记录在资源报告里。source map 还原出的原始文件走同一判定。把 `skip_library_bundles` 设为 `false` 时**仍会解析**这些库文件，但结果全部打上 `vendor` 标记：API 报告与敏感信息报告的对应行会显示虚线 `vendor` 徽标，JSON 里为 `"vendor": true`——便于把库噪声与业务结果分开看。同一路径若同时被业务代码引用，标记会被清除（业务引用优先）。
- `scope.probe_source_maps` 默认 `true`。开启后扫描会探测 JS source map：既解析脚本里 `//# sourceMappingURL=` 指向的 `.map`（含内联 base64 形式），也直接抓取以 `.map` 结尾的资源；拿到 map 后按 shuji 的方式把 `sourcesContent` 里的**原始未压缩源码**取出，重新跑一遍正则与 AST 提取，因此路径、参数与敏感信息都按还原后的源码统计。`source_map_blacklist` 里的片段命中 map 路径时跳过下载，默认覆盖 `chunk-vendors`、`chunk-libs`、`node_modules`、`axios`、`lodash`、`element-ui` 等库 bundle，避免为体积巨大的厂商 map 浪费请求与磁盘。
- `scope.suffix_blacklist` 在请求入队前按 URL path 过滤，忽略后缀大小写、query 和 fragment；`.css` 与 `.svg` 默认过滤，`.js`、`.json`、`.map`、`.txt`、`.xml` 默认不会过滤。
- `--base-url` 不会替换入口目标，只改变相对资源和 API 的解析基准，绝对 URL 保持原值。

## 外部收集器

```yaml
browser:
  collector_script: 'D:\path\to\collect_resource_urls.js'
```

内置收集器是该脚本的增强版，会在页面脚本之前注入，并合并 fetch、XHR、MutationObserver、DOM、Performance API 与 CDP 网络响应。
