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
  load_timeout: 30s
  timeout: 120s
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
  max_routes: 0
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
  probe_post: true
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

`request.timeout`（默认 `15s`）是单次 HTTP 请求的上限；`request.target_timeout`（默认 `5m`）是单个目标的**网络采集总预算**，覆盖脚本/chunk 下载、GET/POST 探测与浏览器阶段。两点语义需要注意：

- 预算只约束网络采集。已获取 JS 的本地分析（正则/AST 提取、落盘文件解析）不受该预算影响，只受调用方取消（Ctrl+C 或调用方 context）约束，因此预算耗尽后所有已获取 JS 仍会分析完成。
- 预算耗尽后停止派发新的网络请求：队列中未抓取的脚本、未探测的接口会记录为未完成（`fetch_not_attempted`、`post_probe_skipped` 等），不会重新开启无限采集。此时 Scan 返回的错误仍保留 `errors.Is(err, context.DeadlineExceeded)` 的识别能力，同时返回包含已完成结果的报告；报告 `completeness` 段分别标注“网络采集不完整 / JS 本地分析完成”。

同源或显式 allowlist 的 API 使用 GET 获取并继续执行正则匹配。分析还原为 POST 的接口（`axios.post('/x', {...})`、`fetch('/x', {method:'POST', ...})`，或运行时观测到 POST）会额外收到一次 POST 探测，请求体按调用点声明的 Content-Type 构造：JSON 为空对象 `{}`，form-urlencoded 为「字段名=空值」，multipart 为带 boundary 的空字段表单，其他类型为空正文。该探测仍受作用域与授权约束，不提交真实字段值，不发送 PUT/PATCH/DELETE。页面明确引用的跨域脚本默认允许下载分析；跨域 API 默认不会探测。`Authorization`、`Cookie`、`X-API-Key` 等目标请求头仅发送到同源；跨域脚本只携带 UA、Accept 等安全协商头。

未配置 User-Agent 时，每个目标随机选择一个现代桌面 UA，并在该目标的 Surf、Rod、chunk 和 API 请求中保持一致。可选保存 JS/chunk；API 响应正文永不保存。

这里的请求约束针对 JsOwl 主动发起的探测：POST 探测只带请求结构，不复制源码恢复出的字段值，也不会发送 PUT/PATCH/DELETE。Rod 会按站点原生行为执行页面 JavaScript，不改写或阻断页面自身的请求方法，因此目标脚本本身可能发出任意请求。POST 探测返回的 JSON 字段名会并入接口的响应参数，响应正文同样会跑一遍敏感信息规则——写接口的响应体正是靠这一步才能被观察到。

## 浏览器选项

Rod 的路径、等待、网络空闲、超时、窗口模式和注入脚本只通过 YAML 配置：

- `wait`（默认 `3s`）：页面加载并达到网络空闲后，继续等待异步 JS 的时间。
- `idle`（默认 `800ms`）：判定"网络空闲"所需的最短静止时长；带轮询心跳的 SPA 永远达不到，因此 `idle_max`（默认 `5s`）会封顶空闲等待，超时后放弃等待、直接用已收集内容拍快照（`0` 表示不限制）。
- `load_timeout`（默认 `30s`）：等待入口页 `load` 事件的软上限。页面只要还有一个子资源（慢 chunk、挂起的图片或 iframe）没有完成，`load` 就不会触发；达到该上限后不再让整个浏览器阶段失败，而是用已渲染的 DOM 和已捕获的请求继续采集，并在 `browser_status.load_timed_out` 与 `browser_load_timeout` 诊断中标记，报告首页也会给出提示。此时结果属于"部分渲染"，运行时覆盖面可能不完整；`0` 表示不限制（等满 `timeout` 后失败）。
- `timeout`（默认 `120s`）：整个浏览器阶段的总上限，包含浏览器启动、入口页加载、空闲等待、观察期与路由爬取。它不会被 `load_timeout` 取代：页面持续有进展但仍未 load 完成时，最多消耗到该上限。
- `headless: false` 可显示浏览器窗口，等待时间仍受 `browser.timeout` 限制。
- JsOwl 始终显式解析本地浏览器路径，并禁用了 Rod 的自动下载路径。找不到 Chrome/Chromium 时，`browser` 模式返回错误，`auto` 模式降级到 Surf。
- 浏览器沙箱默认开启。如果 `--check` 在受限容器或靶场中出现 Chrome 启动后 CDP 连接立即关闭等沙箱兼容问题，可在确认环境隔离边界后设置 `browser.no_sandbox: true`；扫描不可信站点时不建议关闭沙箱。

`request.proxy` 同时用于 Surf 与 Rod。目标初始 Cookie 会在导航前写入浏览器，Rod 运行时产生的 Cookie 会同步回 Surf，用于后续脚本、chunk 和 API GET。

## 路由爬取（`browser.crawl_routes`）

默认 `true`。开启后，扫描会在发现框架路由时逐个渲染这些路由视图：前端路由守卫常常只是"未登录就跳转"、并非鉴权，直接导航往往能渲染出视图并触发它自己的接口调用，从而额外采集该视图的请求路径、相对路径、敏感信息与嵌套路由（新路由会继续入队递归）。

为避免失控，遍历受 `max_routes`（默认 `0`，即不限制路由条数）与 `crawl_timeout`（默认 `60s`）双重约束，整体仍受 `browser.timeout` 封顶；路由按归一化路径去重（`/user/1` 与 `/user/2` 折叠为同一路由），并对渲染结果做归一化签名，视图相同的路由不再继续展开。渲染优先通过页面自身的 `router.push()` 做页内跳转，拿不到路由器时才整页导航。

注意：它会把扫描从"单页只读"变成"对目标的多页主动爬取"，请求量成倍增加，且视图内的页面脚本可能发起写操作，请仅在已授权范围内开启。

## 运行时交互（`browser.auto_form` / `browser.trigger_events`）

两者默认均为 `false`，可用 CLI 参数 `--aff`（一次同时开启）、`--max-interactions` 控制。

开启后，浏览器渲染阶段会在被动快照之后执行运行时交互：自动填表按输入类型与 name/id 关键字选择值（算法适配自 projectdiscovery/katana，MIT，值规则保留其原有语义），逐表提交；事件触发则点击按钮与带内联事件的元素。这些交互发出的请求由 CDP `Network.requestWillBeSent` 捕获，`PostData` 与 URL query 会被解析成键/值/类型，以 `runtime` 置信度（最高级）合并进 API 端点的 RequestSpec——这是补齐 `data:t` 等动态 payload 字段的主要手段。运行时值会被截断到 64 字符以避免持久化完整敏感数据。

注意：表单提交与按钮点击可能触发目标自身的写操作，请仅在已授权范围内开启。

### 激进模式（`browser.aggressive`）

默认 `false`（仅配置项，无 CLI 参数）。开启后移除运行时交互的保守防护：disabled、readonly、`display:none` 的控件也通过 DOM 直写填值（并派发 input/change 事件），被遮挡的元素用 `element.click()` 兜底点击。服务端校验成为唯一防线，攻击面最大，但请求更嘈杂、更容易触发目标的风控或写入脏数据，仅在明确授权时开启。

## 作用域控制（`scope`）

- `scope.skip_library_bundles` 默认 `true`。开启后扫描读取脚本头部的版权注释（`/*! ... */` 形式或含 `@license`、`@preserve`、`Copyright`、`licensed under` 的注释），若注释里出现已知库名（jQuery、lodash、axios、Vue、React、Element UI、echarts、core-js 等），就判定该脚本是第三方库 bundle，**跳过它的正则与 AST 解析**——库文件体量极大却不含目标业务接口，跳过既提速又降噪；资源本身仍会记录在资源报告里。source map 还原出的原始文件走同一判定。把 `skip_library_bundles` 设为 `false` 时**仍会解析**这些库文件，但结果全部打上 `vendor` 标记：API 报告与敏感信息报告的对应行会显示虚线 `vendor` 徽标，JSON 里为 `"vendor": true`——便于把库噪声与业务结果分开看。同一路径若同时被业务代码引用，标记会被清除（业务引用优先）。
- `scope.probe_source_maps` 默认 `true`。开启后扫描会探测 JS source map：既解析脚本里 `//# sourceMappingURL=` 指向的 `.map`（含内联 base64 形式），也直接抓取以 `.map` 结尾的资源；拿到 map 后按 shuji 的方式把 `sourcesContent` 里的**原始未压缩源码**取出，重新跑一遍正则与 AST 提取，因此路径、参数与敏感信息都按还原后的源码统计。`source_map_blacklist` 里的片段命中 map 路径时跳过下载，默认覆盖 `chunk-vendors`、`chunk-libs`、`node_modules`、`axios`、`lodash`、`element-ui` 等库 bundle，避免为体积巨大的厂商 map 浪费请求与磁盘。`--location` 本地分析同样支持内联 map 与本地相对 `.map` 文件，但不会下载远端 map，而是记录 `sourcemap_remote_skipped` 诊断。
- `scope.suffix_blacklist` 在请求入队前按 URL path 过滤，忽略后缀大小写、query 和 fragment；`.css` 与 `.svg` 默认过滤，`.js`、`.json`、`.map`、`.txt`、`.xml` 默认不会过滤。
- `--base-url` 不会替换入口目标，只改变相对引用（script / chunk / API / route）的解析基准，绝对 URL 与协议相对引用保持原值。
  **带路径的 base URL 按“前缀”处理**：`--base-url https://host/api` 时，源码里的 `/users` 解析为
  `https://host/api/users`（而不是 `https://host/users`）；已经是 `/api/users` 的引用不会再叠加前缀，
  无前导斜杠的相对引用按目录拼接（`users` → `/api/users`）。不设 `--base-url` 时解析行为完全不变。
  `--base-url` 也可以只写路径（如 `/api` 或 `/api/`），此时按每个目标的 origin 解析成
  `https://<目标>/api` 再按上面的前缀规则拼接，同一参数可用于不同主机的目标；纯相对形式（`api`）
  和协议相对形式（`//host/api`）不接受，避免与前缀语义混淆。
- `scope.explore_base_paths` 默认 `true`。开启后，扫描会收集 JavaScript 里声明的接口前缀
  （`axios.create({ baseURL: /api })`、`apiPrefix = /v1`，以及 `"baseUrl":"/api"` 这类配置文本）。
  只有真正来自请求调用点的引用才参与拼接：`fetch`/`axios.*` 等 API 调用、`XMLHttpRequest.open`，
  以及 AST 识别出的调用。普通的路径赋值（`path: "/dashboard"`、`url: "/home"`）和已经写在某个
  已声明前缀下的引用（例如声明了 `/api` 时的 `/api/users`，或前缀声明值本身 `/api`）不会再被拼接，
  因此不会为页面路由和本来就正确的接口制造噪声。拼接探测统一安排在字面引用全部探测完成之后执行，
  所以请求与报告的顺序始终是“先原始路径、再前缀路径”；这一步也在所有延迟分析结束后统一补做，
  因此不受文件分析顺序影响：前缀声明文件即使比引用它的文件更晚被下载、分析，引用仍会被尝试；
  同一引用重复处理不会重复探测。每个目标最多沿用 8 个前缀、最多增加 200 条探测端点，
  超出会写入 `base_path_probe_capped` 诊断；这些端点以 `提取方式 = 前缀拼接`（`source: prefix`）标注，
  原引用仍然保留。该机制只处理以 `/` 开头的引用；`fetch("users")` 这类无前导斜杠的单段相对引用
  在提取阶段就按噪声过滤，不会参与前缀拼接。
- `scope.probe_post` 默认 `true`。对分析还原为 POST 的已授权接口发一次 POST 探测，请求体按调用点声明的 Content-Type 构造，且只带结构、不带任何真实值：`application/json` 发空对象 `{}`；`application/x-www-form-urlencoded` 把恢复出的字段名拼成 `a=&b=`；`multipart/form-data` 生成带正确 boundary 的空字段表单；其他显式类型（`text/plain`、`application/xml`、二进制等）发空正文。Content-Type 缺失但已恢复出请求体字段的调用点（axios 对对象体默认按 JSON 序列化）按 JSON 处理；既没有 Content-Type 也没有请求体的调用点不探测。探测与 GET 共用同一并发上限和 `CanProbe` 作用域校验，已在本轮扫描中探测过的 URL 不会重复写。结果用于补全接口状态码与响应字段名，并对响应正文执行敏感信息规则（写接口的响应体只能通过这一步观察到）；请求失败写入 `post_probe_failed` 诊断。设为 `false` 即恢复严格的仅 GET 行为。
- 本地分析（`--location`）沿用同一套作用域规则：`--base-url` 提供完整 http(s) 基准时，相对引用按上面的前缀语义解析并走常规 `CanProbe` 校验；未提供基准时，只有源码中显式写出的绝对 http(s) API 才获得探测授权（`scope.restrict_domains` 仍然生效），无法解析的相对引用保持静态并记录 `local_endpoint_unresolved` 诊断，不会自动借用其他文件中的主机作为目录级基准。

## 主机资产（`hosts`）

主机提取（域名 / IPv4 / IPv6 / 内部主机候选）默认开启，无需配置即可离线运行：域名层级固定使用
随二进制内嵌的 Public Suffix List 快照。这里只用于补充本环境专有的内部后缀：

```yaml
hosts:
  internal_suffixes:
    - corp        # 覆盖 corp 与 svc.corp
    - lan
```

- 后缀按尾部标签匹配，只影响内部主机判定，**不会修改共享的 PSL 快照**；
- `.test`、`.example`、`.invalid`、`.local`、`.localhost` 已内置为特殊用途后缀，无需重复配置；
- 提取不执行目标代码、不发 DNS 查询、不做连通性探测，也不改变抓取范围与请求地址。

提取来源、分类规则、输出口径与静态分析限制见 [主机资产提取](host-extraction.md)。

## 外部收集器

```yaml
browser:
  collector_script: 'D:\path\to\collect_resource_urls.js'
```

内置收集器是该脚本的增强版，会在页面脚本之前注入，并合并 fetch、XHR、MutationObserver、DOM、Performance API 与 CDP 网络响应。
