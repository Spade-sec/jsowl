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
- `Authorization`、`Cookie`、`X-API-Key` 等目标请求头仅发送到同源；跨域脚本只携带 UA、Accept 等安全协商头。
- 未配置 User-Agent 时，每个目标随机选择一个现代桌面 UA，并在该目标的 Surf、Rod、chunk 和 API 请求中保持一致。
- 可选保存 JS/chunk；API 响应正文永不保存。

## 构建

需要 Go 1.25 或兼容版本，以及可用的 C 编译器。JavaScript AST 使用
Tree-sitter，因此构建时必须启用 CGO；交叉编译还需要目标平台对应的 C
交叉编译器。

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
jsowl -u https://example.com -p http://127.0.0.1:8080
jsowl -u https://example.com --base-url https://static.example.com/assets/
jsowl -u https://example.com --silent
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
| `-c, --config` | YAML 配置文件；`-h` 帮助中会显示用户级默认路径 `~/.jsowl/config.yml` |
| `-o, --output` | 覆盖报告目录 |
| `-m, --mode` | `auto`、`direct` 或 `browser` |
| `-p, --proxy` | 覆盖 Surf 与 Rod 使用的 HTTP(S)/SOCKS5 代理 |
| `--base-url` | 覆盖发现的相对 script、chunk、API 和 route 的解析基准 |
| `-H, --header` | `Name: value` 请求头，可重复 |
| `--scope` | 限制只能爬取的域名，逗号分隔、可重复；根目标始终允许，例：`--scope api.example.net,aaa.example.net` |
| `-t, --threads` | 覆盖单目标资源并发数 |
| `-s, --silent` | 不输出成功结果行，错误仍输出到 stderr |
| `-v, --version` | 显示版本 |
| `--check` | 检查配置、规则、输出目录、本地浏览器、CDP、JS 与注入快照 |

CLI 显式值优先于 YAML，YAML 优先于内置默认值。若未传 `-c`，jsowl 会按以下顺序叠加配置：上层设置的每个字段覆盖下层，未指定的字段保留下层值。

1. 当前目录 `config.yml`（项目级；项目自带的 `config.yml` 默认引用 `rules.yml`）；
2. `~/.jsowl/config.yml`（用户级，对本机所有扫描生效）；
3. 内置默认值。

首次运行时若 `~/.jsowl/config.yml` 不存在，会自动创建 `~/.jsowl/` 目录并生成全部注释的默认模板（stderr 提示 `created user config: <路径>`）；之后每次运行都会在 stderr 提示 `user config: <路径>`，方便定位。取消注释任意字段即全局生效，删除该文件后下次运行会重新生成。传 `-c` 时完全以指定文件为准，不叠加用户级配置。

## 用户级配置

`~/.jsowl/config.yml` 适合放全局个性化设置，例如代理、全局请求头与 Cookie、浏览器路径：

```yaml
request:
  proxy: http://127.0.0.1:8080
  headers:
    Authorization: Bearer token
browser:
  path: C:\Program Files\Google\Chrome\Application\chrome.exe
```

其中的相对路径（如 `rules_file`）以 `~/.jsowl` 为基准解析。

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
  idle_max: 5s
  timeout: 45s
  headless: true
  # 发现框架路由后逐个渲染，采集每个视图自己的请求、相对路径与敏感信息。
  # 默认关闭：成倍放大请求量，且可能触发目标自身的写操作。
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

Rod 的路径、等待、网络空闲、超时、窗口模式和注入脚本只通过 YAML 配置。`wait` 默认 `3s`，表示页面加载并达到网络空闲后，继续等待异步 JS 的时间。`idle` 是判定"网络空闲"所需的最短静止时长；带轮询心跳的 SPA 永远达不到，因此 `idle_max`（默认 `5s`）会封顶空闲等待，超时后放弃等待、直接用已收集内容拍快照（`0` 表示不限制）。`headless: false` 可显示浏览器窗口，等待时间仍受 `browser.timeout` 限制。auto 模式下浏览器阶段失败会降级到 direct 并向 stderr 打印一行 `browser degraded` 提示，原因同时记录在报告的 `browser_status` 中。

`scope.skip_library_bundles` 默认 `true`。开启后扫描读取脚本头部的版权注释（`/*! ... */` 形式或含 `@license`、`@preserve`、`Copyright`、`licensed under` 的注释），若注释里出现已知库名（jQuery、lodash、axios、Vue、React、Element UI、echarts、core-js 等），就判定该脚本是第三方库 bundle，**跳过它的正则与 AST 解析**——库文件体量极大却不含目标业务接口，跳过既提速又降噪；资源本身仍会记录在资源报告里。source map 还原出的原始文件走同一判定。把 `skip_library_bundles` 设为 `false` 时**仍会解析**这些库文件，但结果全部打上 `vendor` 标记：API 报告与敏感信息报告的对应行会显示虚线 `vendor` 徽标，JSON 里为 `"vendor": true`——便于你把库噪声与业务结果分开看。同一路径若同时被业务代码引用，标记会被清除（业务引用优先）。

`scope.probe_source_maps` 默认 `true`。开启后扫描会探测 JS source map：既解析脚本里 `//# sourceMappingURL=` 指向的 `.map`（含内联 base64 形式），也直接抓取以 `.map` 结尾的资源；拿到 map 后按 shuji 的方式把 `sourcesContent` 里的**原始未压缩源码**取出，重新跑一遍正则与 AST 提取，因此路径、参数与敏感信息都按还原后的源码统计。`source_map_blacklist` 里的片段命中 map 路径时跳过下载，默认覆盖 `chunk-vendors`、`chunk-libs`、`node_modules`、`axios`、`lodash`、`element-ui` 等库 bundle，避免为体积巨大的厂商 map 浪费请求与磁盘。

`browser.crawl_routes` 默认 `true`。开启后，扫描会在发现框架路由时逐个渲染这些路由视图：前端路由守卫常常只是"未登录就跳转"、并非鉴权，直接导航往往能渲染出视图并触发它自己的接口调用，从而额外采集该视图的请求路径、相对路径、敏感信息与嵌套路由（新路由会继续入队递归）。为避免失控，遍历受 `max_routes`（默认 `30`）与 `crawl_timeout`（默认 `60s`）双重约束；路由按归一化路径去重（`/user/1` 与 `/user/2` 折叠为同一路由），并对渲染结果做归一化签名，视图相同的路由不再继续展开。渲染优先通过页面自身的 `router.push()` 做页内跳转，拿不到路由器时才整页导航。注意它会把扫描从"单页只读"变成"对目标的多页主动爬取"，请求量成倍增加，且视图内的页面脚本可能发起写操作，请仅在已授权范围内开启。

`browser.auto_form` 与 `browser.trigger_events` 默认均为 `false`，两者也可用 CLI 参数 `-aff`（即 `--aff`，automatic form fill，一次同时开启两者；配置文件里仍可分别控制）、`--max-interactions` 控制。开启后，浏览器渲染阶段会在被动快照之后执行运行时交互：自动填表按输入类型与 name/id 关键字选择值（算法适配自 projectdiscovery/katana，MIT，值规则保留其原有语义），逐表提交；事件触发则点击按钮与带内联事件的元素。这些交互发出的请求由 CDP `Network.requestWillBeSent` 捕获，`PostData` 与 URL query 会被解析成键/值/类型，以 `runtime` 置信度（最高级）合并进 API 端点的 RequestSpec——这是补齐 `data:t` 等动态 payload 字段的主要手段。运行时值会被截断到 64 字符以避免持久化完整敏感数据。注意：表单提交与按钮点击可能触发目标自身的写操作，请仅在已授权范围内开启。

`browser.aggressive` 默认 `false`（仅配置项，无 CLI 参数）。开启后移除运行时交互的保守防护：disabled、readonly、`display:none` 的控件也通过 DOM 直写填值（并派发 input/change 事件），被遮挡的元素用 `element.click()` 兜底点击。服务端校验成为唯一防线，攻击面最大，但请求更嘈杂、更容易触发目标的风控或写入脏数据，仅在明确授权时开启。
JsOwl 始终显式解析本地浏览器路径，并禁用了 Rod 的自动下载路径。找不到 Chrome/Chromium 时，`browser` 模式返回错误，`auto` 模式降级到 Surf。

`request.proxy` 同时用于 Surf 与 Rod。目标初始 Cookie 会在导航前写入浏览器，Rod 运行时产生的 Cookie 会同步回 Surf，用于后续脚本、chunk 和 API GET。

`--base-url` 不会替换入口目标，只改变相对资源和 API 的解析基准。绝对
URL 保持原值。`scope.suffix_blacklist` 在请求入队前按 URL path 过滤，
忽略后缀大小写、query 和 fragment；`.css` 与 `.svg` 默认过滤，
`.js`、`.json`、`.map`、`.txt`、`.xml` 默认不会过滤。

上述 GET 限制针对 JsOwl 主动发起的 API 探测。Rod 会按站点原生行为执行页面 JavaScript，不改写或阻断页面自身的请求方法，因此目标脚本本身可能发出 POST 等请求。

浏览器沙箱默认开启。如果 `--check` 在受限容器或靶场中出现 Chrome
启动后 CDP 连接立即关闭等沙箱兼容问题，可在确认环境隔离边界后设置
`browser.no_sandbox: true`；扫描不可信站点时不建议关闭沙箱。

若需要使用外部收集器：

```yaml
browser:
  collector_script: 'D:\project\exercise\reverse\转子女神\grok\assets\collect_resource_urls.js'
```

内置收集器是该脚本的增强版，会在页面脚本之前注入，并合并 fetch、XHR、MutationObserver、DOM、Performance API 与 CDP 网络响应。

## 输出

默认对每个已爬取资源输出一行：

```text
https://example.com/ [18240] [200] [text/html; charset=utf-8]
```

依次为 URL、响应体长度、状态码和 Content-Type。使用 `--silent` 可关闭
成功行输出，但报告写入和 stderr 错误输出不受影响。

```text
jsowl-report/
└── example.com/
    ├── report.html          # 交互式总览 + 分项报告导航（合并入口）
    ├── API报告.html          # API 路径（相对/绝对分组，分页 + 上下文）
    ├── URL报告.html          # 完整 http(s) URL（分页）
    ├── 敏感信息报告.html
    ├── 参数报告.html
    ├── 路由报告.html
    ├── 资源报告.html
    ├── api绝对路径.txt       # /a/b/c 形式的纯路径
    ├── api相对路径.txt       # a/b/c 形式的纯路径
    ├── url.txt              # 完整 http(s) URL
    ├── 路由.txt / 参数.txt / 敏感信息.txt
    ├── report.json
    └── js/
        ├── app.<hash>.js
        └── chunks/
            └── users.<hash>.js
```

同一主机的非根路径或带 query 的多个扫描目标会在主机名后添加稳定 URL 哈希，避免报告相互覆盖。

`output.download_js` 默认为 `true`。开启后只保存普通 JS 和 chunk，文件名会清理 Windows 非法字符并使用稳定哈希避免 query/重名覆盖。超过正文上限的脚本不会保存，并在结果中记录 Issue。开启后流水线会先把所有脚本和 chunk 下载完成，再统一对下载内容做正则匹配和 AST 解析（发现后续脚本/chunk 的递归抓取逻辑不变）。

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

规则独立保存在规则配置文件中。主配置通过 `rules_file` 引用它，相对路径以
主配置文件所在目录为基准：

```yaml
rules_file: ./rules.yml
```

匹配引擎与 [HaE](https://github.com/gh0stkey/HaE) 一致：所有规则经 regexp2
（.NET 风格 NFA）编译，前瞻/后顾断言、反向引用、命名组开箱即用；单次匹配
限时 2 秒，灾难性回溯只会截断该规则自身的匹配，不会挂死扫描。

规则文件支持两种格式，加载时自动识别。

**HaE 原生格式**——直接复用 HaE 规则库文件，无需转换（`scope` 字段接受但
忽略；`color` 映射为严重级别；`sensitive: false` 即默认忽略大小写）：

```yaml
rules:
- group: 疑似漏洞
  rule:
  - name: GET 明文id
    loaded: true
    f_regex: (\b(?<!_)(id|\w+id)=(\d{2,15})\b(?![-_\/]))
    s_regex: ''
    format: '{0}'       # {0}=整个匹配，{N}=第 N 个捕获组
    color: green
    scope: request line # 接受但忽略
    engine: nfa
    sensitive: false
```

每条 HaE 规则生成形如 `hae.<组名>.<规则名>` 的 ID，可在 `disabled` 中引用。

**JsOwl 原生格式**——适合手工维护的精简规则（字段含义等价：`pattern` 对应
`f_regex`、`s_regex`/`s_group`/`format`/`ignore_case` 同名、`enabled` 对应
`loaded`，缺省即 true）：

```yaml
include:                      # 可选：合并更多规则文件（相对本文件，自动防循环）
  - ./hae_rules.yml
disabled: [secret.account]
custom:
  - id: secret.internal-token
    name: Internal token
    category: sensitive       # url 或 sensitive
    severity: high
    pattern: '(?i)internal[_-]?token\s*[:=]\s*["'']([^"'']+)'
    group: 1
    description: Internal test token
    # s_regex: '^[A-Za-z0-9]+$'   # 二级正则：对提取值复检，不命中则丢弃（去误报）
    # format: 'token={1}'         # 输出格式，缺省取 group 提取的文本
```

项目根目录的 [rules.yml](rules.yml) 已加载并适配
`正则表达式总结报告.md` 中适合 Web/JavaScript 信息收集的规则，
[hae_rules.yml](hae_rules.yml) 则是 HaE 原生格式的常用子集（身份证、邮箱、
内网 IP、国内 Webhook、腾讯云密钥、Shiro/Druid 指纹等）。无效正则、捕获组、
模式、时间、并发和资源边界会在扫描前拒绝。

另外，jsowl 首次运行会在用户级配置目录（`~/.jsowl/`）自动生成 `rules.yaml`，内容即内置的 12 条敏感信息规则；之后每次扫描默认加载该文件做敏感信息匹配。规则 ID 与内置规则相同——直接编辑 `pattern`、设置 `enabled: false` 关闭某条、或追加自定义规则即可，下次扫描生效；若配置中设置了 `rules_file`，则以该文件为准，`rules.yaml` 不再加载。
