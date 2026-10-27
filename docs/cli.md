# CLI 用法

CLI 没有子命令，所有能力通过参数提供。

## 常用示例

```bash
jsowl -u https://example.com
jsowl -u https://a.example -u https://b.example
jsowl -l targets.txt
jsowl --location ./dist/assets/app.js
jsowl --location ./dist --location ./legacy
jsowl -u https://example.com -c config/config.yml
jsowl -u https://example.com -o reports
jsowl -u https://example.com -m direct
jsowl -u https://example.com -t 32
jsowl -u https://example.com -p http://127.0.0.1:8080
jsowl -u https://example.com --base-url https://static.example.com/assets/
jsowl -u https://example.com --base-url /api
jsowl -u https://example.com --silent
jsowl -u https://example.com -H "Authorization: Bearer token"
jsowl -u https://example.com --scope api.example.net,aaa.example.net
jsowl --check -c config/config.yml
jsowl -v
jsowl -h
```

## 参数一览

| 参数 | 作用 |
|---|---|
| `-u, --url` | 目标 URL，可重复 |
| `-l, --list` | 目标文件，忽略空行和 `#` 注释 |
| `--location` | 分析本地 JS 文件或目录，可重复；读取本地文件并请求发现的 API，不能与 `-u`/`-l`/`--login` 同用；相对 API 需配合完整的 http(s) `--base-url` |
| `-c, --config` | YAML 配置文件；`-h` 帮助中会显示用户级默认路径 `~/.jsowl/config.yml` |
| `-o, --output` | 覆盖报告目录 |
| `-m, --mode` | `auto`、`direct` 或 `browser` |
| `-p, --proxy` | 覆盖 Surf 与 Rod 使用的 HTTP(S)/SOCKS5 代理 |
| `--base-url` | 覆盖相对引用的解析基准；带路径时作为前缀拼接（`/users` → `/base/users`），绝对 URL 不受影响；也可以只写路径（`/api`），按每个目标的 origin 解析后再拼接 |
| `-H, --header` | `Name: value` 请求头，可重复 |
| `--scope` | 限制只能爬取的域名，逗号分隔、可重复；根目标始终允许 |
| `-t, --threads` | 覆盖单目标资源并发数 |
| `-s, --silent` | 不输出成功结果行，错误仍输出到 stderr |
| `-v, --version` | 显示版本 |
| `--check` | 检查配置、规则、输出目录、本地浏览器、CDP、JS 与注入快照 |
| `--aff` | 一次开启自动填表提交与运行时事件点击（automatic form fill，见[配置指南](configuration.md)） |
| `--max-interactions` | 单页渲染的填表提交 + 事件点击总次数上限（默认 20） |
| `--ai` | 开启 AI 辅助分析，需在配置中设置 `ai.api_key` 与 `ai.base_url` |
| `--login` | 先打开可见浏览器手动登录，再携带该会话完成扫描（可带 `-u`，也可不带） |

## 本地 JS 分析（`--location`）

`--location` 读取本地 JavaScript，复用与在线扫描相同的端点解析、作用域校验、API 探测、响应分析、请求模板与报告生成。它与在线扫描的区别只在采集入口：本地模式不爬取远端页面，也不会因为发现 import、chunk 或 script 引用而下载远端 JS；源码定位仍使用本地 `file://` 路径，HTTP 请求不会以 `file://` 作为基准。

- 传单个文件时始终分析该文件；传目录时递归收集 `.js`、`.mjs`、`.cjs`、`.jsx`、`.ts`、`.tsx`，跳过 `.git` 元数据目录。
- 源码里的绝对 API（`https://api.example.com/users`）会直接进入探测流程，不需要额外传 `-u`；这不会构造虚假目标，也不会关闭作用域检查，`scope.restrict_domains` 仍然生效。
- 源码里的相对 API 需要 `--base-url` 提供主机：`--base-url https://example.com/api` 时，`/users` 解析为 `https://example.com/api/users`（按前缀拼接，已带前缀的路径不会重复叠加），`users` 按目录拼接。`--base-url` 必须是完整的 http(s) URL；只写 `/api` 时无法确定主机，会明确报错，不会猜测目标。
- 不传 `--base-url` 时，相对引用保持为静态结果并写入 `local_endpoint_unresolved` 诊断，不会用某个文件中偶然出现的域名或绝对 API 作为整个目录的基准。调用点自身声明的绝对 `baseURL`（如 `axios.create({ baseURL: "https://api.example.com/v1" })`）只作用于该调用点。
- Source Map：内联 `data:` map 与本地相对 `.map` 文件会被解析，`sourcesContent` 中的原始源码继续走同一提取与探测流程；远端 map 不下载，记录 `sourcemap_remote_skipped` 诊断；读取失败、内容损坏或缺少 `sourcesContent` 分别记录诊断。`webpack://` 等虚拟来源只作为源码名称清理，不会当作磁盘路径读取。
- 每个 `--location` 生成独立结果目录 `<output>/local-<名称>_<时间>_<随机串>/`，报告文件与在线扫描相同。
- 本地分析不接入 `--ai` 增强；`--login` 仍只用于在线扫描，且与 `--location` 互斥。

```bash
jsowl --location ./dist/assets/app.js
jsowl --location ./dist --base-url https://example.com
jsowl --location ./dist --base-url https://example.com/api
```

## 登录态扫描（`--login`）

`--login` 会打开一个可见浏览器，等你在浏览器里完成登录后回到终端按 Enter（最长等待 5 分钟，超时后继续使用当前浏览器状态），随后整批目标都在这个已认证会话内串行扫描：浏览器会周期性回收重启，会话 Cookie 会自动迁移。该参数强制 `browser` 模式、非 headless、目标并发为 1。

登录页与扫描目标是解耦的，两种用法都支持：

- **带 `-u`**：浏览器直接打开该 URL，登录完成后扫描 `-u`/`-l` 指定的目标。
- **不带 `-u`**：浏览器打开一个空白标签页，你在里面自由导航并登录，按 Enter 后 jsowl 就以当前停留的页面为扫描目标（若不是 http/https 页面则会报错提示）。

```bash
jsowl -u https://app.example.com --login   # 打开 app.example.com，登录后扫描它
jsowl --login                              # 打开空白浏览器，登录并导航到目标后扫描当前页
```

## AI 辅助分析（`--ai`）

开启后由大模型对扫描结果做三类增强：参数完整性与真实性复核、未知污点来源推断、敏感发现价值评级。需在配置中提供：

```yaml
ai:
  api_key: "your-api-key"
  base_url: "https://open.bigmodel.cn/api/paas/v4"
  model: "glm-4-flash"
  max_requests: 20
```

支持 `openai-chat`、`openai-responses`、`anthropic-messages`、`gemini-native` 四种接口格式，通过 `ai.format` 指定。单次扫描 AI 请求上限由 `max_requests` 控制。

## 配置加载顺序

CLI 显式值优先于 YAML，YAML 优先于内置默认值。若未传 `-c`，按以下顺序叠加配置：上层设置的每个字段覆盖下层，未指定的字段保留下层值。

1. 当前目录 `config/config.yml`（项目级；旧版顶层 `./config.yml` 仍兼容）；
2. `~/.jsowl/config.yml`（用户级，对本机所有扫描生效）；
3. 内置默认值。

首次运行时若 `~/.jsowl/config.yml` 不存在，会自动创建 `~/.jsowl/` 目录并生成全部注释的默认模板（stderr 提示 `created user config: <路径>`）；之后每次运行都会在 stderr 提示 `user config: <路径>`。取消注释任意字段即全局生效，删除该文件后下次运行会重新生成。传 `-c` 时完全以指定文件为准，不叠加用户级配置。

用户级配置适合放全局个性化设置，例如代理、全局请求头与 Cookie、浏览器路径：

```yaml
request:
  proxy: http://127.0.0.1:8080
  headers:
    Authorization: Bearer token
browser:
  path: C:\Program Files\Google\Chrome\Application\chrome.exe
```

其中的相对路径（如 `rules_file`）以 `~/.jsowl` 为基准解析。

## 运行时输出

请求完成后立即输出一行，多个扫描协程通过容量为 256 的队列交给单个输出协程，按入队顺序逐行写入终端：

```text
[GET] [https://example.com/] [success] [200] [18240]
[POST] [https://example.com/api/users] [success] [403] [128]
[GET] [https://example.com/timeout] [faile] [0] [0]
```

依次为请求方法、链接、请求结果、HTTP 状态码和响应体字节数。收到完整响应（包括 4xx/5xx）为 `success`；请求或响应读取失败为 `faile`，状态码与长度显示 0。HTTP 采集在重试结束后输出最终结果；浏览器页面请求在加载完成或失败时输出。HTTP 长度为实际读取的正文长度（配置截断时为截断后的长度），浏览器长度为 CDP 累计收到的解码正文长度，不含响应头。

队列满时等待，不丢弃请求记录；退出前排空队列。并发请求按完成事件的入队顺序输出，不保证与发起顺序相同。浏览器加载与之后的 HTTP 采集是不同请求，同一链接可能出现多次。扫描结束后不再重复打印资源清单。

使用 `--silent` 可关闭请求行输出，但报告写入和 stderr 错误输出不受影响。
