# CLI 用法

CLI 没有子命令，所有能力通过参数提供。

## 常用示例

```bash
jsowl -u https://example.com
jsowl -u https://a.example -u https://b.example
jsowl -l targets.txt
jsowl -u https://example.com -c config/config.yml
jsowl -u https://example.com -o reports
jsowl -u https://example.com -m direct
jsowl -u https://example.com -t 32
jsowl -u https://example.com -p http://127.0.0.1:8080
jsowl -u https://example.com --base-url https://static.example.com/assets/
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
| `-c, --config` | YAML 配置文件；`-h` 帮助中会显示用户级默认路径 `~/.jsowl/config.yml` |
| `-o, --output` | 覆盖报告目录 |
| `-m, --mode` | `auto`、`direct` 或 `browser` |
| `-p, --proxy` | 覆盖 Surf 与 Rod 使用的 HTTP(S)/SOCKS5 代理 |
| `--base-url` | 覆盖发现的相对 script、chunk、API 和 route 的解析基准 |
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

默认对每个已爬取资源输出一行：

```text
https://example.com/ [18240] [200] [text/html; charset=utf-8]
```

依次为 URL、响应体长度、状态码和 Content-Type。API 探测完成时流式输出：

```text
[200] GET https://api.example.com/v2/user/info [runtime]
```

使用 `--silent` 可关闭成功行输出，但报告写入和 stderr 错误输出不受影响。
