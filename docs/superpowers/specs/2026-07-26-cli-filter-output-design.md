# JsOwl CLI、过滤与输出增强设计

## 目标

在保持根命令 CLI 和 Go 库兼容性的前提下，增加代理覆盖、相对 URL
解析基准、默认后缀黑名单和简洁终端输出。

## 行为

- `--proxy/-p` 覆盖 `request.proxy`，继续复用现有
  `http`、`https`、`socks5` 校验和 Surf/Rod 代理实现。
- `--base-url` 写入每个 `Target.BaseURL`。入口仍请求 `Target.URL`；
  只有发现的相对 script、chunk、API 和 route 使用该基准解析。
  绝对 URL 不受影响。
- `scope.suffix_blacklist` 在资源进入请求队列前过滤 URL path，匹配忽略
  大小写、query 和 fragment。配置项接受带点或不带点后缀。
- 默认黑名单包含图片、字体、音视频、归档、二进制、`.css` 和 `.svg`
  后缀；不包含 `.js`、`.json`、`.map`、`.txt`、`.xml`。
- 默认对每个已爬取资源输出一行：
  `URL [响应体长度] [状态码] [content-type]`。
- `--silent/-s` 禁止成功信息输出，但错误仍写入 stderr，报告仍正常生成。

## 实现边界

- 后缀过滤不阻止入口 URL，避免用户显式目标被静默跳过。
- `BaseURL` 必须是无凭据的绝对 HTTP(S) URL。
- httpx 风格字段直接取每个 `Resource`；结果没有资源时为目标输出
  `0`、`0` 和空 Content-Type。
- 不增加新的第三方依赖。

## 测试

- 配置默认值、YAML 覆盖和后缀大小写/query 行为。
- 管线服务器断言 `.PNG?x=1` 不被请求，文本资源仍请求。
- BaseURL 集成测试断言入口保持不变而相对 API 使用指定基准。
- CLI 测试断言 proxy/base-url 覆盖、默认格式和 silent 无 stdout。
