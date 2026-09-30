# 自定义规则

所有规则统一在 [config/rules.yml](../config/rules.yml)，为 HaE 原生格式，是唯一规则来源，增删改规则只动这一个文件。它身兼三个角色：

- 仓库目录下运行时自动加载为**项目级规则**（stderr 提示 `project rules: <路径>`），修改后立即生效、无需重新编译；
- 编译时经 go:embed 嵌入二进制，供仓库外运行使用；
- 首次运行时播种为 `~/.jsowl/rules.yaml` 作为**用户级规则**的底版。

加载优先级：`rules_file`（显式指定）> `config/rules.yml`（项目级）> `~/.jsowl/rules.yaml`（用户级）> 内嵌默认值。

## 匹配引擎

匹配引擎与 [HaE](https://github.com/gh0stkey/HaE) 一致：所有规则经 regexp2（.NET 风格 NFA）编译，前瞻/后顾断言、反向引用、命名组开箱即用；单次匹配限时 2 秒，灾难性回溯只会截断该规则自身的匹配，不会挂死扫描。

规则文件支持两种格式，加载时自动识别。

## HaE 原生格式

config/rules.yml 即此格式——直接复用 HaE 规则库文件，无需转换（`scope` 字段接受但忽略；`color` 映射为严重级别；`sensitive: false` 即默认忽略大小写）：

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

## JsOwl 原生格式

适合手工维护的精简规则（字段含义等价：`pattern` 对应 `f_regex`、`s_regex`/`s_group`/`format`/`ignore_case` 同名、`enabled` 对应 `loaded`，缺省即 true）：

```yaml
include:                      # 可选：合并更多规则文件（相对本文件，自动防循环）
  - ./more-rules.yml
disabled: [hae.密钥凭证.云账号配置值]
custom:
  - id: my.internal-token
    name: Internal token
    category: sensitive       # url 或 sensitive
    severity: high
    pattern: '(?i)internal[_-]?token\s*[:=]\s*["'']([^"'']+)'
    group: 1
    description: Internal test token
    # s_regex: '^[A-Za-z0-9]+$'   # 二级正则：对提取值复检，不命中则丢弃（去误报）
    # format: 'token={1}'         # 输出格式，缺省取 group 提取的文本
```

## 内置规则集

config/rules.yml 已收录并适配适合 Web/JavaScript 信息收集的规则，以及 HaE 常用子集（身份证、邮箱、内网 IP、国内 Webhook、云厂商密钥、Shiro/Druid 指纹等）。无效正则、捕获组、模式、时间、并发和资源边界会在扫描前拒绝。

## 用户级规则文件

首次运行时 jsowl 会把内嵌规则集播种为 `~/.jsowl/rules.yaml`（HaE 原生格式，stderr 提示 `created user rules: <路径>`）；仓库外运行时默认加载它做敏感信息匹配——同名同组条目覆盖内嵌默认规则，`loaded: false` 关闭某条，编辑后下次扫描生效。项目目录下存在 `config/rules.yml` 时以项目文件为准、`rules.yaml` 不再加载；配置中设置 `rules_file` 时以该文件为准。
