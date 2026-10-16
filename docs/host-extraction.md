# 主机资产提取（域名 / IP / 内部主机）

JsOwl 在扫描过程中从**被分析内容**里发现主机，并用同一套规则归一化**扫描自身接触到的**主机。
本文说明提取来源、分类规则、离线 PSL 初始化方式、输出口径与静态分析的限制。

## 目标与边界

提取的主机是**代码里出现的值**，不是确认存在的资产：

- 不执行目标 JavaScript；不求值函数、getter、`eval`，也不展开动态表达式；
- 为提取目的**不发起任何 DNS 查询、不发起连通性探测**（不新增请求，不改变抓取范围、请求地址与登录态）；
- 报告里出现某个主机，只说明它在代码或扫描记录里出现过，不代表主机可访问、已存活或存在漏洞；
- 不产生置信度或风险的数值评分：证据强度只用“提取方式”这一个有明确规则的字段表达。

## 两类主机（口径必须分开）

| 类别 | 含义 | 数据字段 |
| --- | --- | --- |
| 内容发现 | 出现在 JavaScript、内联脚本、文档（HTML）与 source map 还原源码中的主机值 | `hosts`（`origin: js`） |
| 扫描关联 | 本次扫描实际访问或被引用对象所属主机：目标、资源、端点、发现来源 | `scan_hosts`（`origin: scan`） |

两类使用同一套归一化与分类规则，可以交叉（同一主机同时出现在两类中，报告给出重合数量），
但**统计上不合并**：一个回答“代码提到了什么”，一个回答“这次扫描碰到了什么”。
主报告总览页把两张卡片并排展示，各自标注口径；`domain.txt` / `ip.txt` / `internal_hosts.txt`
输出的是两者的并集（去重后），报告内的分类统计仍按类别分开。

## 提取来源与方式

| 提取方式（`extraction_method`） | 来源 |
| --- | --- |
| `url` | 网络 URL 的 authority：`http(s)`、`ws(s)`、协议相对 `//host/...`，以及把主机作为值的字段 |
| `ast_literal` | 语法树里的字符串字面量与无插值的模板字符串（含 `\/`、`\xNN`、`\uNNNN`、代理对等转义解码） |
| `static_expression` | 全部操作数都是字面量或静态模板的 `+` 拼接 |
| `regex` | 有界的正则兜底：注释、非 JavaScript 文本、以及解析未产生语法树时的整段文本 |

正则兜底的候选上限 `MaxRegexMatchesPerFile`（512）、单文件候选上限 `MaxCandidatesPerFile`（1024）、
单文件时间上限 `MaxExtractionDuration`（300ms）与节点上限 `MaxExtractionNodes`（400000）触发时，
都会写入一条诊断（`扫描诊断` 页可见），记录在案的候选不会被静默丢弃。

### 明确不提取的内容

- 相对路径（`/api/users`、`user/login`）、成员表达式（`window.location`、`a.b`）、
  文件名（`main.js`、`style.css`）：文件名后缀本身不构成域名依据，`.js`/`.css` 不是公共后缀；
- 非网络 URI：`mailto:`、`data:`、`blob:`、`javascript:`、`file:`、`ftp:` 一律不按主机处理；
- 不做任意 Base64 解码或多层递归解码；
- 邮箱地址只有在**明确是地址字面量**（如 `mailto:` 或 `user@host` 形式的字符串）时才取其域名，
  并在证据中标注 `email_domain`。

### 动态表达式

存在动态插值、变量重赋值或作用域不确定时**停止求值**：不会把运行时的值拼成域名。
遇到看起来像主机的动态拼接，只记录一条 `host_dynamic_expression` 诊断。
标识符（常量引用）同样不参与折叠——同一个名字可能被重复赋值或在不同分支绑定不同值，
折叠会生成代码里根本不存在的主机；声明处的字面量本身已经作为证据保留。

## 归一化与分类规则

### URL

从合法 URL 或明确的协议相对 URL 取 `Hostname()`；端口独立处理，不参与主机身份（`https://a:8443/x`
与 `https://a/x` 是同一个主机）；原始 URL 保留在证据里；主机缺失、端口非法（`host:99999`、`host:abc`）
或 authority 不合法的 URL 被拒绝。

### 域名

1. 转小写；允许移除**一个**尾部根点（`EXAMPLE.COM.` → `example.com`），多个尾部点判为无效；
2. 用 `golang.org/x/net/idna` 的显式 profile 转成 ASCII（punycode）：UTS-46 映射、IDNA2008（不做
   `ß`→`ss` 折叠）、仅 STD3 字符、标签校验、连字符检查、DNS 长度校验（标签 1–63、总长 ≤253）；
   Unicode 原始写法保留在 `raw` 证据中；
3. 用 net/url + 上述校验拒绝空标签、首尾连字符、下划线与其他非法字符；
4. 用 Public Suffix List 拆分：`api.example.co.uk` → 公共后缀 `co.uk`、可注册域 `example.co.uk`、
   子域 `api`；**公共后缀本身（`co.uk`）不是可注册域**；
5. 未识别后缀的主机按上下文归类（见下），不伪造层级字段：`registrable_domain` / `public_suffix` /
   `subdomain` 保持为空，`suffix_status` 说明原因。

`suffix_status` 取值：`recognized`（PSL 命中）、`custom`（特殊用途或配置的后缀）、
`unknown`（无后缀规则）、`unresolved`（PSL 不可用，层级未解析）、`not_applicable`（IP 地址）。

### IP

用 `net/netip` 校验与标准化：

- URL 里的 IPv6 方括号由 URL 解析处理；字面量里的 `[::1]` 也会去掉方括号；
- IPv4-mapped IPv6（`::ffff:1.2.3.4`）归一化为对应的 IPv4，同一地址不会有两种写法；
- zone identifier（`fe80::1%eth0`）单独存进 `zone` 字段，**不进入去重键**；
- 不完整 IPv4（`1.2.3`）、越界数字（`999.1.2.3`）、数字片段（`1234`）与版本号（`v1.2.3`）一律拒绝，
  不会从 `999.1.2.3` 里截出 `99.1.2.3`；
- 地址属性按实际情况列出：`private`、`loopback`、`link_local`、`multicast`、`unspecified`；
  都不匹配时标记 `unclassified`。**不把“非私网”写成“公网可路由”**——未做可达性判断。

### 内部主机

- 裸字符串 `f`（任何带引号的单标签值）**直接拒绝**，除非它来自明确的主机上下文；
- 来自 URL（`https://f/`）或主机字段（`host`、`hostname`、`baseURL`、`endpoint`、`origin` 等）的
  单标签值保留为 `internal_host`；
- `localhost` 单独按内部主机处理；
- RFC 6761 特殊用途后缀 `.test`、`.example`、`.invalid`、`.local`、`.localhost` 一律按内部主机处理
  （`suffix_status: custom`，证据标注 `reserved`）：它们不是公共后缀，因此**不计入域名统计**；
- 其他未识别后缀：来自 URL 或主机字段时保留为 `internal_host`（`suffix_status: unknown`），
  否则丢弃；
- `internal_host` 一律不进入域名指标。

## Public Suffix List 与离线初始化

- 快照随源码内嵌：`internal/extract/psl/public_suffix_list.dat`，来源、版本、提交与 SHA-256 见
  `internal/extract/psl/README.md`（PSL 数据本身为 MPL-2.0，文件头保留许可证声明）。
- 运行时把快照规范化后写入应用缓存目录（`os.UserCacheDir()/jsowl/psl/`，回退到临时目录），
  再交给 `github.com/joeguo/tldextract` 初始化。该库在缓存文件缺失时会**自行联网下载**，
  因此实现上总是先落盘、再初始化，**不依赖也不触发**这条路径；缓存目录不可写时初始化失败并降级，
  而不是联网。
- 规范化会把 PSL 里以 Unicode 形式给出的国际化后缀（`中国`、`рф`、`公司` …）逐标签转成 punycode，
  与主机名统一在 ASCII 空间比对；无法转换的规则原样保留并计数，绝不静默丢弃。
- 初始化只做一次（`sync.Once`）：写入缓存、配置 splitter（调用 `SetNoValidate` 与 `SetNoStrip`，
  因为传入的已经是校验过的裸域名，库自带的 scheme 剥离、`@`/`:` 截断与 `.html` 去尾只会造成破坏），
  之后实例只读、可被所有并发分析协程共享。**每条记录都不会再建实例或写缓存。**
- 初始化后先做一次自检（`example.com` 必须解析出 `com`）；缓存文件损坏时会被重写，仍不可用则整体降级。
- 初始化失败**不会中断扫描**：已校验的候选全部保留，`suffix_status` 标记为 `unresolved`，
  并写入一条 `host_psl_unavailable` 诊断。

## 自定义内部后缀（配置）

```yaml
hosts:
  internal_suffixes:
    - corp        # 覆盖 corp 与 svc.corp
    - lan
    - svc.consul
```

自定义后缀只影响内部主机的判定，**不修改共享的 PSL 快照**。`.test` / `.local` 等特殊用途后缀已内置，
无需重复配置。

## 去重与证据

- 去重键是 `kind + 标准化后的值`：大小写、尾部根点、不同端口会合并为同一资产；
  同一地址的 `::ffff:1.2.3.4` 与 `1.2.3.4` 也是同一资产；
- 不同子域各自保留，同时可以通过 `registrable_domain` 归组（主报告“按可注册域归组”视图）；
- 每个资产保留**全部**来源证据：来源文件、原始值（`raw`，不会被标准化结果覆盖）、行列位置、
  提取方式、所属 URL、必要的源码上下文；
- 同一位置、同一原始值、同一提取方式的重复候选算一次观测，note 会合并（例如同一 URL 同时是
  资源、端点来源与发现来源时，证据上的角色会并列显示）；
- 单资产证据上限 32 条、单目标资产上限 8192 个：超出部分不静默丢弃，出现次数仍如实统计，
  并写入 `host_evidence_truncated` / `host_assets_truncated` 诊断；
- 输出顺序是数据的确定函数（先按类型，再按值），并发聚合不会改变报告顺序。

## 输出

| 输出 | 内容 |
| --- | --- |
| `report.json` | `hosts`（内容发现）与 `scan_hosts`（扫描关联）两个数组，含 `sources` 证据 |
| `domain.txt` | 两类中所有**域名**的标准化值，去重排序，每行一条 |
| `ip.txt` | 两类中所有 IPv4/IPv6 的标准化值（zone 不写入），去重排序，每行一条 |
| `internal_hosts.txt` | 内部主机候选，独立清单 |
| 主报告「主机资产」页 | 按类型筛选、关键词搜索、按可注册域归组、来源证据抽屉、复制与 CSV 导出 |
| 主报告总览 | 内容发现与扫描关联两组指标卡片 + 统计口径说明 |

报告侧（`internal/report`）不再自行判断主机：它读取扫描算好的分类结果，只有在对旧版
`report.json`（没有 `scan_hosts` 字段）生成报告时才用同一套共享提取器补算一次，保证口径一致。

## 静态分析的限制

- 只能看到**静态可判定**的值：运行时拼接、加密混淆、后端下发的主机无法提取，只留下动态表达式诊断；
- 提取不到不代表不存在：JS 里没有出现的主机，报告就不会有；
- 不做域名存活、解析、端口或服务识别；
- 库文件（vendor bundle）默认跳过解析（`scope.skip_library_bundles`），其中的主机会缺失，
  但标记为 vendor 的结果仍会带上 `vendor` 标记；
- source map 还原出的源码走同一条提取路径，命中 `source_map_blacklist` 的 map 不会下载。
