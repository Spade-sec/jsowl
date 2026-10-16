# Public Suffix List 快照

`public_suffix_list.dat` 是 Public Suffix List 的原始快照，逐字节取自官方发布地址，供
JsOwl 离线运行使用。

| 项目 | 值 |
| --- | --- |
| 来源 | https://publicsuffix.org/list/public_suffix_list.dat |
| 版本（PSL 自带 VERSION 行） | 2026-10-07_07-28-19_UTC |
| 提交（PSL 自带 COMMIT 行） | 3929462652695bad04f0a27afb600974014a3c8b |
| 获取日期 | 2026-10-12 |
| 文件大小 / 行数 | 335478 字节 / 16507 行 |
| SHA-256 | ba7d836c0ea57a8bcf9f1fcb868066a7554bed029b441ecc6204ad8494a32612 |
| 许可证 | Mozilla Public License 2.0（见文件头部的 MPL 声明） |

## 为什么内嵌而不是运行时下载

JsOwl 的扫描与报告必须能够离线运行，因此快照随源码内嵌（`go:embed`）。运行时
`internal/extract` 会把这份快照规范化后写入应用缓存目录，再交给
`github.com/joeguo/tldextract` 初始化——该库在缓存文件缺失时会自行联网下载，我们不依赖
也不触发这条路径。

## 规范化说明

PSL 中的国际化后缀以 Unicode 形式给出（例如 `中国`、`рф`），而主机名在本项目中统一
转换为 ASCII（punycode）后参与比对，因此初始化时会把规则逐标签转换为 punycode 再写入
缓存文件；无法转换的规则原样保留并计数。原始文件本身不被修改，仅作为证据保留在仓库中。

## 更新方法

```sh
curl -sS -o internal/extract/psl/public_suffix_list.dat \
  https://publicsuffix.org/list/public_suffix_list.dat
sha256sum internal/extract/psl/public_suffix_list.dat
```

更新后请同步本文件中的版本、提交、大小与哈希，并运行
`go test ./internal/extract/...` 确认通配符、例外规则与 IDN 用例仍然通过。
