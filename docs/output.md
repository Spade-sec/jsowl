# 报告输出

每个目标在输出目录下生成独立的报告子目录。扫描完成后用浏览器打开 `report.html` 即可查看交互式总览。

## 目录结构

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

## 报告格式

- **JSON**（`report.json`）：完整序列化 `Result` 结构，适合程序化处理与导入其他工具。
- **HTML**：无需外部资源的交互式报告，`report.html` 是合并总览入口，各分项报告可独立打开。
- **纯文本**：`api绝对路径.txt`、`url.txt` 等纯路径清单，可直接喂给 Burp Suite、fuzz 工具或爬虫。

三者都会保留完整敏感值，不做脱敏。报告会包含完整敏感数据，请严格限制报告目录的访问权限。

## 脚本保存（`output.download_js`）

默认为 `true`。开启后只保存普通 JS 和 chunk，文件名会清理 Windows 非法字符并使用稳定哈希避免 query/重名覆盖。超过正文上限（`limits.max_body_size`）的脚本不会保存，并在结果中记录 Issue。

开启后流水线会先把所有脚本和 chunk 下载完成，再统一对下载内容做正则匹配和 AST 解析（发现后续脚本/chunk 的递归抓取逻辑不变）。API 响应正文永不保存。
