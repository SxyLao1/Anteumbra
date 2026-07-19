# Anteumbra 内存马应急响应参考工具

[English](README.md)

本目录保留第三方 JSP/ASPX 内存马扫描脚本，用于人工应急响应与研究。Anteumbra Runtime
不会导入、部署或执行这些脚本，当前也没有插件会自动编排它们。

## 目录

```text
tools/memory-shell/
|-- README.md
|-- README_cn.md
|-- java/
|   |-- tomcat-memshell-scanner.jsp
|   `-- README_upstream.md
`-- aspnet/
    |-- aspx-memshell-scanner.aspx
    `-- README_upstream.md
```

| 工具 | 上游作者 | 仓库 |
|------|----------|------|
| `tomcat-memshell-scanner.jsp` | c0ny1 | [java-memshell-scanner](https://github.com/c0ny1/java-memshell-scanner) |
| `aspx-memshell-scanner.aspx` | yzddmr6 | [As-Exploits](https://github.com/yzddmr6/As-Exploits) |

每个 `README_upstream.md` 均保留上游中文说明和署名。

## 操作安全

这些文件是可执行诊断页面。上传它们会修改 Web 根目录，并暴露高权限管理入口。使用前：

1. 审阅完整源码与对应上游版本。
2. 尽可能先在受影响服务器的隔离副本测试。
3. 通过网络 ACL 和认证限制访问。
4. 记录文件 Hash、部署时间、操作人员和目标，纳入事件证据。
5. 采集结束后立即删除，并验证删除结果。
6. 扫描结果干净不等于主机未失陷。

Anteumbra 的文件监控可能把诊断页面本身判为可疑文件。应使用明确、限时的维护流程，
不要为这些文件创建永久且宽泛的白名单。

## 其他参考工具

以下项目不会随 Anteumbra 打包：

| 工具 | 范围 |
|------|------|
| [private-xss/memory-shell-detector](https://github.com/private-xss/memory-shell-detector) | Tomcat、Jetty、WebLogic、Spring Java GUI/CLI 检测 |
| [4ra1n/shell-analyzer](https://github.com/4ra1n/shell-analyzer) | JVM 监控、反编译与清理流程 |
| [y1shiny1shin/KMBA](https://github.com/y1shiny1shin/KMBA) | 基于 Arthas 的内存马分析与清理 |

## 许可证与署名

扫描脚本继续遵循各自上游条款，Anteumbra 不主张其著作权。重新分发或生产使用前，请
阅读对应上游仓库与 `README_upstream.md`。
