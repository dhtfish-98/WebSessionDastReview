# 来源、作者与权利

项目代码、HTTP 服务、探针、测试和文档由 `dhtfish98` 新写；两账户、记录与凭据均为合成测试资料。没有复制 `DjangoSessionGuard`、OWASP 指南或任何第三方项目源码，也没有对第三方目标进行扫描或提出漏洞归属。

OWASP 的会话管理、WSTG 固定版本章节只作为公开设计与测试依据，其原作者和原有权利不因本项目而改变。所用 Python 标准库、setuptools、wheel 与 build 工具保留各自许可证；本项目自写文件按[LICENSE](LICENSE)的 MIT 条款授权。没有把第三方代码、许可证或署名改成项目作者。

公开项目去重：`DjangoSessionGuard` 是离线 Django 设置快照检查器，明确不运行 HTTP/session 生命周期；本项目才运行自有两变体的真实请求矩阵。其它认证与重定向项目各有不同目标，本项目不声称覆盖它们。真实授权任务、生产安全效果、第三方漏洞、Anthropic CVP 资格及官方批准均 **OPEN**。
