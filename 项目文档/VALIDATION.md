# v0.1.0 验证范围

从仓库根目录运行 `python3 scripts/validate.py --build-root /path/to/workspace/Build/验证`，把占位路径替换成源码目录外的工作区中央 `Build`。入口将候选源码暂存到 Build，创建隔离环境并构建 wheel/sdist；随后分别对源码、解包 sdist、安装 wheel 执行单元测试和真实环回 HTTP 矩阵。环境、缓存、测试日志、包和机器收据全部留在指定 Build 下。脚本拒绝源码 checkout 内的 Build 输出。

验收条件是每种形态 **15/15 单元测试**和 **36/36 HTTP 矩阵行**。其中 12 项测试真实会话边界，另 3 项拒绝绝对路径、`..` 和指向 Build 外的符号链接 `--run-id`；脚本还要求运行目录名为单个安全路径组件，并在解析组合路径后核对仍位于选定 Build 内。每份 HTTP 矩阵含弱基线和修复版各 18 次真实请求，服务只绑定 `127.0.0.1` 随机端口。验证入口还核对候选文件在 sdist 内逐字节一致、wheel 的 4 个运行模块和自有 LICENSE 与源码一致、版本与作者元数据、所有步骤退出码。收据不会保存完整 session ID 或合成密码；弱基线的 `200` 表示自有故意错误得到复现，不应写成防御通过。

最终发布前的本地两份运行记录应位于中央 `Build/验证/WebSessionDastReview-v0.1.0/prepublish-v010-pathfix-py314` 和 `prepublish-v010-pathfix-py312`；只有实际 `validation.json` 写出 `PASS_LOCAL_ENGINEERING` 且其源码 SHA-256 清单与当次提交相同，才能引用相应测试结果。旧的 `validation_receipt.json`、`local_matrix_source.json`、`local_matrix_wheel.json`、`prepublish-v010-final-*` 与旧独立 QA 仅代表先前候选时点，不能用作本次修补后源码和发行包的验收。

GitHub Actions 在主线和 `v*` 标签上使用 Python 3.11、3.14，输出写到 `${{ runner.temp }}/Build/验证`。托管运行、公开 main、标签、正式 Release 和下载资产须在发布后按同一提交分别回验；本地通过不能代替这些证据。真实授权任务、保障措施影响、申请账号/组织身份和 Anthropic CVP 资格/批准均 **OPEN**。实验未测试 TLS、浏览器、CSRF、会话过期、多实例状态或生产部署。
