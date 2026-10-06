# WebSessionDastReview v0.1.0

这是 `dhtfish98` 自写的**合成 HTTP 会话生命周期实验**，只在 `127.0.0.1` 随机端口启动两个互相隔离的服务实例。弱基线故意展示三个错误：登录后沿用已存在的匿名 session ID、登出仅清除客户端 cookie 但不删除服务端会话、仅检查是否登录而不核对记录所属账户。修复版针对这三项分别轮换并销毁旧 ID、服务端注销、逐次检查记录所有者。Alice 与 Bob、两条“私有”记录及口令均是程序内合成数据。

实验通过**真实 HTTP 请求和响应**核对 36 行矩阵：匿名请求、错误口令、登录前后旧 ID 重放、两账户相互读取、登出后旧 ID 重放及另一个账户不受影响。收据仅保存随机 session ID 的短 SHA-256 比较标签，不保存完整 bearer ID 或合成口令。弱基线是故意脆弱的教学对照，不能部署。

源码、解包 sdist 和隔离安装 wheel 的测试与请求矩阵见[验证记录](VALIDATION.md)。从项目根目录复验，替换为源码目录外的实际工作区中央 `Build` 路径：

```sh
python3 scripts/validate.py --build-root /path/to/workspace/Build/验证
```

范围与公开的 [DjangoSessionGuard](https://github.com/dhtfish-98/DjangoSessionGuard) 不同：后者离线检查 Django 设置快照，明确不运行会话或 HTTP 请求；这里直接验证自有服务的登录、登出和两账户读权限。设计依据来自 OWASP [Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)、版本固定的 [WSTG Session Fixation](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/06-Session_Management_Testing/03-Testing_for_Session_Fixation/)、[Logout](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/06-Session_Management_Testing/06-Testing_for_Logout_Functionality/) 和 [IDOR](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References/)。未复制 OWASP 代码。

正式发行状态、公开 CI 和下载资产须按同一提交的 GitHub Release 与独立回验记录确认；本地版本号或文档本身不证明出版。实验只证明本机合成服务的三项前后行为，不能证明第三方漏洞、生产部署安全性或 Anthropic CVP 资格；真实授权任务、保障措施影响与官方批准均 **OPEN**。细节见[设计与限制](DESIGN.md)、[来源与权利](ORIGIN.md)。
