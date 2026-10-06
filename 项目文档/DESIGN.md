# 自有会话实验设计与边界

## 真实请求矩阵

每个变体使用独立的 `ThreadingHTTPServer` 和内存 session store，服务仅绑定 `127.0.0.1` 随机端口。客户端逐次手动指定 cookie，不依赖浏览器缓存或自动 cookie jar，因此能重放登录前或登出前的**原值**；机器收据只记录其比较用哈希标签。

| 控制点 | 故意脆弱的弱基线 | 修复版 | HTTP 证据 |
| --- | --- | --- | --- |
| 登录前后 ID | 将 Alice 账户绑定到现有匿名 ID | 销毁匿名 ID，签发新随机 ID | 对比两次 `Set-Cookie`；旧 ID 请求 `/me` 分别 200/401 |
| 登出后服务端状态 | 仅令浏览器删除 cookie，store 保留认证状态 | 删除 store 中认证 ID 并清除 cookie | 用原 ID 重发 `/me` 和 `/records/alice-note`，分别 200/401 |
| 两账户读权限 | 任一已登录账户可读 Alice/Bob 记录 | 每次读取检查当前会话账户等于记录 owner | Alice→Bob、Bob→Alice 各返回 200/403，并核响应无跨账户标记 |

匿名 ID 与认证 ID 均由 `secrets.token_urlsafe(32)` 生成。这里的“固定会话”实验**假设**测试方事先知道一个由服务端签发的匿名 ID，并让另一个合成登录流程沿用它；没有演示如何把这个 ID 注入真实用户浏览器。未签发的自选 ID 不能直接登录。登出测试显式恢复先前 cookie，检查服务端是否仍接受它。两个合成账户同时有效，注销 Alice 后还验证 Bob 可正常访问。

OWASP [会话管理指导](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)要求认证等权限变化后换 ID，并在登出时使服务端会话失效；[WSTG-v4.2 SESS-03](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/06-Session_Management_Testing/03-Testing_for_Session_Fixation/)和[SESS-06](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/06-Session_Management_Testing/06-Testing_for_Logout_Functionality/)分别给出旧 ID 与登出后重放的测试思路；[ATHZ-04](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References/)建议使用两个账户与各自资源验证横向越权。本项目自己实现最小服务，不包含这些文档的源码。

## 不能外推的范围

修复版只修正表中三个控制点，**不是完整安全网站**。本机 HTTP 因而没有 TLS 或 `Secure` cookie；响应采用 `HttpOnly`、`SameSite=Lax`、`Cache-Control: no-store`，但没有浏览器验证、CSRF 防护、会话空闲/绝对过期、持久化、多实例并发一致性、密码存储、速率限制、审计集成或生产部署。`POST /login` 和 `/logout` 仅供回环实验。两条记录只读；本矩阵没有验证跨账户写权限。服务器内存状态随测试进程退出而消失，无法说明生产注销传播。

`DjangoSessionGuard` 检查离线配置；本项目运行合成 HTTP 会话。合成弱基线是自有代码，不代表任何第三方上游漏洞。机器收据的 session ID 短哈希仅用于本轮相等性比较，不是对真实敏感令牌的匿名化保证。CVP 适用性与官方批准均 **OPEN**。
