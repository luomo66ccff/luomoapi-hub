# Gateway Model

## Route registry

调用者不能提交目标 URL。每条公开路径在数据库中绑定一个已登记 API、一个 HTTPS base URL、固定 method 和固定 target path。查询参数和请求体可以转发，但不能改变上游主机。

目标 URL 必须满足：

- 仅 HTTPS；
- 不含 username/password；
- 字面 IP 必须是公网地址；
- DNS 的全部当前解析结果都必须是公网地址；
- 网关不跟随上游重定向。

DNS 检查是纵深防御，不替代管理员对上游域名的审核。不要把可由不受信任用户控制解析结果的域名加入目录。

## Key policy

key 可通过 `Authorization: Bearer` 或 `X-API-Key` 提交。每次调用依次验证账号、key、scope、每分钟限制与 UTC 日配额。撤销 key 后立即失效。

上游认证值来自路由记录中的环境变量名称，例如 `ASTRBOT_API_KEY`；数据库只保存名称，不保存秘密本身。

## Logging

使用日志保留公共路径、耗时、状态码、IP 哈希与截断后的预览。带 `token`、`password`、`secret`、`key`、`cookie` 或授权字段的数据会被掩码。对高度敏感的 API，建议完全关闭 body preview，而不是只依赖关键词脱敏。
