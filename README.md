# LuomoAPI Hub

LuomoAPI Hub 是洛墨站的自托管 API 网关，线上运行于 <https://api.luomo.moe>。它同时做两件事：

- **模型换乘**：对外提供 OpenAI 兼容的 `/v1` 入口，按 key 授权模型、限速并用积分计费；
- **API 目录**：管理员登记内部上游与固定路由，开发者申请带 scope 的 key，经 `/api/public/v1/...` 受控调用。

站点按“夜行线换乘枢纽”设计：模型是线路，状态页是发车表，API key 是乘车券，积分钱包是 IC 卡。控制台全中文。

## 功能一览

| 模块 | 内容 |
| --- | --- |
| 模型网关 | `GET /v1/models`、`POST /v1/chat/completions`、`POST /v1/responses`，支持 JSON 与 SSE 流式；其他 `/v1` 路径一律拒绝 |
| 积分计费 | 先预留后结算的整数积分账本；价格表带版本（`app/credit_prices.json`）；兑换码；可选 Stripe Checkout 充值 |
| API 目录 | 上游 API、端点、公开路由登记；key 申请与审批；每 key 的 scope、每分钟限制与日配额 |
| 开发者控制台 | 自助创建模型 key、用量与日志、在线调试台（playground）、积分钱包 |
| 管理后台 | 用户、key、路由、审批、积分发放与冻结处理、模型用量、日志 |
| 公开页面 | 首页、模型线路、实时发车表 `/status`、价格 `/pricing`、文档 `/docs`、安全说明 `/security` |

## 快速开始

需要 Docker 与 Compose。示例 Compose 会接入外部网络 `luomocore_default`，第一次运行前先创建：

```bash
docker network create luomocore_default
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

把生成的随机值写入 `.env` 的 `SESSION_SECRET`（至少 32 个字符，否则 `/ready` 返回 503）。然后设置管理员密码并启动：

```bash
mkdir -p data
docker compose build
docker compose run --rm luomoapi-hub python scripts/set_admin_password.py
docker compose up -d
curl http://127.0.0.1:8790/ready
```

服务只映射到 `127.0.0.1:8790`。生产环境放在 HTTPS 反向代理或 Tunnel 之后，并按实际代理链设置 `TRUSTED_PROXY_PEERS`（见下文）。

## 调用模型

OpenAI 官方 SDK 只需改 `base_url`：

```python
import os
from openai import OpenAI

client = OpenAI(base_url="https://api.example.com/v1", api_key=os.environ["LUOMO_API_KEY"])
response = client.responses.create(model="gpt-6-luna", input="你好")
print(response.output_text)
```

```bash
curl https://api.example.com/v1/chat/completions \
  -H "Authorization: Bearer $LUOMO_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-6-luna", "messages": [{"role": "user", "content": "你好"}]}'
```

上游地址由 `CODEXPROXY_BASE_URL` / `CODEXPROXY_API_KEY` 指定，可以是任意 OpenAI 兼容服务。`/api/public/ai-catalog` 返回公开的模型目录。

### Key 类型

| 类型 | 来源 | 说明 |
| --- | --- | --- |
| 自助模型 key | 开发者控制台 | scope 为 `models:read`、`chat:completions`、`responses:create`；按积分扣费。管理员可在 `/admin/ai-keys/{id}` 限定模型、RPM、日/月额度和到期时间 |
| 目录 key | 申请后由管理员审批 | 用于 `/api/public/v1/...` 的路由调用，按 scope、速率和日配额放行 |
| 管理员免计量 key | `scripts/issue_admin_unmetered_key.py` | 需要精确 scope `admin:unmetered`，且所有者必须是在职管理员；每次调用都实时复核 |

Key 只在创建时显示一次，数据库只保存哈希。支持 `Authorization: Bearer` 与 `X-API-Key` 两种提交方式。

### 积分规则

- 1 元 = 100 积分，1 美元 = 720 积分；模型单价取自 OpenAI 官方 Standard 价格，按版本记录在 `app/credit_prices.json`。
- 每次调用先在短事务里预留积分，连接关闭后才访问上游；完成后按上游返回的真实 token 用量结算，未用完的预留退回钱包。
- 拿不到可靠用量、实际费用超出可用余额或回执冲突时，记录转为“待核”，由管理员在 `/admin/credits` 人工处理并留审计记录；系统不会自动透支。
- 只有经过签名校验的 Stripe 回执才会入账；`CREDIT_PAYMENT_PROVIDER` 留空时不开放在线支付，可用兑换码或管理员发放。

## API 目录网关

```bash
curl https://api.example.com/api/public/v1/demo/status \
  -H "Authorization: Bearer <api-key>"
```

调用方不能提交目标 URL：每条公开路径在数据库中绑定一个已登记的 API、HTTPS base URL、固定方法和固定目标路径。匿名路由需要管理员逐条开启。完整路由模型见 [docs/GATEWAY.md](docs/GATEWAY.md)。

## 安全设计

- **SSRF 防护**：上游只允许 HTTPS、不含用户信息；字面 IP 与全部 DNS 解析结果都必须是公网地址，并把请求钉到已校验的地址；不跟随重定向。
- **有界传输**：请求体上限 20 MB，响应上限 100 MB；上游客户端不保存、不转发 Cookie。
- **登录限流**：15 分钟窗口内，单账号最多 8 次失败、单来源最多 40 次；每次尝试先原子占位，并发请求也无法绕过。
- **真实来源识别**：只信任 `TRUSTED_PROXY_PEERS` 中代理传来的 `X-Forwarded-For`，其余一律按直连地址处理。
- **日志脱敏**：记录路径、耗时、状态码、IP 哈希与截断预览；`token`、`password`、`secret`、`key`、`cookie` 及授权字段会被掩码。
- **页面**：CSP 无内联样式；静态资源带内容指纹，可长期缓存。

漏洞报告方式见 [SECURITY.md](SECURITY.md)。

## 配置

完整列表见 [.env.example](.env.example)。常用项：

| 变量 | 作用 |
| --- | --- |
| `SESSION_SECRET` | 会话签名，至少 32 个字符 |
| `APP_BASE_URL` | 对外地址，用于邮件链接和页面展示 |
| `DATABASE_PATH` | SQLite 路径，默认 `/app/data/luomoapi.db` |
| `TRUSTED_PROXY_PEERS` | 可信反向代理地址，逗号分隔；默认 `127.0.0.1,::1,172.20.0.1` |
| `CODEXPROXY_BASE_URL` / `CODEXPROXY_API_KEY` | 模型网关的 OpenAI 兼容上游 |
| `CREDIT_PAYMENT_PROVIDER` / `CREDIT_STRIPE_*` | 在线充值，留空即关闭 |
| `SMTP_*` | 注册邮箱验证 |
| `SECURITY_CONTACT` | `/.well-known/security.txt` 的联系方式 |

## 健康检查与公开接口

```text
GET /health                 进程存活
GET /ready                  数据库表、会话密钥检查；未就绪返回 503
GET /api/public/status      实时发车表数据
GET /api/public/ai-catalog  公开模型目录
GET /api/public/stats       公开路由统计
GET /api/public/routes      公开路由列表
GET /.well-known/security.txt
```

## 目录结构

```text
app/
  main.py                 应用装配、页面与后台路由
  cliproxy_gateway.py     /v1 模型网关
  public_gateway_secure.py  目录网关与共享的 key / 配额 / 日志工具
  upstream_security.py    上游解析与地址钉定
  ai_*.py                 模型目录、key 策略、用量统计、控制台
  credit_*.py             积分账本、定价、支付、积分控制台
  login_throttle.py       登录限流
  client_ip.py            可信代理与真实来源
  web/templates/          Jinja2 模板
  web/static/             interchange.css、前端脚本、字体
scripts/                  运维脚本
tests/                    unittest 测试
docs/GATEWAY.md           路由模型说明
```

## 运维脚本

| 脚本 | 用途 |
| --- | --- |
| `scripts/init_db.py` | 初始化数据库结构 |
| `scripts/set_admin_password.py` | 交互式设置管理员密码 |
| `scripts/seed_default_apis.py` | 写入示例 API 目录 |
| `scripts/create_admin_api_key.py` | 创建管理员目录 key |
| `scripts/issue_admin_unmetered_key.py` | 签发管理员免计量模型 key，原文只写入服务器私有文件 |
| `scripts/admin_ops.py` | 受控维护操作 |
| `scripts/test_smtp.py` | 检查邮件配置 |
| `scripts/credit_browser_fixture.py` | 本地一次性浏览器测试环境，不连接真实上游与邮件 |
| `scripts/credit_candidate_probe.py` | 对隔离候选库做有界的真实上游验收 |

`data/`、`.env` 与备份目录已在 `.gitignore` 中排除。

## 开发与测试

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt -c requirements.lock
python -m unittest discover -s tests
```

测试使用临时数据库和假上游，不需要网络与真实密钥。CI（`.github/workflows/ci.yml`）在 Python 3.12 上执行 compileall、应用导入和完整测试。

## License

[MIT](LICENSE) © 2026 Luomo
