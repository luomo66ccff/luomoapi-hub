# LuomoAPI Hub

LuomoAPI Hub 是一个小型 API 目录与受控网关。管理员在后台登记上游、端点和公开路由；开发者申请 API key 后，通过统一入口调用被允许的能力，并在自己的控制台查看配额与已脱敏的使用记录。

它的核心不是“转发任意网址”，而是把有限的内部 API 做成可审计、可撤销、带 scope 的产品接口。

## Lifecycle

```text
API catalog -> endpoint definition -> public route -> key request
     -> admin approval -> scoped call -> redacted usage log
```

- 账号注册支持邮箱验证。
- API key 只展示一次，数据库保存 PBKDF2-SHA256 哈希。
- 每把 key 有状态、scope、每分钟限制和每日配额。
- 公共路由绑定固定方法、固定上游 API 与固定目标 path。
- 上游秘密只通过环境变量引用，UI 不展示值。
- 请求/响应预览在入库前按敏感字段清洗并截断。

## Run a local catalog

```bash
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

把随机值写入 `SESSION_SECRET`，再生成管理员密码哈希：

```bash
mkdir -p data
docker compose build
docker compose run --rm luomoapi-hub python scripts/set_admin_password.py
docker compose up -d
curl http://127.0.0.1:8790/health
```

服务只映射到 `127.0.0.1:8790`。本地开发可访问 `http://localhost:8790`，生产环境应放在 HTTPS 与额外的边缘防护之后。

## Gateway request

```bash
curl https://api.example.com/api/public/v1/demo/status \
  -H 'Authorization: Bearer <api-key>'
```

也支持 `X-API-Key`。匿名路由必须由管理员逐条开启；普通路由会检查用户状态、key 状态、scope、速率和每日配额。路由模型与安全限制见 [docs/GATEWAY.md](docs/GATEWAY.md)。

## Administration tools

| Script | Purpose |
| --- | --- |
| `scripts/init_db.py` | 初始化数据结构 |
| `scripts/set_admin_password.py` | 交互式设置管理员密码 |
| `scripts/seed_default_apis.py` | 写入示例 API 目录 |
| `scripts/create_admin_api_key.py` | 创建管理员调用 key |
| `scripts/admin_ops.py` | 执行受控维护动作 |
| `scripts/test_smtp.py` | 验证邮件配置 |

`data/`、`.env` 和备份不会进入 Git。公开排障前仍应检查日志中是否含用户输入或上游数据。

## Public metadata

`/api/public/stats` 与 `/api/public/routes` 只返回公开标记的路由信息；`/.well-known/security.txt` 提供安全联系。内部目录、secret reference 和真实上游凭据不应出现在这些响应里。

## License

[MIT](LICENSE) © 2026 Luomo
