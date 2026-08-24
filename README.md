# opencode-free-proxy

OpenCode Zen 免费模型反向代理（OpenAI 兼容）

- 上游：`https://opencode.ai/zen/v1`
- 伪装官方 `opencode` CLI 指纹头，支持 `Bearer public` 匿名或 `ZEN_KEY` BYOK
- 免费模型动态发现 + 故障转移（`x-model-fallback`）

## 部署

### Deno Deploy
```bash
deno deploy --prod
# Variables: API_KEY, ZEN_KEY
```

### Railway (Dockerfile)
[![Deploy on Railway](https://railway.com/button.svg)](https://railway.com/deploy)

Variables: `API_KEY` (必填), `ZEN_KEY` (可选), `FALLBACK` (可选 `0` 关闭转移)

健康检查：`GET /`

## API

- `GET /v1/models` - 免费模型列表
- `POST /v1/chat/completions` - 对话（支持 `stream:true`）

Header: `Authorization: Bearer <API_KEY>`

Base URL: `https://<your-domain>/v1`
