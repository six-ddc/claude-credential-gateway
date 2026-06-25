# claude-credential-gateway

一个**凭证隔离网关**:让你在自己的多台电脑(包括公共/不完全可信的电脑)上复用同一个 Claude
订阅,而**不在那些电脑上暴露真 token**。真 OAuth token 只留在一台你信任的网关机器上,不可信
电脑只放占位 token + 一个可吊销的设备 key,真请求经网关时被注入真凭证。

设计借鉴 Claude Code 自带的 `claude ssh` 凭证隔离机制(本地持凭证、远端只拿占位、代理注入)。
完整设计依据见 [PLAN.md](./PLAN.md),架构来源分析见 [SSH-ARCHITECTURE.md](./SSH-ARCHITECTURE.md)。

## 组件

| 文件 | 作用 |
|---|---|
| `gateway.js` | 凭证隔离网关。`oauth` 模式注入订阅 token(多设备复用);`apikey` 模式注入自己的 API key(产品后端) |
| `claude-proxy-demo.js` | 单进程透明转发 + 打印请求结构(观察 OAuth/base_url、attestation、metadata 等) |
| `test-gateway.js` | oauth 注入模式的自动化测试(mock 上游 + 假凭证,验证注入/不泄露/字节不变/SSE) |

## 快速开始

**纯链路自测(无需真凭证):**
```bash
node test-gateway.js     # 应输出 8/8 通过
```

**多设备复用(oauth 注入模式):**

网关机器(你信任的常驻机):
```bash
export CLAUDE_GATEWAY_UPSTREAM_OAUTH='<你的订阅 access token>'
export GATEWAY_UPSTREAM_MODE=oauth
export GATEWAY_USERS='{"device-laptop-1":{"id":"laptop-1","dailyLimit":200}}'
node gateway.js          # 生产前面挂 TLS + VPN/IP allowlist
```

不可信电脑(只放占位 + 设备 key,不放真 token):
```bash
unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN
export CLAUDE_CODE_OAUTH_TOKEN='placeholder-anything'
export ANTHROPIC_BASE_URL='https://你的网关'
export ANTHROPIC_CUSTOM_HEADERS='x-gateway-key: device-laptop-1'
claude
```

## 安全与合规边界

- **仅限本人、自己的设备、低并发自用。** 把设备 key 发给别人就成了订阅共享,违反 Anthropic
  服务条款,且会被账号级检测(同一 `account_uuid` + 单 IP + 高并发)命中。
- **网关保护的是 token,不是会话内容。** 不可信电脑仍能截屏/键盘记录你的 prompt 与输出。
  若那台机器真的敌对,优先用 `claude ssh <网关机器>`——让 Claude 跑在你的机器上,什么都不落地。
- **网关须是你信任且可控的机器**,暴露时加 TLS + 设备 key 鉴权 + VPN/allowlist。
- **token 续期**:网关里只贴 access token 会几小时过期;稳妥做法是网关机器正常登录、由网关从
  keychain 读并自动刷新。

> 仅供学习与个人自用。不用于、也不应用于绕过 Anthropic 服务条款。
