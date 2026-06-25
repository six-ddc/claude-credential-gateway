# `claude ssh` 架构分析 —— server/client 拆分与凭证隔离

目标:把 `claude ssh` 的"本地持真凭证、远端跑 agent 只拿占位 token、本地代理注入真 token"
这套机制吃透,提炼出可复用到自己产品的**凭证隔离(credential isolation)模式**。

> 依据:从 sourcemap 还原的 `@anthropic-ai/claude-code@2.1.88`,路径相对 `restored-src/src/`。
> `src/ssh/` 目录(createSSHSession / SSHSessionManager / sshAuthProxy)**未还原**,标为黑盒,按契约反推。

---

## 一、它解决什么问题

`claude ssh <host> [dir]`:在**远端机器**上跑 Claude Code(在远端文件上干活、远端执行工具),
但你的**真凭证永远留在本地**,绝不落到远端。

这是一个经典的"信任边界"问题:**跑 agent 的一方(远端,可能不可信)≠ 持凭证的一方(本地)。**
解法是把认证从"agent 运行处"剥出来,放到本地一个受信代理里,远端只拿一个用不了多少的占位 token。

---

## 二、三个角色 + 两条通道

```
            本地(受信,持真凭证)                          远端(跑 agent)
   ┌───────────────────────────────────┐        ┌──────────────────────────────┐
   │  REPL / UI (你看到的界面)          │        │  真正的 Claude Code agent loop │
   │  SSHSessionManager  ◀── 控制通道 ──┼────────┼──▶ 工具执行 / 读写远端文件     │
   │   (JSON-RPC over ssh stdio)        │        │                              │
   │                                    │        │  发 API 请求时:             │
   │  本地 auth proxy (sshAuthProxy)    │        │   getProxyFetchOptions()      │
   │   - 监听 unix socket               │        │   见 ANTHROPIC_UNIX_SOCKET     │
   │   - 注入真 OAuth token   ◀─ 认证通道┼────────┼── 改走 unix socket            │
   │   - 转发到 api.anthropic.com        │ ssh -R │   (占位 token 在请求里)        │
   └───────────────────────────────────┘        └──────────────────────────────┘
```

**关键:有两条独立通道,别混淆。**

| 通道 | 走什么 | 方向 | 载荷 |
|---|---|---|---|
| 控制通道 | ssh 子进程 stdio(JSON-RPC) | 远端 agent ↔ 本地 UI | SDK 消息、权限请求、会话事件 |
| 认证通道 | unix socket + `ssh -R` 反向转发 | 远端 API 调用 → 本地 auth proxy → api.anthropic.com | 真正的推理请求,token 在本地被注入 |

agent loop 在**远端**跑(所以 `ANTHROPIC_UNIX_SOCKET` 是远端的 env);它发出的 API 请求被路由回
本地代理注入真 token。UI 在本地。两边用 ssh stdio 上的 JSON-RPC 同步。

---

## 三、完整时序

### Setup(都在本地 main.tsx 启动期完成 —— 见 `hooks/useSSHSession.ts:1-10` 注释)

```
本地 launcher (main.tsx)
  1. 解析 `claude ssh <host> [dir]`,需 SSH_REMOTE flag
  2. 启动本地 auth proxy:监听一个 unix socket;它能读你本地 keychain 里的真凭证   [黑盒 sshAuthProxy.ts]
  3. spawn ssh,带 -R 反向转发:把【远端的 socket 路径】转发回【本地 auth proxy 的 socket】
  4. (按需)探测/部署远端的 claude 二进制                                       [黑盒 createSSHSession.ts]
  5. 在远端进程注入 env:
       ANTHROPIC_UNIX_SOCKET = <远端被转发的 socket 路径>
       CLAUDE_CODE_OAUTH_TOKEN = <占位符>      (本地是订阅用户时才设)
  6. 得到 SSHSession 对象,连同 proxy 句柄一起交给 useSSHSession hook
```

### Request(一次推理)

```
远端 agent loop
  1. 拼请求:body 含 sysprompt 前缀 + attribution(cch=00000)+ metadata + betas(含 oauth-2025)
  2. 远端是【真二进制】→ 原生层把 cch 覆写成合法 attestation
  3. auth 头 = Bearer <占位 token>
  4. getProxyFetchOptions({forAnthropicAPI:true}) 见到 ANTHROPIC_UNIX_SOCKET → 请求写进 unix socket
       (proxy.ts:300-305;只对 Anthropic API 这条路,MCP/SSE 不受影响)
        │  ssh -R 隧道
        ▼
本地 auth proxy
  5. 剥掉占位 Authorization,换成本地 keychain 的【真 OAuth token】
  6. 上游硬编码 api.anthropic.com,HTTPS 转发(注释 proxy.ts:297-299)
        │
        ▼  SSE 响应原路流回远端 agent → 远端继续 loop
```

### Control / 权限 / 收尾

```
- 远端 agent 产生的 assistant 消息、工具结果、权限请求
    → JSON-RPC over ssh stdio → 本地 SSHSessionManager → useSSHSession → REPL 渲染
- 权限确认在【本地】弹给你,决定再回传远端
- 断开:useSSHSession 清理时 session.proxy.stop(),代理生命周期绑定 ssh 会话
```

---

## 四、凭证隔离的 5 个锚点(逐条对应源码)

这是整套设计的精华,每一条都是"让远端拿到 token 也没用 / 改不了"的一道闸:

1. **远端拿的是 inference-only 占位 token**(`auth.ts:1255-1300`)
   `CLAUDE_CODE_OAUTH_TOKEN` 走的分支返回 `{refreshToken:null, expiresAt:null, scopes:['user:inference']}`
   → 远端**不能刷新、不能查 profile、能力被钉死**。真 token 从不下发。

2. **真 token 只在本地注入**(黑盒 `sshAuthProxy.ts`,契约见 `proxy.ts:297-299`)
   远端请求带占位头,本地代理换成真 token 再转发。**信任边界 = unix socket 这一跳。**

3. **远端 settings 不能翻转认证**(`managedEnv.ts:17-36` `withoutSSHTunnelVars`)
   从所有 settings 来源的 env 里 strip 掉这 5 个:
   `ANTHROPIC_UNIX_SOCKET`(防改 socket 路径)、`ANTHROPIC_BASE_URL`(防重定向到攻击者端点)、
   `ANTHROPIC_API_KEY` / `ANTHROPIC_AUTH_TOKEN`(防覆盖凭证)、`CLAUDE_CODE_OAUTH_TOKEN`(防顶掉占位)。

4. **认证判定锁死在隧道模式**(`auth.ts:104-113`)
   `if (process.env.ANTHROPIC_UNIX_SOCKET) return !!process.env.CLAUDE_CODE_OAUTH_TOKEN`
   → 远端的 apiKeyHelper / ANTHROPIC_API_KEY **不能**翻转认证;否则会跟代理注入的产生 header 冲突,
   API 报假的 "invalid x-api-key"(注释明示)。

5. **scope 隔离 + 路由隔离**
   - scope 只有 `user:inference` → 占位 token 即使泄露也只能推理,碰不到 profile/账号操作。
   - `forAnthropicAPI` flag(`proxy.ts:300`)让**只有 Anthropic API** 走 socket,MCP/SSE/其他不被误导到这条隧道。

---

## 五、占位 token 的设计巧思

为什么远端要设一个"假" token,而不是干脆不设?

因为请求的**形状**必须在远端就拼对。`isClaudeAISubscriber()` 为 true 时才会加
`oauth-2025-04-20` beta 头(`betas.ts:251`)、才会按订阅形状构建。远端要"看起来是订阅请求",
就得有个 token 让它进 OAuth 分支——但这个 token 不需要是真的,因为真值会在本地代理被换掉。

所以占位 token 的作用是:**让远端拼出和本地代理将注入的真 token 相匹配的请求形状**,
而不泄露任何真凭证。这是"形状在不可信侧拼、凭证在可信侧注入"的分离。

---

## 六、为什么 attestation 不会被这套破坏

- 远端跑**真二进制** → 原生层照常算 `cch`,算在 **body** 上(`constants/system.ts:64-95`)。
- 本地代理换的是 **Authorization 头**,不动 body → attestation 仍然有效。
- 这套能跑起来,本身就证明 **attestation 没和 token 值绑定**,只绑客户端真实性 + body。

---

## 七、套用到你自己产品:可复用的凭证隔离模式

把上面抽象成一套"持凭证方 / 用凭证方分离"的设计,跟具体是不是 ssh 无关:

1. **能力最小化的占位凭证**:发给"用凭证方"的,是一个 scope 受限、不能续期、不能做账号操作的
   短能力 token(对应 inference-only)。真凭证永不下发。
2. **在受信侧注入真凭证**:注入点是你信任边界的最后一跳(对应本地 auth proxy)。用凭证方只拼请求形状。
3. **形状在外、凭证在内**:让不可信侧能拼出正确请求形状(带对 header / beta),但真值在受信侧补。
4. **锁死配置,防篡改**:把能改变"发去哪 / 用什么认证"的 env / 配置项从不可信侧 strip 掉
   (对应 `withoutSSHTunnelVars`)——否则它能把流量重定向到攻击者、或顶掉你的注入。
5. **通道隔离**:控制通道(消息/权限)和认证通道(带凭证的请求)分开走,各自最小权限
   (对应 ssh stdio vs unix socket,以及 `forAnthropicAPI` 只让 API 走隧道)。
6. **上游硬编码**:注入代理的上游目标写死,不接受被注入方指定(对应"硬编码 api.anthropic.com")。

> 注意边界:这套模式本身是"把凭证从 agent 运行处隔离出来",它对**单一主体**(你自己,或你产品里
> 一个合法用户对一份合法凭证)成立。把它用成"一份凭证服务多个不同主体"就回到共享问题——
> 那是部署语义的事,不是这套机制能解决的。

---

## 八、黑盒部分(`src/ssh/`,未还原)的契约反推

| 文件 | 反推职责 |
|---|---|
| `createSSHSession.ts` | `createSSHSession({host,cwd,...})` / `createLocalSSHSession(...)`:探测/部署远端二进制、启动本地 auth proxy、spawn `ssh -R`、注入远端 env、返回 `SSHSession`(带 `proxy` 句柄) |
| `SSHSessionManager.ts` | ssh 子进程 stdio 上的双向 JSON-RPC:路由 SDK 消息、权限请求、重连信号 |
| `sshAuthProxy.ts` | 监听 unix socket;拦截带占位 token 的请求;从本地 keychain 取真 OAuth token 注入;补订阅头;转发到硬编码的 api.anthropic.com |

类型来源:`hooks/useSSHSession.ts:23-24` 导入 `SSHSession`(from `../ssh/createSSHSession.js`)、
`SSHSessionManager`(from `../ssh/SSHSessionManager.js`)。

---

## 九、源码索引(相对 `restored-src/src/`,标注 已还原 / 黑盒)

- 命令解析 + 启动期建 ssh 进程与 auth proxy:`main.tsx`(已还原;`useSSHSession.ts:1-10` 注释佐证)
- REPL 集成 hook + 代理生命周期:`hooks/useSSHSession.ts`(已还原)
- 认证锁定在隧道模式:`utils/auth.ts:104-113`(已还原)
- 占位 token → inference-only:`utils/auth.ts:1255-1300`(已还原)
- 请求改走 unix socket:`utils/proxy.ts:288-319`(已还原)
- 防篡改 strip env:`utils/managedEnv.ts:17-36`(已还原)
- 跳过 TCP 预热:`utils/apiPreconnect.ts:43-54`(已还原)
- SDK client 用 forAnthropicAPI:`services/api/client.ts:146`(已还原)
- 订阅 beta:`utils/betas.ts:251`;attestation:`constants/system.ts:64-95`(已还原)
- ssh 隧道机制实现:`src/ssh/createSSHSession.ts`、`SSHSessionManager.ts`、`sshAuthProxy.ts`(黑盒,未还原)
