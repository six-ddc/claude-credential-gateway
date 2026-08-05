# `ANTHROPIC_UNIX_SOCKET` 在 Claude Code 里到底是怎么用的

> 本文只讲**客户端(Claude Code CLI)**这一侧:`ANTHROPIC_UNIX_SOCKET` 这个环境变量在源码里如何生效、
> 完整的技术链路是什么、为什么必须信任证书。最后一节说明本网关如何复用同一形态、方向为何相反。
>
> 依据两处:
> - **还原源码** `@anthropic-ai/claude-code` v2.1.88 的 sourcemap(`restored-src/src/...`,下称「源码」);
> - **官方二进制** v2.1.220 内嵌的打包 JS(下称「binary」),用于确认 2.1.88 里尚未收录源文件的实现。
>
> 引用行号对应 `../claude-code-sourcemap/restored-src/`。

---

## 0. 一句话结论

`ANTHROPIC_UNIX_SOCKET` 是官方 `claude ssh` 远端会话专用的机制:它**只把 HTTP 请求的传输层从 TCP 换成一个
unix domain socket**,目标 URL 和 TLS 握手完全不变——请求仍然发往 `https://api.anthropic.com`、仍然做完整
TLS 握手、SNI 仍是 `api.anthropic.com`。socket 另一端是一个**本地鉴权代理**,它终结 TLS、把占位凭证换成真凭证、
再转发到真正的 Anthropic API。

因为客户端会对 `api.anthropic.com` 做完整证书校验,所以代理必须拿一张**客户端认可的 `api.anthropic.com` 证书**;
在私有 CA / 自签场景下,客户端靠 `NODE_EXTRA_CA_CERTS` 信任那把 CA。**所以「要不要信任证书」的答案是:要。**

---

## 1. 官方场景:`claude ssh <host>` 远端会话

`ANTHROPIC_UNIX_SOCKET` 不是给终端用户直接设的,它是 `claude ssh` 在远端主机上自动注入的。整条链路:

```
你的本机(有订阅凭证)                          远端主机(裸机,没登录过 claude)
┌───────────────────────────┐                  ┌────────────────────────────────┐
│ claude ssh <host>         │                  │  claude(远端进程)              │
│  ├─ 探测/部署远端 binary   │                  │   ANTHROPIC_UNIX_SOCKET=<sock>  │
│  ├─ 起本地 auth proxy      │◀── ssh -R ──────▶│   CLAUDE_CODE_OAUTH_TOKEN=占位  │
│  │   (终结 TLS,注入真凭证)│   unix socket    │   → 所有 API 请求走 socket       │
│  └─ 驱动远端 REPL          │   反向转发        │                                │
└───────────────────────────┘                  └────────────────────────────────┘
      凭证只留在你本机                                远端始终拿不到真凭证
```

- 远端**不需要**装 Claude、也**不需要** `claude auth login`。binary 通过 SSH 部署,API 鉴权「隧道回」你本机。
  这一点在 `program.command('ssh <host> [dir]')` 的描述里写死:*"Deploys the binary and tunnels API auth back
  through your local machine — no remote setup needed."*(`src/main.tsx:4046`)
- 方向是 **`ssh -R`**(remote forward):远端**发布**一个 unix socket,连接反向流回你本机的 auth proxy。
  源码注释:*"ANTHROPIC_UNIX_SOCKET routes auth through a -R forwarded socket to a local proxy"*
  (`src/utils/managedEnv.ts:18`);*"spawn ssh with unix-socket -R forward to a local auth proxy"*
  (`src/main.tsx:3195`)。
- REPL 侧的会话对象持有这个代理:`useSSHSession` 清理时调用 `session.proxy.stop()`(`src/hooks/useSSHSession.ts:211`)。
  代理 + ssh 子进程在 `main.tsx` 启动阶段就创建好,再交给 hook(`src/hooks/useSSHSession.ts:6-9`)。

> 注:`createSSHSession.js` / `sshAuthProxy.ts` 的源文件在 2.1.88 的 sourcemap 里没有收录内容(只有 import 引用),
> 所以本文对「本地代理内部实现」的描述来自注释、类型签名与 binary 里 SRT MITM 模块的对照(见 §5),而非逐行原文。

---

## 2. 传输层替换:唯一真正改变的东西

核心只有一个函数 `getProxyFetchOptions`(`src/utils/proxy.ts:289`):

```ts
export function getProxyFetchOptions(opts?: { forAnthropicAPI?: boolean }) {
  // ANTHROPIC_UNIX_SOCKET tunnels through the `claude ssh` auth proxy, which
  // hardcodes the upstream to the Anthropic API. Scope to the Anthropic API
  // client so MCP/SSE/other callers don't get their requests misrouted.
  if (opts?.forAnthropicAPI) {
    const unixSocket = process.env.ANTHROPIC_UNIX_SOCKET
    if (unixSocket && typeof Bun !== 'undefined') {
      return { ...base, unix: unixSocket }   // ← 全部改动就这一行
    }
  }
  // ...否则走 proxy / mTLS / 直连
}
```

binary v2.1.220 里是同一行逻辑:`if(e.forAnthropicAPI){let i=Z.ANTHROPIC_UNIX_SOCKET;if(i)return{...n,unix:i}}`。

要点:

1. **只多了 `{ unix: <path> }` 一个字段**。请求的 URL、method、header、以及 TLS 层**一概不动**。Bun 的
   `fetch` 支持 `unix` 选项:走这个 socket 建立字节流,但**在这条字节流之上照常发起对
   `api.anthropic.com` 的 HTTPS**。所以传输是 socket,协议仍是完整 HTTPS。
2. **严格限定 `forAnthropicAPI: true`**。只有 Anthropic SDK 客户端这一个调用点传 `true`
   (`src/services/api/client.ts:147`)。MCP 的 HTTP/SSE 传输、遥测、其它 fetch 都不传,
   否则它们会被错误地灌进这个「硬编码上游是 Anthropic API」的 socket。注释明确警告了这一点
   (`src/utils/proxy.ts:281-288`)。
3. **base URL 不变**。socket 模式下不设 `ANTHROPIC_BASE_URL`,SDK 用默认的 `https://api.anthropic.com`。
   这就是为什么代理必须能应答 `api.anthropic.com` 的 TLS——客户端就是冲着这个域名握手的。

---

## 3. 鉴权:占位 token + `oauth-2025`,真凭证在代理侧注入

远端进程手里的 `CLAUDE_CODE_OAUTH_TOKEN` 是**占位值**,不参与真正鉴权。它存在的唯一目的,是让客户端
**走订阅(subscriber)分支、带上 `oauth-2025` beta 头**,使远端发出的请求形状与代理即将注入的真订阅 token 对齐。

`isAnthropicAuthEnabled()`(`src/utils/auth.ts:104-113`):

```ts
// `claude ssh` remote: ANTHROPIC_UNIX_SOCKET tunnels API calls through a
// local auth-injecting proxy. The launcher sets CLAUDE_CODE_OAUTH_TOKEN as a
// placeholder iff the local side is a subscriber (so the remote includes the
// oauth-2025 beta header to match what the proxy will inject). The remote's
// ~/.claude settings (apiKeyHelper, settings.env.ANTHROPIC_API_KEY) MUST NOT
// flip this — they'd cause a header mismatch with the proxy and a bogus
// "invalid x-api-key" from the API.
if (process.env.ANTHROPIC_UNIX_SOCKET) {
  return !!process.env.CLAUDE_CODE_OAUTH_TOKEN   // 占位 token 存在 → 启用 1P 订阅鉴权路径
}
```

配套的保护:

- **组织校验短路**。`validateForceLoginOrg()` 在 socket 模式直接返回 `{ valid: true }`——真鉴权在你本机侧,
  占位 token 没法拿去 profile 端点校验,本机在建会话前已经查过了(`src/utils/auth.ts:1927`)。
- **远端 settings 不许翻盘**。远端 `~/.claude/settings.json` 里的 `apiKeyHelper` /
  `settings.env.ANTHROPIC_API_KEY` 若生效,会让客户端改发 `x-api-key`、与代理注入的 Bearer 头冲突,
  上游报假的 "invalid x-api-key"。为此 `withoutSSHTunnelVars()` 把这几个变量从 settings 来源的 env 里
  **整组剥掉**(`src/utils/managedEnv.ts:23-36`):

  ```ts
  const { ANTHROPIC_UNIX_SOCKET, ANTHROPIC_BASE_URL, ANTHROPIC_API_KEY,
          ANTHROPIC_AUTH_TOKEN, CLAUDE_CODE_OAUTH_TOKEN, ...rest } = env
  return rest   // 这 5 个只认「启动器注入的那份」,settings 别想覆盖
  ```

真凭证注入发生在代理侧:把请求里的占位 `Authorization` 换成你订阅的真 OAuth token,再转发到真 API。

---

## 4. 为什么必须终结 TLS、必须信任证书

把上面拼起来:

- 客户端对 `api.anthropic.com` 发**完整 HTTPS**(SNI = `api.anthropic.com`),只不过传输走 socket;
- 代理要替换 `Authorization`,就必须先**解密**这条 TLS——也就是**终结 TLS**;
- 终结 TLS 就得给客户端一张它认可的 `api.anthropic.com` 证书。真 CA 不可能给你签,只能**自建 CA 现签一张**;
- 客户端默认会校验证书链,自签 CA 不在信任库里 → 握手失败。解决办法:让客户端信任那把 CA。

客户端读取信任锚的逻辑(`getCACertificates()`,`src/utils/caCerts.ts`):

- 设了 `ca` 就会**替换**默认证书库,所以实现里始终把系统 / 内置 Mozilla 根证书**并上**再返回;
- 分支:两者都没设 → `undefined`(用运行时默认);只设 `NODE_EXTRA_CA_CERTS` → 内置 Mozilla CA + 你的额外 CA;
  `--use-system-ca` → 系统 CA;两者都设 → 系统 CA + 你的额外 CA。

于是**两条信任路径**任选其一:

1. **`NODE_EXTRA_CA_CERTS=/path/to/ca.pem`** —— 指向那把自建 CA 的 PEM。最通用,native binary 与 Node 都认。
2. **把 CA 装进操作系统信任库** —— native binary 与 Node ≥ 22.15 会默认读系统信任库(见下方报错提示原文)。

binary 里对「验不过证书」给出的诊断,把这两条路都写明了:

> Could not verify the gateway's TLS certificate. If your gateway uses a private CA or self-signed
> certificate: Claude Code reads your OS trust store by default on the native binary and Node ≥22.15,
> so if the CA is already installed there, upgrade to a current runtime. Otherwise set
> `NODE_EXTRA_CA_CERTS` to the CA certificate PEM file before starting — e.g.
> `export NODE_EXTRA_CA_CERTS=/path/to/ca.pem` — or add it under `env.NODE_EXTRA_CA_CERTS` in your
> user settings (`~/.claude/settings.json`).

**结论:socket 形态下必须信任证书。** 只有一种例外——如果代理选择**不终结 TLS**、把加密字节原样透传到真
上游(纯 TCP 隧道),那就不需要 CA;但那样代理也**改不了 `Authorization`**,无法注入凭证。凡是要「替换凭证」,
就必然终结 TLS、必然要信任那把 CA。

### 附:preconnect 会主动跳过 socket 模式

启动优化 `preconnectAnthropicApi()`(提前打 TCP+TLS 握手预热连接池)在检测到 `ANTHROPIC_UNIX_SOCKET`
时**直接跳过**——因为 SDK 会用自定义 dispatcher,预热的全局连接池根本不会被复用
(`src/utils/apiPreconnect.ts:43-54`)。这从侧面印证:socket 模式确实换掉了底层 transport。

---

## 5. 一个容易混淆的点:binary 里的 `tlsTerminate` / `[mitm-ca]` 不是这条链路

在 binary 里搜 TLS 终结,会撞见一整套 `tlsTerminate` / `[mitm-ca]` / `srt-ca-` / `createSecureContext` /
node-forge 签证书的代码。**注意别张冠李戴**:那是 **sandbox-runtime(SRT)/ CCR 容器**的上游代理
(`src/upstreamproxy/upstreamproxy.ts`),用于在**云端容器沙箱**里 MITM 出站流量、给 curl/gh/python 注入
CA——服务于 `CLAUDE_CODE_REMOTE` + `CCR_UPSTREAM_PROXY_ENABLED`,和 `claude ssh` 的 auth proxy 是**两套东西**。

有意思的是它对 `anthropic.com` 反而**加进 NO_PROXY 不拦截**,注释理由:*"the MITM breaks non-Bun runtimes
(Python httpx/certifi doesn't trust the forged CA)"*(`src/upstreamproxy/upstreamproxy.ts:44-51`)。
这恰好反向说明了 §4 的道理——**伪造 `api.anthropic.com` 证书要生效,客户端就得信任那把伪造 CA**;它对付不了
不读该 CA 的运行时,所以官方在容器里干脆绕开 Anthropic 域名。而 `claude ssh` 的 auth proxy 之所以能对
`api.anthropic.com` 做 MITM,正是因为客户端跑在 Bun 上、并被配置了信任那把 CA。

---

## 6. 本网关如何复用同一形态(方向相反)

本网关的目标与 `claude ssh` **相反**:官方是「凭证在你本机、算力在远端」;本网关是
「**凭证在网关(服务端)、设备是消费方**」。但两者的**传输形态完全一致**,都是「unix socket + 对
`api.anthropic.com` 的完整 TLS + 服务端终结 TLS 注入真凭证」。区别只在 **socket 发布的方向**:

| | 官方 `claude ssh` | 本网关 |
|---|---|---|
| 凭证位置 | 你的本机 | 网关机 |
| socket 方向 | `ssh -R`,远端发布、连回本机代理 | `ssh -L`,设备本地发布、连到网关 |
| TLS 终结方 | 本机 auth proxy | 网关 `tlsterm.go` |
| 设备/远端信任 | `NODE_EXTRA_CA_CERTS` → 本机 CA | `NODE_EXTRA_CA_CERTS` → 网关自建 CA |
| 占位 token | 启动器注入 | 设备手动设(所有设备同一个假值) |

网关侧对应实现:

- **TLS 终结 + 伪证书**:`tlsterm.go`。自建 CA 落盘长期复用(设备 pin 它),每次启动在内存里用它现签一张
  `api.anthropic.com` 叶证书(`forgedHost = "api.anthropic.com"`)。设备用 `NODE_EXTRA_CA_CERTS` 信任该 CA,
  或经已认证隧道自取 `GET /ca`。
- **凭证注入**:`main.go` 透明转发,只把 `Authorization` 覆盖成订阅真 token,并剥掉设备残留的 `x-api-key`
  (`ANTHROPIC_API_KEY` 会让客户端改发 `x-api-key`,优先级高于 Authorization,不剥就 401)。
- **两形态自动区分**:`sshfwd.go` 首字节嗅探——`0x16` 是 TLS handshake record(socket 形态)→ 交 TLS 终结;
  否则当明文 HTTP(`ANTHROPIC_BASE_URL` 调试形态)。

设备侧跑 `claude` 需要的环境变量,与官方远端进程拿到的是同一组(见 `scripts/setup-device.sh` / README):

```bash
unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN ANTHROPIC_BASE_URL
export ANTHROPIC_UNIX_SOCKET=$HOME/.ccgw-<device>.sock   # 传输层换成 socket
export NODE_EXTRA_CA_CERTS=$HOME/.ccgw/ccgw_ca.crt        # 信任网关自建 CA —— 就是本文 §4 的那把
export CLAUDE_CODE_OAUTH_TOKEN='sk-ant-oat01-placeholder' # 占位:走订阅分支、带 oauth-2025 头
```

---

## 7. 关键引用一览

| 主题 | 位置 |
|---|---|
| transport 只加 `{unix}` | `src/utils/proxy.ts:289`(`getProxyFetchOptions`) |
| 唯一传 `forAnthropicAPI:true` 的调用点 | `src/services/api/client.ts:147` |
| 占位 token → 启用订阅鉴权 | `src/utils/auth.ts:104-113`(`isAnthropicAuthEnabled`) |
| 组织校验短路 | `src/utils/auth.ts:1927`(`validateForceLoginOrg`) |
| 剥掉 settings 里的隧道变量 | `src/utils/managedEnv.ts:23-36`(`withoutSSHTunnelVars`) |
| `-R` 转发、本地 auth proxy | `src/main.tsx:3195`、`src/utils/managedEnv.ts:18` |
| ssh 会话持有 proxy、清理时 stop | `src/hooks/useSSHSession.ts:9,211` |
| CA 信任库加载 | `src/utils/caCerts.ts`(`getCACertificates`) |
| preconnect 跳过 socket 模式 | `src/utils/apiPreconnect.ts:43-54` |
| 证书校验失败诊断文案 | binary(offset ≈ 239138524) |
| SRT/CCR 上游 MITM(**另一套**) | `src/upstreamproxy/upstreamproxy.ts` |
| 网关 TLS 终结 / 伪证书 | `tlsterm.go` |
| 网关凭证注入 / 剥 x-api-key | `main.go` |
| 首字节嗅探两形态 | `sshfwd.go:192`(`sniffTunnelConn`) |
