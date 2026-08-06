# 网关的传输层:HTTP 正向代理 + TLS 终结

> 这篇讲**设备上的 Claude Code 是怎么把流量交到网关手里的**,以及每一步为什么只能这么做。
>
> 依据三处:
> - **Claude Code 客户端源码** —— `@anthropic-ai/claude-code` v2.1.88 的 sourcemap 还原产物,
>   下文写作「客户端源码」,行号相对还原出来的 `src/` 目录(如 `utils/proxy.ts:300-305`);
> - **官方文档** ——《[Enterprise network configuration](https://code.claude.com/docs/en/network-config)》
>   与《[LLM gateway](https://code.claude.com/docs/en/llm-gateway)》;
> - **网关自身代码** —— `proxy.go`、`sshfwd.go`、`main.go`、`tlsterm.go`。

---

## 0. 一句话结论

设备侧把 `HTTPS_PROXY` 指向 SSH 隧道的本地口。Claude Code 于是对**每一个** HTTPS 目标先发
`CONNECT <host>:443`,网关按名单二选一:`api.anthropic.com` 就地终结 TLS、把 `Authorization`
换成真凭证再转发;其余主机纯 TCP 盲转发。因为要解密,网关必须拿一张客户端认可的
`api.anthropic.com` 证书 —— 自建 CA 现签,设备用 `NODE_EXTRA_CA_CERTS` 信任那把 CA。

选代理而不选 unix socket,不是口味问题:**unix socket 在客户端里根本覆盖不了全部流量**。

---

## 1. 为什么 `ANTHROPIC_UNIX_SOCKET` 这条路走不通

`ANTHROPIC_UNIX_SOCKET` 是官方 `claude ssh` 用的机制,乍看很合适 —— 它把 API 请求的传输层
换成一个 unix socket,天然适合「设备在外、凭证在内」。但把它当网关的传输层会漏掉大半流量。

### 1.1 它只改一条 fetch 路径

在传输层面,这个变量只有一处生效:`getProxyFetchOptions()`(客户端源码 `utils/proxy.ts:288-305`)。
签名带一个开关,只有开关为真才会返回 `unix`:

```ts
export function getProxyFetchOptions(opts?: { forAnthropicAPI?: boolean }): {
  tls?: TLSConfig
  dispatcher?: undici.Dispatcher
  proxy?: string
  unix?: string
  keepalive?: false
}
```

```ts
  if (opts?.forAnthropicAPI) {
    const unixSocket = process.env.ANTHROPIC_UNIX_SOCKET
    if (unixSocket && typeof Bun !== 'undefined') {
      return { ...base, unix: unixSocket }
    }
  }
```

函数上方的 JSDoc(`utils/proxy.ts:277-287`)把限制写死了:

> `@param opts.forAnthropicAPI` - Enables ANTHROPIC_UNIX_SOCKET tunneling. This env var is set by
> `claude ssh` on the remote CLI to route API calls through an ssh -R forwarded unix socket to a
> local auth proxy. It **MUST NOT leak into non-Anthropic-API fetch paths** (MCP HTTP/SSE transports,
> etc.) or those requests get misrouted to api.anthropic.com. **Only the Anthropic SDK client should
> pass `true` here.**

而全仓传 `forAnthropicAPI: true` 的调用点确实只有一个 —— Anthropic SDK 客户端的构造参数
(`services/api/client.ts:146-148`,结果塞进 SDK `ClientOptions` 的 `fetchOptions` 字段):

```ts
    fetchOptions: getProxyFetchOptions({
      forAnthropicAPI: true,
    }) as ClientOptions['fetchOptions'],
```

其余四处调用(`services/mcp/client.ts:657/682/815/887`)全是无参的,正是注释点名不许泄漏进去的路径。

所以能进 socket 的,只有 SDK 发出的那条流 —— 实际上就是 `/v1/messages`。

> 这个变量还在另外三个文件里被读到,但都跟传输无关:`utils/auth.ts:104-113` 用它翻转
> `isAnthropicAuthEnabled()`(设了之后改判 `!!CLAUDE_CODE_OAUTH_TOKEN`)、`utils/auth.ts:1927-1929`
> 让 `validateForceLoginOrg()` 直接放行、`utils/managedEnv.ts:26-28` 把一组隧道变量从 settings 来源的
> env 里剥掉、`utils/apiPreconnect.ts:49` 跳过预连接。这些改的是鉴权判定和启动行为,
> 不会多接管一个字节。

### 1.2 面板和启动流程的请求走的是另一条栈

`/usage` 面板要的额度数据来自 `GET /api/oauth/usage`,它用的是**全局 axios**
(`services/api/usage.ts:55-60`);`/api/oauth/profile`(`services/oauth/getOauthProfile.ts:40-41`)、
`/api/claude_cli/bootstrap`(`services/api/bootstrap.ts:63,84`)同样。三者的 base URL 取自
`getOauthConfig().BASE_API_URL`,生产值就是 `https://api.anthropic.com`(`constants/oauth.ts:83-84`)。

客户端源码里没有自定义 axios 实例给它们用 —— 唯一的实例工厂 `createAxiosInstance()`
(`utils/proxy.ts:168`)只服务 CCR 传输(`cli/transports/ccrClient.ts:273`),`utils/http.ts` 只导出
UA、鉴权头和 401 重试包装,不建实例。这几个端点跑在全局默认实例上,而全局实例完全看不见
`ANTHROPIC_UNIX_SOCKET`。

值得单独记一笔:这三个端点**也不读** `ANTHROPIC_BASE_URL`。就算把 SDK 的上游改到别处,
它们照样直奔真实的 `api.anthropic.com`。

### 1.3 还有两道更硬的门

- **`unix` 是 Bun 专属选项,并且被显式门控**:`utils/proxy.ts:302` 那句
  `if (unixSocket && typeof Bun !== 'undefined')` 意味着 Node 运行时下这个变量在 fetch 层完全没有效果。
  axios 在 Bun 里走的是 node:http polyfill,同样拿不到 Bun fetch 的 `unix`。
- **没有全局 unix dispatcher**:全仓 `setGlobalDispatcher` 只有两处(`utils/proxy.ts:372`、`383`),
  装的是代理 agent 和 mTLS dispatcher。`unix` 只出现在 `getProxyFetchOptions` 的按次返回值里,
  没有任何机制能让它对全局生效。

**结论**:socket 形态能接管的只有 `/v1/messages`。其余请求带着占位凭证直连真 API,轻则功能失灵
(`/usage` 拿不到数据),重则从设备真实 IP 直接发出去。这不是补几条白名单能救的,是覆盖面天生不够。

---

## 2. 为什么 `HTTPS_PROXY` 可以

同一个文件里的 `configureGlobalAgents()`(`utils/proxy.ts:327-388`)把**两条 HTTP 栈都装上了**:

- **全局 axios**:注册 request interceptor(`350-368`),每个请求先过 `shouldBypassProxy(config.url)`
  判断 `NO_PROXY`(`352`),不绕行就走代理;
- **undici / fetch**:`setGlobalDispatcher(getProxyAgent(proxyUrl))`(`372-374`),装的是
  `EnvHttpProxyAgent`(`utils/proxy.ts:236`)。

于是 axios 那批(usage / profile / bootstrap / 遥测)和 fetch 那批(SDK 的 `/v1/messages`、MCP)
一起进代理。这正是 socket 形态缺的那一半。

而且这是**官方文档化的受支持配置**,不是挖出来的偏门用法。《Enterprise network configuration》
明确列出 `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY`(大小写变体都认,取值顺序是
`https_proxy` → `HTTPS_PROXY` → `http_proxy` → `HTTP_PROXY`)、自定义 CA `NODE_EXTRA_CA_CERTS`、
以及 mTLS 客户端证书 `CLAUDE_CODE_CLIENT_CERT` / `CLAUDE_CODE_CLIENT_KEY`。同一页还写明
`api.anthropic.com` 这个域名承载的是「Claude API 请求、WebFetch 域名安全检查、特性开关拉取、
遥测事件上报」—— 官方自己也是按「这些都该经过你的代理」来描述的。

代价是网关得会说 HTTP 代理协议。这就是 `proxy.go` 存在的理由。

> 官方明说不支持 SOCKS 代理,所以只有 HTTP CONNECT 代理这一种形态可选。

---

## 3. TLS 终结仍然必需,只是时机变了

客户端的目标 URL 始终是 `https://api.anthropic.com`,代理不改变这一点。代理形态下的顺序是:

```
设备 claude ──CONNECT api.anthropic.com:443──▶ 网关
设备 claude ◀──HTTP/1.1 200 Connection Established── 网关
设备 claude ══════ TLS ClientHello (SNI=api.anthropic.com) ══════▶ 网关
```

网关要把 `Authorization` 换成真凭证,就必须读到明文 HTTP,也就必须解密这条 TLS;要解密就得拿一张
客户端认可的 `api.anthropic.com` 证书。真 CA 不会签,只能自建 CA 现签一张。

`tlsterm.go` 干的就是这件事:CA 落盘长期复用(设备 pin 它),叶证书每次启动在内存里重签,
CN/SAN 都是 `forgedHost = "api.anthropic.com"`,另带 `localhost` 和回环 IP 方便用 curl 直接调试。
设备端 `NODE_EXTRA_CA_CERTS` 指向那把 CA 的 `.crt`,或者经已认证的隧道 `GET /ca` 自取。

跟 socket 形态相比,**握手时机从「连上来就握手」变成「回完 200 之后再握手」,别的没变**。
`serverTLSConfig()` 只报 `http/1.1`(`tlsterm.go:198-199`):网关这侧是 HTTP/1.1 server,不让客户端谈成 h2。

一个实现细节:客户端可能不等 200 就把 ClientHello 贴着 CONNECT 一起发出去,那几个字节已经落进
`bufio.Reader`。`handleConnect` 用 `replayBuffered` 把它们接回连接头部(`proxy.go:104`),
否则握手会缺开头字节。

---

## 4. CONNECT 必须在连接层处理,不能丢给 handler 去 Hijack

这条最容易被后人「顺手重构」掉,所以单独讲。

直觉做法是让 `http.Server` 收下 CONNECT 请求,在 handler 里 `ResponseWriter.(http.Hijacker).Hijack()`
拿回裸连接。**在这里会挂死。**

原因在 Go 的实现:`Hijack()` 要先 `abortPendingRead()`。`http.Server` 为了感知客户端提前关闭,
在处理请求期间挂着一个后台预读;要中断它,Go 的办法是**把连接的读 deadline 设成一个过去的时刻**,
逼那次 `Read` 立刻返回超时错误,然后等它退出。

而隧道连接是 `channelConn` —— 一个 SSH channel 的 `net.Conn` 包装。`ssh.Channel` 不支持 deadline,
所以它的三个 deadline 方法全是 no-op(`sshfwd.go:182-184`):

```go
func (c *channelConn) SetDeadline(t time.Time) error      { return nil }
func (c *channelConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *channelConn) SetWriteDeadline(t time.Time) error { return nil }
```

deadline 打不断预读,预读就一直挂着,`Hijack()` 就一直等 —— 直到对端主动关闭连接为止。实测现象是
测试整个卡住,加日志能看到 `Hijack()` 阻塞了整整三秒,直到客户端超时断开才返回。

所以 CONNECT 在 `serveTunnelConn`(`sshfwd.go:212`)里就地读、就地应答,压根不进 `http.Server`。
`main.go` 的 handler 里留了一道兜底:真收到 CONNECT 就回 501 明说「这应该在隧道层处理掉」
(`main.go:162-164`),分派逻辑漏了要吵出来,而不是默默当普通请求转出去。

---

## 5. 连接怎么分派、凭证怎么注入

### 5.1 首字节分三种形态

`serveTunnelConn` 窥探开头几个字节决定去向(`sshfwd.go:201-241`),30 秒内不说话就关掉,
免得空闲 channel 永久占着 goroutine:

| 开头 | 形态 | 处理 |
|---|---|---|
| `0x16` | TLS handshake record —— 连上来直接握手 | 直接交 TLS 终结,再塞回 HTTP Server |
| `"CONNECT "` | HTTP 代理协议 | 就地读请求,交 `handleConnect` |
| 其余 | 明文 HTTP | 塞回 HTTP Server(取 CA、`/status` 调试) |

第三种是设备接入脚本用的:同一个本地端口既当代理入口,也当 `GET /ca` 的明文口 —— 网关按开头字节
自己分得清,设备端不用开两个口。

### 5.2 CONNECT 之后按名单二选一

`handleConnect`(`proxy.go:123-154`)拿 CONNECT 的目标主机名比两份名单:

- 命中注入主机(`isMITMHost`,`proxy.go:64`)→ 回 200,就地 TLS 终结,解密出的请求塞回 HTTP
  Server,走正常的注入 + 转发;
- 命中盲转发名单(`tunnelHosts`,`proxy.go:38-55`)→ 回 200,纯 TCP 对拷,不解密也不注入
  (账号认证、文档查询、包源、MCP connector、Datadog 遥测走这条);
- 两处都不命中 → 403。

**两份名单都写死在代码里,不是配置项。**「真凭证送给谁」和「设备能出到哪儿」都不该是部署时随手
能改的东西,要放行别的主机就改 `proxy.go` 重新编译,让它进代码评审。`tunnelHosts` 声明成 `var`
只是为了让测试能临时替换它。名单项支持 `*`、`*.example.com`、精确主机名三种写法
(`hostMatches`,`proxy.go:77-86`)。

- **注入路径只认一个主机**:`tlsterm.go` 里的 `forgedHost`,也就是 `api.anthropic.com`(比对大小写
  不敏感)。客户端无论上游配到哪儿,URL 里的主机名始终是它,一个就够;多放一个域名就等于把真凭证
  送到那儿去。官方表里挂在这个域下的「WebFetch 域名安全检查、特性开关拉取、遥测事件上报」因此
  走的都是注入路径 —— 遥测是通的,并没有被关掉。也正因为归注入路径先判,`api.anthropic.com`
  不在 `tunnelHosts` 里。
- **盲转发名单**对齐官方《Enterprise network configuration》列出的「Claude Code 需要访问的
  URL」,共 12 个:账号认证与文档查询(`claude.ai`、`claude.com`、`code.claude.com`)、
  OAuth token 的交换 / 刷新 / 吊销(`platform.claude.com`)、插件下载与自动更新(`downloads.claude.ai`)、
  changelog(`raw.githubusercontent.com`)、两个包源(`registry.npmjs.org`、`formulae.brew.sh`)、
  MCP connector 代理(`mcp-proxy.anthropic.com`)、Chrome 桥(`bridge.claudeusercontent.com`)、
  两个 Datadog 端点(`http-intake.logs.us5.datadoghq.com`、`browser-intake-us5-datadoghq.com`)。
  它只覆盖**工具自身需要的主机**:WebFetch 抓名单外的站点、连第三方 remote MCP server 都会被
  403,这是有意的取舍。
- `storage.googleapis.com` 是唯一刻意留在名单外的官方主机 —— 多租户通用存储主机,放行等于开一条
  很宽的出口;而官方写明它被挡时会回落到 `api.anthropic.com`,代价只是 `/plugin` 里看不到安装数
  与插件元数据。

网关启动时把两份名单各打一行(`main.go:122-123`),不用翻源码就知道放行了谁。被拦的 CONNECT 回的
是带缘由的 403(`writeConnectDenied`,`proxy.go:159-166`):body 是 JSON,带被拒的主机名和该往
盲转发名单里加的提示。客户端那头只看得到代理的状态码,不这么写排查时只剩一个光秃秃的 403。

### 5.3 注入与透传

解密后的请求进 `main.go` 的 `handle`:

- **身份来自连接本身**。SSH 层公钥认证出的 device id 由 `ConnContext` 写进每个请求的 context;
  客户端 `Authorization` 里的占位 token 不参与鉴权,随后被整个覆盖成真订阅 token。
- **上游 path 原样透传**(`main.go:205-207`)。客户端要打哪个端点就转哪个 —— 这是 `/usage` 能工作的前提之一。
  路径一旦被改写,客户端拿到的报错就跟它请求的端点毫无关系,极难排查。
- **剥掉客户端的凭证企图**(`main.go:52-65`)。`x-api-key` 必剥:设备上残留的 `ANTHROPIC_API_KEY` 会让
  客户端改发这个头,它优先级高于 `Authorization`,不剥就是上游拿假 key 校验后 401。
  `proxy-authorization` 也剥 —— 那是客户端发给**代理**的,不该转给上游。
- **明文 HTTP 按同样两份名单分流**(`main.go:180-193`)。经代理的明文请求是绝对形式
  (`GET http://host/path`):`api.anthropic.com` 换上游并注入真凭证;命中盲转发名单的原样转过去且
  **不注入**(WebFetch 抓 http 站点靠这条);都不命中才 403。真凭证只进 `api.anthropic.com`。
  不注入的那条同时也不采样限额、不记 token 用量 —— 第三方响应里的同名字段不是那个意思。

---

## 6. 设备端的占位凭证:为什么必须写文件,不能用环境变量

网关注入真凭证,设备手里那份是假的。但假凭证长什么样有讲究 —— 它决定客户端**肯不肯发某些请求**。

### 6.1 `/usage` 有一道硬门槛

`fetchUtilization()`(`services/api/usage.ts:33-36`)在发请求前先过两道判断,不满足就直接返回空对象,
**一个网络包都不发**:

```ts
export async function fetchUtilization(): Promise<Utilization | null> {
  if (!isClaudeAISubscriber() || !hasProfileScope()) {
    return {}
  }
```

- `isClaudeAISubscriber()`(`utils/auth.ts:1564-1570`)最终落到 scopes 里有没有 `user:inference`
  (`services/oauth/client.ts:38-40`,常量在 `constants/oauth.ts:33`);
- `hasProfileScope()`(`utils/auth.ts:1580-1584`)看 scopes 里有没有 `user:profile`
  (`constants/oauth.ts:34`)。

函数上方的注释把用意说得很白(`utils/auth.ts:1572-1579`):真正 `/login` 拿到的 token 一定带
profile scope,而环境变量和文件描述符来的 token 把 scopes 硬编码成只有 `user:inference`,
这道门就是拦住它们,免得对 profile 类端点打出一片 403。

### 6.2 `CLAUDE_CODE_OAUTH_TOKEN` 正好撞在这道门上

设了这个环境变量,`getClaudeAIOAuthTokens()`(`utils/auth.ts:1255-1272`)在读任何存储之前就 return:

```ts
  if (process.env.CLAUDE_CODE_OAUTH_TOKEN) {
    // Return an inference-only token (unknown refresh and expiry)
    return {
      accessToken: process.env.CLAUDE_CODE_OAUTH_TOKEN,
      refreshToken: null,
      expiresAt: null,
      scopes: ['user:inference'],
      ...
    }
  }
```

scopes 是字面量写死的(`utils/auth.ts:1266`),keychain 和凭证文件都不读;异步版本同样短路
(`utils/auth.ts:1402-1408`)。于是链条闭合:环境变量占位 → scopes 只有 `user:inference` →
`hasProfileScope()` 为假 → `/usage` 返回空、零请求。**面板上那句 "only available for subscription plans"
就是这么来的,跟网关放不放行没关系。**

要自己定 scopes,就只能走凭证文件那条路。所以设备端写的是
`$CLAUDE_CONFIG_DIR/.credentials.json`,scopes 里带上 `user:profile`,并且不设 `CLAUDE_CODE_OAUTH_TOKEN`。

### 6.3 用独立 `CLAUDE_CONFIG_DIR` 的额外好处

凭证文件的路径由 `getClaudeConfigHomeDir()` 决定 —— 有 `CLAUDE_CONFIG_DIR` 就用它,否则 `~/.claude`
(`utils/envUtils.ts:7-14`),文件名固定 `.credentials.json`(`utils/secureStorage/plainTextStorage.ts:13-17`,
写入时 `chmod 600`)。用一个独立目录,首先意味着**完全不碰你真的 `~/.claude`**。

其次,它在 macOS 上顺带绕开了 keychain。macOS 的存储是「keychain 优先,拿不到才回落明文文件」
(`utils/secureStorage/index.ts:9-17`,`fallbackStorage.ts:13-19`);Linux 和 Windows 本来就只有明文文件。
而 keychain 的 service name 是按配置目录算的(`utils/secureStorage/macOsKeychainHelpers.ts:27-41`):

```ts
  const isDefaultDir = !process.env.CLAUDE_CONFIG_DIR
  const dirHash = isDefaultDir
    ? ''
    : `-${createHash('sha256').update(configDir).digest('hex').substring(0, 8)}`
  return `Claude Code${getOauthConfig().OAUTH_FILE_SUFFIX}${serviceSuffix}${dirHash}`
```

只要显式设了 `CLAUDE_CONFIG_DIR`,service name 就带上这个目录路径的 sha256 前 8 位后缀,
跟默认目录的条目(`Claude Code-credentials`)必然不同名。查不到条目 → 回落明文文件 → 读到我们写的
那份占位凭证。**所以「写文件」这招在 macOS 和 Linux 上都成立,而且两边都碰不到你真正的登录凭证。**

> 一个边角:macOS 的 keychain 读取带 30 秒缓存,并且在「之前读到过、这次 `security` 调用失败」时
> 会继续返回旧值而不回落明文(`utils/secureStorage/macOsKeychainStorage.ts:50-63`)。用独立配置目录
> 从一开始就查不到条目,不会踩到这个粘滞行为。

---

## 7. 引用一览

| 主题 | 位置 |
|---|---|
| `unix` 只在 `forAnthropicAPI` 时返回,且被 Bun 门控 | 客户端 `utils/proxy.ts:288-305`(注释 `277-287`) |
| 唯一传 `forAnthropicAPI: true` 的调用点 | 客户端 `services/api/client.ts:146-148` |
| MCP 传输一律无参调用 | 客户端 `services/mcp/client.ts:657,682,815,887` |
| 代理同时装 axios interceptor 与 undici dispatcher | 客户端 `utils/proxy.ts:327-388`(`EnvHttpProxyAgent` 在 `236`) |
| `/api/oauth/usage` 走全局 axios | 客户端 `services/api/usage.ts:55-60` |
| `/api/oauth/profile`、`/api/claude_cli/bootstrap` 同上 | 客户端 `services/oauth/getOauthProfile.ts:40-41`、`services/api/bootstrap.ts:63,84` |
| oauth 端点的 base URL | 客户端 `constants/oauth.ts:83-84` |
| `/usage` 的 scope 门槛 | 客户端 `services/api/usage.ts:33-36`、`utils/auth.ts:1564-1584` |
| env token 分支硬编码 scopes | 客户端 `utils/auth.ts:1255-1272`(`1266`)、`1402-1408` |
| 凭证文件路径 / keychain service name | 客户端 `utils/envUtils.ts:7-14`、`utils/secureStorage/plainTextStorage.ts:13-17`、`macOsKeychainHelpers.ts:27-41`、`index.ts:9-17` |
| 代理 / CA / mTLS 的官方支持说明 | 《Enterprise network configuration》 |
| CONNECT 分流、盲转发 | `proxy.go`(`handleConnect` 在 `121`) |
| 首字节分派、deadline no-op 与 Hijack 陷阱 | `sshfwd.go:182-184`、`201-241` |
| TLS 终结、自建 CA、伪造叶证书 | `tlsterm.go`(`forgedHost` 在 `44`) |
| 凭证注入、剥头、path 透传 | `main.go:52-65`、`145-323` |
| 两份写死的主机名单(注入 / 盲转发) | `proxy.go:29-64`(启动时打印在 `main.go:122-123`) |
