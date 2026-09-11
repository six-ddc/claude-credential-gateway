# claude-credential-gateway

一个**凭证隔离网关**(Go 实现):让**你本人名下的多台设备**(包括公共/不完全可信的电脑)用你
自己的 Claude 订阅工作,而**不在那些电脑上暴露真 token**。真 OAuth token 只留在一台你信任的
网关机器上;设备上只有一把可单独吊销的 SSH 密钥,请求经网关时才被注入真凭证。

> 这是**个人自用**工具,解决的是「同一个人换机器时凭证落地太多份」的问题,不是给多人共享订阅用的
> —— 把设备密钥给别人就成了订阅共享,违反 Anthropic 服务条款(详见文末「安全与合规边界」)。

设计借鉴 Claude Code 自带的 `claude ssh` 凭证隔离机制(凭证留在可信侧、另一侧只拿占位、代理注入)。

## 工作原理

```
设备(原生 claude,HTTPS_PROXY 指向本机分流代理 ccgw-device)
  │
  ▼
设备侧分流代理(:8788,唯一常驻进程)—— 按 CONNECT/请求的目标主机分两路
  │
  ├─ Claude 相关主机(内置名单 = api.anthropic.com + tunnelHosts,和网关同一份)
  │    ──▶ 经它自己维护的 SSH 连接(公钥认证,known_hosts pin,断了按需重拨)
  │           │
  │           ▼
  │    转发-only SSH 层(:2222,网关唯一对外端口)
  │     · 公钥 → device id,这是唯一门禁
  │     · 只接受白名单内的转发目标
  │     · session 只认一条 exec:发设备端二进制,无 shell / 无 pty
  │     · 禁 -R 反向转发,host key pin 防 MITM
  │           │
  │           ▼
  │    进程内网关(转发 channel 直连,不监听任何 HTTP 端口)
  │     · CONNECT api.anthropic.com    → 就地 TLS 终结 → 剥掉客户端凭证、注入真订阅 token
  │     · CONNECT tunnelHosts 里的主机 → 纯字节盲转发,不解密、不碰凭证
  │     · 路径黑名单(Artifact、Remote Control)按 path 拦(只挡注入路径)
  │     · per-device 审计 + 5h/7d 限额被动采样
  │           │
  │     ┌─────┴───────────────────────────────┐
  │     ▼                                     ▼
  │  api.anthropic.com(注入真凭证)    claude.ai / platform.claude.com / npm /
  │                                   mcp-proxy / Datadog ……(盲转发)
  │
  └─ 名单外的主机(WebFetch 抓的网站、第三方 MCP server、github.com……)
       ──▶ 分流代理自己直连,纯字节对拷,网关完全看不见
```

几个要点:

- **设备上只有一个常驻进程**:分流代理 `ccgw-device`。`HTTPS_PROXY` 指向它,它按目标主机分流:
  分流代理内置的名单(`api.anthropic.com` 加 `tunnelHosts`,和网关同一份,即全部 Claude 相关
  主机)送去网关,由网关按主机分别处理(解密注入 / 盲转发);名单外的主机(WebFetch 抓的网站、
  第三方 MCP server、`github.com` 之类)由设备本机直接连出去,不到网关。
- **网关不监听任何 HTTP 端口**。转发 channel 在进程内被直接喂给 HTTP handler,不经过本机端口,
  所以网关机上的其它进程也偷用不了真凭证。
- **身份来自 SSH 公钥**,写进每个请求的 context,客户端伪造不了。设备台账的单一数据源就是
  `ssh.authorized_keys`。
- **设备对网关机没有任何登录权限**。SSH 层的 session channel 只认一条 exec(`device-binary
  <os>/<arch>`,分发分流代理二进制本身),没有 shell、没有 pty。
- **上游 path 原样透传**:客户端打哪个端点就转哪个(`/v1/messages`、`/api/oauth/usage`……),
  网关只换 `Host` 和 `Authorization`。
- 同时,网关会**打印每个请求的 model 与 token 使用量**(input / output / cache),用 `gjson`
  从上游响应解析,支持 SSE 流式与普通 JSON。

### 为什么传输层是 HTTP 代理

Claude Code 内部有**两条 HTTP 栈**:Anthropic SDK 走 undici/fetch,打 `/v1/messages`;
`/usage` 查额度、`/api/oauth/profile`、bootstrap 这些一律走**全局 axios**。

`ANTHROPIC_UNIX_SOCKET` 只在 `getProxyFetchOptions({ forAnthropicAPI: true })` 这一处生效,
而全仓只有 SDK 的 client 传了这个参数 —— 也就是说它只能盖住 `/v1/messages`,其余端点会直连
真实的 `api.anthropic.com`,根本进不了隧道。

`HTTPS_PROXY` 则两条栈都覆盖:客户端启动时的 `configureGlobalAgents()` 既给全局 axios 装
interceptor,又 `setGlobalDispatcher` 给 undici 装 `EnvHttpProxyAgent`。这也是 Claude Code
官方文档化的受支持配置(Enterprise network configuration 与 LLM gateway 两页明文支持
`HTTPS_PROXY`/`HTTP_PROXY`/`NO_PROXY`、自定义 CA、mTLS)。

代价是网关要会说 HTTP 代理协议:客户端先发 `CONNECT api.anthropic.com:443`,网关回
`200 Connection Established`,之后才在这条连接上做 TLS 握手 —— TLS 终结这一步该干的活不变,
只是触发时机从「连上来就握手」变成「CONNECT 之后再握手」。

`HTTPS_PROXY` 实际指向的是设备侧的分流代理(`ccgw-device`),不是网关本身:它对客户端伪装成
一个普通的 HTTP 代理,同样吃 CONNECT,只是按目标主机再分一次流 —— 命中它内置的名单
(`api.anthropic.com` 加 `tunnelHosts`,和网关同一份)才继续往网关走,其余主机它自己拨号应答。
为什么这层分流不能靠 `NO_PROXY` 之类的环境变量做,见 [docs/transport.md](docs/transport.md#7-设备侧分流代理)。

## 技术栈

- Go 1.25+(`go.mod` 声明;低版本工具链会按 `GOTOOLCHAIN` 自动下载)
- [`golang.org/x/crypto/ssh`](https://pkg.go.dev/golang.org/x/crypto/ssh) —— 转发-only SSH 层(唯一对外入口)
- [`gopkg.in/yaml.v3`](https://pkg.go.dev/gopkg.in/yaml.v3) —— YAML 配置解析
- [`github.com/tidwall/gjson`](https://github.com/tidwall/gjson) —— 高性能 token 用量解析
- [`github.com/andybalholm/brotli`](https://github.com/andybalholm/brotli) —— br 响应解压(打印/解析用)

## 配置

```bash
go build -o claude-credential-gateway .   # 或 go run .
cp config.example.yaml config.yaml        # config.yaml 已在 .gitignore,改它不污染版本库
```

配置是 YAML([`config.example.yaml`](./config.example.yaml)),真凭证建议用**环境变量注入**
(env 覆盖 YAML),这样模板可以安全提交:

```yaml
upstream:
  base: https://api.anthropic.com
  oauth: ""               # 静态 access token(setup-token 那种);留空则用 CLAUDE_GATEWAY_UPSTREAM_OAUTH 注入
  credentials: ""         # 或指一份 .credentials.json;两个都留空 → 回退 ~/.claude/.credentials.json
ssh:                      # 唯一对外入口;设备台账的单一数据源
  addr: ":2222"                       # 唯一对外端口
  host_key: ./ssh_host_ed25519_key    # 服务端私钥;不存在则首启自动生成
  ca_key: ./ccgw_ca_key               # TLS 终结 CA;自动生成,另导出 .crt
  permit_targets:                     # 分流代理开 channel 时声明的目标须在其中(网关并不真监听它们)
    - 127.0.0.1:8788
    - unix:/run/ccgw.sock
  device_bin_dir: ./dist/device       # 设备端二进制目录(<dir>/<os>/<arch>),`make device-bins` 产出
  authorized_keys:                    # 每台设备一把公钥;改完热重载即生效,无需重启
    - id: laptop-1
      key: "ssh-ed25519 AAAA... laptop-1"
```

配置路径优先级:`GATEWAY_CONFIG` 指定 > 本地 `config.yaml` > `config.example.yaml`(模板,并提示拷贝)。

可用环境变量覆盖:`GATEWAY_UPSTREAM_BASE`、`CLAUDE_GATEWAY_UPSTREAM_OAUTH`、
`CLAUDE_GATEWAY_UPSTREAM_CREDENTIALS`、`CLAUDE_GATEWAY_UPSTREAM_REFRESH`、
`CLAUDE_GATEWAY_CLAUDE_BIN`、`GATEWAY_SSH_ADDR`、`GATEWAY_SSH_HOST_KEY`、
`GATEWAY_SSH_CA_KEY`、`GATEWAY_SSH_PERMIT_TARGETS`(逗号分隔)、`GATEWAY_SSH_DEVICE_BIN_DIR`、
`GATEWAY_SSH_AUTHORIZED_KEYS`(JSON `[{id,key}]`)。

日志还有一个:`GATEWAY_LOG_FORMAT=json` 把事件日志切成 JSON(给采集器)。见「日志」。

### 上游凭证从哪来

`oauth` 和 `credentials` **只能配一个**,都配则启动直接失败 —— 凭证来源必须唯一,静默择一
只会让「我明明改了配置却没生效」变成一次线上排查。两个都留空则回退到本机
`~/.claude/.credentials.json`(启动日志会明说这次用的是哪一份,回退不是隐形的)。

| | `oauth`(静态 token) | `credentials`(凭证文件) |
|---|---|---|
| 来源 | `claude setup-token` | 交互式 `/login` 写出的 `.credentials.json` |
| scopes | 只有 `user:inference` | 含 `user:profile` |
| 设备上 `/usage` | ✗ 上游 403 | ✓ 有数据 |
| 有效期 | 长期,网关不管 | 约 8 小时;网关默认自己续(见下节) |
| 自刷新 | 恒关(没有 refreshToken) | 默认开,含回退那条 |

**网关从不写凭证文件** —— 自刷新也是 fork `claude auth login` 让客户端去写(见下节)。
它还会按 mtime 热重载,所以别人换掉凭证网关也跟得上(取 token 时至多每秒看一眼,
后台每 30 秒再兜一遍)。

上游返回 401 或 scope 不足的 403 时,日志里会补一句根因,不用再顺着 `request_id` 猜。

### 让上游凭证一直是新的

access token TTL 是 **8 小时**,refresh token 约 **30 天**。凭证文件形态下网关
**默认自己续命**,不需要外部 cron。

**做法**:剩余不足 30 分钟时,fork 一个 `claude auth login`,靠客户端官方的
**非交互 refresh-token 登录**路径(埋点 `tengu_login_from_refresh_token`)换一份新凭证,
2 秒出结果,不起会话、不开浏览器、不跑推理、不加载 hooks。网关传给子进程的是:

```
CLAUDE_CONFIG_DIR=<凭证所在目录>      决定新凭证写回哪里
CLAUDE_CODE_OAUTH_REFRESH_TOKEN=…    每次都从文件重读(它会轮换,不能缓存)
CLAUDE_CODE_OAUTH_SCOPES=…           客户端要求与签发时一致,缺了直接报错
IS_SANDBOX=1                          没有 tty,不设会卡在交互提示上
```

环境是**显式构造**的,不继承网关进程 —— 继承下来 `HTTPS_PROXY` 会让子进程绕回网关自己
(自指环路),`ANTHROPIC_API_KEY` 会让客户端走别的鉴权分支,刷了个寂寞。

**为什么外包给 claude 而不是自己发 OAuth 请求**:刷新协议(端点、client_id、字段)是未公开的,
自己实现哪天会静默炸掉;交给客户端则升级 claude 就跟上了。写回和轮换持久化也一并外包 ——
网关永远不写凭证文件,**唯一不可逆的风险(写坏它就得重新登录)直接消失**。

**刷新是临界区。** 刷新会【立即】作废旧的 access token,不是等它自然过期,所以并发请求只
fork 一次(单飞)。两条路径对「等」的容忍度不同:401 之后**阻塞等**(手里那份确定是废的);
到期前的例行检查**等不到就走**(手里那份还够用几十分钟,后台巡检本来就会去刷,
不该把一次刷新的耗时摊给所有并发请求)。

三道闸门防止刷新失控:失败按 30s→5min 指数退避;**不论成败**都有 1 分钟的最小间隔;
子进程 20 秒超时。最小间隔那道是必需的 —— 账号被吊销时刷新会一直「成功」而 401 不消失,
只靠退避的话每个 401 都会 fork 一次,而刷新又立即作废上一个 token,自我强化成进程风暴。

> **`upstream.refresh` 是三态开关**:不配 = 开,凭证文件形态一律如此,**包括回退到本机
> `~/.claude/.credentials.json` 那条** —— access token 只活 8 小时,不自刷新就是每 8 小时
> 静默断一次,而「网关正好跑在一台有人天天用 claude 的机器上」并不成立。静态 token 恒关
> (没有 `refreshToken` 可用)。显式 `true`/`false` 一律照办。
>
> 和本机 claude 共用那份凭证是安全的:刷新走的就是 claude 自己那套(fork `auth login`),
> 写回同一个文件,客户端会重读。轮换只废掉内存里那份旧的,拿它的一方重读即可恢复。
>
> 默认开出来的自刷新是**尽力而为**:找不到 `claude`、凭证里没有 `refreshToken`,都只告警降级、
> 不拦启动。显式配 `refresh: true` 则是**说到做到**:同样的情况直接启动失败 ——
> 你明说要它,它就不该悄悄不干活。

> **三条兜底**,应对别人(本机 claude、cron、手动)带外换掉凭证:
> 取 token 时至多每秒 stat 一次,mtime 变了就重读 —— 绝大多数情况在**发请求之前**就发现了;
> 后台每 30 秒再兜一遍(没流量时也能跟上到期告警);上游真返回 401 时立刻刷新/重读并
> **用新 token 重放这次请求**。凭证没变就不重放,不会把上游请求量翻倍。
>
> **`refreshTokenExpiresAt` 不会因刷新而延长**,它锚定在最初那次交互式登录上。
> **约 30 天是硬死线,刷得再勤也躲不过**,到点必须有人去重新 `claude /login`。
> 网关会在剩 7d / 3d / 1d 时各告警一次。

> **占位凭证会被拒绝启动。** 设备侧那份假凭证(`~/.ccgw/claude-home/.credentials.json`,
> `sk-ant-oat01-placeholder`)长得跟真凭证一模一样 —— scopes 齐全、`expiresAt` 在 2100 年,
> 混进上游凭证的位置会让每个请求都 401,而启动日志一片祥和。宁可起不来。
> 凭证里没有 `refreshToken` 时也会告警:那种凭证到期即死,没人能给它续命。

> `host_key` 与 `ca_key` 都是**私钥**,已 gitignore、权限 0600。生产上建议把它们放到仓库之外
> (如 `/etc/ccgw/`),免得被 `git clean` 之类的操作误删。

### 代理放行哪些主机

配置里没有主机名单。哪个主机会被解密并注入真凭证、哪些只做盲转发,都写死在
[`proxy.go`](./proxy.go) 里,**要放行别的主机就改代码重新编译** —— 让它进代码评审,而不是躺在
某台机器的 YAML 里。「真凭证送给谁」和「哪些 Claude 相关主机经网关」都不该是部署时能随手改的
东西。

两份名单不是「白名单 vs 黑名单」,而是**两种不同的放行方式** —— 判断是「或」:

| 主机 | 判在哪 | 网关怎么处理 |
|---|---|---|
| `api.anthropic.com` | `isMITMHost` | 解密 → 把占位 token 换成真凭证 → 转发 |
| `tunnelHosts` 里的那些 | `hostInList` | 纯字节对拷,**不解密、不碰凭证** |
| 其它 | 都不命中 | 403 |

- **解密注入只认 `api.anthropic.com`**(大小写不敏感)。客户端无论上游配到哪儿,URL 里的主机名
  始终是它,所以一个就够。它也**只能**走这条路:盲转发不解密,就没法替换 `Authorization`,而
  设备手上只有占位 token —— 那样每个请求都会 401,网关就白做了。所以它不在 `tunnelHosts` 里
  不是被漏掉,是压根不该在那儿。

  官方表里挂在这个域下的「WebFetch 域名安全检查、特性开关拉取、遥测事件上报」因此走的都是注入
  路径 —— 也就是说遥测是通的,并没有被关掉。
- **`tunnelHosts` 管的是其余 Claude 相关流量能出到哪儿**。设备侧的分流代理(见「隧道口上跑的
  是什么」)默认把这份名单连同 `api.anthropic.com` 一起送来网关,这份名单就是那部分的闸门。
  内容以官方《Enterprise network configuration》列出的「Claude Code 需要访问的 URL」为底:
  `claude.ai`、`claude.com`、`code.claude.com`、`platform.claude.com`、`downloads.claude.ai`、
  `raw.githubusercontent.com`、`registry.npmjs.org`、`formulae.brew.sh`、`mcp-proxy.anthropic.com`、
  `bridge.claudeusercontent.com`,以及两个遥测主机 `http-intake.logs.us5.datadoghq.com`、
  `browser-intake-us5-datadoghq.com`。再加上 Anthropic 自家站点 `www.anthropic.com`、
  `docs.anthropic.com`、`support.claude.com`、`status.claude.com`(WebFetch 抓到它们时也经网关),
  和 Anthropic 托管的远程 MCP server `*.mcp.claude.com`(`slack.`、`microsoft365.` 等,用户
  `claude mcp add` 之后才会连)。

盲转发名单里的每一项支持三种写法:`*`(任意主机)、`*.example.com`(子域,不含 `example.com`
自身)、精确主机名。

**这两份名单只覆盖 Claude Code 自身需要的主机。** WebFetch 抓名单外的站点、连第三方 MCP
server、`git`/`gh` 打 `github.com` 这类跟 Claude 无关的流量,由设备侧分流代理默认直接从设备
本机连出去,根本不到网关这儿。误把 `HTTPS_PROXY` 直接指到网关隧道口(而不是经分流代理)的话,
被拒的 `CONNECT` 会回一个说得清缘由的 403,body 里带主机名和提示 —— 客户端那头只看得到代理的
状态码,这个 body 是排查依据。

`storage.googleapis.com` 是唯一刻意留在名单外的官方主机:它是多租户通用存储主机,放行等于开一条
很宽的出口;而官方文档写明这个用途在它被挡时会回落到 `api.anthropic.com`,代价只是 `/plugin` 里
看不到安装数与插件元数据。

网关启动时会把两份名单打出来,不用翻源码就知道放行了谁:

```
代理: 解密注入 api.anthropic.com
代理: 盲转发 claude.ai, claude.com, code.claude.com, ...
```

**注入主机上还有一份路径黑名单** `blockedPaths`。有些功能跟模型调用打同一个
`api.anthropic.com`、用同一个 OAuth token,按主机分不开,只能按路径拦。模式是 Go `path.Match`
语法(`*` 匹配一段),路径本身或它的任一父路径命中即算命中。只拦让功能跑不起来的核心端点,
不追求列全外围请求:

| 模式 | 拦的是什么 |
|---|---|
| `/api/frame` | Artifact 工具:把网页产物发布到 `claude.ai/code/artifact/…`,以及读写它的评论、数据库、附件。发布走 `/api/frame/deploy/*`,读回走 `/api/frame/read/<slug>`,其余 contract / comments / db / blob / subscribe 都在这个前缀下 |
| `/v1/code/sessions/*/worker`、`/v1/code/sessions/*/bridge`、`/v1/environments/bridge` | Remote Control(`/remote-control`):本地会话向后端注册成 worker、建立 bridge 之后,claude.ai 网页和手机端就能读本地会话转录、向它下发指令。注册不成整个功能起不来。自托管 runner 复用同一组端点,一并失效 |

命中时回 403,日志里 `reason=path_blocked`;客户端那头对应功能报错,模型调用不受影响。同在
`/v1/code/sessions` 下的 `/teleport`、`/ultrareview`、`/schedule` 不在名单里,仍然可用。

网关启动时会把这条也打出来:

```
代理: 路径黑名单 /api/frame, /v1/code/sessions/*/worker, /v1/code/sessions/*/bridge, /v1/environments/bridge
```

## 快速开始

> **设备使用者**看这份手把手教程更省事:[docs/device-setup.md](docs/device-setup.md) ——
> 从装 Claude Code 到跑起 `ccgw` 的完整流程,含故障排查与环境变量速查。
> 下面的「快速开始」是**管理员视角**的全景速览(网关 + 设备两侧都有)。

### ① 网关机(你信任的常驻机)

```bash
# 先把设备端二进制编译好(darwin/linux × amd64/arm64,进 dist/device/<os>/<arch>)——
# 网关经 SSH exec 把它发给设备,设备侧不需要装 Go
make device-bins

# 网关机上先 claude /login 登录你的订阅账号,凭证就位后直接跑 ——
# 不配任何凭证时网关回退读 ~/.claude/.credentials.json(scopes 含 user:profile,/usage 才有数据)
./claude-credential-gateway

# 或者显式指一份网关专属凭证(推荐:自刷新默认开)
export CLAUDE_GATEWAY_UPSTREAM_CREDENTIALS=/var/lib/claude-gateway/.credentials.json
# —— 二选一,不能同时配 —— 静态 token(setup-token,scopes 只有 inference)
# export CLAUDE_GATEWAY_UPSTREAM_OAUTH='<你的订阅 access token>'
```

首次启动会自动生成 SSH host key 与 TLS 终结 CA,并在日志里打印 host key 指纹。

### ② 设备:第一趟 —— 生成密钥、拿到公钥

```bash
GATEWAY_HOST=你的网关 ./scripts/setup-device.sh laptop-1
```

这一趟**故意连不上网关的 SSH 层**(公钥还没登记),脚本会把本机公钥打印出来。把公钥和 device-id
交给网关管理员,渠道随意 —— 公钥不是机密。

### ③ 管理员:在网关机上登记

```bash
./scripts/add-device.sh laptop-1 "ssh-ed25519 AAAA... laptop-1"   # 热重载即生效
./scripts/add-device.sh --list                                    # 已登记设备 + host key 指纹
./scripts/add-device.sh --remove laptop-1                         # 吊销
```

登记后把它打印的 **host key 指纹带外**回给设备(当面/IM/邮件均可)。

> 指纹是防 MITM 的信任锚,必须带外传 —— 从待连接的那个网络里取指纹,等于让攻击者自己给你发指纹。

### ④ 设备:第二趟 —— 带上指纹接入

```bash
GATEWAY_HOST=你的网关 GATEWAY_HOST_KEY_FP='SHA256:xxxx' \
  ./scripts/setup-device.sh laptop-1
```

脚本会核对指纹(不符即中止)、经 SSH exec 取回分流代理二进制、拉起它(设备上唯一的常驻进程)、
经它自取 CA 证书、经它验证整条链路、检查 Claude Code 版本、写占位凭证,最后生成一个**包装命令**
`~/.ccgw/bin/ccgw` —— 那一堆 `unset`/`export` 都收在里面,不用手敲:

```bash
export PATH="$HOME/.ccgw/bin:$PATH"    # 加进 ~/.zshrc 或 ~/.bashrc,一次即可

ccgw                                   # 等价于「经网关的 claude」
ccgw -p "写个快排"                      # 参数原样透传
```

真的 `claude` 命令**不受影响**(仍然直连官方),两者并存、互不干扰。

> 只想要交互式 shell 里的别名也行:`alias ccgw="$HOME/.ccgw/bin/ccgw"`。但推荐 PATH 形态 ——
> 别名在脚本、`make`、编辑器插件等子进程里不生效。
>
> **别把它命名成 `cc`**:`/usr/bin/cc` 是 C 编译器,抢占它会让 `make`、cgo、npm 原生模块
> 全部走岔。要改名用 `CMD_NAME=xxx ./scripts/setup-device.sh laptop-1`,脚本会做同名冲突检测。

包装命令做的事(等价于手动设这些):

```bash
# 分流代理没在跑就先拉起来
curl -sf http://127.0.0.1:8788/status >/dev/null 2>&1 || ~/.ccgw/bin/ccgw-device start

unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN ANTHROPIC_BASE_URL ANTHROPIC_CUSTOM_HEADERS
unset ANTHROPIC_UNIX_SOCKET CLAUDE_CODE_OAUTH_TOKEN CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR
export HTTPS_PROXY=http://127.0.0.1:8788   HTTP_PROXY=http://127.0.0.1:8788
export https_proxy=http://127.0.0.1:8788   http_proxy=http://127.0.0.1:8788
# 本机地址必须排除,否则本地跑的 MCP server / dev server 也会被绕去分流代理
export NO_PROXY=localhost,127.0.0.1,::1    no_proxy=localhost,127.0.0.1,::1
export NODE_EXTRA_CA_CERTS=$HOME/.ccgw/ccgw_ca.crt
export CLAUDE_CONFIG_DIR=$HOME/.ccgw/claude-home
exec claude "$@"
```

外加一个启动前自检:CA 缺失就提示重跑 `setup-device.sh` —— 比让 `claude` 抛一个含糊的连接
错误好定位。分流代理本身则用 `ccgw-device start|stop|status|log` 管理,不用记这几行:

```bash
ccgw-device status    # 在不在跑、网关链路通不通
ccgw-device log       # 跟一下它的日志
ccgw-device stop      # 手动停掉(平时不需要,ccgw 会在需要时自动拉起)
```

> 设备密钥与 CA 存 `~/.ccgw/`(不进仓库)。分流代理断了会在下次请求时自动重连;进程本身没了
> (比如电脑重启过),下次跑 `ccgw` 会自动检测并拉起,或手动 `ccgw-device start`。
>
> **占位凭证不能省**:`claude` 自己要求手里有凭证才肯启动,什么都不设会停在
> `Not logged in · Please run /login`。网关不校验它、只覆盖,所有设备填同一个假值即可。
> 脚本把它写成**凭证文件** `$CLAUDE_CONFIG_DIR/.credentials.json`:
>
> ```json
> {"claudeAiOauth":{"accessToken":"sk-ant-oat01-placeholder","expiresAt":4102444800000,
>   "scopes":["user:inference","user:profile"],"subscriptionType":"max"}}
> ```
>
> **要用文件而不是 `CLAUDE_CODE_OAUTH_TOKEN`**:设了那个环境变量,客户端就走 env token 分支,
> scopes 被硬编码成只有 `user:inference`、凭证文件根本不读;而 `/usage` 要求 scopes 含 `user:profile`,
> 拿不到就直接返回空、连请求都不发。写文件才能自己定 scopes,`/usage` 才有数据。
> 不给 `refreshToken`、`expiresAt` 设到 2100 年,两条各自都能让客户端不去刷新(拿占位 token
> 刷新必然失败,还要重试拖慢启动)。
>
> **凭证放独立的 `CLAUDE_CONFIG_DIR`**(`~/.ccgw/claude-home`),完全不碰你真的
> `~/.claude/.credentials.json`。与凭证无关的东西(`settings.json`、`CLAUDE.md`、`commands`、
> `agents`、`skills`、`plugins`、`projects`、`todos`、`statsig`)由脚本用**符号链接**从真
> `~/.claude` 接过来,设置、记忆和历史都还在。
>
> **客户端版本下限 `>= 2.1.197`**:脚本会检查 `claude --version`,低于就**直接中止**。
> v2.1.91(2026-04-02)~v2.1.196 的客户端一旦发现配了代理,就会读系统时区、提取代理主机名与
> 两份加密列表比对,再把结果隐写进系统提示词 `Today's date is ...` 那一行(日期分隔符 `-`↔`/`,
> 撇号在 U+0027/2019/02BC/02B9 间切换)发给上游;官方 v2.1.197 已移除。代理形态下**每次调用都
> 命中**这条,而网关是透明转发、不改写请求体,客户端埋进 body 的任何标记都会绑着真凭证送达上游。
> 详见 [docs/transport.md](docs/transport.md)。`MIN_CLAUDE_VERSION=x.y.z`
> 可覆盖这个下限,`ALLOW_OLD_CLAUDE=1` 可强行放行(自担后果)。
>
> **经网关的是 Claude 相关主机,不是设备全部流量。** 分流代理按目标主机分流:内置名单
> (`api.anthropic.com` 加 `tunnelHosts`,和网关同一份)送去网关,由网关解密注入或盲转发;
> WebFetch 抓的网页、第三方 MCP server、`github.com` 这类跟 Claude 无关的主机由分流代理直接
> 从设备本机连出去,网关看不到、也管不着那部分流量。

## 隧道口上跑的是什么

设备侧只有**一个本地端口**(默认 `127.0.0.1:8788`),但它现在是分流代理(`ccgw-device`)
自己的监听口,不是 SSH 转发出来的隧道口。`HTTPS_PROXY` 指向它,它按请求分两路:

| 请求形态 | Claude 相关主机(内置名单 = `api.anthropic.com` + `tunnelHosts`,和网关同一份) | 其余主机 |
|---|---|---|
| `CONNECT host:443` | 分流代理开一个到网关的 direct-tcpip channel,把原始 CONNECT 请求行转发进去,由**网关**回 200 | 分流代理自己直接拨号、自己回 200 |
| 绝对形式 HTTP(`GET http://host/path`) | 同上,经 SSH channel 转给网关 | 分流代理自己直连目标站 |
| 相对路径(`GET /ca`、`GET /status`) | 转给网关自己 | 不适用 |

命中网关的 CONNECT 有个细节:分流代理**不自己应答 200**,它把原始请求行照抄一遍发给网关,
网关的 `200 Connection Established` 顺着这条连接原样传回客户端 —— 客户端验证的、之后握手的,
始终是网关那次应答。之后两边纯字节对拷,分流代理不解密。

命中网关的那部分流量,到了网关这一侧走的还是同一套协议:网关按连接开头的字节自动分辨,
不需要任何配置开关:

| 开头字节 | 当作什么 | 谁在用 |
|---|---|---|
| `CONNECT ` | HTTP 代理协议 | 分流代理转发的 CONNECT |
| `0x16` | 直接 TLS 握手 | `ANTHROPIC_UNIX_SOCKET` 形态(未受此次改动影响) |
| 其它 | 普通 HTTP | 分流代理转发的 `GET /ca`、`GET /status` |

`CONNECT api.anthropic.com` 到达网关后,网关回 `200 Connection Established` 之后**就地终结
TLS**:它用自建 CA 现签一张 `api.anthropic.com` 证书,设备用 `NODE_EXTRA_CA_CERTS` 信任这把 CA
即可;解密出来的请求走正常的注入 + 转发流程。`tunnelHosts` 里的主机则是回 200 之后纯字节对拷,
网关不解密、也不碰凭证。真正到不了网关这一层的,是这份内置名单外的主机 —— 它们由分流代理
直接在设备本机处理掉了。

限额快照两种拿法都行:

```bash
curl http://127.0.0.1:8788/status                                   # 分流代理的本机口
curl -x http://127.0.0.1:8788 --cacert ~/.ccgw/ccgw_ca.crt \
     https://api.anthropic.com/status                               # 经分流代理 + 网关,顺带验证整条链路
```

> `--target`(默认 `127.0.0.1:8788`)必须在网关 `ssh.permit_targets` 里。它只是白名单口令,
> 网关并不真监听这个地址;分流代理自己的本机监听端口(`--listen` / `LOCAL_PROXY_PORT`)随便改。

### 手动接入(不用脚本)

```bash
# ① 设备本地生成密钥,把 .pub 交给管理员登记(见「快速开始」③);known_hosts 按指纹手工核对后写入
ssh-keygen -t ed25519 -f ~/.ccgw/ccgw_laptop-1 -N "" -C laptop-1
ssh-keyscan -p 2222 -t ed25519 网关机 > /tmp/hk
ssh-keygen -lf /tmp/hk   # 核对这个指纹和管理员给的一致,再写进 known_hosts
awk '!/^#/ && NF>=3 {print "[网关机]:2222", $2, $3}' /tmp/hk > ~/.ccgw/known_hosts

# ② 经【网关的转发-only SSH 层】把分流代理二进制取下来 —— session 上只认这一条 exec
ssh -p 2222 -i ~/.ccgw/ccgw_laptop-1 -o UserKnownHostsFile=~/.ccgw/known_hosts \
    laptop-1@网关机 "device-binary darwin/arm64" > ~/.ccgw/bin/ccgw-device-bin
chmod +x ~/.ccgw/bin/ccgw-device-bin

# ③ 跑起来:设备上唯一的常驻进程
~/.ccgw/bin/ccgw-device-bin device \
  --listen 127.0.0.1:8788 --gateway 网关机:2222 --device-id laptop-1 \
  --key ~/.ccgw/ccgw_laptop-1 --known-hosts ~/.ccgw/known_hosts --target 127.0.0.1:8788 &

# ④ 经【已认证的 SSH 连接】自取 CA —— 不需要、也不该有登录网关机的权限
curl -s http://127.0.0.1:8788/ca -o ~/.ccgw/ccgw_ca.crt
```

> CA 之所以能自取而 host key 指纹不能:分流代理连上网关时,SSH 已用 host key 认证了服务端
> 身份,这条连接内的字节可信;而指纹是这条信任链的**起点**,不能从还没建立的链里取。
>
> `GET /ca` 转发给网关走的是相对路径那一路(见上表),不需要先验 `api.anthropic.com` 的
> TLS 证书 —— 证书正是要取的东西。这条连接在 SSH 内,机密性和完整性由 SSH 保证。
>
> `device-binary <os>/<arch>` 是 SSH session channel 上唯一认得的命令,`<os>/<arch>` 须匹配
> `dist/device/<os>/<arch>` 下已编译好的文件(`make device-bins` 产出);其它命令、以及任何
> shell / pty / subsystem 请求都会被拒绝。

## 首次初始化:跳过交互式引导

**全新机器、或 `claude logout` 之后,光有占位凭证不够用** —— Claude Code 检测到没完成
onboarding 会进入首次运行引导,而里面的登录步骤**不会因为手里有凭证就被跳过**。表现:占位凭证
明明写好了,`claude` 还是要你去浏览器登录账号。

> 说明:这里跳过的只是**首次运行的交互式 UI 引导**(选主题那一步),不涉及绕过任何鉴权或计费 ——
> 真正的鉴权发生在网关注入你自己订阅凭证的那一刻,用的仍是你自己付费的订阅。

触发条件是 `!theme || !hasCompletedOnboarding`,**两个字段缺一个就触发**。所以在客户端预置好这两个
字段即可绕过,完全不需要真账号登录:

**1) 先定位对的全局配置文件**。`ccgw` 把 `CLAUDE_CONFIG_DIR` 指向 `~/.ccgw/claude-home`,
所以它读的是**那个目录里**的文件,而不是你平时用的 `~/.claude.json` —— 哪怕真 `~` 下早就
onboard 过,`ccgw` 第一次跑仍可能被拦:

```bash
ls -la ~/.ccgw/claude-home/.claude.json ~/.ccgw/claude-home/.config.json 2>/dev/null
```

解析优先级(对应 Claude Code 的 `getGlobalClaudeFile()`):
- 若存在 `<CLAUDE_CONFIG_DIR 或 ~/.claude>/.config.json` → **它优先**(老版本路径);
- 否则 → `(CLAUDE_CONFIG_DIR || ~)/.claude.json`,`ccgw` 形态下即 `~/.ccgw/claude-home/.claude.json`。

> 常见踩坑:把 `hasCompletedOnboarding` 写进了 `settings.json` —— 那是 settings,schema 不同,
> **没有这个字段**,写了也不生效。

**2) 往上一步定位到的文件里补两个字段**(文件已存在就合并进去,别覆盖掉原有的 theme 等):

```json
{
  "hasCompletedOnboarding": true,
  "theme": "dark"
}
```

手懒可以用 `jq` 安全合并(把 `$F` 换成第 1 步定位到的文件;文件不存在会新建):

```bash
F=~/.ccgw/claude-home/.claude.json
[ -f "$F" ] || echo '{}' > "$F"
jq '.hasCompletedOnboarding = true | .theme = (.theme // "dark")' "$F" > "$F.tmp" && mv "$F.tmp" "$F"
```

之后再跑 `ccgw`,就能直接用、不再要求登录账号。

## 日志

日志分两类,故意用两套写法:

- **启动横幅**:给人读一次的中文说明,走 `log`,不带前缀和时间戳。它是「文档」不是「数据」。
- **事件日志**:每个请求/连接一条,走 `log/slog`。要被 grep、被眼睛快速扫、必要时被采集器吃掉。

```
time=23:38:27 level=INFO msg=connect mode=mitm user=laptop-1 host=api.anthropic.com:443
time=23:38:27 level=INFO msg=request user=laptop-1 method=GET  path=/api/oauth/usage status=200 dur=1ms
time=23:38:27 level=INFO msg=request user=laptop-1 method=POST path=/v1/messages model=claude-opus-4-8 status=200 dur=2.1s
time=23:38:29 level=INFO msg=usage user=laptop-1 model=claude-opus-4-8 input=1234 output=567 cache_create=0 cache_read=8900 total=10701
time=23:38:29 level=INFO msg=ratelimit 5h=37% reset5h=15:59 7d=12%
time=06:39:33 level=INFO msg="已刷新上游凭证" detail="订阅 OAuth token (len=108) ← …,14:39:33 到期(剩余 8h0m)"
```

凭证的刷新/重载/到期告警也走这一路 —— 它们是**运行期事件**,需要时间戳才能和请求日志对上。
只有启动横幅留在 `log`。

`user` 是 SSH 公钥认定的 device id(伪造不了)。`usage` 各字段对应 Anthropic API 的 `usage`:
`input` = `input_tokens`,`output` = `output_tokens`(流式取最后一个 `message_delta` 的累计值),
`cache_create` / `cache_read` 为缓存写/读 token。

`GATEWAY_LOG_FORMAT=json` 切成 JSON 给采集器。限额接近/耗尽会自动升到 `WARN`/`ERROR`,
便于按 level 告警。

> **`model` 为空是正常的**,而且占了大头 —— `model` 取自**请求体**,只有 `/v1/messages`
> 这类推理请求才有;`/api/oauth/usage` 这些 GET 根本没有 body。空字段直接不打,
> 想知道是哪个端点看 `path`。

> 网关不做任何配额/限流;用量仅打印,不拦截。

## 查额度

设备上直接用 `/usage`:它打的是 `GET /api/oauth/usage`(客户端走全局 axios 的端点),代理把这条
也送进隧道,网关按 path 原样转给上游并注入真凭证 —— 于是设备看到的是**你订阅账号的真实额度**。

三个前提缺一不可,前两个 `ccgw` 都替你处理好了,第三个在网关侧:

- 占位凭证的 scopes 含 `user:profile`。少了它客户端**连请求都不发**,面板显示
  "only available for subscription plans";
- 环境里没有 `CLAUDE_CODE_OAUTH_TOKEN`。设了它就走 env token 分支,scopes 退回 inference-only;
- **网关注入的真凭证 scopes 也要含 `user:profile`。** 客户端肯发了,上游还得认 ——
  用 `claude setup-token` 签的静态 token 只有 `user:inference`,上游会回
  `403 OAuth token does not meet scope requirement`(推理照常,只有账号类端点受影响)。
  改用 `upstream.credentials` 指一份真登录的凭证即可,见「上游凭证从哪来」。

不进客户端也能看:`curl http://127.0.0.1:8788/status` 给的是网关**被动采样**的 5h/7d 限额快照
(从上游响应头取,零额外请求),还没转发过任何请求时返回 `{}`。

## 运维

- **加设备**:设备跑 `setup-device.sh` 拿公钥 → 管理员 `add-device.sh <id> "<公钥>"` → 热重载即生效。
- **吊销设备**:`add-device.sh --remove <id>`,立即生效,其它设备不受影响。
- **host key 轮换**:换掉 `ssh_host_ed25519_key` 重启 → 把新指纹带外发给各设备,设备重跑
  `setup-device.sh`(会更新 `known_hosts`)。
- **CA 轮换**:删掉 `ccgw_ca_key`(含 `.crt`)重启自动生成 → 设备重跑脚本重新取 CA。
  旧 CA 还留在设备上的话,`ccgw` 会报证书错误。
- **升级分流代理**:改了 `device.go` 之类的代码后,网关侧 `make build device-bins` 重新编译、
  重启网关;设备侧重跑 `setup-device.sh`(会经 SSH exec 重新取一份二进制、重启分流代理),
  或手动 `ccgw-device stop` 后重跑取二进制的那步再 `ccgw-device start`。

## 安全与合规边界

- **仅限本人、自己的设备、低并发自用。** 把设备密钥发给别人就成了订阅共享,违反 Anthropic
  服务条款,且会被账号级检测(同一 `account_uuid` + 单 IP + 高并发)命中。
- **网关保护的是 token,不是会话内容。** 不可信电脑仍能截屏/键盘记录你的 prompt 与输出。
  若那台机器真的敌对,优先用 `claude ssh <网关机器>`——让 Claude 跑在你的机器上,什么都不落地。
- **网关须是你信任且可控的机器。** 对外只有一个转发-only SSH 端口:公钥即门禁,没有 shell,
  也不存在任何 HTTP 监听面。
- **设备不该有登录网关机的权限。** 有的话它直接 `cat config.yaml` 就把真 token 拿走了,
  凭证隔离当场失效。所以登记设备由管理员在网关侧做,设备只会建隧道。
- **CA 私钥比 host key 更敏感**:拿到 `ccgw_ca_key` 就能对任何信任该 CA 的设备伪造
  `api.anthropic.com`。它只该待在网关机上;分发给设备的 `.crt` 不是密钥。
- **网关不是设备的通用出口代理。** 设备侧的分流代理默认把 Claude 相关主机(`api.anthropic.com`
  加 `tunnelHosts`)送去网关,网关承担这部分的带宽和出口 IP(解密注入或盲转发);跟 Claude
  无关的流量(WebFetch 抓的网页、第三方 MCP server、`github.com` 之类)由设备本机直连出去,
  网关看不到、也管不了。网关的职责是「Claude 相关流量的凭证隔离 + 路径黑名单」,不是接管设备
  的全部出口。
- **真凭证只会送给 `api.anthropic.com`**,这条写死在代码里(`isMITMHost`),不是配置项 ——
  换成别的域名就等于把订阅 token 交给那个域名。`tunnelHosts` 里的其余主机虽然也经网关,走的
  是纯字节盲转发,网关不解密、不碰凭证;完全在这两份名单之外的流量则根本不经过网关。
- **真凭证只走环境变量。** 别把 token 写进提交的文件;含明文 token 的本地启动脚本(如 `gateway.sh`)
  与本地 `config.yaml` 都已在 `.gitignore` 中。
- **token 续期**:网关里只贴 access token 会几小时过期;稳妥做法是网关机器正常登录、由网关从
  keychain 读并自动刷新。

## License

[MIT](./LICENSE) · 仅供学习与个人自用,不用于、也不应用于绕过 Anthropic 服务条款。
