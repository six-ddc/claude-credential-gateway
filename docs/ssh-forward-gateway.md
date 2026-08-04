# 方案文档 · 转发-only SSH 层(复刻 `claude ssh` 传输形态)

> 目的:把凭证隔离网关的传输层,从「明文 HTTP + Bearer 设备 key(有公网监听面)」
> 换成「自建的**转发-only SSH 服务**」,在**不改系统 sshd**、**单一对外端口**的前提下,
> 复刻 `claude ssh` 的安全属性:无普通登录、无命令执行、无公网 HTTP 监听、
> SSH 公钥认证 + host key pin 防 MITM。

---

## 1. 目标 / 非目标

**目标**
- 对外只暴露**一个**端口,且这个端口是「只能做端口/socket 转发、不能登录、不能执行命令」的 SSH。
- 真凭证只留在网关机;不可信设备只建隧道。
- 传输加密 + host key pin(等价 `claude ssh` 的 host-key 变更检测),防 MITM。
- 每台设备一把独立公钥,可单独审计、单独吊销。
- SSH 是**唯一接入方式**(始终启用):内部 HTTP 只绑 `127.0.0.1`,不再直接暴露。

**非目标**
- 不改变账号级风控画像(多设备复用同一凭证这件事本身)——那由**并发闸门 + 单一出口**处理,不在本方案范围。
- 不替代系统 `sshd`,不占用 22 端口。
- 不保护会话内容:不可信设备仍能截屏/键盘记录你的 prompt 与输出(见 §9)。

---

## 2. 架构总览

```
不可信设备(原生 claude,零自定义头)
  │  ① ssh -N -L 8788:127.0.0.1:8788 -p 2222 laptop-1@gateway   (公钥认证,唯一对外端口)
  │  ② export ANTHROPIC_BASE_URL=http://127.0.0.1:8788           (Level 1: 明文走隧道)
  │     (Level 2: ANTHROPIC_UNIX_SOCKET=~/.ccgw.sock + NODE_EXTRA_CA_CERTS,见 §12)
  ▼
══════════ 单一对外端口 :2222 —— 转发-only SSH(自建 Go, golang.org/x/crypto/ssh) ══════════
  · 公钥认证:pubkey → device id(真正的门禁)
  · 只接受 direct-tcpip / direct-streamlocal@openssh.com
  · session 类型一律 Reject → 无 shell / 无 exec / 无 pty
  · 全局请求 DiscardRequests → 禁 -R 反向转发
  · 转发目标白名单(PermitOpen 等价物)→ 只准连到进程内网关
  ▼
进程内网关 handler(转发 channel 进程内直连,不监听任何 HTTP 端口)
  · 注入真凭证(setup-token 长效 / keychain 自动刷新)
  · 限额被动采样 + per-device 审计(并发闸门尚未实现,见 §8)
  ▼
api.anthropic.com
```

> **一个进程搞定**:「转发-only SSH」+「凭证注入网关」是**同一个二进制**,对外只露 `:2222`。
> 实现上更进一步:`direct-tcpip` 的目标(`permit_target`)只是白名单口令,网关并不真监听它 ——
> 转发 channel 被直接包装成 net.Conn 喂给进程内 HTTP Server,设备身份随连接进入每个请求。

---

## 3. 可信公钥的存放方案(核心决策)

### 决策:可信公钥直接写在 `config.yaml` 里(`ssh.authorized_keys`)

配置单一数据源:SSH 相关的一切(监听、host key 路径、转发白名单、可信公钥)都在 `config.yaml`
的一个 `ssh:` 块内。

```yaml
ssh:
  addr: ":2222"                       # 唯一对外端口(SSH 层始终启用,默认 :2222)
  host_key: ./ssh_host_ed25519_key    # 服务端私钥(机密,见下),按路径引用,不内联
  permit_target: 127.0.0.1:8788       # 转发白名单;Level 2 填 unix:/run/ccgw.sock
  authorized_keys:                    # 可信公钥,每台设备一项
    - id: laptop-1
      key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...key1"
    - id: phone-1
      key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...key2"
```

- **格式**:每项 `{ id, key }`;`key` 是标准 OpenSSH 公钥单行文本。
- **解析**:对每个 `key` 调 `ssh.ParseAuthorizedKey`,建立 `map[string(pubkey.Marshal())] = id`。
- **id**:即设备 id,直接喂给审计;与现有 `users`(占位 Bearer)共用同一套 device id 语义。
- **重载**:改 `config.yaml` 后重读即生效(增删设备)。
- **保密性**:公钥**不是机密**;且 `config.yaml` 本就在 `.gitignore`(设备台账留在本地),
  仓库只提交 `config.example.yaml`(放占位公钥)。
- **env 覆盖(可选)**:沿用现有风格,提供 `GATEWAY_SSH_AUTHORIZED_KEYS`(JSON)覆盖该列表,
  便于容器/env 注入。

> 备选(未选定):独立 OpenSSH `authorized_keys` 文件。熟悉度高、可热重载,但会多一个文件、
> 与网关其余配置分家。既然你要单一数据源,默认走 `config.yaml` 内联。

### host key(服务端私钥)仍是独立文件 —— 这是机密,不进 config.yaml
- **路径**:`config.yaml` 的 `ssh.host_key`(默认 `./ssh_host_ed25519_key`),或 env `GATEWAY_SSH_HOST_KEY`。
- **只按路径引用,绝不把私钥内联进配置**:私钥和一堆公钥混在一起既危险又难管。
- **机密**:必须 gitignore,权限 `0600`。
- **首启自动生成**:文件不存在时自动生成一把 ed25519 host key 并落盘(0600)。
- **客户端 pin**:各设备首次连接把该 host key 记入 `~/.ssh/known_hosts`;之后 host key 若变化 → SSH 报警(等价 `claude ssh` 的 host-key 变更检测)。

---

## 4. 配置模型

主配置在 `config.yaml` 的 `ssh:` 块(见 §3)。环境变量作为**可选覆盖**,沿用现有 `env 覆盖 YAML` 风格:

| 配置项(config.yaml) | env 覆盖 | 默认 | 说明 |
|---|---|---|---|
| `ssh.addr` | `GATEWAY_SSH_ADDR` | `:2222` | 唯一对外端口;SSH 层**始终启用** |
| `ssh.host_key` | `GATEWAY_SSH_HOST_KEY` | `./ssh_host_ed25519_key` | 服务端私钥;不存在则自动生成 |
| `ssh.ca_key` | `GATEWAY_SSH_CA_KEY` | `./ccgw_ca_key` | TLS 终结 CA(机密);自动生成,另导出 `.crt` 供设备信任 |
| `ssh.permit_targets` | `GATEWAY_SSH_PERMIT_TARGETS`(逗号分隔) | `127.0.0.1:8788`, `unix:/run/ccgw.sock` | 转发白名单(列表),两档形态各一项 |
| `ssh.authorized_keys` | `GATEWAY_SSH_AUTHORIZED_KEYS`(JSON) | (空) | 可信公钥列表 `[{id,key}]` |

`.gitignore` 追加(host key 与 CA 私钥都必须排除;`config.yaml` 已在其中):
```
ssh_host_ed25519_key
ssh_host_ed25519_key.pub
ccgw_ca_key
ccgw_ca_key.crt
```
仓库保留 `config.example.yaml`(含占位公钥的 `ssh:` 块)。

---

## 5. 认证与审计(两层身份,统一到 device id)

- **SSH 层(权威)**:`PublicKeyCallback` 把 pubkey 映射到 device id,写进 `ssh.Permissions.Extensions["device"]`。这是隧道的**真门禁**。
- **HTTP 层(审计标签,可选)**:客户端仍可发占位 `CLAUDE_CODE_OAUTH_TOKEN`,网关映射到 device id 供审计;但因隧道已按设备认证,**此层可降级或省略**。
- **简化选项**:有了 SSH 层每设备认证后,HTTP 占位 Bearer key 变冗余 —— 可用单一占位、甚至不校验;真身份来自 SSH 公钥。
- **审计打通**:SSH 连接建立、每个转发 channel、每个 HTTP 请求都带同一个 device id,进现有 `[audit]` 行。

---

## 6. 转发策略(= sshd 的 PermitOpen / ForceCommand,但写在代码里)

- 只 `Accept`:
  - `direct-tcpip` —— 解析目标 `host:port`,必须 `== GATEWAY_SSH_PERMIT_TARGET`,否则 `Reject(Prohibited)`。
  - `direct-streamlocal@openssh.com` —— 解析 socket 路径,必须在白名单内。
- 其它 channel(尤其 `session`)→ `Reject(Prohibited, "forwarding only")` → **shell/exec/pty 从结构上不存在**。
- 连接级与 channel 级请求 → `ssh.DiscardRequests`(回 false)→ 禁 `-R` 反向转发、禁其它扩展。

> 相比 sshd 的 `ForceCommand nologin`(还得靠客户端 `-N` 不触发),这里因为**根本没实现 session channel**,更彻底。

---

## 7. 威胁模型 & 安全属性

| 威胁 | 是否防住 | 靠什么 |
|---|---|---|
| 公网扫描 / 撞库 | ✅ | 唯一端口是 SSH,公钥认证,无口令 |
| 中间人 MITM | ✅ | host key pin(known_hosts) |
| 拿到隧道后横向渗透网关机 | ✅ | 无 shell/exec + 转发目标白名单(只能到网关自己) |
| `-R` 把网关机变成开放中继 | ✅ | 全局请求全拒 |
| 真 token 落到不可信设备 | ✅ | 真凭证只在网关机注入 |
| 不可信设备本地截屏/键盘记录 prompt | ❌ | 传输层管不了;真敌对机器别用(见 §9) |
| 账号级风控(多设备复用画像) | ❌(超出本方案) | 靠并发闸门 + 单一出口 |
| crypto/ssh 自身漏洞 | ⚠️ | 保持 `golang.org/x/crypto` 更新;auth 失败计数封禁 |

---

## 8. 落地里程碑

**已完成**

1. **`sshfwd.go`**:SSH server + `PublicKeyCallback` + channel 分发(`direct-tcpip` / `direct-streamlocal` / 其余 Reject)+ host key 加载/自动生成 + `authorized_keys` 热重载。
2. **wiring**:SSH 是常开的唯一入口;转发 channel 不落地、不拨号,在进程内直接包装成
   `net.Conn` 交给 HTTP Server,网关不监听任何 HTTP 端口。
3. **`tlsterm.go`**:自建 CA + 现签 `api.anthropic.com` 叶证书,支持 `ANTHROPIC_UNIX_SOCKET`
   形态;首字节嗅探自动区分明文与 TLS(见 §12)。
4. **接入流程**:`add-device.sh`(管理员侧)/ `setup-device.sh`(设备侧),设备零网关登录权限(见 §9.5)。
5. **测试**:授权公钥放行 / 未授权拒绝 / `session` 拒绝 / 目标白名单 / `-R` 拒绝 /
   TLS 终结与身份透传 / CA 生成与复用 / 端到端 `claude` 跑通。

**未做(独立议题)**

6. **并发闸门**:单账号单飞/低并发限制器(反误杀关键)。目前网关不做任何配额/限流,用量仅打印。
7. **凭证自动刷新**:现在贴的是 access token,会过期;稳妥做法是从 keychain 读 +
   `grant_type=refresh_token` 自动刷新。

---

## 9. 设备端接入步骤(Mac)

> 以一台新 Mac(设备 id `laptop-1`)接入为例。全程只在设备本地生成密钥,**私钥不外传**;
> 网关只拿到公钥。设备端是**原生 `claude`**,不需要任何自定义头。

日常用 `scripts/setup-device.sh` + `scripts/add-device.sh` 即可(见 README「快速开始」)。
这里写明它们背后做了什么,以及为什么这么分工。

**① 设备本地生成专用密钥对**
```bash
ssh-keygen -t ed25519 -f ~/.ccgw/ccgw_laptop-1 -N "" -C "laptop-1"
# 私钥 ~/.ccgw/ccgw_laptop-1     ← 只留本机,别外传
# 公钥 ~/.ccgw/ccgw_laptop-1.pub ← 交给管理员
```
> `-N ""` 空密码免每次输;想更稳可去掉它设 passphrase。私钥自动 `0600`,ssh 只认权限不认目录。
> 别在仓库目录里生成 —— 虽然 `.gitignore` 有 `ccgw_*` 兜底,但密钥就不该待在版本库旁边。

**② 管理员在网关机上登记**(设备**没有**登录网关机的权限,见 §9.5)
```bash
./scripts/add-device.sh laptop-1 "ssh-ed25519 AAAAC3Nz... laptop-1"
```
写进 `config.yaml` 的 `ssh.authorized_keys`,网关按 mtime 热重载,增删设备无需重启。

**③ 带外核对 host key 指纹**(防 MITM 的关键一步)

管理员侧 `add-device.sh --list` 会打印指纹(等价于 `ssh-keygen -lf ssh_host_ed25519_key.pub`),
通过当面/IM/邮件发给设备。设备侧用 `ssh-keyscan` 取到实际指纹后比对,不符即中止 ——
**不要**直接 `yes` 接受未核对的指纹,那等于放弃 MITM 防护。

**④ 建隧道**(同时开两个转发:明文口取 CA,socket 口跑 claude)
```bash
ssh -N -L 8788:127.0.0.1:8788 -L $HOME/.ccgw.sock:/run/ccgw.sock \
    -p 2222 -i ~/.ccgw/ccgw_laptop-1 \
    -o IdentitiesOnly=yes -o ExitOnForwardFailure=yes -o StreamLocalBindUnlink=yes \
    laptop-1@gateway-host &
```
> 也可以把这些写成 `~/.ssh/config` 里的 `Host` 别名(那是配置不是密钥,放 `~/.ssh` 没问题)。

**⑤ 取 CA + 跑 claude**
```bash
curl -s http://127.0.0.1:8788/ca -o ~/.ccgw/ccgw_ca.crt   # 经已认证的隧道自取

unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN ANTHROPIC_BASE_URL
export ANTHROPIC_UNIX_SOCKET=$HOME/.ccgw.sock
export NODE_EXTRA_CA_CERTS=~/.ccgw/ccgw_ca.crt
export CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-placeholder   # 占位,网关不校验
claude
```
> 想用明文形态(不涉及 CA):`export ANTHROPIC_BASE_URL=http://127.0.0.1:8788` 代替上面两行。
> 全新机器若被 onboarding 拦,按 README「绕过 onboarding」补 `hasCompletedOnboarding`/`theme` 两字段即可,无需真登录。

**换机 / 疑似泄漏**:`./scripts/add-device.sh --remove laptop-1`,这把 key 立即作废,其它设备不受影响。

---

## 9.5 接入流程的信任边界(重要)

**设备绝不该有登录网关机的权限。** 有的话它 `cat config.yaml` 就把真 token 拿走了,
整个凭证隔离失效。所以接入流程按「谁该知道什么」拆成两侧:

| 环节 | 谁做 | 在哪 | 为什么 |
|---|---|---|---|
| 生成密钥 | 设备 | 设备本地 | 私钥永不外传 |
| 登记公钥 | **管理员** | 网关机 (`add-device.sh`) | 准入决策权属于网关持有者,不能让设备自助 |
| host key 指纹 | 管理员 → 设备 | **带外** | 它是防 MITM 的信任锚;从待连网络里取等于让攻击者自发指纹 |
| CA 证书 | 设备自取 | **经已认证的隧道** `GET /ca` | SSH 已认证+加密这一跳,拿到的 CA 可信,无需带外分发 |
| 建隧道 | 设备 | 只连 `:2222` | 转发-only,没有 shell |

CA 之所以能自取而指纹不能,差别在于:建隧道时 SSH 已用 host key **认证了服务端身份**,
隧道内的字节可信;而指纹本身是这条信任链的起点,不能从这条还没建立的链里取。

`GET /ca` 走隧道内的**明文口**(`permit_targets` 里的 tcp 项)—— 因为 unix socket 那一路
要先验 TLS 证书,而证书正是要取的东西,存在先有鸡还是先有蛋的问题。明文口在 SSH 隧道里,
安全性由 SSH 保证。

---

## 10. 运维

- **加设备**:重复 §9 的 ①②(设备生成密钥 + 网关登记公钥)→ 重载生效。
- **吊销设备**:从 `ssh.authorized_keys` 删掉对应项 → 重载生效。
- **host key 轮换**:替换 host key 文件 + 通知各设备更新 `known_hosts`。
- **CA 轮换**:删掉 `ccgw_ca_key`(+`.crt`)重启自动生成新的 → 各设备重新取 `.crt`。
  只影响 Level 2 的设备;Level 1(明文)不受影响。

---

## 11. 合规边界(不随传输加固而改变)

- **仅限本人、自己的设备、低并发自用。** 传输层再硬,也不改变「多设备复用同一订阅」这件事的性质;
  把设备公钥/隧道给**别人**用,就成了订阅共享,违反 Anthropic 服务条款,且会被账号级检测命中。
- **网关保护的是 token,不是会话内容。** 不可信设备仍能截屏/键盘记录。真正敌对的机器,
  优先让 Claude 跑在你信任的机器上,什么都不落地。
- **网关须是你信任且可控的机器。**

---

## 12. Level 2:`ANTHROPIC_UNIX_SOCKET` 的真实机制(实测修订)

本方案初稿假设「Level 2 = 把 TCP 转发换成 unix socket,里面还是明文 HTTP」。**这是错的。**
翻 Claude Code 还原源码 + 实测抓包后,真实情况如下。

### 客户端侧(源码证据)

- `utils/proxy.ts:288-306`:设了 `ANTHROPIC_UNIX_SOCKET` 且跑在 Bun 上时,fetch options 只多一个
  `{unix: socketPath}` —— **仅替换传输层**。URL 仍是 `https://api.anthropic.com`,
  所以客户端照常发起**完整 TLS 握手**(SNI=`api.anthropic.com`,ALPN=`http/1.1`)。
  注释写明这是「ssh **-R** forwarded unix socket to a local auth proxy」。
- `utils/auth.ts:104-113`:远端的 `CLAUDE_CODE_OAUTH_TOKEN` 是**占位值**,作用是让客户端走订阅分支、
  发出 `oauth-2025` beta 头,**与代理即将注入的真凭证形状对齐**,否则上游报 `invalid x-api-key`。
- `utils/auth.ts:1923-1929`:设了该变量就跳过 token 自校验(真凭证不在这台机器上)。
- `utils/managedEnv.ts:17-36`:远端 settings.json 不得覆盖这些隧道变量。

> 注:`src/ssh/{createSSHSession,sshAuthProxy}.ts` 因 feature flag 未打包,代理侧实现无源码可读。

### 实测结论

在 unix socket 上挂一个自签 CA + `CN=api.anthropic.com` 叶证书的 TLS 终结服务:

| 设备端 | 结果 |
|---|---|
| 设 `NODE_EXTRA_CA_CERTS=<ca.crt>` | TLS 握手成功,解密得到明文 `POST /v1/messages?beta=true`、`Authorization: Bearer <占位>`、完整 `anthropic-beta` 头 |
| 不设 | `SSL certificate verification failed`,握手后立即断开 |

即:**代理必须做 TLS 终结,设备必须显式信任那张伪造证书** —— 纯 TCP 透传无法注入凭证(改不了 HTTP 头)。

### 本网关的实现

- `tlsterm.go`:首启生成 CA(`ccgw_ca_key`,0600)并导出 `ccgw_ca_key.crt`(0644,给设备);
  每次启动用 CA 在内存里现签一张 `api.anthropic.com` 叶证书(设备信任的是 CA,叶证书更替无感)。
- `sshfwd.go`:隧道连接**首字节嗅探** —— `0x16`(TLS handshake record)→ 走 TLS 终结,
  否则按明文 HTTP。所以两档形态**同时可用**,不需要配置开关。
- 设备身份透传:`tls.Conn` / `peekConn` 都把 `RemoteAddr()` 委托给底层 channel,
  `ConnContext` 认地址不认类型,包几层都取得到 device id。

### 与官方 `claude ssh` 的方向差异

官方是 `-R`:在**远端**发布 socket、连接回流到**本地**代理(凭证在你手边的机器)。
本网关相反 —— 凭证在服务端网关,所以设备侧用 `-L` + 本地 socket。二者传输形态一致,方向相反。

### 占位凭证:为什么不能省,以及必须剥 `x-api-key`

`utils/auth.ts:104-113` 的 `isAnthropicAuthEnabled()`:

```ts
// The launcher sets CLAUDE_CODE_OAUTH_TOKEN as a placeholder iff the local side
// is a subscriber (so the remote includes the oauth-2025 beta header to match
// what the proxy will inject). The remote's ~/.claude settings (apiKeyHelper,
// settings.env.ANTHROPIC_API_KEY) MUST NOT flip this — they'd cause a header
// mismatch with the proxy and a bogus "invalid x-api-key" from the API.
if (process.env.ANTHROPIC_UNIX_SOCKET) {
  return !!process.env.CLAUDE_CODE_OAUTH_TOKEN
}
```

实测三种情况:

| 设备端 | 结果 |
|---|---|
| 两个都不设 | `Not logged in · Please run /login` —— 客户端自己就不启动 |
| `CLAUDE_CODE_OAUTH_TOKEN=<占位>` | 走订阅分支,发 `Authorization: Bearer <占位>` + `oauth-2025` beta 头 ✅ |
| `ANTHROPIC_API_KEY=<占位>` | 走 API key 分支,改发 `x-api-key`(无 oauth beta 头) |

第三种曾**复现出源码注释预告的那个 401** —— 因为网关注入了真 `Authorization`,却把客户端
那个假 `x-api-key` 一并转发上去,上游优先按 `x-api-key` 校验 → `API key is invalid`。
修法:把 `x-api-key` 加进 `stripHeaders` —— 凭证一律由网关注入,客户端的任何凭证企图都不该到上游。
修完三种情况里后两种都能跑通,但**推荐第二种**(与官方一致,beta 头形状对齐)。

### 新增的信任边界

CA 私钥 `ccgw_ca_key` **是机密且威力更大**:拿到它可以对**任何信任该 CA 的设备**伪造
`api.anthropic.com`。它只该待在网关机(0600 + gitignore);分发的 `.crt` 不是密钥。
设备侧 `NODE_EXTRA_CA_CERTS` 只对该进程生效,不污染系统信任库。

---

*本文档描述传输层加固方案;凭证自动刷新、并发闸门为配套的独立议题。*
