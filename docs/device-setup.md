# 设备端接入教程（从 0 到 1）

面向**设备使用者**：你有一台电脑（自己的笔记本、公司机器、临时的开发机），想用上网关背后那个订阅，
但**不想在这台机器上落地真 token**。

> 全程你**不需要、也不会拿到**登录网关机的权限。设备能做的只有建一条隧道。
>
> 跑完之后你会得到一个 `ccgw` 命令：用法和 `claude` 一模一样，额度算在网关那个订阅上，
> `/usage` 也能正常看到剩余额度。
>
> 网关管理员侧的部署看 [README](../README.md#快速开始)；隧道口上跑什么协议看
> [README「隧道口上跑的是什么」](../README.md#隧道口上跑的是什么)；客户端行为的源码依据看
> [transport.md](./transport.md)。

---

## 0. 开始之前

### 你需要向管理员要两样东西

| 要什么 | 长什么样 | 什么时候要 |
|---|---|---|
| 网关地址和端口 | `gateway.example.com` + `2222` | 一开始 |
| **host key 指纹** | `SHA256:abc123...` | 第 3 步之后 |

指纹**必须带外拿**——当面、微信、电话、邮件都行，**唯独不能从网关那条网络里取**。它是防中间人的
信任锚：从待验证的网络里取指纹，等于让攻击者自己给你发指纹。为什么必须这样，见
[§9 为什么要核对指纹](#9-附为什么非要核对指纹)。

### 本机需要装的东西

```bash
# 检查这些命令都在（macOS / 常见 Linux 一般自带）
for c in ssh ssh-keygen ssh-keyscan curl openssl awk pkill; do
  command -v "$c" >/dev/null && echo "✓ $c" || echo "✗ $c  ← 缺这个"
done
```

缺 `pkill` 的话（少数精简 Linux 镜像）装 `procps`：`apt install procps` / `yum install procps-ng`。

### Claude Code：先查现状，再决定要不要动

**别上来就装。** 很多机器已经装过了，盲目再装一遍容易搞出两份不同来源的安装（npm 一份、
原生安装器一份），后面排查问题会很痛苦。先看现状：

```bash
claude --version 2>/dev/null || echo "未安装"
command -v claude        # 顺便看看装在哪、是哪种安装方式
```

对照下面三种情况处理：

| 现状 | 怎么做 |
|---|---|
| 输出 `未安装` | 按下面「首次安装」装一份 |
| 版本 **≥ 2.1.197** | ✅ 什么都不用做，直接进第 1 步 |
| 版本 **< 2.1.197** | 按下面「升级」升一下，**这是硬性要求** |

> 记不住版本号没关系：`setup-device.sh` 会自己检查。但注意低于 2.1.197 **脚本直接中止**，
> 不是告警——原因见本节末尾。

**首次安装**（挑一种，别混着来）：

```bash
curl -fsSL https://claude.ai/install.sh | bash    # 官方原生安装器（推荐）
npm i -g @anthropic-ai/claude-code                # 或者走 npm
brew install --cask claude-code                   # 或者 macOS Homebrew
```

**升级**——优先用内置命令，它会自己识别安装方式并走对应路径：

```bash
claude update            # 别名 claude upgrade：检查并安装更新
claude doctor            # 升级完不放心可以体检一下安装状态
```

`claude update` 不灵的话（比如权限不够），按你的安装方式手动来：

| 安装方式 | 升级命令 |
|---|---|
| 原生安装器 | `claude install stable` |
| npm | `npm i -g @anthropic-ai/claude-code` |
| Homebrew | `brew upgrade claude-code` |
| mise | `mise upgrade claude` |
| winget | `winget upgrade Anthropic.ClaudeCode` |

**为什么卡在 2.1.197**：v2.1.91 ~ v2.1.196 的客户端一旦发现配了代理，就会读系统时区、
提取代理主机名，把比对结果隐写进系统提示词 `Today's date is ...` 那一行发给上游（官方
v2.1.197 已移除）。`ccgw` 靠 `HTTPS_PROXY` 接管流量，这条**每次调用都会命中**，所以脚本
不放行低版本。确实要用旧版就 `ALLOW_OLD_CLAUDE=1 ./scripts/setup-device.sh laptop-1`，
后果自负。

### 拿到接入脚本

设备端**只需要一个文件** `scripts/setup-device.sh`，不需要网关的 Go 代码：

```bash
git clone https://github.com/six-ddc/claude-credential-gateway.git
cd claude-credential-gateway
```

或者只把那个脚本拷过来也行（`chmod +x` 一下）。

---

## 1. 第一趟：生成密钥、拿到公钥

```bash
GATEWAY_HOST=gateway.example.com ./scripts/setup-device.sh laptop-1
```

- `laptop-1` 是**设备 id**，你自己起，只能用字母数字和 `. _ -`。它会出现在网关的审计日志里，
  起个能认出是哪台机器的名字。不传的话默认是 `<主机名小写>-dev`。
- 端口不是 2222 就再加 `GATEWAY_SSH_PORT=xxxx`。

**这一趟一定会失败，这是设计好的。** 因为公钥还没在网关登记，隧道建不起来。脚本会捕获这个失败，
把公钥打印出来：

```
== 设备 id: laptop-1
== 网关: gateway.example.com:2222
== 已生成密钥: ~/.ccgw/ccgw_laptop-1(私钥只留本机)
⚠ 未提供 GATEWAY_HOST_KEY_FP,按 TOFU 接受。请与管理员人工核对:
     SHA256:abc123...

✗ 隧道没建起来。最常见的原因是【这台设备的公钥还没在网关登记】。

  把下面这行公钥,连同设备 id "laptop-1",交给网关管理员:

ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... laptop-1
```

**私钥永远留在本机**（`~/.ccgw/ccgw_laptop-1`，权限 600），任何时候都不要发给任何人。

---

## 2. 把公钥交给管理员

把打印出来的那**一整行**公钥 + 你的设备 id 发给管理员，渠道随意——**公钥不是机密**，
发微信、贴 issue 都无所谓。

管理员会在网关机上跑：

```bash
./scripts/add-device.sh laptop-1 "ssh-ed25519 AAAAC3Nz... laptop-1"
```

登记后网关**热重载即生效，不用重启**。管理员会把 **host key 指纹**回给你，形如：

```
SHA256:abc123defg456...
```

**收到后先核对**：它应该和你第一趟输出里那行 `SHA256:...` 一致。不一致就停下来问管理员，
别继续（可能是中间人，也可能是网关轮换了 host key）。

---

## 3. 第二趟：带指纹正式接入

```bash
GATEWAY_HOST=gateway.example.com \
GATEWAY_HOST_KEY_FP='SHA256:abc123defg456...' \
  ./scripts/setup-device.sh laptop-1
```

顺利的话输出长这样：

```
== 设备 id: laptop-1
== 网关: gateway.example.com:2222
== host key 指纹已核对: SHA256:abc123defg456...
== 隧道已建立: 127.0.0.1:8788 → gateway.example.com:2222
== 网关 CA: ~/.ccgw/ccgw_ca.crt (CN=claude-credential-gateway CA)
== /status: {}
== Claude Code 版本: 2.1.222 (>= 2.1.197,OK)
== 占位凭证: ~/.ccgw/claude-home/.credentials.json (scopes 含 user:profile,/usage 才肯发请求)
== 已生成包装命令: ~/.ccgw/bin/ccgw
```

脚本这一趟做了 8 件事：核对指纹并 pin → 建隧道（一个本地端口）→ 经隧道自取 CA 证书 →
**经代理**打一次 `https://api.anthropic.com/status` 验证整条链路 → 检查 claude 版本 →
写占位凭证 → 生成包装命令 → 打印下一步。

> `== /status: {}` 是**正常的**。网关还没转发过真实请求时没有限额快照可报，就回空对象。
> 用过一阵之后这里会显示 5h/7d 的剩余额度。

> 那一个本地端口（默认 `127.0.0.1:8788`）身兼两职：`ccgw` 的 `HTTPS_PROXY` 指向它，
> 取 CA 和查 `/status` 的普通 HTTP 请求也打它。网关按连接开头的字节自动分辨。

**指纹不符会直接中止**，这是它该做的：

```
✗ host key 指纹不符 —— 可能是中间人,或网关轮换了 host key。已中止。
  期望: SHA256:aaa...
  实际: SHA256:bbb...
```

---

## 4. 配好 PATH，开始用

脚本生成了 `~/.ccgw/bin/ccgw`，把那一堆环境变量都封在里面了。把目录加进 PATH：

```bash
# zsh
echo 'export PATH="$HOME/.ccgw/bin:$PATH"' >> ~/.zshrc && source ~/.zshrc

# bash
echo 'export PATH="$HOME/.ccgw/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc
```

然后：

```bash
ccgw                       # 等价于「经网关的 claude」，交互式
ccgw -p "写个快速排序"       # 参数原样透传，和 claude 完全一致
ccgw --version
```

**真的 `claude` 命令不受影响**，仍然直连官方。两者可以并存，互不干扰。

交互式里敲 `/usage` 能看到网关那个订阅的剩余额度（5h / 7d 那几条）——它依赖脚本写的占位凭证里
带了 `user:profile` scope，详见 [§7 环境变量速查](#7-环境变量速查)。

> 只想要交互式 shell 里的别名也行：`alias ccgw="$HOME/.ccgw/bin/ccgw"`。
> 但推荐 PATH 形态——别名在脚本、`make`、编辑器插件等子进程里**不生效**。
>
> **别把它命名成 `cc`**：`/usr/bin/cc` 是 C 编译器，抢占它会让 `make`、cgo、npm 原生模块全部走岔。
> 想改名用 `CMD_NAME=xxx ./scripts/setup-device.sh laptop-1`，脚本会做同名冲突检测。

---

## 5. 全新机器：跳过首次运行引导

**如果 `ccgw` 起来后还是让你去浏览器登录账号**，是撞上了 Claude Code 的首次运行引导——
它检测到没完成 onboarding 就会走引导流程，**这一步不会因为设了 token 就跳过**。

> 跳过的只是**选主题那个交互式 UI**，不涉及绕过任何鉴权或计费——真正的鉴权发生在网关注入
> 你自己订阅凭证的那一刻，用的仍然是你自己付费的订阅。

触发条件是 `!theme || !hasCompletedOnboarding`，**两个字段缺一个就触发**。

**第 1 步，先定位对的配置文件**。`ccgw` 把 `CLAUDE_CONFIG_DIR` 指向 `~/.ccgw/claude-home`，
所以它读的是**那个目录里**的 `.claude.json`，跟你平时用的 `~/.claude.json` 不是同一个文件——
哪怕你早就用真 `claude` 登录过，第一次跑 `ccgw` 照样可能被引导拦下：

```bash
ls -la ~/.ccgw/claude-home/.claude.json ~/.ccgw/claude-home/.config.json 2>/dev/null
```

优先级：存在 `<CLAUDE_CONFIG_DIR 或 ~/.claude>/.config.json` → **它优先**；否则
→ `(CLAUDE_CONFIG_DIR || ~)/.claude.json`，`ccgw` 形态下就是 `~/.ccgw/claude-home/.claude.json`。

**第 2 步，补两个字段**（用 `jq` 安全合并，不会覆盖已有内容）：

```bash
F=~/.ccgw/claude-home/.claude.json     # 换成上一步定位到的文件
[ -f "$F" ] || echo '{}' > "$F"
jq '.hasCompletedOnboarding = true | .theme = (.theme // "dark")' "$F" > "$F.tmp" && mv "$F.tmp" "$F"
```

> **常见踩坑**：把 `hasCompletedOnboarding` 写进了 `settings.json`。那是 settings，
> schema 不同，**根本没有这个字段**，写了也不生效。

> 同理，`.claude.json` 里记的东西（「信任这个目录吗」的应答、`~/.claude.json` 级的 MCP 配置等）
> `ccgw` 和真 `claude` 各记各的，第一次进某个目录可能要再确认一次信任。
> 而 `settings.json`、`CLAUDE.md`、`commands`、`agents`、`skills`、`plugins`、`projects`、
> `todos`、`statsig` 是脚本用符号链接从真 `~/.claude` 接过来的，设置和会话历史都还在，
> 那边改了这边立刻跟着变。

---

## 6. 日常使用

### 隧道断了怎么办

隧道是一个后台 `ssh -f -N` 进程，带 `ServerAliveInterval=30` 保活。网络切换、休眠唤醒、
网关重启都可能让它断掉。**重跑脚本即可**，密钥和登记都会复用：

```bash
GATEWAY_HOST=gateway.example.com \
GATEWAY_HOST_KEY_FP='SHA256:abc...' \
  ./scripts/setup-device.sh laptop-1
```

> ⚠️ **每次重跑都建议带上 `GATEWAY_HOST_KEY_FP`。**
> 当前脚本在重跑时会用**新扫到的** host key **无条件覆盖** `~/.ccgw/known_hosts`
> （`awk ... > "$KNOWN_HOSTS"`，不管有没有传指纹）。也就是说**不带指纹重跑 = 又做了一次 TOFU**，
> 之前 pin 住的那把会被静默替换掉——此时如果正好有中间人，你不会收到任何警告。
> 带上指纹就会走显式比对，不符即中止。
>
> 把它连同网关地址存成一个 shell 函数会省事很多：
>
> ```bash
> # ~/.zshrc
> ccgw-up() {
>   GATEWAY_HOST=gateway.example.com \
>   GATEWAY_HOST_KEY_FP='SHA256:abc123defg456...' \
>     ~/path/to/setup-device.sh laptop-1
> }
> ```

### 检查隧道到底活没活

```bash
# ① 看 ssh 进程还在不在
pgrep -fl "ccgw_laptop-1"

# ② 打一下明文口（最轻）
curl -s http://127.0.0.1:8788/status

# ③ 完整走一遍客户端要走的路：代理 + TLS 终结 + 校验网关 CA（最可靠）
curl -s -x http://127.0.0.1:8788 --cacert ~/.ccgw/ccgw_ca.crt \
     https://api.anthropic.com/status
```

第 ② 条能通说明隧道活着（`ccgw` 启动前的自检就是它）；第 ③ 条还额外验证了 CA 对不对。

### 开机自动重连（可选）

macOS 用 launchd、Linux 用 systemd user unit 或 cron `@reboot` 都行。最省事的办法是往 rc 里塞一行
惰性检查——只在代理口连不上时才重建：

```bash
# ~/.zshrc（可选）
curl -sf -m 2 http://127.0.0.1:8788/status >/dev/null 2>&1 || \
  GATEWAY_HOST=gateway.example.com ~/path/to/setup-device.sh laptop-1 >/dev/null 2>&1
```

---

## 7. 环境变量速查

跑 `setup-device.sh` 时可以覆盖的：

| 变量 | 默认值 | 说明 |
|---|---|---|
| `GATEWAY_HOST` | `gateway.example.com` | **必改**，网关地址 |
| `GATEWAY_SSH_PORT` | `2222` | 网关 SSH 端口 |
| `GATEWAY_HOST_KEY_FP` | 空 | 管理员给的指纹；不给则 TOFU 并要求你人工核对 |
| `CMD_NAME` | `ccgw` | 生成的包装命令名；不能叫 `claude` |
| `MIN_CLAUDE_VERSION` | `2.1.197` | 版本下限，低于**直接中止** |
| `ALLOW_OLD_CLAUDE` | 空 | 设成 `1` 强行放行低版本（自担后果） |
| `CCGW_HOME` | `~/.ccgw` | 密钥、CA、占位凭证、包装命令的存放目录 |
| `PLACEHOLDER_TOKEN` | `sk-ant-oat01-placeholder` | 占位凭证里的假 token，所有设备可以一样 |
| `SUBSCRIPTION_TYPE` | `max` | 占位凭证声明的档位；只影响 `/usage` 显示哪几条限额 |
| `LOCAL_PROXY_PORT` | `8788` | 本机代理入口端口，`HTTPS_PROXY` 指向它 |
| `PERMIT_TCP` | `127.0.0.1:8788` | 隧道右端目标，须与网关 `permit_targets` 一致 |
| `REAL_CLAUDE_HOME` | `~/.claude` | 从哪儿把设置/记忆/历史链过来 |

`ccgw` 内部**替你设好**的（你不用管，列出来只为让你知道发生了什么）：

| 变量 | 值 | 作用 |
|---|---|---|
| `HTTPS_PROXY` / `HTTP_PROXY`（含小写） | `http://127.0.0.1:8788` | 把 claude 的全部 HTTP(S) 流量赶进隧道 |
| `NO_PROXY` / `no_proxy` | `localhost,127.0.0.1,::1` | 本机地址不走代理，否则本地跑的 MCP server / dev server 也会被绕去网关 |
| `NODE_EXTRA_CA_CERTS` | `~/.ccgw/ccgw_ca.crt` | 信任网关自建 CA（它要终结 `api.anthropic.com` 的 TLS） |
| `CLAUDE_CONFIG_DIR` | `~/.ccgw/claude-home` | 独立配置目录，占位凭证放这儿，不碰你真的 `~/.claude` |
| `ANTHROPIC_API_KEY` 等 4 个 | **unset** | 任何残留都会让 claude 绕开网关或改发 `x-api-key` |
| `ANTHROPIC_UNIX_SOCKET` | **unset** | 残留会让传输层走回 socket，只盖得住 `/v1/messages` |
| `CLAUDE_CODE_OAUTH_TOKEN`、`CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR` | **unset** | 见下 |

**为什么要 unset 那两个 OAuth token 变量**：设了其中任何一个，客户端就走环境变量／文件描述符
凭证分支，scopes 被硬编码成只有 `user:inference`，凭证文件根本不读。而 `/usage` 要求 scopes 含
`user:profile`，拿不到就直接返回空、**连请求都不发**——面板上就是那句
"only available for subscription plans"。
所以占位凭证写成文件 `~/.ccgw/claude-home/.credentials.json`，自己把 scopes 定全：

```json
{"claudeAiOauth":{"accessToken":"sk-ant-oat01-placeholder","expiresAt":4102444800000,
  "scopes":["user:inference","user:profile"],"subscriptionType":"max"}}
```

不给 `refreshToken`、`expiresAt` 又设到 2100 年，是为了让客户端别去刷新——拿占位 token 刷新
必然失败，还会重试、拖慢启动。

> **设备上的全部 HTTPS 流量都会经过网关**：遥测、WebFetch 抓的网页、MCP server 全走这条代理，
> 没有从你本机 IP 直连出去的旁路。能出到哪些站点由网关代码里的盲转发名单决定，名单只放行
> Claude Code 自身要用的那些主机，抓名单外的站点会拿到 403（要加得找管理员改网关代码）。
> 只有 `api.anthropic.com` 会被网关解密并换上真凭证，其余都是不解密的 TCP 盲转发。

---

## 8. 故障排查

### `✗ 连不上 gateway:2222(网关没起?端口没放行?)`

`ssh-keyscan` 都没连上，问题在网络层，还没到认证：

```bash
nc -vz gateway.example.com 2222      # 通不通
```

不通 → 网关没启动、防火墙/安全组没放行、或者地址端口写错了。找管理员。

### `✗ 隧道没建起来`

99% 是**公钥还没登记**（第一趟必然如此）。如果第二趟还这样，检查：

- 交给管理员的公钥是不是**完整一行**（`ssh-ed25519 AAAA... laptop-1`，别漏尾巴也别多换行）
- 用的**设备 id 是否一致**——脚本用 `laptop-1@网关` 登录，id 和登记时必须一模一样
- 让管理员跑 `./scripts/add-device.sh --list` 确认登记上了

### `✗ host key 指纹不符`

**不要绕过。** 两种可能：网关轮换了 host key（找管理员要新指纹），或者有中间人。
确认是前者后，删掉旧记录再重跑：

```bash
rm ~/.ccgw/known_hosts
```

### `✗ 取 CA 失败(网关版本太旧?需要支持 GET /ca)`

隧道建起来了但 `GET /ca` 没成功。多半是网关版本旧、没有 `/ca` 这个端点。找管理员升级。

### `✗ 经代理访问 /status 失败(网关版本太旧?需要支持 CONNECT)`

隧道和 CA 都拿到了，但代理这条路不通。基本是网关版本旧、还不会处理 `CONNECT`。找管理员升级。

### `✗ Claude Code 版本过低`

必须升级，见 [§0](#claude-code先查现状再决定要不要动)。真要用旧版：
`ALLOW_OLD_CLAUDE=1 ./scripts/setup-device.sh laptop-1`。

### `✗ 隧道未就绪(http://127.0.0.1:8788 连不上)`（跑 `ccgw` 时）

隧道断了，重跑 `setup-device.sh`。

### 端口 8788 被本机别的程序占了

换一个：`LOCAL_PROXY_PORT=18788 ./scripts/setup-device.sh laptop-1`。改的只是本机这一端，
隧道右端（`PERMIT_TCP`）不用动，包装命令会跟着一起重建。

### `⚠ PATH 里已存在同名命令 ccgw -> /usr/bin/ccgw`

撞名了。换个名字重跑：`CMD_NAME=myclaude ./scripts/setup-device.sh laptop-1`。

### `ccgw` 起来了但要求登录账号

看 [§5 跳过首次运行引导](#5-全新机器跳过首次运行引导)。

### `ccgw` 报 TLS / 证书错误

`NODE_EXTRA_CA_CERTS` 指的 CA 和网关当前的对不上（常见于网关重新生成过 CA）。重跑脚本重新取：

```bash
rm ~/.ccgw/ccgw_ca.crt
GATEWAY_HOST=... GATEWAY_HOST_KEY_FP='SHA256:...' ./scripts/setup-device.sh laptop-1
```

### 请求 401 / `invalid x-api-key`

环境里有残留的 `ANTHROPIC_API_KEY` 或 `ANTHROPIC_AUTH_TOKEN`——它会让客户端改发 `x-api-key`，
和网关注入的 Bearer 头冲突。`ccgw` 内部会 unset 这几个，但如果你是**手动**设环境变量跑 `claude`，
就得自己清干净。用 `ccgw` 就不会有这个问题。

### WebFetch 抓不到某个网站 / 第三方 MCP server 连不上

网关只放行 Claude Code 自身要用的那些主机，其它目标一律 403。确认一下是不是撞在这上面：

```bash
curl -sv -x http://127.0.0.1:8788 https://example.com 2>&1 | grep -i '403\|host not permitted'
```

看到 `host not permitted by gateway` 就是名单拦的，响应 body 里带被拒的主机名。名单写死在网关
代码里，要放行得找管理员改代码重新部署——这是有意的设计，不是配置漏了。

### `/usage` 显示 "only available for subscription plans"

客户端手里的 scopes 不含 `user:profile`，于是它压根不发那个请求。按顺序查：

```bash
echo "$CLAUDE_CODE_OAUTH_TOKEN"                    # 必须是空的
echo "$CLAUDE_CONFIG_DIR"                          # 应为 ~/.ccgw/claude-home
cat ~/.ccgw/claude-home/.credentials.json          # scopes 应含 user:profile
```

`CLAUDE_CODE_OAUTH_TOKEN` 非空是最常见的原因（比如写进了 `~/.zshrc`）——它一设，客户端就走
环境变量分支，scopes 退回 inference-only，凭证文件不再被读。`ccgw` 会 unset 它，
但你若是手动跑 `claude` 就得自己清掉。凭证文件不对就重跑 `setup-device.sh` 重写一份。

### 想确认额度是不是真的走了网关

`curl -s http://127.0.0.1:8788/status` 看网关侧采样到的 5h/7d 快照，和 `ccgw` 里 `/usage`
显示的对一下。网关那边还会给每个请求打一行 `[usage] user=<你的设备 id> ...`，找管理员一看便知。

---

## 9. 附：为什么非要核对指纹？

常见疑问：*「我公钥都发给网关登记了，链路不就可信了吗？为什么还要指纹？」*

因为**认证是双向的，两边防的是完全不同的攻击**：

| 做的事 | 谁认谁 | 防谁 |
|---|---|---|
| 公钥登记进 `authorized_keys` | **网关**确认「你是我认识的设备」 | 防陌生人蹭网关和订阅 |
| 核对 host key 指纹 | **设备**确认「你是我要连的那个网关」 | 防有人**冒充网关** |

公钥登记只完成了第一行，它保护的是**网关**，对**设备**一点保护都没有。攻击者要冒充网关，
根本不需要你的设备公钥。

那能不能「把拉下来的 CA 直接信了」？不能，那是循环论证：

```
CA 可信 ← 因为隧道可信 ← 因为对面确实是网关 ← ？？？
```

最后那个问号就是指纹。拿掉它，你信任的就是「**任何应答了这个连接的人**」给你的 CA。

**不核对会怎样**：攻击者在网络路径上应答你的连接 → 你拿到**他的** CA → 写进
`NODE_EXTRA_CA_CERTS` → 他就能伪造 `api.anthropic.com` 证书而你完全信任 →
**你发给 Claude 的每一句 prompt、每一个读进上下文的文件、每一段代码全部明文暴露**，
并且返回内容可以被任意篡改（比如给你注入带后门的代码）。

> 其实 HTTPS 也是这么干的，只是你没感觉到——根 CA 早就预装在操作系统/浏览器里了，那同样是一次
> 带外分发，只不过厂商出厂时替你做了。你从来不会「从网站下载它的根证书然后信任它」。
> 这个网关没有公共 CA 签发的证书，所以那颗种子得你手工种一次。

**指纹本身是一次性索取的**——管理员给你一次，你存下来长期复用。但注意当前脚本的实现细节：
每次重跑都会用新扫到的 key 覆盖 `known_hosts`，**所以每次重跑都该把指纹带上**，
否则那一次就退化成 TOFU（见 [§6](#隧道断了怎么办)）。指纹不变的话，存成 shell 函数一劳永逸。

只有网关真的轮换了 host key 时，你才需要向管理员要一个新指纹。

---

## 10. 附：本机都生成了什么

```
~/.ccgw/
├── ccgw_laptop-1          # 设备 SSH 私钥（600）—— 永不外传
├── ccgw_laptop-1.pub      # 公钥 —— 就是交给管理员的那行
├── ccgw_ca.crt            # 网关 CA 证书 —— NODE_EXTRA_CA_CERTS 指它
├── known_hosts            # pin 住的网关 host key
├── bin/
│   └── ccgw               # 包装命令
└── claude-home/           # ccgw 专用的 CLAUDE_CONFIG_DIR
    ├── .credentials.json  # 占位凭证（600）—— 假 token + user:profile scope
    ├── .claude.json       # ccgw 自己的 onboarding / 目录信任记录（跑过才有）
    ├── settings.json      → ~/.claude/settings.json      （符号链接）
    ├── CLAUDE.md          → ~/.claude/CLAUDE.md          （符号链接）
    └── commands / agents / skills / plugins / projects / todos / statsig  （符号链接）
```

目录权限 700，只有你自己能进。链接过去的那些**不是拷贝**：真 `~/.claude` 里改了，`ccgw` 立刻
跟着变；反过来在 `ccgw` 里改也是写进真目录。只有凭证是隔离的。

**不再用了想彻底清掉**：

```bash
pkill -f "ccgw_laptop-1"          # 断隧道
rm -rf ~/.ccgw                    # 只删链接本身，不会动到真 ~/.claude 里的内容
# 再把 ~/.zshrc 里那行 export PATH=... 删掉
```

同时**让管理员吊销**这台设备（否则公钥还留在网关上）：

```bash
./scripts/add-device.sh --remove laptop-1     # 管理员在网关机上执行，热重载即生效
```
