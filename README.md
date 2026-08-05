# claude-credential-gateway

一个**凭证隔离网关**(Go 实现):让**你本人名下的多台设备**(包括公共/不完全可信的电脑)用你
自己的 Claude 订阅工作,而**不在那些电脑上暴露真 token**。真 OAuth token 只留在一台你信任的
网关机器上;设备上只有一把可单独吊销的 SSH 密钥,请求经网关时才被注入真凭证。

> 这是**个人自用**工具,解决的是「同一个人换机器时凭证落地太多份」的问题,不是给多人共享订阅用的
> —— 把设备密钥给别人就成了订阅共享,违反 Anthropic 服务条款(详见文末「安全与合规边界」)。

设计借鉴 Claude Code 自带的 `claude ssh` 凭证隔离机制(凭证留在可信侧、另一侧只拿占位、代理注入)。

## 工作原理

```
设备(原生 claude,零自定义头)
  │  ssh -N -L ... -p 2222 laptop-1@网关机     ← 唯一对外端口,公钥认证
  ▼
转发-only SSH 层(:2222)
  · 公钥 → device id,这是唯一门禁
  · 只接受转发 channel,且目标必须在白名单里
  · 无 shell / 无 exec / 无 pty,禁 -R 反向转发
  · host key pin 防 MITM
  ▼
进程内网关 handler(转发 channel 直连,不监听任何 HTTP 端口)
  · 剥掉客户端的凭证企图,注入真订阅 token
  · per-device 审计 + 5h/7d 限额被动采样
  ▼
api.anthropic.com
```

几个要点:

- **网关不监听任何 HTTP 端口**。转发 channel 在进程内被直接喂给 HTTP handler,不经过本机端口,
  所以网关机上的其它进程也偷用不了真凭证。
- **身份来自 SSH 公钥**,写进每个请求的 context,客户端伪造不了。设备台账的单一数据源就是
  `ssh.authorized_keys`。
- **设备对网关机没有任何登录权限**,能做的只有建隧道。
- 同时,网关会**打印每个请求的 model 与 token 使用量**(input / output / cache),用 `gjson`
  从上游响应解析,支持 SSE 流式与普通 JSON。

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
  oauth: ""               # 你订阅的真 access token;留空则用 CLAUDE_GATEWAY_UPSTREAM_OAUTH 注入
ssh:                      # 唯一对外入口;设备台账的单一数据源
  addr: ":2222"                       # 唯一对外端口
  host_key: ./ssh_host_ed25519_key    # 服务端私钥;不存在则首启自动生成
  ca_key: ./ccgw_ca_key               # TLS 终结 CA;自动生成,另导出 .crt
  permit_targets:                     # 客户端 -L 声明的目标须在其中(网关并不真监听它们)
    - 127.0.0.1:8788
    - unix:/run/ccgw.sock
  authorized_keys:                    # 每台设备一把公钥;改完热重载即生效,无需重启
    - id: laptop-1
      key: "ssh-ed25519 AAAA... laptop-1"
```

配置路径优先级:`GATEWAY_CONFIG` 指定 > 本地 `config.yaml` > `config.example.yaml`(模板,并提示拷贝)。

可用环境变量覆盖:`GATEWAY_UPSTREAM_BASE`、`CLAUDE_GATEWAY_UPSTREAM_OAUTH`、
`GATEWAY_SSH_ADDR`、`GATEWAY_SSH_HOST_KEY`、`GATEWAY_SSH_CA_KEY`、
`GATEWAY_SSH_PERMIT_TARGETS`(逗号分隔)、`GATEWAY_SSH_AUTHORIZED_KEYS`(JSON `[{id,key}]`)。

> `host_key` 与 `ca_key` 都是**私钥**,已 gitignore、权限 0600。生产上建议把它们放到仓库之外
> (如 `/etc/ccgw/`),免得被 `git clean` 之类的操作误删。

## 快速开始

> **设备使用者**看这份手把手教程更省事:[docs/device-setup.md](docs/device-setup.md) ——
> 从装 Claude Code 到跑起 `ccgw` 的完整流程,含故障排查与环境变量速查。
> 下面的「快速开始」是**管理员视角**的全景速览(网关 + 设备两侧都有)。

### ① 网关机(你信任的常驻机)

```bash
export CLAUDE_GATEWAY_UPSTREAM_OAUTH='<你的订阅 access token>'
./claude-credential-gateway
```

首次启动会自动生成 SSH host key 与 TLS 终结 CA,并在日志里打印 host key 指纹。

### ② 设备:第一趟 —— 生成密钥、拿到公钥

```bash
GATEWAY_HOST=你的网关 ./scripts/setup-device.sh laptop-1
```

这一趟隧道会**故意失败**(公钥还没登记),脚本会把本机公钥打印出来。把公钥和 device-id
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

脚本会核对指纹(不符即中止)、建隧道、经隧道自取 CA 证书、验证链路、检查 Claude Code 版本,
最后生成一个**包装命令** `~/.ccgw/bin/ccgw` —— 那一堆 `unset`/`export` 都收在里面,不用手敲:

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
unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN ANTHROPIC_BASE_URL ANTHROPIC_CUSTOM_HEADERS
export ANTHROPIC_UNIX_SOCKET=$HOME/.ccgw-laptop-1.sock
export NODE_EXTRA_CA_CERTS=$HOME/.ccgw/ccgw_ca.crt
export CLAUDE_CODE_OAUTH_TOKEN='sk-ant-oat01-placeholder'
export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
exec claude "$@"
```

外加两个启动前自检:socket 不在就提示「重跑 setup-device.sh 建隧道」,CA 缺失同理 ——
比让 `claude` 抛一个含糊的连接错误好定位。

> 设备密钥与 CA 存 `~/.ccgw/`(不进仓库)。隧道断了重跑脚本即可,包装命令会一并重建。
>
> **占位凭证不能省**:`claude` 自己要求手里有凭证才肯启动,什么都不设会停在
> `Not logged in · Please run /login`。网关不校验它、只覆盖,所有设备填同一个假值即可。
> `CLAUDE_CODE_OAUTH_TOKEN` 与 `ANTHROPIC_API_KEY` 设哪个都能跑(网关会剥掉客户端的
> `x-api-key` 再注入真凭证),但**建议用前者** —— 它让客户端走订阅分支、带上 `oauth-2025`
> beta 头,与网关注入的订阅 token 形状一致,这也是官方 `claude ssh` 的做法。
>
> **旁路流量要关**:`ANTHROPIC_UNIX_SOCKET`/`ANTHROPIC_BASE_URL` 只接管 API 主链路;遥测
> (`event_logging/batch`)和 GrowthBook 特性开关拉取是独立的直连请求,从设备**真实 IP** 发出
> (GrowthBook 那路还会把占位 token 以 Bearer 带给 `api.anthropic.com`,虽被 401 但暴露 IP)。
> `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` 让客户端进入 essential-traffic 模式,这些请求
> **在源头就不发**,顺带禁掉错误上报、`/feedback`、DesignSync、Projects、自动更新检查等依赖
> claude.ai 的功能。若只想关遥测但保留这些功能,退一档用 `DISABLE_TELEMETRY=1` —— 源码里
> GrowthBook 拉取以「遥测未关」为前提,所以它同样会停,只是错误上报、更新检查等仍直连。
>
> **客户端版本下限 `>= 2.1.197`**:脚本会检查 `claude --version`,低于就告警(不中止 ——
> 隧道本身已经好了)。v2.1.91(2026-04-02)~v2.1.196 的客户端在设了 `ANTHROPIC_BASE_URL` 时,
> 会读系统时区、提取代理主机名与两份加密列表比对,再把结果隐写进系统提示词
> `Today's date is ...` 那一行(日期分隔符 `-`↔`/`,撇号在 U+0027/2019/02BC/02B9 间切换)发给上游;
> 官方 v2.1.197 已移除。**socket 形态不设 `ANTHROPIC_BASE_URL`,本就不在触发面上**,但明文调试
> 形态会;且网关是透明转发、不改写请求体,客户端埋进 body 的任何标记都会绑着真凭证送达上游。
> 详见 [docs/anthropic-unix-socket.md](docs/anthropic-unix-socket.md)。用
> `MIN_CLAUDE_VERSION=x.y.z` 可覆盖这个下限。

## 两种传输形态

网关**同时**支持两种,靠首字节嗅探自动区分(TLS 记录以 `0x16` 开头),不需要任何配置开关。

**① unix socket + TLS(脚本默认,推荐)** —— 复刻官方 `claude ssh` 的传输形态。本机不开
TCP 端口,socket 文件 `0600` 只有你自己能连。

Claude Code 设了 `ANTHROPIC_UNIX_SOCKET` 后,只把**传输层**换成 unix socket,**目标 URL 仍是
`https://api.anthropic.com`,照常发起完整 TLS 握手**。所以网关必须自己终结 TLS 才能读到明文
HTTP 去替换 `Authorization`:它用自建 CA 现签一张 `api.anthropic.com` 证书,设备用
`NODE_EXTRA_CA_CERTS` 信任这把 CA 即可。

**② 明文 HTTP(调试友好)** —— 用 `ANTHROPIC_BASE_URL` 指向隧道本地口,不涉及 CA:

```bash
ssh -N -L 8788:127.0.0.1:8788 -p 2222 -i ~/.ccgw/ccgw_laptop-1 laptop-1@网关机 &
unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN ANTHROPIC_UNIX_SOCKET
export ANTHROPIC_BASE_URL=http://127.0.0.1:8788
export CLAUDE_CODE_OAUTH_TOKEN='sk-ant-oat01-placeholder'
export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
claude
```

`ANTHROPIC_BASE_URL` 在这个形态下**不能省** —— 不设它,`claude` 会拿占位 token 直连官方 API,
直接 401,网关被整个绕过。

> **明文形态请只当调试用**,暴露面严格大于 socket 形态:它必须设 `ANTHROPIC_BASE_URL`,而客户端
> 里若干逻辑正是以「设了非官方 base URL」为入口 —— 比如 GrowthBook 用户属性里的
> `apiBaseUrlHost`(把代理主机名连同 deviceId/accountUUID/email 一起上报,v2.1.220 仍在),
> 以及旧版那套隐写标记。socket 形态下 `ANTHROPIC_BASE_URL` 未设,这些分支取不到值。
> 日常请用脚本生成的 `ccgw`(socket 形态)。

> 两种形态下 `-L` 右边的目标(`127.0.0.1:8788` / `/run/ccgw.sock`)都必须在网关
> `ssh.permit_targets` 里。它们只是白名单口令,网关并不真监听这些地址。
>
> 限额快照:socket 形态 `curl --unix-socket $SOCK --cacert $CA https://api.anthropic.com/status`;
> 明文形态 `curl http://127.0.0.1:8788/status`。

### 手动接入(不用脚本)

```bash
# ① 设备本地生成密钥,把 .pub 交给管理员登记(见「快速开始」③)
ssh-keygen -t ed25519 -f ~/.ccgw/ccgw_laptop-1 -N "" -C laptop-1

# ② 核对指纹后建隧道(两个转发:明文口取 CA,socket 口跑 claude)
ssh -N -L 8788:127.0.0.1:8788 -L $HOME/.ccgw.sock:/run/ccgw.sock \
    -p 2222 -i ~/.ccgw/ccgw_laptop-1 laptop-1@网关机 &

# ③ 经【已认证的隧道】自取 CA —— 不需要、也不该有登录网关机的权限
curl -s http://127.0.0.1:8788/ca -o ~/.ccgw/ccgw_ca.crt
```

> CA 之所以能自取而 host key 指纹不能:建隧道时 SSH 已用 host key 认证了服务端身份,隧道内的
> 字节可信;而指纹是这条信任链的**起点**,不能从还没建立的链里取。
>
> `GET /ca` 走明文口是因为 socket 那一路要先验 TLS 证书,而证书正是要取的东西。明文口在 SSH
> 隧道内,安全性由 SSH 保证。

## 首次初始化:跳过交互式引导

**全新机器、或 `claude logout` 之后,光设占位 token 不够用** —— Claude Code 检测到没完成
onboarding 会进入首次运行引导,而里面的登录步骤**不会因为设了 token 就被跳过**。表现:明明设了
占位 token,`claude` 还是要你去浏览器登录账号。

> 说明:这里跳过的只是**首次运行的交互式 UI 引导**(选主题那一步),不涉及绕过任何鉴权或计费 ——
> 真正的鉴权发生在网关注入你自己订阅凭证的那一刻,用的仍是你自己付费的订阅。

触发条件是 `!theme || !hasCompletedOnboarding`,**两个字段缺一个就触发**。所以在客户端预置好这两个
字段即可绕过,完全不需要真账号登录:

**1) 先定位对的全局配置文件**(不是 `~/.claude/` 目录里的文件,常见的是 `~/.claude.json`):

```bash
echo "CLAUDE_CONFIG_DIR=$CLAUDE_CONFIG_DIR"
ls -la ~/.claude.json ~/.claude/.config.json "$CLAUDE_CONFIG_DIR/.claude.json" 2>/dev/null
```

解析优先级(对应 Claude Code 的 `getGlobalClaudeFile()`):
- 若存在 `<CLAUDE_CONFIG_DIR 或 ~/.claude>/.config.json` → **它优先**(老版本路径,改 `~/.claude.json` 就没用);
- 否则 → `(CLAUDE_CONFIG_DIR || ~)/.claude.json`(最常见)。

> 常见踩坑:把 `hasCompletedOnboarding` 写进了 `~/.claude/settings.json` —— 那是 settings,schema 不同,
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
F=~/.claude.json
[ -f "$F" ] || echo '{}' > "$F"
jq '.hasCompletedOnboarding = true | .theme = (.theme // "dark")' "$F" > "$F.tmp" && mv "$F.tmp" "$F"
```

之后再按「快速开始 ④」设好环境变量跑 `claude`,就能直接用、不再要求登录账号。

## Token 用量日志

每个成功请求,网关都会打印一行(从**上游响应**解析):

```
[usage] user=laptop-1 model=claude-opus-4-8 input=1234 output=567 cache_create=0 cache_read=8900 total=10701
```

`user` 是 SSH 公钥认定的 device id(伪造不了)。其余字段对应 Anthropic API 的 `usage`:
`input` = `input_tokens`,`output` = `output_tokens`(流式取最后一个 `message_delta` 的累计值),
`cache_create` / `cache_read` 为缓存写/读 token。

> 网关不做任何配额/限流;用量仅打印,不拦截。

## 运维

- **加设备**:设备跑 `setup-device.sh` 拿公钥 → 管理员 `add-device.sh <id> "<公钥>"` → 热重载即生效。
- **吊销设备**:`add-device.sh --remove <id>`,立即生效,其它设备不受影响。
- **host key 轮换**:换掉 `ssh_host_ed25519_key` 重启 → 把新指纹带外发给各设备,设备重跑
  `setup-device.sh`(会更新 `known_hosts`)。
- **CA 轮换**:删掉 `ccgw_ca_key`(含 `.crt`)重启自动生成 → 设备重跑脚本重新取 CA。
  只影响 socket 形态。

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
- **真凭证只走环境变量。** 别把 token 写进提交的文件;含明文 token 的本地启动脚本(如 `gateway.sh`)
  与本地 `config.yaml` 都已在 `.gitignore` 中。
- **token 续期**:网关里只贴 access token 会几小时过期;稳妥做法是网关机器正常登录、由网关从
  keychain 读并自动刷新。

## License

[MIT](./LICENSE) · 仅供学习与个人自用,不用于、也不应用于绕过 Anthropic 服务条款。
