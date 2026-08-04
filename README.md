# claude-credential-gateway

一个**凭证隔离网关**(Go 实现):让你在自己的多台电脑(包括公共/不完全可信的电脑)上复用同一个
Claude 订阅,而**不在那些电脑上暴露真 token**。真 OAuth token 只留在一台你信任的网关机器上,不可
信电脑只放占位 token + 一个可吊销的设备 key,真请求经网关时被注入真凭证。

**唯一对外入口是一个自建的转发-only SSH 端口**(复刻 `claude ssh` 的传输形态):公钥认证、
只能转发到网关自己、无 shell / 无 exec / 禁 `-R`,host key pin 防 MITM。网关**不监听任何
HTTP 端口**:转发 channel 在进程内直连 HTTP handler,设备一律经 SSH 隧道接入。方案详见
[docs/ssh-forward-gateway.md](./docs/ssh-forward-gateway.md)。

同时,网关会**打印每个请求的 model 与 token 使用量**(input / output / cache),用 `gjson` 从上游响应
高性能解析,支持 SSE 流式与普通 JSON。

设计借鉴 Claude Code 自带的 `claude ssh` 凭证隔离机制(本地持凭证、远端只拿占位、代理注入)。

## 技术栈

- Go 1.22+,标准 `go mod` 工具链
- [`gopkg.in/yaml.v3`](https://pkg.go.dev/gopkg.in/yaml.v3) —— YAML 配置解析
- [`github.com/tidwall/gjson`](https://github.com/tidwall/gjson) —— 高性能 token 用量解析
- [`github.com/andybalholm/brotli`](https://github.com/andybalholm/brotli) —— br 响应解压(打印/解析用)
- [`golang.org/x/crypto/ssh`](https://pkg.go.dev/golang.org/x/crypto/ssh) —— 转发-only SSH 层(唯一对外入口)

## 构建与运行

```bash
go build -o claude-credential-gateway .   # 或 go run .
cp config.example.yaml config.yaml        # config.yaml 已在 .gitignore,改它不污染版本库
```

## 配置

配置是 YAML 文件 [`config.example.yaml`](./config.example.yaml),真凭证建议用**环境变量注入**
(env 覆盖 YAML),这样模板可以安全提交:

```yaml
upstream:
  base: https://api.anthropic.com
  oauth: ""               # 你订阅的真 access token;留空则用 CLAUDE_GATEWAY_UPSTREAM_OAUTH 注入
ssh:                      # 唯一对外入口:转发-only SSH;设备身份的单一数据源
  addr: ":2222"                       # 唯一对外端口
  host_key: ./ssh_host_ed25519_key    # 服务端私钥;不存在则首启自动生成
  ca_key: ./ccgw_ca_key               # TLS 终结 CA;自动生成,另导出 .crt 供设备信任
  permit_targets:                     # 客户端 -L 声明的目标须在其中(网关并不真监听它们)
    - 127.0.0.1:8788
    - unix:/run/ccgw.sock
  authorized_keys:                    # 每台设备一把公钥;改完重读即生效,无需重启
    - id: laptop-1
      key: "ssh-ed25519 AAAA... laptop-1"
```

配置路径优先级:`GATEWAY_CONFIG` 指定 > 本地 `config.yaml` > `config.example.yaml`(模板,并提示拷贝)。

可用环境变量覆盖:`GATEWAY_UPSTREAM_BASE`、`CLAUDE_GATEWAY_UPSTREAM_OAUTH`、
`GATEWAY_SSH_ADDR`、`GATEWAY_SSH_HOST_KEY`、`GATEWAY_SSH_CA_KEY`、
`GATEWAY_SSH_PERMIT_TARGETS`(逗号分隔)、`GATEWAY_SSH_AUTHORIZED_KEYS`(JSON `[{id,key}]`)。

## 快速开始

**① 网关机器**(你信任的常驻机):在 `config.yaml` 登记设备公钥(见下),然后:
```bash
export CLAUDE_GATEWAY_UPSTREAM_OAUTH='<你的订阅 access token>'
./claude-credential-gateway
# 启动日志会打印 SSH host key 指纹,发给设备首连时比对
```

**② 设备**(每台一把专用密钥,私钥不外传;公钥整行交给管理员登记):
```bash
ssh-keygen -t ed25519 -f ~/keys/ccgw_laptop-1 -N "" -C "laptop-1"
cat ~/keys/ccgw_laptop-1.pub   # ← 把这行交给网关管理员,id 填 laptop-1
```

> 设备**不需要、也不应该有**登录网关机的权限 —— 有的话它直接读 `config.yaml` 就把真
> token 拿走了,凭证隔离当场失效。登记动作由管理员在网关侧完成(见下文脚本)。

**③ 起隧道 + 跑 claude**(首连核对 host key 指纹,之后指纹变化 SSH 直接拦,防 MITM):
```bash
ssh -N -L 8788:127.0.0.1:8788 -p 2222 -i ~/keys/ccgw_laptop-1 laptop-1@网关机 &
unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN
export ANTHROPIC_BASE_URL=http://127.0.0.1:8788
export CLAUDE_CODE_OAUTH_TOKEN='sk-ant-oat01-placeholder'  # 任意占位,只为让 claude 肯启动
claude
```

> 想更严一点,可以改用 **unix socket 形态**(复刻 `claude ssh` 的传输形态):本机不开 TCP 端口,
> socket 文件 `0600` 只有你自己能连。见下节。

> 门禁与身份都是 SSH 公钥:转发 channel 在网关进程内直连 HTTP handler,每个请求天然携带
> 设备 id(审计用),伪造不了。占位 token 网关不校验、只覆盖,所有设备可以填同一个假值,
> 建议仿真凭证前缀(`sk-ant-oat01-...`)以免客户端校验格式报错。
>
> **占位凭证不能省**:`claude` 自己要求手里有凭证才肯启动,两个都不设会停在
> `Not logged in · Please run /login`。`CLAUDE_CODE_OAUTH_TOKEN` 与 `ANTHROPIC_API_KEY`
> 设哪个都能跑(网关会把客户端的 `x-api-key` 剥掉再注入真凭证),但**建议用前者** ——
> 它让客户端走订阅分支、带上 `oauth-2025` beta 头,与网关注入的订阅 token 形状一致,
> 这也是官方 `claude ssh` 的做法。
> 吊销设备:从 `ssh.authorized_keys` 删掉对应项,立即生效、其它设备不受影响。
> 网关不监听任何 HTTP 端口,真 token 只为隧道流量注入 —— 网关机上其它进程也偷用不了。
> 限额快照可在设备上经隧道查:`curl http://127.0.0.1:8788/status`。

### ⚠ 首次初始化:绕过 onboarding(否则会逼你登录)

**全新机器、或 `claude logout` 之后,光设 `CLAUDE_CODE_OAUTH_TOKEN` 不够用** —— Claude Code 检测到
没完成 onboarding 会强制进入引导流程,而里面的 OAuth 登录步骤**不会因为设了 token 就被跳过**(只有批
准 API key 才跳)。表现:明明设了占位 token,`claude` 还是要你去浏览器登录账号。

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

之后再 `export CLAUDE_CODE_OAUTH_TOKEN=...` + `export ANTHROPIC_BASE_URL=...` 跑 `claude`,就能直接用、
不再要求登录账号。

## unix socket 形态(`ANTHROPIC_UNIX_SOCKET`)

Claude Code 认一个 `ANTHROPIC_UNIX_SOCKET` 环境变量 —— 这正是官方 `claude ssh` 用的传输形态。
设了它之后,客户端只把**传输层**换成 unix socket,**目标 URL 仍是 `https://api.anthropic.com`,
照常发起完整 TLS 握手**。所以网关必须自己终结 TLS 才能读到明文 HTTP 去替换 `Authorization`:
网关首启会自动生成一把 CA(`ccgw_ca_key`),用它现签 `api.anthropic.com` 的证书;设备端用
`NODE_EXTRA_CA_CERTS` 信任这把 CA 即可。

网关**同时**支持两种形态,靠首字节嗅探自动区分(TLS 记录以 `0x16` 开头),无需任何配置开关。

**脚本接入**:分设备侧与管理员侧两个脚本 —— **设备对网关机没有任何登录权限**,
它能做的只有建隧道。登记谁由管理员在网关上决定。

设备侧([`scripts/setup-device.sh`](./scripts/setup-device.sh)),第一趟拿公钥:
```bash
GATEWAY_HOST=你的网关 ./scripts/setup-device.sh laptop-1
# 隧道会失败(公钥还没登记),脚本打印出本机公钥,把它和 device-id 交给管理员
```

管理员侧([`scripts/add-device.sh`](./scripts/add-device.sh)),**在网关机上**跑:
```bash
./scripts/add-device.sh laptop-1 "ssh-ed25519 AAAA... laptop-1"   # 登记,热重载即生效
# 它会打印 host key 指纹,带外回给设备
./scripts/add-device.sh --list            # 看已登记设备 + 指纹
./scripts/add-device.sh --remove laptop-1 # 吊销
```

设备侧第二趟,带上指纹:
```bash
GATEWAY_HOST=你的网关 GATEWAY_HOST_KEY_FP='SHA256:xxxx' \
  ./scripts/setup-device.sh laptop-1
```

> 指纹必须**带外**拿(当面/IM/邮件),它是防 MITM 的信任锚 —— 从待连接的网络里取指纹等于
> 让攻击者自己给你发指纹。不带指纹也能跑(TOFU),脚本会打印实际指纹要求你人工核对。
>
> **CA 证书不需要带外分发**:隧道建起来之后,SSH 已经完成认证与加密,脚本经隧道
> `GET /ca` 自取即可。设备密钥与 CA 存 `~/.ccgw/`(不进仓库)。

手动做的话,设备侧相对 Level 1 改三处:
```bash
scp -P 2222 ... 网关机:/data/.../ccgw_ca_key.crt ~/keys/    # ① 取网关 CA(公开,不是密钥)
ssh -N -L $HOME/.ccgw.sock:/run/ccgw.sock -p 2222 -i ~/keys/ccgw_laptop-1 laptop-1@网关机 &   # ② socket 转发

unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN ANTHROPIC_BASE_URL
export ANTHROPIC_UNIX_SOCKET=$HOME/.ccgw.sock                # ③ 不再需要 ANTHROPIC_BASE_URL
export NODE_EXTRA_CA_CERTS=~/keys/ccgw_ca_key.crt
export CLAUDE_CODE_OAUTH_TOKEN='sk-ant-oat01-placeholder'
claude
```

> `-L` 左边是本机 socket 路径,右边 `/run/ccgw.sock` 必须在网关 `ssh.permit_targets` 里
> (它只是白名单口令,网关并不真监听这个路径)。加 `-o StreamLocalBindUnlink=yes` 可自动清理旧 socket。
>
> **CA 私钥 `ccgw_ca_key` 是机密**:拿到它就能伪造 `api.anthropic.com` 证书骗过任何信任该 CA 的设备。
> 它只该待在网关机上(已 gitignore、权限 0600);分发给设备的是 `.crt`,那个不是密钥。

## Token 用量日志

每个成功请求,网关都会打印一行(从**上游响应**解析):

```
[usage] user=laptop-1 model=claude-opus-4-8 input=1234 output=567 cache_create=0 cache_read=8900 total=10701
```

字段对应 Anthropic API 的 `usage`:`input` = `input_tokens`,`output` = `output_tokens`(流式取最后一个
`message_delta` 的累计值),`cache_create` / `cache_read` 为缓存写/读 token。

> 网关不做任何配额/限流;用量仅打印,不拦截。

## 安全与合规边界

- **仅限本人、自己的设备、低并发自用。** 把设备 key 发给别人就成了订阅共享,违反 Anthropic
  服务条款,且会被账号级检测(同一 `account_uuid` + 单 IP + 高并发)命中。
- **网关保护的是 token,不是会话内容。** 不可信电脑仍能截屏/键盘记录你的 prompt 与输出。
  若那台机器真的敌对,优先用 `claude ssh <网关机器>`——让 Claude 跑在你的机器上,什么都不落地。
- **网关须是你信任且可控的机器**。唯一对外面是转发-only SSH:公钥即门禁,内部 HTTP 不见公网。
- **真凭证只走环境变量。** 别把 token 写进提交的文件;含明文 token 的本地启动脚本(如 `gateway.sh`)
  与本地 `config.yaml` 都已在 `.gitignore` 中。
- **token 续期**:网关里只贴 access token 会几小时过期;稳妥做法是网关机器正常登录、由网关从
  keychain 读并自动刷新。

## License

[MIT](./LICENSE) · 仅供学习与个人自用,不用于、也不应用于绕过 Anthropic 服务条款。
