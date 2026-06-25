# claude-credential-gateway

一个**凭证隔离网关**(Go 实现):让你在自己的多台电脑(包括公共/不完全可信的电脑)上复用同一个
Claude 订阅,而**不在那些电脑上暴露真 token**。真 OAuth token 只留在一台你信任的网关机器上,不可
信电脑只放占位 token + 一个可吊销的设备 key,真请求经网关时被注入真凭证。

同时,网关会**打印每个请求的 model 与 token 使用量**(input / output / cache),用 `gjson` 从上游响应
高性能解析,支持 SSE 流式与普通 JSON。

设计借鉴 Claude Code 自带的 `claude ssh` 凭证隔离机制(本地持凭证、远端只拿占位、代理注入)。

## 技术栈

- Go 1.22+,标准 `go mod` 工具链
- [`gopkg.in/yaml.v3`](https://pkg.go.dev/gopkg.in/yaml.v3) —— YAML 配置解析
- [`github.com/tidwall/gjson`](https://github.com/tidwall/gjson) —— 高性能 token 用量解析
- [`github.com/andybalholm/brotli`](https://github.com/andybalholm/brotli) —— br 响应解压(打印/解析用)

## 构建与运行

```bash
go build -o claude-credential-gateway .   # 或 go run .
cp config.example.yaml config.yaml        # config.yaml 已在 .gitignore,改它不污染版本库
```

## 配置

配置是 YAML 文件 [`config.example.yaml`](./config.example.yaml),真凭证建议用**环境变量注入**
(env 覆盖 YAML),这样模板可以安全提交:

```yaml
host: 127.0.0.1
port: 8788
upstream:
  base: https://api.anthropic.com
  oauth: ""               # 你订阅的真 access token;留空则用 CLAUDE_GATEWAY_UPSTREAM_OAUTH 注入
users:
  sk-ant-oat01-alice-REPLACE-ME: { id: alice }
```

配置路径优先级:`GATEWAY_CONFIG` 指定 > 本地 `config.yaml` > `config.example.yaml`(模板,并提示拷贝)。

可用环境变量覆盖:`GATEWAY_HOST`、`GATEWAY_PORT`、`GATEWAY_UPSTREAM_BASE`、
`CLAUDE_GATEWAY_UPSTREAM_OAUTH`、`GATEWAY_USERS`(JSON)。

## 快速开始

网关机器(你信任的常驻机):
```bash
export CLAUDE_GATEWAY_UPSTREAM_OAUTH='<你的订阅 access token>'
export GATEWAY_HOST=0.0.0.0
export GATEWAY_USERS='{"sk-ant-oat01-laptop-1-REPLACE-ME":{"id":"laptop-1"}}'
./claude-credential-gateway       # 生产前面挂 TLS + VPN/IP allowlist
```

不可信电脑(只放占位 token,不放真 token)—— 纯原生 Claude Code,无需自定义头:
```bash
unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN
export CLAUDE_CODE_OAUTH_TOKEN='sk-ant-oat01-laptop-1-REPLACE-ME'  # 该设备的占位,即网关里的设备 key
export ANTHROPIC_BASE_URL='https://你的网关'
claude
```

> 占位 token 本身就是设备 key:网关从 `Authorization: Bearer` 里读它识别设备,再覆盖成真凭证。
> 每台设备用**不同的**占位以便区分审计;占位最好仿真凭证前缀,避免客户端校验 token 格式时报错。

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
- **网关须是你信任且可控的机器**,暴露时加 TLS + 设备 key 鉴权 + VPN/allowlist。
- **真凭证只走环境变量。** 别把 token 写进提交的文件;含明文 token 的本地启动脚本(如 `gateway.sh`)
  与本地 `config.yaml` 都已在 `.gitignore` 中。
- **token 续期**:网关里只贴 access token 会几小时过期;稳妥做法是网关机器正常登录、由网关从
  keychain 读并自动刷新。

## License

[MIT](./LICENSE) · 仅供学习与个人自用,不用于、也不应用于绕过 Anthropic 服务条款。
