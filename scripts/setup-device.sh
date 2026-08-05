#!/usr/bin/env bash
# setup-device.sh —— 设备侧接入脚本。【设备对网关机没有任何登录权限】,只会建隧道。
#
# 分两趟跑:
#   第一趟(还没登记):生成密钥 → 打印公钥 → 停下。把公钥和 <device-id> 交给网关管理员,
#                    管理员在网关机上跑 scripts/add-device.sh 登记,并把 host key 指纹回给你。
#   第二趟(已登记):  带上指纹重跑 → 核对指纹并 pin → 建隧道 → 经隧道自取 CA → 验证链路。
#
# 用法:
#   ./scripts/setup-device.sh laptop-1                       # 第一趟,拿公钥
#   GATEWAY_HOST_KEY_FP='SHA256:xxxx' ./scripts/setup-device.sh laptop-1   # 第二趟
#
# 为什么要带指纹:它是防 MITM 的信任锚,必须【带外】从管理员那里拿(当面/IM/邮件均可),
# 不能从待连接的网络里取 —— 那等于让攻击者自己给你发指纹。不带指纹也能跑(TOFU),
# 脚本会把实际指纹打出来要求你人工核对。
set -euo pipefail

# ---- 网关信息(改这里,或用同名环境变量覆盖)------------------------------
GATEWAY_HOST=${GATEWAY_HOST:-gateway.example.com}   # 网关机地址
GATEWAY_SSH_PORT=${GATEWAY_SSH_PORT:-2222}          # 网关 ssh.addr 的端口
GATEWAY_HOST_KEY_FP=${GATEWAY_HOST_KEY_FP:-}        # 管理员给的 host key 指纹(SHA256:...)

# ---- 一般不用改 ----------------------------------------------------------
# 这个目标须在网关 ssh.permit_targets 里。它只是白名单口令,网关并不真监听。
PERMIT_TCP=${PERMIT_TCP:-127.0.0.1:8788}
LOCAL_PROXY_PORT=${LOCAL_PROXY_PORT:-8788}          # 本机代理入口,给 HTTPS_PROXY 用
PLACEHOLDER_TOKEN=${PLACEHOLDER_TOKEN:-sk-ant-oat01-placeholder}
# 占位凭证声明的订阅档位。只影响 /usage 面板显示哪几条限额条,不影响能否取到数据。
SUBSCRIPTION_TYPE=${SUBSCRIPTION_TYPE:-max}

# 生成的包装命令名。不叫 claude(会和真命令递归),也不建议叫 cc —— /usr/bin/cc 是 C 编译器,
# 抢占它会让 make/cgo/npm 原生模块全部走岔。改名用 CMD_NAME=xxx 覆盖,脚本会做冲突检测。
CMD_NAME=${CMD_NAME:-ccgw}

# 设备端 Claude Code 版本下限 —— 代理形态下这是硬性要求,不是建议。
# v2.1.91(2026-04-02)~v2.1.196 期间,客户端在配置了非官方 API 端点时会读系统时区、
# 【提取代理主机名】,把比对结果隐写进系统提示词 "Today's date is ..." 那一行
# (日期分隔符 - / ,撇号在 U+0027/2019/02BC/02B9 之间切换)。官方 v2.1.197 已移除。
# 老的 socket 形态不设代理,不在触发面上;换成 HTTPS_PROXY 之后【每次调用都在】,
# 所以这里改成直接中止。确实要用旧版就显式设 ALLOW_OLD_CLAUDE=1 自担后果。
# 详见 docs/transport.md。
MIN_CLAUDE_VERSION=${MIN_CLAUDE_VERSION:-2.1.197}
ALLOW_OLD_CLAUDE=${ALLOW_OLD_CLAUDE:-}

DEVICE_ID=${1:-$(hostname -s | tr '[:upper:]' '[:lower:]')-dev}
# 设备凭证放家目录,不放仓库 —— 私钥永远不该进版本库。
CCGW_HOME=${CCGW_HOME:-$HOME/.ccgw}
KEY="$CCGW_HOME/ccgw_${DEVICE_ID}"
CA="$CCGW_HOME/ccgw_ca.crt"
KNOWN_HOSTS="$CCGW_HOME/known_hosts"
BIN_DIR="$CCGW_HOME/bin"
WRAPPER="$BIN_DIR/$CMD_NAME"
# 独立的 CLAUDE_CONFIG_DIR:占位凭证只放这儿,绝不碰你真的 ~/.claude/.credentials.json。
# (macOS 上 keychain 的 service name 会按 CLAUDE_CONFIG_DIR 的路径 hash 加后缀,
#  查不到条目就 fallback 到明文文件 —— 所以这一招在 macOS 和 Linux 上都成立。)
CLAUDE_HOME="$CCGW_HOME/claude-home"
REAL_CLAUDE_HOME="${REAL_CLAUDE_HOME:-$HOME/.claude}"

if [ "$CMD_NAME" = "claude" ]; then
  echo "✗ CMD_NAME 不能叫 claude —— 包装脚本内部要调真的 claude,同名会无限递归。" >&2
  exit 1
fi

mkdir -p "$CCGW_HOME" "$BIN_DIR"
chmod 700 "$CCGW_HOME"

# ver_lt A B —— A 是否严格小于 B。逐段比较 major.minor.patch;
# 不用 sort -V:BSD sort(macOS 自带)对它的支持随版本变,靠不住。
ver_lt() {
  if [ "$1" = "$2" ]; then return 1; fi
  local IFS=. i x y
  local -a a b
  read -r -a a <<<"$1"
  read -r -a b <<<"$2"
  for i in 0 1 2; do
    x=${a[i]:-0}; y=${b[i]:-0}
    x=${x%%[!0-9]*}; y=${y%%[!0-9]*}   # 削掉 "220 (Claude Code)" 之类的尾巴
    x=${x:-0}; y=${y:-0}
    if ((10#$x < 10#$y)); then return 0; fi
    if ((10#$x > 10#$y)); then return 1; fi
  done
  return 1
}

echo "== 设备 id: $DEVICE_ID"
echo "== 网关: $GATEWAY_HOST:$GATEWAY_SSH_PORT"

# ① 生成密钥(已存在则复用;私钥永不外传)
if [ ! -f "$KEY" ]; then
  ssh-keygen -q -t ed25519 -f "$KEY" -N "" -C "$DEVICE_ID"
  echo "== 已生成密钥: $KEY(私钥只留本机)"
fi

# ② 取网关 host key 并核对指纹 —— 这一步只读公开信息,不需要登录网关机
HK=$(mktemp); trap 'rm -f "$HK"' EXIT
if ! ssh-keyscan -p "$GATEWAY_SSH_PORT" -t ed25519 "$GATEWAY_HOST" 2>/dev/null > "$HK" || [ ! -s "$HK" ]; then
  echo "✗ 连不上 $GATEWAY_HOST:$GATEWAY_SSH_PORT(网关没起?端口没放行?)" >&2
  exit 1
fi
GOT_FP=$(ssh-keygen -lf "$HK" | awk '{print $2}')

if [ -n "$GATEWAY_HOST_KEY_FP" ]; then
  if [ "$GOT_FP" != "$GATEWAY_HOST_KEY_FP" ]; then
    echo "✗ host key 指纹不符 —— 可能是中间人,或网关轮换了 host key。已中止。" >&2
    echo "  期望: $GATEWAY_HOST_KEY_FP" >&2
    echo "  实际: $GOT_FP" >&2
    exit 1
  fi
  echo "== host key 指纹已核对: $GOT_FP"
else
  echo "⚠ 未提供 GATEWAY_HOST_KEY_FP,按 TOFU 接受。请与管理员人工核对:"
  echo "     $GOT_FP"
fi
# 只把核对过的那把写进 known_hosts,后续连接严格校验
awk -v h="[$GATEWAY_HOST]:$GATEWAY_SSH_PORT" '{print h, $2, $3}' "$HK" > "$KNOWN_HOSTS"

# ③ 建隧道。一个本地端口就够了 —— 它同时当代理入口和取 CA 的明文口
#   (网关按开头字节分辨:"CONNECT " 走代理协议,其余按普通 HTTP)。
pkill -f "ssh.*ccgw_${DEVICE_ID} " 2>/dev/null || true
if ! ssh -f -N \
  -L "$LOCAL_PROXY_PORT:$PERMIT_TCP" \
  -p "$GATEWAY_SSH_PORT" -i "$KEY" \
  -o UserKnownHostsFile="$KNOWN_HOSTS" -o StrictHostKeyChecking=yes \
  -o IdentitiesOnly=yes -o ExitOnForwardFailure=yes \
  -o ServerAliveInterval=30 \
  -o ControlMaster=no -o ControlPath=none \
  "$DEVICE_ID@$GATEWAY_HOST" 2>/dev/null
then
  cat >&2 <<EOF

✗ 隧道没建起来。最常见的原因是【这台设备的公钥还没在网关登记】。

  把下面这行公钥,连同设备 id "$DEVICE_ID",交给网关管理员:

$(cat "$KEY.pub")

  管理员在【网关机上】执行(不需要给你任何登录权限):
      ./scripts/add-device.sh $DEVICE_ID '<上面那行公钥>'
  然后把它打印的 host key 指纹回给你,你再这样重跑:
      GATEWAY_HOST_KEY_FP='<管理员给的指纹>' $0 $DEVICE_ID
EOF
  exit 1
fi
echo "== 隧道已建立: 127.0.0.1:$LOCAL_PROXY_PORT → $GATEWAY_HOST:$GATEWAY_SSH_PORT"

# ④ 经【已认证的隧道】自取 CA 证书。发普通 HTTP:SSH 已经认证并加密了这一跳,
#    所以拿到的 CA 是可信的,不需要任何带外分发,也不需要登录网关机。
if ! curl -sf -m 10 "http://127.0.0.1:$LOCAL_PROXY_PORT/ca" -o "$CA" || [ ! -s "$CA" ]; then
  echo "✗ 取 CA 失败(网关版本太旧?需要支持 GET /ca)" >&2
  exit 1
fi
echo "== 网关 CA: $CA ($(openssl x509 -in "$CA" -noout -subject | sed 's/^subject=//'))"

# ⑤ 验证链路:完整走一遍客户端要走的路 —— CONNECT + TLS 终结 + 校验网关 CA。
STATUS=$(curl -s -m 5 -x "http://127.0.0.1:$LOCAL_PROXY_PORT" --cacert "$CA" \
  https://api.anthropic.com/status) || {
  echo "✗ 经代理访问 /status 失败(网关版本太旧?需要支持 CONNECT)" >&2
  exit 1
}
echo "== /status: $STATUS"

# ⑥ 检查设备端 Claude Code 版本。代理形态下低版本会每次调用都被打标,所以这里中止。
if CLAUDE_BIN=$(command -v claude 2>/dev/null); then
  # || true 不能省:claude 装坏时 --version 会非零退出,set -euo pipefail 会就地中止整个脚本,
  # 而此刻隧道已经建好了 —— 版本读不出来不该让接入直接崩掉。
  CLAUDE_VER=$("$CLAUDE_BIN" --version 2>/dev/null | awk '{print $1}' || true)
  if [ -z "$CLAUDE_VER" ]; then
    echo "⚠ 读不出 claude 版本(claude --version 无输出?),跳过版本检查。"
  elif ver_lt "$CLAUDE_VER" "$MIN_CLAUDE_VERSION"; then
    if [ -n "$ALLOW_OLD_CLAUDE" ]; then
      echo "⚠ Claude Code $CLAUDE_VER < $MIN_CLAUDE_VERSION,已按 ALLOW_OLD_CLAUDE=1 放行(自担后果)。"
    else
      cat >&2 <<WARN
✗ Claude Code 版本过低: $CLAUDE_VER < $MIN_CLAUDE_VERSION。

  v2.1.91~v2.1.196 的客户端一旦发现配了代理,就会读系统时区、提取代理主机名,
  把比对结果隐写进系统提示词发给上游(v2.1.197 已移除)。老的 socket 形态不设代理、
  碰不到这条;本脚本改用 HTTPS_PROXY 之后【每次调用都会命中】,所以这里直接中止。

  升级: npm i -g @anthropic-ai/claude-code   (或按你的安装方式)
  确实要用旧版: ALLOW_OLD_CLAUDE=1 $0 $DEVICE_ID
WARN
      exit 1
    fi
  else
    echo "== Claude Code 版本: $CLAUDE_VER (>= $MIN_CLAUDE_VERSION,OK)"
  fi
else
  echo "⚠ 没找到 claude 命令,跳过版本检查。装好后请确认版本 >= $MIN_CLAUDE_VERSION。"
fi

# ⑦ 占位凭证。必须写成文件,不能用 CLAUDE_CODE_OAUTH_TOKEN 环境变量:
#    客户端走 env token 分支时会把 scopes 硬编码成 ['user:inference'],凭证文件根本
#    不读。而 /usage 要求 scopes 里有 'user:profile',拿不到就直接返回空、连请求都不发
#    (界面上表现为 "only available for subscription plans")。写文件才能自己定 scopes。
#
#    放独立的 CLAUDE_CONFIG_DIR 里,不动你真的 ~/.claude/.credentials.json。
mkdir -p "$CLAUDE_HOME"
chmod 700 "$CLAUDE_HOME"

# 真 ~/.claude 里与凭证无关的东西链过来,保住设置/记忆/历史/MCP 配置。
# 只链不拷:那边改了这边立刻跟着变。已存在的条目不动,反复跑本脚本是幂等的。
if [ -d "$REAL_CLAUDE_HOME" ]; then
  for item in settings.json CLAUDE.md commands agents skills plugins projects todos statsig; do
    src="$REAL_CLAUDE_HOME/$item"
    dst="$CLAUDE_HOME/$item"
    if [ -e "$src" ] && [ ! -e "$dst" ] && [ ! -L "$dst" ]; then
      ln -s "$src" "$dst"
    fi
  done
fi

# expiresAt 设到 2100 年、且不给 refreshToken:两条各自都能让客户端不去刷新。
# (刷新会拿占位 refresh token 去打 platform.claude.com,必然失败,还要重试拖慢启动。)
cat > "$CLAUDE_HOME/.credentials.json" <<CRED
{
  "claudeAiOauth": {
    "accessToken": "$PLACEHOLDER_TOKEN",
    "expiresAt": 4102444800000,
    "scopes": ["user:inference", "user:profile"],
    "subscriptionType": "$SUBSCRIPTION_TYPE"
  }
}
CRED
chmod 600 "$CLAUDE_HOME/.credentials.json"
echo "== 占位凭证: $CLAUDE_HOME/.credentials.json (scopes 含 user:profile,/usage 才肯发请求)"

# 换了 CLAUDE_CONFIG_DIR,onboarding 状态也跟着换了个地方记 —— 不给个初值的话,
# 哪怕你真 ~ 早就走过引导,第一次跑 ccgw 还会被引导拦一道。只在文件不存在时种。
if [ ! -f "$CLAUDE_HOME/.claude.json" ]; then
  printf '{"hasCompletedOnboarding":true,"theme":"dark"}\n' > "$CLAUDE_HOME/.claude.json"
  chmod 600 "$CLAUDE_HOME/.claude.json"
fi

# ⑧ 生成包装命令 —— 把那一堆 unset/export 收进一个可执行文件,
#    不碰 shell 配置、不影响真的 claude(它仍然直连官方)。
cat > "$WRAPPER" <<WRAP
#!/usr/bin/env bash
# 由 scripts/setup-device.sh 自动生成(设备 $DEVICE_ID) —— 请勿手改,重跑脚本会覆盖。
# 经 ccgw 网关跑 claude:走代理 + 信任网关 CA + 独立配置目录里的占位凭证。
set -euo pipefail

PROXY="http://127.0.0.1:$LOCAL_PROXY_PORT"
CA="$CA"
CLAUDE_HOME="$CLAUDE_HOME"

curl -sf -m 5 "\$PROXY/status" >/dev/null 2>&1 || {
  echo "✗ 隧道未就绪(\$PROXY 连不上)。重跑 setup-device.sh 建隧道。" >&2; exit 1; }
[ -s "\$CA" ] || { echo "✗ CA 缺失(\$CA)。重跑 setup-device.sh。" >&2; exit 1; }

# 这几个必须清掉,任何一个残留都会让 claude 绕开网关或改用 x-api-key 形状。
# 后两个尤其要清:设了它们客户端就走 env/fd 分支,scopes 被硬编码成只有
# user:inference、凭证文件根本不读,/usage 直接拿不到数据。
unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN ANTHROPIC_BASE_URL ANTHROPIC_CUSTOM_HEADERS
unset ANTHROPIC_UNIX_SOCKET CLAUDE_CODE_OAUTH_TOKEN CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR

# 代理同时覆盖两条 HTTP 栈:全局 axios(/usage、profile、bootstrap 等)和
# undici/fetch(SDK 的 /v1/messages)。两条都要覆盖,/usage 才拿得到额度。
export HTTPS_PROXY="\$PROXY" HTTP_PROXY="\$PROXY"
export https_proxy="\$PROXY" http_proxy="\$PROXY"
# 本机地址必须排除,否则本地跑的 MCP server / dev server 也会被绕去网关。
export NO_PROXY="localhost,127.0.0.1,::1" no_proxy="localhost,127.0.0.1,::1"
export NODE_EXTRA_CA_CERTS="\$CA"
export CLAUDE_CONFIG_DIR="\$CLAUDE_HOME"

# 这里【不】设 CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC:代理已经把 axios 收编,
# 遥测和 API 调用一样从网关出口走,没有绕过网关的旁路可掐。
exec claude "\$@"
WRAP
chmod 755 "$WRAPPER"
echo "== 已生成包装命令: $WRAPPER"

# 冲突检测:PATH 里已有同名命令的话,把它抢过来可能弄坏别的东西(典型:cc 是 C 编译器)
if EXISTING=$(command -v "$CMD_NAME" 2>/dev/null) && [ "$EXISTING" != "$WRAPPER" ]; then
  echo "⚠ PATH 里已存在同名命令 $CMD_NAME -> $EXISTING"
  echo "  把 $BIN_DIR 放在 PATH 前面会覆盖它。换个名字重跑: CMD_NAME=别的名字 $0 $DEVICE_ID"
fi

cat <<TIP

接下来把 $BIN_DIR 加进 PATH(二选一,写进 ~/.zshrc 或 ~/.bashrc):

  export PATH="$BIN_DIR:\$PATH"          # 推荐:脚本形态,子进程/脚本里也能用
  alias $CMD_NAME="$WRAPPER"             # 或者只加个别名(仅交互 shell 生效)

然后直接跑:

  $CMD_NAME                              # 等价于经网关的 claude
  $CMD_NAME -p "写个快排"                 # 参数原样透传

真的 claude 命令不受影响(仍然直连官方),两者可以并存。

隧道断了重跑本脚本即可(密钥、登记、包装命令都会复用/重建)。
TIP
