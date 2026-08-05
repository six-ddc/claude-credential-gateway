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
# 这两个目标须在网关 ssh.permit_targets 里。它们只是白名单口令,网关并不真监听。
PERMIT_TCP=${PERMIT_TCP:-127.0.0.1:8788}
PERMIT_SOCKET=${PERMIT_SOCKET:-/run/ccgw.sock}
LOCAL_HTTP_PORT=${LOCAL_HTTP_PORT:-8788}            # 本机明文入口(取 CA / 调试用)
PLACEHOLDER_TOKEN=${PLACEHOLDER_TOKEN:-sk-ant-oat01-placeholder}

DEVICE_ID=${1:-$(hostname -s | tr '[:upper:]' '[:lower:]')-dev}
# 设备凭证放家目录,不放仓库 —— 私钥永远不该进版本库。
CCGW_HOME=${CCGW_HOME:-$HOME/.ccgw}
KEY="$CCGW_HOME/ccgw_${DEVICE_ID}"
CA="$CCGW_HOME/ccgw_ca.crt"
KNOWN_HOSTS="$CCGW_HOME/known_hosts"
SOCK="$HOME/.ccgw-${DEVICE_ID}.sock"   # 放 $HOME:unix socket 路径有长度上限

mkdir -p "$CCGW_HOME"
chmod 700 "$CCGW_HOME"

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

# ③ 建隧道。同时开两个转发:明文口(取 CA / 调试)+ unix socket(跑 claude)
pkill -f "ssh.*ccgw_${DEVICE_ID} " 2>/dev/null || true
rm -f "$SOCK"
if ! ssh -f -N \
  -L "$LOCAL_HTTP_PORT:$PERMIT_TCP" \
  -L "$SOCK:$PERMIT_SOCKET" \
  -p "$GATEWAY_SSH_PORT" -i "$KEY" \
  -o UserKnownHostsFile="$KNOWN_HOSTS" -o StrictHostKeyChecking=yes \
  -o IdentitiesOnly=yes -o ExitOnForwardFailure=yes \
  -o StreamLocalBindUnlink=yes -o ServerAliveInterval=30 \
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
echo "== 隧道已建立: 127.0.0.1:$LOCAL_HTTP_PORT(明文)、$SOCK(TLS)→ $GATEWAY_HOST:$GATEWAY_SSH_PORT"

# ④ 经【已认证的隧道】自取 CA 证书。走明文口:SSH 已经认证并加密了这一跳,
#    所以拿到的 CA 是可信的,不需要任何带外分发,也不需要登录网关机。
if ! curl -sf -m 10 "http://127.0.0.1:$LOCAL_HTTP_PORT/ca" -o "$CA" || [ ! -s "$CA" ]; then
  echo "✗ 取 CA 失败(网关版本太旧?需要支持 GET /ca)" >&2
  exit 1
fi
echo "== 网关 CA: $CA ($(openssl x509 -in "$CA" -noout -subject | sed 's/^subject=//'))"

# ⑤ 验证链路:经 socket + TLS 打 /status
STATUS=$(curl -s -m 5 --unix-socket "$SOCK" --cacert "$CA" https://api.anthropic.com/status)
echo "== /status: $STATUS"

cat <<TIP

接下来这样跑 claude:
  unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN ANTHROPIC_BASE_URL
  export ANTHROPIC_UNIX_SOCKET=$SOCK
  export NODE_EXTRA_CA_CERTS=$CA
  export CLAUDE_CODE_OAUTH_TOKEN=$PLACEHOLDER_TOKEN
  export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1   # 遥测/GrowthBook 等旁路流量不走网关,
  claude                                              # 会从本机真实 IP 直连;这个开关让它们根本不发

隧道断了重跑本脚本即可(密钥与登记都已就绪)。
TIP
