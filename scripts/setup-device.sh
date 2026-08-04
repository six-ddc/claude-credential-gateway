#!/usr/bin/env bash
# setup-device.sh —— 设备侧一次性接入脚本(unix socket 形态,复刻 claude ssh 的传输形态)。
#
#   ① 生成设备专用 ed25519 密钥(私钥只留本机,绝不外传)
#   ② 经管理通道把公钥登记进网关 config.yaml(幂等;网关热重载即生效)
#   ③ 取网关 host key 写 known_hosts 完成 pin;取网关 CA 证书供 TLS 校验
#   ④ 起 -N -L unix socket 转发隧道(无 shell,本机不开 TCP 端口)
#   ⑤ 验证链路(经 socket + TLS 打网关 /status)
#
# 用法:
#   1) 改下面的「必填」几项(或用环境变量覆盖,见每项说明)
#   2) ./scripts/setup-device.sh [device-id]      # device-id 默认 <hostname>-dev
#
# 前提:你对网关机有一个【管理通道】(能 ssh 上去改 config.yaml、读证书),
#      通常就是常规的 ssh root@网关机。它只在接入时用一次,跑 claude 时不需要。
set -euo pipefail

# ---- 必填:网关信息 -------------------------------------------------------
GATEWAY_HOST=${GATEWAY_HOST:-gateway.example.com}          # 网关机地址
GATEWAY_SSH_PORT=${GATEWAY_SSH_PORT:-2222}                 # 网关 ssh.addr 的端口
GATEWAY_ADMIN=${GATEWAY_ADMIN:-root@gateway.example.com}   # 管理通道(登记公钥/取证书用)
GATEWAY_DIR=${GATEWAY_DIR:-/opt/claude-credential-gateway} # 网关机上的部署目录

# ---- 一般不用改 ----------------------------------------------------------
# 须在网关 ssh.permit_targets 里。它只是白名单口令,网关并不真监听这个路径。
PERMIT_SOCKET=${PERMIT_SOCKET:-/run/ccgw.sock}
# 占位 token:网关不校验它,只是让 claude 肯启动(仿真凭证前缀避免客户端校验格式报错)。
PLACEHOLDER_TOKEN=${PLACEHOLDER_TOKEN:-sk-ant-oat01-placeholder}

DEVICE_ID=${1:-$(hostname -s | tr '[:upper:]' '[:lower:]')-dev}
# 密钥等设备凭证放家目录,不放仓库 —— 私钥永远不该进版本库。
CCGW_HOME=${CCGW_HOME:-$HOME/.ccgw}
KEY="$CCGW_HOME/ccgw_${DEVICE_ID}"
CA="$CCGW_HOME/ccgw_ca.crt"
KNOWN_HOSTS="$CCGW_HOME/known_hosts"
SOCK="$HOME/.ccgw-${DEVICE_ID}.sock"   # 放 $HOME:unix socket 路径有长度上限,别用深层临时目录

mkdir -p "$CCGW_HOME"
chmod 700 "$CCGW_HOME"

echo "== 设备 id: $DEVICE_ID"
echo "== 网关: $GATEWAY_HOST:$GATEWAY_SSH_PORT"

# ① 生成密钥(已存在则复用)
if [ ! -f "$KEY" ]; then
  ssh-keygen -q -t ed25519 -f "$KEY" -N "" -C "$DEVICE_ID"
  echo "== 已生成密钥: $KEY"
fi
PUB=$(cat "$KEY.pub")

# ② 登记公钥(幂等)。变量在【本地】展开后作为脚本文本发给远端,
#    避免 ssh 远程命令重新分词把公钥拆散。
ssh "$GATEWAY_ADMIN" bash -s <<EOF
set -e
cfg="$GATEWAY_DIR/config.yaml"
if grep -qF "$PUB" "\$cfg"; then
  echo "== 公钥已登记过,跳过"
else
  printf '    - id: %s\n      key: "%s"\n' "$DEVICE_ID" "$PUB" >> "\$cfg"
  echo "== 已登记公钥: $DEVICE_ID"
fi
EOF

# ③ pin host key(防 MITM)+ 取 TLS 终结 CA(是公开证书,不是密钥)
ssh "$GATEWAY_ADMIN" "cat $GATEWAY_DIR/ssh_host_ed25519_key.pub" \
  | awk -v h="[$GATEWAY_HOST]:$GATEWAY_SSH_PORT" '{print h, $1, $2}' > "$KNOWN_HOSTS"
echo "== host key 指纹: $(ssh-keygen -lf "$KNOWN_HOSTS" | awk '{print $2}')"

ssh "$GATEWAY_ADMIN" "cat $GATEWAY_DIR/ccgw_ca_key.crt" > "$CA"
echo "== 网关 CA: $CA ($(openssl x509 -in "$CA" -noout -subject | sed 's/^subject=//'))"

# ④ 起隧道(后台;重复运行前先清掉旧隧道)
pkill -f "ssh.*ccgw_${DEVICE_ID} " 2>/dev/null || true
rm -f "$SOCK"
ssh -f -N -L "$SOCK:$PERMIT_SOCKET" -p "$GATEWAY_SSH_PORT" -i "$KEY" \
  -o UserKnownHostsFile="$KNOWN_HOSTS" -o StrictHostKeyChecking=yes \
  -o IdentitiesOnly=yes -o ExitOnForwardFailure=yes \
  -o StreamLocalBindUnlink=yes -o ServerAliveInterval=30 \
  -o ControlMaster=no -o ControlPath=none \
  "$DEVICE_ID@$GATEWAY_HOST"
echo "== 隧道已建立: $SOCK → $GATEWAY_HOST:$GATEWAY_SSH_PORT → $PERMIT_SOCKET"

# ⑤ 验证链路
STATUS=$(curl -s -m 5 --unix-socket "$SOCK" --cacert "$CA" https://api.anthropic.com/status)
echo "== /status: $STATUS"

cat <<TIP

接下来这样跑 claude:
  unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN ANTHROPIC_BASE_URL
  export ANTHROPIC_UNIX_SOCKET=$SOCK
  export NODE_EXTRA_CA_CERTS=$CA
  export CLAUDE_CODE_OAUTH_TOKEN=$PLACEHOLDER_TOKEN
  claude

隧道断了重跑本脚本即可(公钥已登记,会直接复用)。
TIP
