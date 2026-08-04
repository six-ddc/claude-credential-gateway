#!/usr/bin/env bash
# add-device.sh —— 【在网关机上、由管理员运行】登记一台可信设备。
#
# 设备侧只把公钥交给你(任意渠道,公钥不是机密);你在这里登记,再把打印出来的
# host key 指纹回给设备做带外核对。全程不需要给设备任何登录网关机的权限。
#
# 用法:
#   ./scripts/add-device.sh laptop-1 "ssh-ed25519 AAAAC3Nz... laptop-1"
#   ./scripts/add-device.sh --list                # 列出已登记设备 + 打印 host key 指纹
#   ./scripts/add-device.sh --remove laptop-1     # 吊销设备
#
# 改完立即生效:网关按 config.yaml 的 mtime 热重载公钥列表,无需重启。
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CONFIG=${GATEWAY_CONFIG:-$HERE/../config.yaml}
HOST_KEY=${GATEWAY_SSH_HOST_KEY:-$HERE/../ssh_host_ed25519_key}

die() { echo "✗ $*" >&2; exit 1; }

# 设备 id 会进 YAML、审计日志与正则,限制成安全字符集
valid_id() { [[ "$1" =~ ^[A-Za-z0-9._-]+$ ]]; }

print_fingerprint() {
  if [ -f "$HOST_KEY.pub" ]; then
    echo ""
    echo "把下面这个指纹带外发给设备(当面/IM/邮件均可),让它这样接入:"
    echo "    GATEWAY_HOST_KEY_FP='$(ssh-keygen -lf "$HOST_KEY.pub" | awk '{print $2}')' \\"
    echo "      ./scripts/setup-device.sh <device-id>"
  else
    echo "⚠ 找不到 $HOST_KEY.pub,无法打印指纹(网关还没启动过?)" >&2
  fi
}

# 原子写回:先写临时文件再替换,避免半截配置被网关热重载读到
replace_config() {
  local tmp="$CONFIG.tmp.$$"
  cat > "$tmp"
  chmod --reference="$CONFIG" "$tmp" 2>/dev/null || chmod 600 "$tmp"
  mv "$tmp" "$CONFIG"
}

[ -f "$CONFIG" ] || die "找不到配置 $CONFIG(可用 GATEWAY_CONFIG 指定)"

case "${1:-}" in
  --list)
    echo "已登记设备:"
    grep -E '^[[:space:]]+- id:' "$CONFIG" | sed -E 's/^[[:space:]]+- id:[[:space:]]*/  - /' || echo "  (无)"
    print_fingerprint
    exit 0
    ;;
  --remove)
    ID=${2:-}
    [ -n "$ID" ] || die "用法: $0 --remove <device-id>"
    valid_id "$ID" || die "设备 id 只允许字母数字与 . _ -"
    grep -qE "^[[:space:]]+- id:[[:space:]]*${ID}[[:space:]]*$" "$CONFIG" || die "没有登记过设备 $ID"
    # 删掉该 id 行与紧随其后的 key 行(ID 经环境变量传入,不拼进程序文本)
    ID="$ID" awk '
      skip { skip=0; next }
      $0 ~ "^[[:space:]]*- id:[[:space:]]*" ENVIRON["ID"] "[[:space:]]*$" { skip=1; next }
      { print }
    ' "$CONFIG" | replace_config
    echo "✓ 已吊销设备 $ID(热重载即生效,其它设备不受影响)"
    exit 0
    ;;
  ""|-h|--help)
    sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
    ;;
esac

ID=$1
PUBKEY=${2:-}
[ -n "$PUBKEY" ] || die "用法: $0 <device-id> \"<ssh-ed25519 AAAA... 公钥整行>\""
valid_id "$ID" || die "设备 id 只允许字母数字与 . _ -"

# 校验公钥格式,别把垃圾写进配置(网关解析失败会拒绝启动)
CHECK=$(mktemp); trap 'rm -f "$CHECK"' EXIT
printf '%s\n' "$PUBKEY" > "$CHECK"
ssh-keygen -lf "$CHECK" >/dev/null 2>&1 || die "公钥格式不对: $PUBKEY"
case "$PUBKEY" in *'"'*) die "公钥里不该有引号";; esac

grep -qE '^[[:space:]]*authorized_keys:' "$CONFIG" \
  || die "$CONFIG 的 ssh: 块里没有 authorized_keys:,请先按 config.example.yaml 补上这一行"

if grep -qF "$PUBKEY" "$CONFIG"; then
  echo "= 这把公钥已登记过,跳过"
else
  grep -qE "^[[:space:]]+- id:[[:space:]]*${ID}[[:space:]]*$" "$CONFIG" \
    && die "设备 id $ID 已被另一把公钥占用;换个 id,或先 --remove $ID"
  # 插到 authorized_keys: 那一行之后(不假设它在文件末尾);
  # id 与公钥都经环境变量传入,公钥里的 / + = 不会破坏程序。
  ID="$ID" PUBKEY="$PUBKEY" awk '
    !added && $0 ~ /^[[:space:]]*authorized_keys:/ {
      sub(/\[\][[:space:]]*$/, "")           # authorized_keys: [] → authorized_keys:
      sub(/[[:space:]]+$/, "")
      print
      printf "    - id: %s\n      key: \"%s\"\n", ENVIRON["ID"], ENVIRON["PUBKEY"]
      added = 1
      next
    }
    { print }
  ' "$CONFIG" | replace_config
  grep -qF "$PUBKEY" "$CONFIG" || die "写入失败,请检查 $CONFIG 的 authorized_keys 格式"
  echo "✓ 已登记设备 $ID(热重载即生效)"
fi

print_fingerprint
