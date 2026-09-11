# 从旧版 `ssh -L` 接入迁移到分流代理

这篇只写给**还在用旧版接入方式**的设备和管理员。新接入统一看
[device-setup.md](./device-setup.md)，本文不重复那边已经讲清楚的东西。

旧版的设备侧只有一条 `ssh -f -N -L 8788:127.0.0.1:8788 <device>@网关` 隧道，`HTTPS_PROXY`
直接指向这个本地端口，于是设备的全部 HTTPS 流量都原样怼进这条隧道；网关那边一直是两份名单——
解密注入 `api.anthropic.com`，`tunnelHosts` 里的其它 Claude 相关主机纯字节盲转发，两者之外
403，这一点新版没有变。现在设备侧多了一个新的常驻进程——分流代理（`ccgw-device`），它先在设备
本机按目标主机分流：内置名单（`api.anthropic.com` 加 `tunnelHosts`，和网关同一份，不是
命令行参数）里的主机才转发进 SSH 隧道，名单外的主机（`github.com`、第三方 MCP server 这类）
直接从设备本机连出去，不用再送到网关碰一鼻子灰。旧的隧道方式和网关新版不兼容,升级完必须跟着换。

---

## 怎么判断自己是不是旧版

看下面任意一条都算数：

- `ps` 里能看到一个 `ssh -f -N -L ... ccgw_<device-id> ...` 进程,而不是 `ccgw-device`。
- 你的 `~/.ccgw/bin/ccgw` 包装命令里,`HTTPS_PROXY` 是直接指向那条隧道的本地端口
  (脚本自己起的 `ssh -L`),没有单独的 `ccgw-device` 控制脚本。

两条占一条就是旧版。

**旧版接入新网关不会当场报错**——`api.anthropic.com` 和 `tunnelHosts` 里的主机该怎么通还是
怎么通,网关一直是这两份名单,升级不改这一点。值得迁移的理由(细节见下面「日常有什么不一样」)是
`tunnelHosts` 名单外的主机(`github.com`、`mcp.figma.com` 这类第三方 MCP server)不用再挨网关
的 403、分流代理断线能自己接上;而且**网关重启会把旧的 `ssh -L` 隧道一并断掉**,升级网关这一步
就得重新接入,不如趁这次换成分流代理。

---

## 管理员这边要做的事

```bash
git pull
make build device-bins   # 编译网关本体,顺带把设备端二进制编译进 dist/device/<os>/<arch>
```

重启网关。`ssh.permit_targets`、`ssh.authorized_keys` 都不用改——设备台账、白名单目标和
之前完全一样，分流代理开的 SSH channel 用的还是同一个 `permit_targets` 项。唯一新增的是
`ssh.device_bin_dir`（不配就是默认值 `./dist/device`，`make device-bins` 的产出目录正好对上，
一般不用管）。

---

## 设备这边要做的事

**先把占着本地端口的旧隧道进程杀掉**，不然新的分流代理起不来（监听同一个端口）：

```bash
pkill -f "ssh.*ccgw_laptop-1 "   # 把 laptop-1 换成你自己的设备 id
```

然后拉最新的接入脚本，带上指纹重跑**第二趟**（不是第一趟——公钥已经登记过，不用重新走注册流程）：

```bash
git pull   # 或者只更新 scripts/setup-device.sh 这一个文件

GATEWAY_HOST=gateway.example.com \
GATEWAY_HOST_KEY_FP='SHA256:...(还是原来那个指纹)' \
  ./scripts/setup-device.sh laptop-1
```

设备 id 和指纹都用原来的——密钥、`known_hosts`、网关那边的注册信息全部复用，不需要管理员
重新操作。脚本会经 SSH 取回新的分流代理二进制、拉起它、重新取一份 CA、重新生成
`~/.ccgw/bin/ccgw` 包装命令。

跑完用这两条确认一下：

```bash
ccgw-device status
ccgw -p "说一句话确认代理链路正常"
```

**顺便清掉任何你之前为了绕开旧版限制加的 `NO_PROXY` 补丁**（比如把 `github.com`、
`mcp.figma.com` 之类塞进 `NO_PROXY` 让它们跳过隧道走直连）——现在这些主机本来就由
分流代理直接从本机连出去，不需要再手工排除。

---

## 日常有什么不一样

- **只有一个进程**：以前是一条 `ssh -L` 隧道，现在是常驻的分流代理 `ccgw-device`，多了
  `start|stop|status|log` 几个子命令可以直接管它。
- **断线会自己接上**：旧的 `ssh -L` 断了不会自动重连，得重跑脚本。新的分流代理自己维护到
  网关的连接，断了在下一个请求时按需重拨，不需要你干预；进程本身没了才需要 `ccgw-device start`
  或者跑一次 `ccgw`（它会自动检测并拉起）。
- **名单外的主机直接从设备出去**：WebFetch 抓的网页、第三方 MCP server、`github.com` 这类跟
  Claude 无关的主机不再挤过网关，直接由分流代理从设备本机连出去；`tunnelHosts` 里的 Claude
  相关主机（账号认证、包源、MCP connector、遥测……）还是照旧经网关盲转发，网关继续维护那份
  名单。
