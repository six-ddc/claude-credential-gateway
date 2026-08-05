// proxy.go 实现 HTTP 正向代理形态(CONNECT),这是设备接入网关的传输层。
//
// 为什么是代理而不是 unix socket:客户端设 ANTHROPIC_UNIX_SOCKET 时,只有 Anthropic
// SDK 那一条 fetch 路径会走 socket(utils/proxy.ts 的 getProxyFetchOptions 只在
// forAnthropicAPI 时返回 {unix: path},而全仓只有 services/api/client.ts 传了这个参数)。
// /usage、/api/oauth/profile、bootstrap 等一律走全局 axios,直连真实的 api.anthropic.com,
// 根本进不了隧道。
//
// HTTPS_PROXY 则两条栈都覆盖:configureGlobalAgents() 既给全局 axios 装 interceptor,
// 又 setGlobalDispatcher 装 undici 的 EnvHttpProxyAgent。这也是官方文档化的受支持配置
// (Enterprise network configuration / LLM gateway 两页)。
//
// 代价是网关要说 HTTP 代理协议:客户端先发 CONNECT api.anthropic.com:443,
// 网关回 200 之后才在这条连接上做 TLS 握手。TLS 终结本身照做(要解密才能换
// Authorization),只是握手时机在 CONNECT 之后。
package main

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// 两份主机名单都写死在代码里,不做成配置项:
//
//   - 「真凭证送给谁」不该是部署时能随手改的东西;
//   - 「设备能出到哪儿」也一样,改宽了就等于把网关变成通用出口代理。
//
// 需要放行别的主机(WebFetch 抓的站点、自建 remote MCP server)就改这里、重新编译,
// 让它进代码评审,而不是躺在某台机器的 YAML 里。
//
// tunnelHosts 是 var 而非 const 切片,仅因为测试要临时替换它。
var tunnelHosts = []string{
	// 账号、文档、下载
	"claude.ai",                 // 账号认证
	"claude.com",                // 预置文档查询(登录页会重定向到 claude.ai)
	"code.claude.com",           // claude-code-guide 与预置 WebFetch 的文档查询
	"platform.claude.com",       // OAuth token 的交换 / 刷新 / 吊销
	"downloads.claude.ai",       // 插件下载、原生安装器与自动更新
	"raw.githubusercontent.com", // /release-notes 的 changelog
	// 包源(按安装方式二选一,留着不碍事)
	"registry.npmjs.org", // npm / bun 安装方式
	"formulae.brew.sh",   // Homebrew 安装方式的版本检查
	// MCP 与浏览器扩展
	"mcp-proxy.anthropic.com",      // claude.ai 侧 MCP connector(claude.ai 账号默认开启)
	"bridge.claudeusercontent.com", // Claude in Chrome 的 WebSocket 桥
	// 遥测与错误上报(没关 telemetry,这两个要通)
	"http-intake.logs.us5.datadoghq.com",
	"browser-intake-us5-datadoghq.com",
}

// 解密并注入真凭证的主机只有一个,就是 tlsterm.go 里的 forgedHost:客户端无论上游配到
// 哪儿,URL 里的主机名始终是 api.anthropic.com,要解密就得冒充它。官方表里挂在这个域下的
// 「WebFetch 域名安全检查、特性开关拉取、遥测事件上报」因此走的都是注入路径。
//
// storage.googleapis.com 刻意不在 tunnelHosts 里:多租户通用存储主机,放行等于开一条很宽的
// 出口;而官方文档写明这个用途在它被挡时会回落到 api.anthropic.com,代价只是 /plugin 里
// 看不到安装数与插件元数据。
func isMITMHost(hostname string) bool { return strings.EqualFold(hostname, forgedHost) }

// dialTimeout 是盲转发拨号上游的上限。
const dialTimeout = 15 * time.Second

// connectEstablished 是 CONNECT 的成功应答。之后这条连接上跑的就不再是 HTTP 了。
const connectEstablished = "HTTP/1.1 200 Connection Established\r\n\r\n"

// hostMatches 判断 host 是否命中 pattern。支持三种写法:
//
//	"*"              任意主机
//	"*.example.com"  子域(不含 example.com 自身)
//	"example.com"    精确匹配
func hostMatches(pattern, host string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "*" {
		return true
	}
	if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
		return strings.HasSuffix(host, "."+suffix)
	}
	return strings.EqualFold(pattern, host)
}

func hostInList(list []string, host string) bool {
	for _, p := range list {
		if hostMatches(p, host) {
			return true
		}
	}
	return false
}

// hostnameOf 剥掉 host:port 里的端口。没有端口就原样返回。
func hostnameOf(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

// withPort 给缺端口的 host 补上默认端口(CONNECT 理论上总带端口,但别指望客户端)。
func withPort(hostport, defPort string) string {
	if _, _, err := net.SplitHostPort(hostport); err == nil {
		return hostport
	}
	return net.JoinHostPort(hostport, defPort)
}

// handleConnect 处理一条已经读出 CONNECT 请求的隧道连接。放行有两种方式,不是
// 「白名单 vs 黑名单」而是「两种不同的处理办法」:
//
//   - 命中注入主机(api.anthropic.com):回 200 后就地 TLS 终结,解密出来的请求塞回
//     HTTP Server,走注入+转发流程。它只能走这条 —— 盲转发不解密,就没法替换
//     Authorization,而设备手上只有占位 token,那样每个请求都会 401;
//   - 命中 tunnelHosts:回 200 后纯 TCP 对拷,不解密、也不碰凭证(账号认证、文档查询、
//     包源、MCP connector、Datadog 遥测走这条)。
//
// 两种都不命中才 403。
func (s *sshServer) handleConnect(c net.Conn, br *bufio.Reader, req *http.Request, device string) {
	target := req.URL.Host
	if target == "" {
		target = req.Host
	}
	hostname := hostnameOf(target)

	mitm := isMITMHost(hostname)
	if !mitm && !hostInList(tunnelHosts, hostname) {
		writeConnectDenied(c, hostname)
		audit(map[string]any{"ts": nowMs(), "ok": false, "reason": "connect_host",
			"user": device, "host": hostname})
		return
	}

	if _, err := io.WriteString(c, connectEstablished); err != nil {
		c.Close()
		return
	}
	// 客户端可能不等 200 就把 ClientHello 贴着 CONNECT 一起发了,那部分已经落进
	// bufio,得接回去,否则握手缺开头字节。
	client := replayBuffered(c, br)

	if mitm {
		audit(map[string]any{"ts": nowMs(), "ok": true, "event": "connect_mitm",
			"user": device, "host": target})
		// 握手本身留给 HTTP Server 的连接 goroutine 做。
		s.pushTunnel(tls.Server(client, s.tlsConf))
		return
	}

	audit(map[string]any{"ts": nowMs(), "ok": true, "event": "connect_tunnel",
		"user": device, "host": target})
	relay(client, withPort(target, "443"))
}

// writeConnectDenied 回一个说得清缘由的 403。名单收紧之后被拦是常态(WebFetch 抓
// 名单外的站点就会撞上),客户端那头只看得到代理的状态码,所以这里把主机名和该动
// 哪个配置项都写进去 —— 否则排查时只剩一个光秃秃的 403。
func writeConnectDenied(c net.Conn, hostname string) {
	body := `{"error":"host not permitted by gateway","host":"` + hostname +
		`","hint":"add it to tunnelHosts in proxy.go and redeploy the gateway"}`
	io.WriteString(c, "HTTP/1.1 403 Forbidden\r\n"+
		"Content-Type: application/json\r\n"+
		"Content-Length: "+strconv.Itoa(len(body))+"\r\n\r\n"+body)
	c.Close()
}

// relay 拨通目标后纯字节对拷。
//
// 任一方向结束就把两边都关掉,不去等另一个方向:上游先关而客户端还挂着时,
// 那个方向正阻塞在 client.Read 上,不会自己返回 —— 等它就是永久泄漏一条
// goroutine 和一条 SSH channel。关掉连接会让它的读写立刻出错退出。
func relay(client net.Conn, target string) {
	up, err := net.DialTimeout("tcp", target, dialTimeout)
	if err != nil {
		client.Close() // 200 已经发出去了,只能靠断开告诉客户端
		return
	}

	done := make(chan struct{}, 2)
	copyOne := func(dst, src net.Conn) {
		io.Copy(dst, src)
		done <- struct{}{}
	}
	go copyOne(up, client)
	go copyOne(client, up)

	<-done
	client.Close()
	up.Close()
}
