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
	"strings"
	"time"
)

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

// handleConnect 处理一条已经读出 CONNECT 请求的隧道连接。两条去向:
//
//   - 命中 mitm_hosts:回 200 后就地 TLS 终结,解密出来的请求塞回 HTTP Server,
//     走正常的注入+转发流程;
//   - 命中 tunnel_hosts:回 200 后纯 TCP 对拷,不解密、不注入(遥测、WebFetch 抓的
//     任意站点、MCP 走这条 —— 设了 HTTPS_PROXY 之后它们也都会经过网关)。
//
// 两个名单都不命中就 403。
func (s *sshServer) handleConnect(c net.Conn, br *bufio.Reader, req *http.Request, device string) {
	target := req.URL.Host
	if target == "" {
		target = req.Host
	}
	hostname := hostnameOf(target)

	mitm := hostInList(cfg.Proxy.MITMHosts, hostname)
	if !mitm && !hostInList(cfg.Proxy.TunnelHosts, hostname) {
		io.WriteString(c, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
		c.Close()
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
