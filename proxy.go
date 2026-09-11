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
	"path"
	"strconv"
	"strings"
	"time"
)

// 网关只服务一个主机,就是 tlsterm.go 里的 forgedHost:解密并注入真凭证。客户端无论上游
// 配到哪儿,URL 里的主机名始终是 api.anthropic.com,要解密就得冒充它。官方表里挂在这个域下的
// 「WebFetch 域名安全检查、特性开关拉取、遥测事件上报」因此走的都是注入路径。
//
// 其它主机一律 403:设备侧的分流代理(device.go)只把这一个主机送过来,其余流量从设备
// 本机直连。网关不是出口代理,「真凭证送给谁」写死在代码里,不做成配置项。
func isMITMHost(hostname string) bool { return strings.EqualFold(hostname, forgedHost) }

// blockedPaths 是注入主机上不放行的端点。这些功能与模型调用共用主机和 OAuth token,
// 只能按路径拦;同主机名单一样写死在代码里。模式是 path.Match 语法(`*` 匹配一段),
// 路径本身或它的任一父路径命中即算命中,所以 "/v1/code/sessions/*/worker" 同时盖住
// /worker/register、/worker/events。
//
// 只拦让功能跑不起来的核心端点,不追求把每条外围请求都列全:
//   - /api/frame/*:Artifact 工具,把网页产物发布到 claude.ai/code/artifact 并读写其评论、
//     数据库、附件。
//   - /v1/code/sessions/<id>/worker*、/bridge、/v1/environments/bridge:Remote Control
//     (/remote-control)。本地会话向后端注册成 worker、建立 bridge 之后,claude.ai 网页和
//     手机端就能读取本地会话转录并向它下发指令、打断轮次。自托管 runner 复用同一组端点,
//     一并失效。/teleport、/ultrareview、/schedule 用的 /v1/code/sessions 本身不在此列。
var blockedPaths = []string{
	"/api/frame",
	"/v1/code/sessions/*/worker",
	"/v1/code/sessions/*/bridge",
	"/v1/environments/bridge",
}

func isBlockedPath(p string) bool {
	for p = path.Clean("/" + p); p != "/"; p = path.Dir(p) {
		for _, pattern := range blockedPaths {
			if ok, _ := path.Match(pattern, p); ok {
				return true
			}
		}
	}
	return false
}

// dialTimeout 是设备侧分流代理直连目标主机时的拨号上限。
const dialTimeout = 15 * time.Second

// connectEstablished 是 CONNECT 的成功应答。之后这条连接上跑的就不再是 HTTP 了。
const connectEstablished = "HTTP/1.1 200 Connection Established\r\n\r\n"

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

// handleConnect 处理一条已经读出 CONNECT 请求的隧道连接。只放行注入主机
// (api.anthropic.com):回 200 后就地 TLS 终结,解密出来的请求塞回 HTTP Server,
// 走注入+转发流程。其它主机 403 —— 它们该由设备侧的分流代理直连,不该到这里。
func (s *sshServer) handleConnect(c net.Conn, br *bufio.Reader, req *http.Request, device string) {
	target := req.URL.Host
	if target == "" {
		target = req.Host
	}
	hostname := hostnameOf(target)

	if !isMITMHost(hostname) {
		writeConnectDenied(c, hostname)
		events.Warn("connect denied", "reason", "host_not_allowed", "user", device, "host", hostname)
		return
	}

	if _, err := io.WriteString(c, connectEstablished); err != nil {
		c.Close()
		return
	}
	events.Info("connect", "mode", "mitm", "user", device, "host", target)
	// 客户端可能不等 200 就把 ClientHello 贴着 CONNECT 一起发了,那部分已经落进
	// bufio,得接回去,否则握手缺开头字节。握手本身留给 HTTP Server 的连接 goroutine 做。
	s.pushTunnel(tls.Server(replayBuffered(c, br), s.tlsConf))
}

// writeConnectDenied 回一个说得清缘由的 403。到这里的非注入主机基本都是设备没跑
// 分流代理、把整个 HTTPS_PROXY 直接指到了隧道上,客户端那头只看得到代理的状态码,
// 所以把主机名和原因写进 body —— 否则排查时只剩一个光秃秃的 403。
func writeConnectDenied(c net.Conn, hostname string) {
	body := `{"error":"host not served by gateway","host":"` + hostname +
		`","hint":"the gateway only serves ` + forgedHost + `; run the device split proxy (ccgw-device) so other hosts go direct"}`
	io.WriteString(c, "HTTP/1.1 403 Forbidden\r\n"+
		"Content-Type: application/json\r\n"+
		"Content-Length: "+strconv.Itoa(len(body))+"\r\n\r\n"+body)
	c.Close()
}
