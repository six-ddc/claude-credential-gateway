// device.go 是设备侧的分流代理(子命令 `device`):Claude Code 的 HTTPS_PROXY 指向它,
// 它按主机把流量分成两路 ——
//
//   - Claude 相关主机(api.anthropic.com + proxy.go 的 tunnelHosts,和网关同一份名单),
//     CONNECT 经它自己维护的 SSH 连接原样转给网关:api.anthropic.com 由网关 TLS 终结并
//     注入真凭证,其余由网关盲转发;
//   - 名单外的主机由它直接拨号,纯字节对拷。WebFetch 抓的网站、第三方 MCP server、
//     git/gh 这些从设备本机出去,不到网关。
//
// 明文 HTTP 同样分流:经网关的以绝对形式(GET http://host/path)交给网关按同一份名单处理;
// 不带主机的相对路径请求(GET /ca、GET /status)是发给网关自己的,接入脚本和包装命令靠它
// 取 CA、探活。
//
// SSH 连接是内建的:公钥认证、known_hosts 严格校验、定时 keepalive、断了按需重拨。
// 设备上只需要这一个常驻进程。
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// runDevice 是 `claude-credential-gateway device ...` 的入口。
func runDevice(args []string) error {
	fs := flag.NewFlagSet("device", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:8788", "本机代理监听地址,给 HTTPS_PROXY 用")
	gateway := fs.String("gateway", "", "网关 SSH 地址 host:port(必填)")
	deviceID := fs.String("device-id", "", "设备 id,即 SSH 用户名(必填)")
	keyPath := fs.String("key", "", "设备私钥路径(必填)")
	knownHostsPath := fs.String("known-hosts", "", "已核对过的网关 host key(必填)")
	target := fs.String("target", "127.0.0.1:8788", "SSH 转发目标,须在网关 permit_targets 里")
	keepalive := fs.Duration("keepalive", 30*time.Second, "SSH keepalive 间隔")
	keepaliveMax := fs.Int("keepalive-max", 3, "连续几次 keepalive 无应答就判定链路已死")
	pidfile := fs.String("pidfile", "", "把自己的 pid 写到这个文件,便于脚本停掉旧进程")
	verbose := fs.Bool("verbose", false, "每条连接都打一行日志")
	if err := fs.Parse(args); err != nil {
		return err
	}
	for _, f := range []struct{ name, value string }{
		{"gateway", *gateway}, {"device-id", *deviceID}, {"key", *keyPath}, {"known-hosts", *knownHostsPath},
	} {
		if f.value == "" {
			return fmt.Errorf("--%s 必填", f.name)
		}
	}

	link, err := newSSHLink(*gateway, *deviceID, *keyPath, *knownHostsPath, *target, *keepalive, *keepaliveMax)
	if err != nil {
		return err
	}
	p := newSplitProxy(link, gatewayHosts())
	p.verbose = *verbose

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return fmt.Errorf("监听 %s: %w", *listen, err)
	}
	if *pidfile != "" {
		if err := os.WriteFile(*pidfile, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o644); err != nil {
			return fmt.Errorf("写 pidfile: %w", err)
		}
	}

	log.Printf("分流代理监听 %s", *listen)
	log.Printf("经网关 %s(SSH %s,设备 %s): %s", *gateway, *target, *deviceID, strings.Join(p.viaList(), ", "))
	log.Printf("名单外的主机由本机直连")
	// 先拨一次,让接入脚本立刻知道链路通不通;拨不通也照常监听,之后按需重试。
	if _, err := link.connect(); err != nil {
		log.Printf("⚠ 网关暂时连不上: %v(会在有请求时重试)", err)
	}
	return p.serve(ln)
}

// gatewayHosts 是要送去网关的主机:注入主机加上网关盲转发的那份名单。
// 和网关是同一个二进制、同一个切片,两边不会对不上,所以不做成参数。
func gatewayHosts() []string {
	return append([]string{forgedHost}, tunnelHosts...)
}

// tunnelDialer 打开一条到网关的连接。生产实现是 sshLink;测试里换成直连假网关。
type tunnelDialer interface {
	Dial() (net.Conn, error)
}

// sshLink 维护一条到网关的 SSH 连接,按需建立、死了重拨。
// 每个到网关的 CONNECT 在这条连接上开一个 direct-tcpip channel,等价于 ssh -L。
type sshLink struct {
	addr, user, target string
	conf               *ssh.ClientConfig
	keepalive          time.Duration
	keepaliveMax       int

	mu      sync.Mutex
	client  *ssh.Client
	nextTry time.Time     // 上次拨号失败后的退避截止
	backoff time.Duration // 当前退避时长,成功后归零
}

const (
	sshDialTimeout = 15 * time.Second
	sshBackoffMin  = time.Second
	sshBackoffMax  = 30 * time.Second
)

func newSSHLink(addr, user, keyPath, knownHostsPath, target string, keepalive time.Duration, keepaliveMax int) (*sshLink, error) {
	pem, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("读设备私钥: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(pem)
	if err != nil {
		return nil, fmt.Errorf("解析设备私钥 %s: %w", keyPath, err)
	}
	// 严格校验:known_hosts 里没有或不符都拒绝,和 StrictHostKeyChecking=yes 一样。
	hostKey, err := knownhosts.New(knownHostsPath)
	if err != nil {
		return nil, fmt.Errorf("读 known_hosts: %w", err)
	}
	return &sshLink{
		addr: addr, user: user, target: target,
		conf: &ssh.ClientConfig{
			User:            user,
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
			HostKeyCallback: hostKey,
			Timeout:         sshDialTimeout,
		},
		keepalive:    keepalive,
		keepaliveMax: keepaliveMax,
	}, nil
}

// Dial 在 SSH 连接上开一个到网关转发目标的 channel。开不出来就认为连接已死,重拨一次再试。
func (l *sshLink) Dial() (net.Conn, error) {
	c, err := l.connect()
	if err != nil {
		return nil, err
	}
	ch, err := c.Dial("tcp", l.target)
	if err == nil {
		return ch, nil
	}
	l.drop(c)
	if c, err = l.connect(); err != nil {
		return nil, err
	}
	return c.Dial("tcp", l.target)
}

// connect 返回当前可用的 SSH 连接,没有就拨一条。拨号失败按指数退避,退避期内直接报错,
// 免得每个请求都去撞一次超时。
func (l *sshLink) connect() (*ssh.Client, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.client != nil {
		return l.client, nil
	}
	if wait := time.Until(l.nextTry); wait > 0 {
		return nil, fmt.Errorf("网关 %s 暂不可达,%s 后重试", l.addr, wait.Round(time.Second))
	}
	c, err := ssh.Dial("tcp", l.addr, l.conf)
	if err != nil {
		if l.backoff == 0 {
			l.backoff = sshBackoffMin
		} else {
			l.backoff = min(l.backoff*2, sshBackoffMax)
		}
		l.nextTry = time.Now().Add(l.backoff)
		log.Printf("✗ 连网关 %s 失败: %v(%s 后重试)", l.addr, err, l.backoff)
		return nil, err
	}
	l.backoff = 0
	l.client = c
	log.Printf("SSH 已连上网关 %s(设备 %s)", l.addr, l.user)
	go l.keepAlive(c)
	go func() {
		err := c.Wait()
		l.drop(c)
		log.Printf("SSH 连接断开: %v(下次请求时重连)", err)
	}()
	return c, nil
}

// drop 丢弃一条连接;它不再是当前连接时只负责关掉。
func (l *sshLink) drop(c *ssh.Client) {
	l.mu.Lock()
	if l.client == c {
		l.client = nil
	}
	l.mu.Unlock()
	c.Close()
}

// keepAlive 定时探测连接是否还活着。连续 keepaliveMax 次无应答就关掉它,
// 让下一个请求触发重拨 —— 笔记本休眠唤醒后 TCP 早就死了,不探测的话要等内核超时才知道。
func (l *sshLink) keepAlive(c *ssh.Client) {
	if l.keepalive <= 0 {
		return
	}
	t := time.NewTicker(l.keepalive)
	defer t.Stop()
	failures := 0
	for range t.C {
		replied := make(chan error, 1)
		go func() {
			_, _, err := c.SendRequest("keepalive@openssh.com", true, nil)
			replied <- err
		}()
		select {
		case err := <-replied:
			if err != nil {
				return // 连接已关,Wait goroutine 会收尾
			}
			failures = 0
		case <-time.After(l.keepalive):
			failures++
			if failures >= l.keepaliveMax {
				log.Printf("SSH keepalive 连续 %d 次无应答,断开重连", failures)
				l.drop(c)
				return
			}
		}
	}
}

// splitProxy 是本机 HTTP 代理:CONNECT 与明文 HTTP 都按主机分两路。
type splitProxy struct {
	tunnel  tunnelDialer
	via     map[string]bool
	verbose bool

	gatewayHTTP http.RoundTripper // 相对路径的明文请求 → 网关自己(GET /ca、/status)
	viaHTTP     http.RoundTripper // 经网关主机的明文请求 → 以绝对形式交给网关转发
	directHTTP  http.RoundTripper // 名单外主机的明文请求 → 目标站直连
}

func newSplitProxy(tunnel tunnelDialer, via []string) *splitProxy {
	p := &splitProxy{tunnel: tunnel, via: map[string]bool{}}
	for _, h := range via {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			p.via[h] = true
		}
	}
	tunnelDial := func(context.Context, string, string) (net.Conn, error) { return tunnel.Dial() }
	p.gatewayHTTP = &http.Transport{
		DialContext:       tunnelDial,
		DisableKeepAlives: true, // 每个请求一条 channel,不和连接复用的键(主机名)纠缠
	}
	// 装成「网关是我的上游代理」:Transport 会把请求写成绝对形式 GET http://host/path,
	// 网关据此按主机名分流(注入主机换上游+注入;盲转发名单里的原样转过去)。
	gatewayAsProxy, _ := url.Parse("http://gateway")
	p.viaHTTP = &http.Transport{
		Proxy:             http.ProxyURL(gatewayAsProxy),
		DialContext:       tunnelDial,
		DisableKeepAlives: true,
	}
	p.directHTTP = &http.Transport{
		Proxy:             nil, // 自己就是代理,绝不能再读 HTTPS_PROXY 绕回自己
		DialContext:       (&net.Dialer{Timeout: dialTimeout}).DialContext,
		DisableKeepAlives: true,
	}
	return p
}

func (p *splitProxy) viaList() []string {
	out := make([]string, 0, len(p.via))
	for h := range p.via {
		out = append(out, h)
	}
	return out
}

func (p *splitProxy) viaGateway(hostname string) bool {
	return p.via[strings.ToLower(hostname)]
}

func (p *splitProxy) serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go p.handle(c)
	}
}

// handle 处理一条客户端连接。CONNECT 之后连接就变成裸字节流,处理完即结束;
// 明文 HTTP 可以在同一条连接上连续发多个请求。
func (p *splitProxy) handle(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		if req.Method == http.MethodConnect {
			p.connect(c, br, req)
			return
		}
		if !p.plain(c, req) {
			return
		}
	}
}

// connect 处理 CONNECT:Claude 相关主机的把原始 CONNECT 转给网关,由网关应答
// (注入主机 TLS 终结,其余盲转发);名单外的主机自己拨号、自己回 200。之后两边纯字节对拷。
func (p *splitProxy) connect(c net.Conn, br *bufio.Reader, req *http.Request) {
	target := req.Host
	if target == "" {
		target = req.URL.Host
	}
	hostname := hostnameOf(target)

	var up net.Conn
	var err error
	if p.viaGateway(hostname) {
		if up, err = p.tunnel.Dial(); err == nil {
			// 网关只看主机名,请求行原样重写一遍即可;200 由网关回。
			_, err = fmt.Fprintf(up, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
		}
		p.logf("connect via=gateway host=%s err=%v", target, err)
	} else {
		if up, err = net.DialTimeout("tcp", withPort(target, "443"), dialTimeout); err == nil {
			_, err = io.WriteString(c, connectEstablished)
		}
		p.logf("connect via=direct host=%s err=%v", target, err)
	}
	if err != nil {
		if up != nil {
			up.Close()
		}
		writeBadGateway(c, hostname, err)
		return
	}
	// 客户端可能不等应答就把 TLS ClientHello 贴着 CONNECT 发过来了,那部分已经在 bufio 里。
	pipe(replayBuffered(c, br), up)
}

// plain 处理一个明文 HTTP 请求并把响应写回。返回 false 表示这条连接不该再复用。
func (p *splitProxy) plain(c net.Conn, req *http.Request) bool {
	var rt http.RoundTripper
	var route string
	switch {
	case !req.URL.IsAbs():
		// 相对路径(GET /ca、GET /status)是发给网关自己的,保持相对形式。
		req.URL.Scheme, req.URL.Host = "http", "gateway"
		rt, route = p.gatewayHTTP, "gateway-self"
	case p.viaGateway(req.URL.Hostname()):
		rt, route = p.viaHTTP, "gateway"
	default:
		rt, route = p.directHTTP, "direct"
	}
	req.RequestURI = "" // 客户端侧 Transport 不接受带 RequestURI 的请求
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authorization")

	res, err := rt.RoundTrip(req)
	p.logf("%s via=%s url=%s err=%v", req.Method, route, req.URL, err)
	if err != nil {
		writeBadGateway(c, req.URL.Host, err)
		return false
	}
	defer res.Body.Close()
	if err := res.Write(c); err != nil {
		return false
	}
	return !res.Close && !req.Close
}

func (p *splitProxy) logf(format string, args ...any) {
	if p.verbose {
		log.Printf(format, args...)
	}
}

// writeBadGateway 回 502:目标拨不通,或网关 SSH 链路暂时不可用。
func writeBadGateway(c net.Conn, host string, err error) {
	body := fmt.Sprintf(`{"error":"upstream unreachable","host":%q,"cause":%q}`, host, err.Error())
	io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n"+
		"Content-Type: application/json\r\n"+
		"Content-Length: "+strconv.Itoa(len(body))+"\r\n\r\n"+body)
}

// pipe 两条连接之间纯字节对拷,任一方向结束就把两边都关掉。
func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	copyOne := func(dst, src net.Conn) {
		io.Copy(dst, src)
		done <- struct{}{}
	}
	go copyOne(a, b)
	go copyOne(b, a)
	<-done
	a.Close()
	b.Close()
}
