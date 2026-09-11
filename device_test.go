package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// fakeGateway 模拟网关在隧道那头的行为:CONNECT 回 200 后回显,相对路径的明文 HTTP 回一个标记。
// 记录收到的 CONNECT 目标,用来断言分流是否正确。
type fakeGateway struct {
	ln       net.Listener
	connects chan string
}

func startFakeGateway(t *testing.T) *fakeGateway {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	g := &fakeGateway{ln: ln, connects: make(chan string, 16)}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go g.serve(c)
		}
	}()
	return g
}

func (g *fakeGateway) serve(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method == http.MethodConnect {
		g.connects <- req.Host
		io.WriteString(c, connectEstablished)
		io.Copy(c, br) // 回显
		return
	}
	body := "gateway:" + req.URL.RequestURI()
	io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: "+strconv.Itoa(len(body))+"\r\nConnection: close\r\n\r\n"+body)
}

// Dial 实现 tunnelDialer:直连假网关,代替真实的 SSH channel。
func (g *fakeGateway) Dial() (net.Conn, error) {
	return net.DialTimeout("tcp", g.ln.Addr().String(), time.Second)
}

// deadTunnel 模拟网关连不上。
type deadTunnel struct{}

func (deadTunnel) Dial() (net.Conn, error) { return nil, errors.New("gateway unreachable") }

// startSplitProxy 起一个分流代理,返回它的监听地址。
func startSplitProxy(t *testing.T, tunnel tunnelDialer, via ...string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go newSplitProxy(tunnel, via).serve(ln)
	return ln.Addr().String()
}

// connectVia 经代理发 CONNECT,返回应答行和建立好的裸连接。
func connectVia(t *testing.T, proxy, target string) (string, net.Conn) {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxy, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	io.WriteString(c, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n")
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	br := bufio.NewReader(c)
	res, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("读 CONNECT 应答: %v", err)
	}
	res.Body.Close()
	c.SetReadDeadline(time.Time{})
	return res.Status, replayBuffered(c, br)
}

// 命中 --via-gateway 的 CONNECT 原样转给网关,由网关应答;之后是裸字节流。
func TestSplitProxyRoutesGatewayHostThroughTunnel(t *testing.T) {
	gw := startFakeGateway(t)
	proxy := startSplitProxy(t, gw, forgedHost)

	status, conn := connectVia(t, proxy, forgedHost+":443")
	if !strings.HasPrefix(status, "200") {
		t.Fatalf("网关应回 200,实际 %q", status)
	}
	select {
	case got := <-gw.connects:
		if got != forgedHost+":443" {
			t.Fatalf("网关收到的 CONNECT 目标应为 %s:443,实际 %q", forgedHost, got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("网关没收到 CONNECT")
	}
	roundTrip(t, conn)
}

// 其它主机由代理自己拨号、自己回 200,网关完全不知道。
func TestSplitProxyDialsOtherHostsDirectly(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go echoLoop(echo)

	gw := startFakeGateway(t)
	proxy := startSplitProxy(t, gw, forgedHost)

	status, conn := connectVia(t, proxy, echo.Addr().String())
	if !strings.HasPrefix(status, "200") {
		t.Fatalf("直连目标应回 200,实际 %q", status)
	}
	roundTrip(t, conn)
	select {
	case got := <-gw.connects:
		t.Fatalf("直连主机不该经过网关,网关却收到了 CONNECT %q", got)
	case <-time.After(200 * time.Millisecond):
	}
}

// 直连目标拨不通 → 502,带主机名和原因,不能悄悄断开。
func TestSplitProxyReportsUnreachableTarget(t *testing.T) {
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := dead.Addr().String()
	dead.Close()

	proxy := startSplitProxy(t, startFakeGateway(t), forgedHost)
	status, _ := connectVia(t, proxy, addr)
	if !strings.HasPrefix(status, "502") {
		t.Fatalf("拨不通应回 502,实际 %q", status)
	}
}

// 网关链路不可用时,经网关的 CONNECT 回 502;直连的不受影响。
func TestSplitProxyGatewayDownOnlyAffectsGatewayHosts(t *testing.T) {
	echo, _ := net.Listen("tcp", "127.0.0.1:0")
	defer echo.Close()
	go echoLoop(echo)

	proxy := startSplitProxy(t, deadTunnel{}, forgedHost)
	if status, _ := connectVia(t, proxy, forgedHost+":443"); !strings.HasPrefix(status, "502") {
		t.Fatalf("网关不可达时应回 502,实际 %q", status)
	}
	status, conn := connectVia(t, proxy, echo.Addr().String())
	if !strings.HasPrefix(status, "200") {
		t.Fatalf("直连不该受网关影响,实际 %q", status)
	}
	roundTrip(t, conn)
}

// 明文 HTTP:相对路径(GET /ca、/status)转给网关;绝对 URL 按主机分流。
func TestSplitProxyPlainHTTP(t *testing.T) {
	third := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "third:"+r.URL.Path)
	}))
	defer third.Close()

	proxy := startSplitProxy(t, startFakeGateway(t), forgedHost)

	// 相对路径:直接打代理端口,像 curl http://127.0.0.1:8788/ca 那样
	res, err := http.Get("http://" + proxy + "/ca")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if string(body) != "gateway:/ca" {
		t.Fatalf("相对路径应转给网关,实际 %q", body)
	}

	// 绝对 URL、非注入主机:直连
	proxyURL, _ := url.Parse("http://" + proxy)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	res, err = client.Get(third.URL + "/x")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if string(body) != "third:/x" {
		t.Fatalf("明文 http 到第三方应直连,实际 %q", body)
	}
}

// 真实 SSH 链路:sshLink 用设备私钥登录本仓库的 SSH 服务,known_hosts 严格校验,
// 开出来的 channel 到达网关的 HTTP 层;连接断掉后下一次 Dial 自动重拨。
func TestSSHLinkDialsAndReconnects(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privBlock, err := ssh.MarshalPrivateKey(privKey, "")
	if err != nil {
		t.Fatal(err)
	}
	sshPub, _ := ssh.NewPublicKey(pubKey)
	pub := string(ssh.MarshalAuthorizedKey(sshPub))
	s := newTestSSHServer(t, []string{"127.0.0.1:8788"}, []AuthorizedKey{{ID: "laptop-1", Key: pub}})
	addr := listen(t, s)
	go echoLoop(s.tunnels)

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(privBlock), 0o600); err != nil {
		t.Fatal(err)
	}
	khPath := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(khPath, []byte(knownhosts.Line([]string{addr}, hostKeyOf(t, addr))+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	link, err := newSSHLink(addr, "laptop-1", keyPath, khPath, "127.0.0.1:8788", 0, 3)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := link.Dial()
	if err != nil {
		t.Fatalf("经 SSH 开 channel 应成功: %v", err)
	}
	roundTrip(t, conn)
	conn.Close()

	// 掐断 SSH 连接,下一次 Dial 应自动重连
	link.mu.Lock()
	old := link.client
	link.mu.Unlock()
	old.Close()
	time.Sleep(50 * time.Millisecond)
	conn, err = link.Dial()
	if err != nil {
		t.Fatalf("SSH 断开后应自动重连: %v", err)
	}
	roundTrip(t, conn)
	conn.Close()

	// known_hosts 不符 → 拒绝,和 StrictHostKeyChecking=yes 一致
	otherSigner, _ := genClientKey(t)
	if err := os.WriteFile(khPath, []byte(knownhosts.Line([]string{addr}, otherSigner.PublicKey())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bad, err := newSSHLink(addr, "laptop-1", keyPath, khPath, "127.0.0.1:8788", 0, 3)
	if err != nil {
		t.Fatal(err)
	}
	if c, err := bad.Dial(); err == nil {
		c.Close()
		t.Fatal("host key 不符应被拒绝")
	}
}

// hostKeyOf 拨一次 SSH 只为拿到服务端 host key(认证随后失败无所谓)。
func hostKeyOf(t *testing.T, addr string) ssh.PublicKey {
	t.Helper()
	var got ssh.PublicKey
	c, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User: "probe",
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			got = key
			return nil
		},
		Timeout: 5 * time.Second,
	})
	if err == nil {
		c.Close()
	}
	if got == nil {
		t.Fatal("没拿到 host key")
	}
	return got
}
