package main

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

const testRealToken = "sk-ant-oat01-REAL-UPSTREAM"

func TestHostMatches(t *testing.T) {
	cases := []struct {
		pattern, host string
		want          bool
	}{
		{"*", "anything.example.com", true},
		{"api.anthropic.com", "api.anthropic.com", true},
		{"api.anthropic.com", "API.ANTHROPIC.COM", true}, // 主机名大小写不敏感
		{"api.anthropic.com", "evil.com", false},
		{"*.anthropic.com", "statsig.anthropic.com", true},
		{"*.anthropic.com", "anthropic.com", false}, // 子域通配不含裸域
		{"*.anthropic.com", "api.anthropic.com.evil.com", false},
	}
	for _, c := range cases {
		if got := hostMatches(c.pattern, c.host); got != c.want {
			t.Errorf("hostMatches(%q, %q) = %v,期望 %v", c.pattern, c.host, got, c.want)
		}
	}
}

func TestHostnameOf(t *testing.T) {
	for in, want := range map[string]string{
		"api.anthropic.com:443": "api.anthropic.com",
		"api.anthropic.com":     "api.anthropic.com",
		"127.0.0.1:8788":        "127.0.0.1",
	} {
		if got := hostnameOf(in); got != want {
			t.Errorf("hostnameOf(%q) = %q,期望 %q", in, got, want)
		}
	}
}

// setGatewayGlobals 把 handle() 依赖的那几个包级变量指到测试实例上,并在收尾时还原。
func setGatewayGlobals(t *testing.T, upstreamBase string, mitm, tunnel []string) {
	t.Helper()
	prevCfg, prevURL, prevClient := cfg, upstreamURL, httpClient
	t.Cleanup(func() { cfg, upstreamURL, httpClient = prevCfg, prevURL, prevClient })

	c := &Config{}
	c.Upstream.Base = upstreamBase
	c.Upstream.OAuth = testRealToken
	c.Proxy.MITMHosts = mitm
	c.Proxy.TunnelHosts = tunnel
	cfg = c

	u, err := url.Parse(upstreamBase)
	if err != nil {
		t.Fatal(err)
	}
	upstreamURL = u
	httpClient = &http.Client{Transport: &http.Transport{DisableCompression: true}}

}

// serveGatewayHTTP 用真正的 handle() 消费隧道连接。
func serveGatewayHTTP(t *testing.T, s *sshServer) {
	t.Helper()
	srv := &http.Server{Handler: http.HandlerFunc(handle), ConnContext: deviceConnContext}
	go srv.Serve(s.tunnels)
	t.Cleanup(func() { srv.Close() })
}

// proxyClient 造一个「把 HTTPS_PROXY 指向隧道」的客户端 —— 等价于设备端
// export HTTPS_PROXY=http://127.0.0.1:8788 之后 Claude Code 的行为。
func proxyClient(t *testing.T, sshc interface {
	Dial(string, string) (net.Conn, error)
}, ca []byte) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		t.Fatal("CA 证书应可解析")
	}
	proxyURL, _ := url.Parse("http://127.0.0.1:8788")
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) { return proxyURL, nil },
			Dial: func(network, addr string) (net.Conn, error) {
				return sshc.Dial("tcp", "127.0.0.1:8788")
			},
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
	}
}

// 这条是整个改动的由来:/usage 命令打的是 GET /api/oauth/usage。
// 改动前非 /v1/ 的路径会被静默改写成 /v1/messages,上游收到牛头不对马嘴的请求。
func TestProxyForwardsNonV1Path(t *testing.T) {
	var gotPath, gotAuth, gotBeta string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.RequestURI(), r.Header.Get("authorization")
		gotBeta = r.Header.Get("anthropic-beta")
		w.Header().Set("content-type", "application/json")
		io.WriteString(w, `{"five_hour":{"utilization":37,"resets_at":"2026-08-05T15:59:00Z"}}`)
	}))
	defer up.Close()

	signer, pub := genClientKey(t)
	s := newTestSSHServer(t, []string{"127.0.0.1:8788"}, []AuthorizedKey{{ID: "laptop-1", Key: pub}})
	addr := listen(t, s)
	setGatewayGlobals(t, up.URL, []string{forgedHost}, []string{"*"})
	serveGatewayHTTP(t, s)

	sshc, err := dialSSH(addr, signer)
	if err != nil {
		t.Fatal(err)
	}
	defer sshc.Close()

	req, _ := http.NewRequest("GET", "https://"+forgedHost+"/api/oauth/usage", nil)
	req.Header.Set("authorization", "Bearer sk-ant-oat01-placeholder")
	req.Header.Set("anthropic-beta", "oauth-2025-04-20")
	res, err := proxyClient(t, sshc, readFile(t, s.ca.certPath)).Do(req)
	if err != nil {
		t.Fatalf("经代理请求 /api/oauth/usage 应成功: %v", err)
	}
	defer res.Body.Close()

	if gotPath != "/api/oauth/usage" {
		t.Fatalf("上游应收到原始路径 /api/oauth/usage,实际 %q", gotPath)
	}
	if gotAuth != "Bearer "+testRealToken {
		t.Fatalf("Authorization 应被换成真凭证,实际 %q", gotAuth)
	}
	if gotBeta != "oauth-2025-04-20" {
		t.Fatalf("anthropic-beta 应原样透传(官方 gateway 文档要求),实际 %q", gotBeta)
	}
	body, _ := io.ReadAll(res.Body)
	if len(body) == 0 {
		t.Fatal("响应体应透传回客户端")
	}
}

// 带 query 的路径也要原样转发。
func TestProxyPreservesQuery(t *testing.T) {
	var gotPath string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.RequestURI()
	}))
	defer up.Close()

	signer, pub := genClientKey(t)
	s := newTestSSHServer(t, []string{"127.0.0.1:8788"}, []AuthorizedKey{{ID: "laptop-1", Key: pub}})
	addr := listen(t, s)
	setGatewayGlobals(t, up.URL, []string{forgedHost}, []string{"*"})
	serveGatewayHTTP(t, s)

	sshc, err := dialSSH(addr, signer)
	if err != nil {
		t.Fatal(err)
	}
	defer sshc.Close()

	res, err := proxyClient(t, sshc, readFile(t, s.ca.certPath)).
		Get("https://" + forgedHost + "/api/claude_cli_profile?account_uuid=abc")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()

	if gotPath != "/api/claude_cli_profile?account_uuid=abc" {
		t.Fatalf("query 应原样保留,实际 %q", gotPath)
	}
}

// 设备残留的 x-api-key 不能到上游(代理形态下这条老规矩仍然要成立)。
func TestProxyStripsClientCredentials(t *testing.T) {
	var gotAPIKey, gotProxyAuth string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAPIKey = r.Header.Get("x-api-key")
		gotProxyAuth = r.Header.Get("proxy-authorization")
	}))
	defer up.Close()

	signer, pub := genClientKey(t)
	s := newTestSSHServer(t, []string{"127.0.0.1:8788"}, []AuthorizedKey{{ID: "laptop-1", Key: pub}})
	addr := listen(t, s)
	setGatewayGlobals(t, up.URL, []string{forgedHost}, []string{"*"})
	serveGatewayHTTP(t, s)

	sshc, err := dialSSH(addr, signer)
	if err != nil {
		t.Fatal(err)
	}
	defer sshc.Close()

	req, _ := http.NewRequest("POST", "https://"+forgedHost+"/v1/messages", nil)
	req.Header.Set("x-api-key", "sk-ant-api03-leftover")
	req.Header.Set("proxy-authorization", "Basic bogus")
	res, err := proxyClient(t, sshc, readFile(t, s.ca.certPath)).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()

	if gotAPIKey != "" {
		t.Fatalf("x-api-key 必须剥掉,实际 %q", gotAPIKey)
	}
	if gotProxyAuth != "" {
		t.Fatalf("proxy-authorization 是给代理的,不该转给上游,实际 %q", gotProxyAuth)
	}
}

// 不在任何名单里的主机 → CONNECT 拒绝(不能拿真凭证去打无关目标)。
func TestConnectRejectsUnlistedHost(t *testing.T) {
	signer, pub := genClientKey(t)
	s := newTestSSHServer(t, []string{"127.0.0.1:8788"}, []AuthorizedKey{{ID: "laptop-1", Key: pub}})
	addr := listen(t, s)
	setGatewayGlobals(t, "http://127.0.0.1:1", []string{forgedHost}, []string{"*.anthropic.com"})
	serveGatewayHTTP(t, s)

	sshc, err := dialSSH(addr, signer)
	if err != nil {
		t.Fatal(err)
	}
	defer sshc.Close()

	if res, err := proxyClient(t, sshc, readFile(t, s.ca.certPath)).Get("https://evil.example.com/x"); err == nil {
		res.Body.Close()
		t.Fatal("名单外主机的 CONNECT 应被拒绝")
	}
}

// 盲转发:命中 tunnel_hosts 的主机纯 TCP 对拷,不解密、不注入凭证。
// (设了 HTTPS_PROXY 之后 WebFetch / MCP / 遥测都会走这条,断了会弄坏功能。)
func TestConnectBlindTunnel(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go echoLoop(echo)

	signer, pub := genClientKey(t)
	s := newTestSSHServer(t, []string{"127.0.0.1:8788"}, []AuthorizedKey{{ID: "laptop-1", Key: pub}})
	addr := listen(t, s)
	setGatewayGlobals(t, "http://127.0.0.1:1", []string{forgedHost}, []string{"127.0.0.1"})
	serveGatewayHTTP(t, s)

	sshc, err := dialSSH(addr, signer)
	if err != nil {
		t.Fatal(err)
	}
	defer sshc.Close()

	conn, err := sshc.Dial("tcp", "127.0.0.1:8788")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if _, err := io.WriteString(conn, "CONNECT "+echo.Addr().String()+" HTTP/1.1\r\nHost: "+echo.Addr().String()+"\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 39) // "HTTP/1.1 200 Connection Established\r\n\r\n"
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("应收到 200 Connection Established: %v", err)
	}
	if string(buf) != "HTTP/1.1 200 Connection Established\r\n\r\n" {
		t.Fatalf("CONNECT 应答不符: %q", buf)
	}
	roundTrip(t, conn) // 隧道建立后是裸 TCP,回显应原样穿过
}
