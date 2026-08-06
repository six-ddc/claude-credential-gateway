package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
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

// 写死的盲转发名单:放行 Claude Code 自身要用的主机,但不放行 storage.googleapis.com
// 这类多租户通用主机,也不放行任意第三方站点(WebFetch 抓名单外的站要改代码)。
func TestTunnelHostsAllowlist(t *testing.T) {
	// 官方《Enterprise network configuration》列的主机都该放行
	for _, h := range []string{
		"claude.ai", "claude.com", "code.claude.com", "platform.claude.com",
		"downloads.claude.ai", "raw.githubusercontent.com",
		"registry.npmjs.org", "formulae.brew.sh",
		"mcp-proxy.anthropic.com", "bridge.claudeusercontent.com",
		"http-intake.logs.us5.datadoghq.com", "browser-intake-us5-datadoghq.com",
	} {
		if !hostInList(tunnelHosts, h) {
			t.Errorf("%s 应在盲转发名单里", h)
		}
	}

	// storage.googleapis.com 刻意留在外面:多租户通用存储主机,且官方说明它被挡时
	// 会回落到 api.anthropic.com。任意第三方站同样不放行。
	for _, h := range []string{
		"storage.googleapis.com",
		"evil.example.com", "github.com", "api-staging.anthropic.com",
	} {
		if hostInList(tunnelHosts, h) {
			t.Errorf("%s 不该在盲转发名单里", h)
		}
	}

	// 名单绝不能含 "*" —— 那等于把网关变成通用出口代理
	for _, p := range tunnelHosts {
		if p == "*" {
			t.Fatal(`名单不该含 "*"`)
		}
	}

	// api.anthropic.com 归注入路径,不该同时出现在盲转发名单里
	if hostInList(tunnelHosts, forgedHost) {
		t.Errorf("%s 该走注入路径,不该在盲转发名单里", forgedHost)
	}
}

// 注入路径只认 api.anthropic.com 一个主机,且大小写不敏感。
func TestIsMITMHost(t *testing.T) {
	for _, h := range []string{forgedHost, "API.ANTHROPIC.COM"} {
		if !isMITMHost(h) {
			t.Errorf("%s 应走注入路径", h)
		}
	}
	for _, h := range []string{
		"claude.ai", "api.anthropic.com.evil.com", "evil.com", "",
	} {
		if isMITMHost(h) {
			t.Errorf("%s 不该走注入路径(真凭证只能进 %s)", h, forgedHost)
		}
	}
}

// 被拒的 CONNECT 要回一个说得清缘由的 403:带主机名,还得告诉人该动哪个配置。
func TestConnectDeniedResponseIsActionable(t *testing.T) {
	cl, srv := net.Pipe()
	go func() {
		writeConnectDenied(srv, "blocked.example.com")
	}()
	res, err := http.ReadResponse(bufio.NewReader(cl), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 403 {
		t.Fatalf("应为 403,实际 %d", res.StatusCode)
	}
	body, _ := io.ReadAll(res.Body)
	for _, want := range []string{"blocked.example.com", "tunnelHosts", "proxy.go"} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("403 响应体应含 %q,实际 %s", want, body)
		}
	}
}

// setGatewayGlobals 把 handle() 依赖的那几个包级变量指到测试实例上,并在收尾时还原。
func setGatewayGlobals(t *testing.T, upstreamBase string) {
	t.Helper()
	prevCfg, prevURL, prevClient, prevTokens := cfg, upstreamURL, httpClient, tokens
	t.Cleanup(func() {
		cfg, upstreamURL, httpClient, tokens = prevCfg, prevURL, prevClient, prevTokens
	})

	c := &Config{}
	c.Upstream.Base = upstreamBase
	c.Upstream.OAuth = testRealToken
	cfg = c
	tokens = &tokenSource{token: testRealToken}

	u, err := url.Parse(upstreamBase)
	if err != nil {
		t.Fatal(err)
	}
	upstreamURL = u
	httpClient = &http.Client{Transport: &http.Transport{DisableCompression: true}}

}

// withTunnelHosts 临时替换写死的盲转发名单(名单本身没有配置项,测试只能这么改)。
func withTunnelHosts(t *testing.T, hosts ...string) {
	t.Helper()
	prev := tunnelHosts
	t.Cleanup(func() { tunnelHosts = prev })
	tunnelHosts = hosts
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
	setGatewayGlobals(t, up.URL)
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

// upstreamAuthRecorder 造一个只认某一个 token 的假上游,并记下每次收到的 Authorization。
func upstreamAuthRecorder(t *testing.T, wantToken string) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("authorization")
		mu.Lock()
		seen = append(seen, auth)
		mu.Unlock()
		if wantToken == "" || auth != "Bearer "+wantToken {
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, `{"type":"error","error":{"type":"authentication_error","message":"Invalid authentication"}}`)
			return
		}
		w.Header().Set("content-type", "application/json")
		io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

// fileBackedTokens 让网关用一份盘上的凭证文件,并返回改写它的钩子(模拟外部刷新)。
func fileBackedTokens(t *testing.T, token string) (string, func(string)) {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".credentials.json")
	write := func(tok string) {
		writeCreds(t, path, tok, time.Now().Add(8*time.Hour), "user:inference", "user:profile")
	}
	write(token)
	return path, write
}

// 外部刷新会【立即】作废旧的 access token(实测:旧 token 当场 401),网关手里那份当场变废纸。
// 所以 401 之后必须立刻重读凭证、用新 token 重放,否则每次刷新都要黑掉一整个巡检周期。
func TestProxyRetriesAfterCredentialRefresh(t *testing.T) {
	up, seen := upstreamAuthRecorder(t, "sk-ant-oat01-new")

	credPath, rewrite := fileBackedTokens(t, "sk-ant-oat01-old")
	ts, err := newTokenSource("", credPath, boolPtr(false), "")
	if err != nil {
		t.Fatal(err)
	}

	signer, pub := genClientKey(t)
	s := newTestSSHServer(t, []string{"127.0.0.1:8788"}, []AuthorizedKey{{ID: "laptop-1", Key: pub}})
	addr := listen(t, s)
	setGatewayGlobals(t, up.URL)
	tokens = ts // setGatewayGlobals 的 cleanup 会还原
	serveGatewayHTTP(t, s)

	// 模拟 cron 刚刚刷新过:盘上已经是新 token,网关内存里还是旧的。
	rewrite("sk-ant-oat01-new")

	sshc, err := dialSSH(addr, signer)
	if err != nil {
		t.Fatal(err)
	}
	defer sshc.Close()

	req, _ := http.NewRequest("POST", "https://"+forgedHost+"/v1/messages", strings.NewReader(`{"model":"claude-haiku-4-5-20251001"}`))
	req.Header.Set("authorization", "Bearer sk-ant-oat01-placeholder")
	res, err := proxyClient(t, sshc, readFile(t, s.ca.certPath)).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		t.Fatalf("401 后应当用新凭证重放并成功,实际状态 %d", res.StatusCode)
	}
	got := seen()
	if len(got) != 2 {
		t.Fatalf("上游应当被打两次(旧的一次 + 重放一次),实际 %d 次: %v", len(got), got)
	}
	if got[0] != "Bearer sk-ant-oat01-old" || got[1] != "Bearer sk-ant-oat01-new" {
		t.Fatalf("第一次该用旧 token、重放该用新 token,实际 %v", got)
	}
}

// 凭证是真废了(文件没变)的时候不能重放:否则每个请求都翻倍打到上游。
func TestProxyDoesNotRetryWhenCredentialUnchanged(t *testing.T) {
	up, seen := upstreamAuthRecorder(t, "") // 一律 401

	credPath, _ := fileBackedTokens(t, "sk-ant-oat01-dead")
	ts, err := newTokenSource("", credPath, boolPtr(false), "")
	if err != nil {
		t.Fatal(err)
	}

	signer, pub := genClientKey(t)
	s := newTestSSHServer(t, []string{"127.0.0.1:8788"}, []AuthorizedKey{{ID: "laptop-1", Key: pub}})
	addr := listen(t, s)
	setGatewayGlobals(t, up.URL)
	tokens = ts
	serveGatewayHTTP(t, s)

	sshc, err := dialSSH(addr, signer)
	if err != nil {
		t.Fatal(err)
	}
	defer sshc.Close()

	req, _ := http.NewRequest("GET", "https://"+forgedHost+"/api/oauth/usage", nil)
	req.Header.Set("authorization", "Bearer sk-ant-oat01-placeholder")
	res, err := proxyClient(t, sshc, readFile(t, s.ca.certPath)).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	if res.StatusCode != 401 {
		t.Fatalf("凭证真废了就该把 401 透传回去,实际 %d", res.StatusCode)
	}
	if got := seen(); len(got) != 1 {
		t.Fatalf("凭证没变就不该重放,上游应当只被打一次,实际 %d 次: %v", len(got), got)
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
	setGatewayGlobals(t, up.URL)
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
	setGatewayGlobals(t, up.URL)
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

// 明文 http:// 经代理时按同样两种方式分流。命中 tunnelHosts 的原样转过去,
// 且【不注入】真凭证 —— 凭证只能进注入主机 api.anthropic.com。
func TestPlainHTTPTunnelHostNotInjected(t *testing.T) {
	var gotAuth, gotHost string
	third := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotHost = r.Header.Get("authorization"), r.Host
		io.WriteString(w, "third-party")
	}))
	defer third.Close()
	thirdHost := hostnameOf(third.Listener.Addr().String())

	signer, pub := genClientKey(t)
	s := newTestSSHServer(t, []string{"127.0.0.1:8788"}, []AuthorizedKey{{ID: "laptop-1", Key: pub}})
	addr := listen(t, s)
	setGatewayGlobals(t, "http://127.0.0.1:1")
	withTunnelHosts(t, thirdHost)
	serveGatewayHTTP(t, s)

	sshc, err := dialSSH(addr, signer)
	if err != nil {
		t.Fatal(err)
	}
	defer sshc.Close()

	res, err := proxyClient(t, sshc, readFile(t, s.ca.certPath)).Get(third.URL + "/some/path")
	if err != nil {
		t.Fatalf("明文 http 到 tunnelHosts 应可达: %v", err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()

	if string(body) != "third-party" {
		t.Fatalf("应原样转给第三方,实际 %q", body)
	}
	if gotAuth != "" {
		t.Fatalf("盲转发不该注入真凭证,第三方却收到了 %q", gotAuth)
	}
	if gotHost == upstreamURL.Host {
		t.Fatalf("Host 不该被改写成上游,实际 %q", gotHost)
	}
}

// 明文 http:// 打到两个名单都不命中的主机 → 403。
func TestPlainHTTPUnlistedHostRejected(t *testing.T) {
	signer, pub := genClientKey(t)
	s := newTestSSHServer(t, []string{"127.0.0.1:8788"}, []AuthorizedKey{{ID: "laptop-1", Key: pub}})
	addr := listen(t, s)
	setGatewayGlobals(t, "http://127.0.0.1:1")
	serveGatewayHTTP(t, s)

	sshc, err := dialSSH(addr, signer)
	if err != nil {
		t.Fatal(err)
	}
	defer sshc.Close()

	res, err := proxyClient(t, sshc, readFile(t, s.ca.certPath)).Get("http://evil.example.com/x")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 403 {
		t.Fatalf("名单外主机的明文请求应 403,实际 %d", res.StatusCode)
	}
}

// 不在任何名单里的主机 → CONNECT 拒绝(不能拿真凭证去打无关目标)。
func TestConnectRejectsUnlistedHost(t *testing.T) {
	signer, pub := genClientKey(t)
	s := newTestSSHServer(t, []string{"127.0.0.1:8788"}, []AuthorizedKey{{ID: "laptop-1", Key: pub}})
	addr := listen(t, s)
	setGatewayGlobals(t, "http://127.0.0.1:1")
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

// 盲转发:命中 tunnelHosts 的主机纯 TCP 对拷,不解密、不注入凭证。
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
	setGatewayGlobals(t, "http://127.0.0.1:1")
	withTunnelHosts(t, "127.0.0.1")
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
