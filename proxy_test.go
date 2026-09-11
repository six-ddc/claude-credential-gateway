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

	"golang.org/x/crypto/ssh"
)

const testRealToken = "sk-ant-oat01-REAL-UPSTREAM"

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
	for _, want := range []string{"blocked.example.com", forgedHost, "ccgw-device"} {
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

// 别人带外换掉凭证后,get() 的节流 stat 会在【发请求之前】就发现,连那次注定 401 的
// 上游往返都省了。这是最常见的路径 —— 只要两次请求间隔超过 statThrottle。
func TestProxyPicksUpExternalRefreshBeforeSending(t *testing.T) {
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
	tokens = ts
	serveGatewayHTTP(t, s)

	rewrite("sk-ant-oat01-new") // 模拟本机 claude / cron 刚刷过

	sshc, err := dialSSH(addr, signer)
	if err != nil {
		t.Fatal(err)
	}
	defer sshc.Close()

	res := proxyGet(t, sshc, s, "/api/oauth/usage")
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("应当直接用新凭证成功,实际状态 %d", res.StatusCode)
	}
	if got := seen(); len(got) != 1 || got[0] != "Bearer sk-ant-oat01-new" {
		t.Fatalf("上游只该被打一次、且用的是新 token,实际 %v", got)
	}
}

// 凭证在 get() 之后才被换掉(或者恰好落在节流窗口里)时,靠 401 兜底:
// 刷新会【立即】作废旧的 access token,网关手里那份当场变废纸,必须重读并用新 token 重放,
// 否则每次带外刷新都要黑掉一整个巡检周期。
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
	tokens = ts
	serveGatewayHTTP(t, s)

	rewrite("sk-ant-oat01-new")
	// 把节流窗口按住,模拟「凭证正好在 get() 之后才变」—— 这样才测得到 401 那条路,
	// 而不是被 get() 的预检顺手救掉。
	ts.mu.Lock()
	ts.lastStat = time.Now()
	ts.mu.Unlock()

	sshc, err := dialSSH(addr, signer)
	if err != nil {
		t.Fatal(err)
	}
	defer sshc.Close()

	res := proxyGet(t, sshc, s, "/api/oauth/usage")
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

// proxyGet 经隧道发一个注入路径上的 GET。
func proxyGet(t *testing.T, sshc *ssh.Client, s *sshServer, path string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("GET", "https://"+forgedHost+path, nil)
	req.Header.Set("authorization", "Bearer sk-ant-oat01-placeholder")
	res, err := proxyClient(t, sshc, readFile(t, s.ca.certPath)).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
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

// 明文 http:// 打到非注入主机 → 403(该由设备侧分流代理直连,不该到网关)。
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
		t.Fatalf("非注入主机的明文请求应 403,实际 %d", res.StatusCode)
	}
}

// 非注入主机 → CONNECT 拒绝(网关不是出口代理,也不能拿真凭证去打无关目标)。
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
		t.Fatal("非注入主机的 CONNECT 应被拒绝")
	}
}
