package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// genClientKey 生成一把设备密钥对,返回签名器与 authorized_keys 单行文本。
func genClientKey(t *testing.T) (ssh.Signer, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return signer, string(ssh.MarshalAuthorizedKey(sshPub))
}

// echoLoop 消费一个 listener 的连接并原样回显 —— 测试里代替进程内 HTTP Server 消费隧道。
func echoLoop(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			io.Copy(c, c)
		}(c)
	}
}

// newTestSSHServer 在临时目录里造一个 SSH 服务(host key 与 CA 都落到 t.TempDir)。
func newTestSSHServer(t *testing.T, permit []string, keys []AuthorizedKey) *sshServer {
	t.Helper()
	dir := t.TempDir()
	s, err := newSSHServer(SSHConfig{
		HostKey:        filepath.Join(dir, "hostkey"),
		CAKey:          filepath.Join(dir, "ca_key"),
		PermitTargets:  permit,
		AuthorizedKeys: keys,
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// listen 让 SSH 服务开始接受连接,返回监听地址。
func listen(t *testing.T, s *sshServer) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.serve(ln)
	t.Cleanup(func() { ln.Close(); s.tunnels.Close() })
	return ln.Addr().String()
}

// startSSHServer 起一个转发-only SSH 服务,隧道连接由 echoLoop 消费(代替 HTTP Server)。
func startSSHServer(t *testing.T, permit string, keys []AuthorizedKey) (string, *sshServer) {
	t.Helper()
	s := newTestSSHServer(t, []string{permit}, keys)
	addr := listen(t, s)
	go echoLoop(s.tunnels)
	return addr, s
}

func dialSSH(addr string, signer ssh.Signer) (*ssh.Client, error) {
	return ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "dev",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
}

// roundTrip 通过隧道发一段数据并核对回显。
func roundTrip(t *testing.T, conn net.Conn) {
	t.Helper()
	msg := []byte("hello through tunnel")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("回显不符: %q", got)
	}
}

// 授权公钥 → 放行,direct-tcpip 命中白名单 → channel 直连进程内消费端。
func TestAuthorizedForward(t *testing.T) {
	signer, pub := genClientKey(t)
	addr, _ := startSSHServer(t, "127.0.0.1:8788", []AuthorizedKey{{ID: "laptop-1", Key: pub}})

	client, err := dialSSH(addr, signer)
	if err != nil {
		t.Fatalf("授权公钥应放行: %v", err)
	}
	defer client.Close()

	conn, err := client.Dial("tcp", "127.0.0.1:8788")
	if err != nil {
		t.Fatalf("白名单目标应可转发: %v", err)
	}
	defer conn.Close()
	roundTrip(t, conn)
}

// 未登记的公钥 → 握手直接失败。
func TestUnauthorizedKeyRejected(t *testing.T) {
	_, pub := genClientKey(t)
	stranger, _ := genClientKey(t)
	addr, _ := startSSHServer(t, "127.0.0.1:8788", []AuthorizedKey{{ID: "laptop-1", Key: pub}})

	if client, err := dialSSH(addr, stranger); err == nil {
		client.Close()
		t.Fatal("未授权公钥不应通过认证")
	}
}

// session channel(shell/exec/pty)→ Reject。
func TestSessionRejected(t *testing.T) {
	signer, pub := genClientKey(t)
	addr, _ := startSSHServer(t, "127.0.0.1:8788", []AuthorizedKey{{ID: "laptop-1", Key: pub}})

	client, err := dialSSH(addr, signer)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if sess, err := client.NewSession(); err == nil {
		sess.Close()
		t.Fatal("session channel 应被拒绝")
	}
}

// 白名单外的转发目标 → Reject。
func TestOffTargetRejected(t *testing.T) {
	signer, pub := genClientKey(t)
	addr, _ := startSSHServer(t, "127.0.0.1:8788", []AuthorizedKey{{ID: "laptop-1", Key: pub}})

	client, err := dialSSH(addr, signer)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if conn, err := client.Dial("tcp", "127.0.0.1:9"); err == nil {
		conn.Close()
		t.Fatal("白名单外目标应被拒绝")
	}
}

// -R 反向转发(tcpip-forward 全局请求)→ 拒绝。
func TestRemoteForwardRejected(t *testing.T) {
	signer, pub := genClientKey(t)
	addr, _ := startSSHServer(t, "127.0.0.1:8788", []AuthorizedKey{{ID: "laptop-1", Key: pub}})

	client, err := dialSSH(addr, signer)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if ln, err := client.Listen("tcp", "127.0.0.1:0"); err == nil {
		ln.Close()
		t.Fatal("-R 反向转发应被拒绝")
	}
}

// unix 白名单:direct-streamlocal 放行(路径匹配即可,无需真实 socket 文件),tcp 拒绝。
func TestUnixSocketForward(t *testing.T) {
	signer, pub := genClientKey(t)
	addr, _ := startSSHServer(t, "unix:/run/ccgw.sock", []AuthorizedKey{{ID: "laptop-1", Key: pub}})

	client, err := dialSSH(addr, signer)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	conn, err := client.Dial("unix", "/run/ccgw.sock")
	if err != nil {
		t.Fatalf("白名单 unix 路径应可转发: %v", err)
	}
	defer conn.Close()
	roundTrip(t, conn)

	if c2, err := client.Dial("tcp", "127.0.0.1:8788"); err == nil {
		c2.Close()
		t.Fatal("unix 白名单下 tcp 转发应被拒绝")
	}
	if c3, err := client.Dial("unix", "/tmp/other.sock"); err == nil {
		c3.Close()
		t.Fatal("白名单外 unix 路径应被拒绝")
	}
}

// serveTunnelHTTP 让 HTTP Server 消费隧道连接,handler 回显请求所属的 device id 与是否走了 TLS。
func serveTunnelHTTP(t *testing.T, s *sshServer) {
	t.Helper()
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			scheme := "plain"
			if r.TLS != nil {
				scheme = "tls:" + r.TLS.ServerName
			}
			io.WriteString(w, deviceFrom(r.Context())+"/"+scheme)
		}),
		ConnContext: deviceConnContext,
	}
	go srv.Serve(s.tunnels)
	t.Cleanup(func() { srv.Close() })
}

// Level 1:明文 HTTP 穿隧道,请求带上 SSH 层认证出的 device id。
func TestDeviceIdentityOverHTTP(t *testing.T) {
	signer, pub := genClientKey(t)
	s := newTestSSHServer(t, []string{"127.0.0.1:8788"}, []AuthorizedKey{{ID: "laptop-1", Key: pub}})
	addr := listen(t, s)
	serveTunnelHTTP(t, s)

	client, err := dialSSH(addr, signer)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	tr := &http.Transport{Dial: func(network, addr string) (net.Conn, error) {
		return client.Dial("tcp", "127.0.0.1:8788")
	}}
	res, err := (&http.Client{Transport: tr}).Get("http://gateway/whoami")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	got, _ := io.ReadAll(res.Body)
	if string(got) != "laptop-1/plain" {
		t.Fatalf("明文请求应是 laptop-1/plain,实际 %q", got)
	}
}

// Level 2:客户端按 https://api.anthropic.com 握手(ANTHROPIC_UNIX_SOCKET 的形态),
// 网关用自建 CA 终结 TLS,解密后仍拿得到 device id。
func TestTLSTerminationOverTunnel(t *testing.T) {
	signer, pub := genClientKey(t)
	s := newTestSSHServer(t, []string{"unix:/run/ccgw.sock"}, []AuthorizedKey{{ID: "laptop-1", Key: pub}})
	addr := listen(t, s)
	serveTunnelHTTP(t, s)

	client, err := dialSSH(addr, signer)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(readFile(t, s.ca.certPath)) {
		t.Fatal("CA 证书应可被解析")
	}
	tr := &http.Transport{
		Dial:            func(network, addr string) (net.Conn, error) { return client.Dial("unix", "/run/ccgw.sock") },
		TLSClientConfig: &tls.Config{RootCAs: pool},
	}
	res, err := (&http.Client{Transport: tr}).Get("https://" + forgedHost + "/whoami")
	if err != nil {
		t.Fatalf("信任网关 CA 后应能完成 TLS 握手: %v", err)
	}
	defer res.Body.Close()
	got, _ := io.ReadAll(res.Body)
	if string(got) != "laptop-1/tls:"+forgedHost {
		t.Fatalf("TLS 请求应是 laptop-1/tls:%s,实际 %q", forgedHost, got)
	}
}

// 不信任网关 CA 的客户端 → TLS 校验失败(证明证书没被无脑接受)。
func TestTLSRejectedWithoutCA(t *testing.T) {
	signer, pub := genClientKey(t)
	s := newTestSSHServer(t, []string{"unix:/run/ccgw.sock"}, []AuthorizedKey{{ID: "laptop-1", Key: pub}})
	addr := listen(t, s)
	serveTunnelHTTP(t, s)

	client, err := dialSSH(addr, signer)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	tr := &http.Transport{
		Dial:            func(network, addr string) (net.Conn, error) { return client.Dial("unix", "/run/ccgw.sock") },
		TLSClientConfig: &tls.Config{RootCAs: x509.NewCertPool()}, // 空信任库
	}
	if res, err := (&http.Client{Transport: tr}).Get("https://" + forgedHost + "/whoami"); err == nil {
		res.Body.Close()
		t.Fatal("未信任网关 CA 时不应通过 TLS 校验")
	}
}

// 同一个网关同时接受两种形态:tcp 目标走明文、unix 目标走 TLS(靠首字节嗅探,不靠配置)。
func TestBothTransportsCoexist(t *testing.T) {
	signer, pub := genClientKey(t)
	s := newTestSSHServer(t, []string{"127.0.0.1:8788", "unix:/run/ccgw.sock"},
		[]AuthorizedKey{{ID: "laptop-1", Key: pub}})
	addr := listen(t, s)
	serveTunnelHTTP(t, s)

	client, err := dialSSH(addr, signer)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	plain := &http.Client{Transport: &http.Transport{
		Dial: func(network, addr string) (net.Conn, error) { return client.Dial("tcp", "127.0.0.1:8788") },
	}}
	res, err := plain.Get("http://gateway/whoami")
	if err != nil {
		t.Fatalf("明文形态应可用: %v", err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if string(body) != "laptop-1/plain" {
		t.Fatalf("明文形态实际 %q", body)
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(readFile(t, s.ca.certPath))
	secure := &http.Client{Transport: &http.Transport{
		Dial:            func(network, addr string) (net.Conn, error) { return client.Dial("unix", "/run/ccgw.sock") },
		TLSClientConfig: &tls.Config{RootCAs: pool},
	}}
	res2, err := secure.Get("https://" + forgedHost + "/whoami")
	if err != nil {
		t.Fatalf("TLS 形态应可用: %v", err)
	}
	body2, _ := io.ReadAll(res2.Body)
	res2.Body.Close()
	if string(body2) != "laptop-1/tls:"+forgedHost {
		t.Fatalf("TLS 形态实际 %q", body2)
	}
}

// host key 不存在 → 自动生成(0600),重启复用同一把(指纹稳定)。
func TestHostKeyAutoGenerated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hostkey")
	cfg := SSHConfig{HostKey: path, CAKey: filepath.Join(dir, "ca_key"), PermitTargets: []string{"127.0.0.1:1"}}

	s1, err := newSSHServer(cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("host key 应已落盘: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("host key 权限应为 0600,实际 %o", perm)
	}
	if _, err := os.Stat(path + ".pub"); err != nil {
		t.Fatalf(".pub 应已落盘: %v", err)
	}

	s2, err := newSSHServer(cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	if s1.fingerprint != s2.fingerprint {
		t.Fatalf("重启后应复用同一把 host key: %s != %s", s1.fingerprint, s2.fingerprint)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// 改 config.yaml → 公钥列表热重载(吊销立即生效、新设备立即可用)。
func TestAuthorizedKeysHotReload(t *testing.T) {
	signerA, pubA := genClientKey(t)
	signerB, pubB := genClientKey(t)
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")

	writeCfg := func(entries string) {
		t.Helper()
		if err := os.WriteFile(cfgPath, []byte("ssh:\n  authorized_keys:\n"+entries), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeCfg("    - id: dev-a\n      key: \"" + pubA[:len(pubA)-1] + "\"\n")

	auth, err := newAuthorizedKeys([]AuthorizedKey{{ID: "dev-a", Key: pubA}}, cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := auth.lookup(signerA.PublicKey()); !ok {
		t.Fatal("dev-a 应在列表中")
	}

	// 换成只剩 dev-b,并把 mtime 推到未来以确保被视为「已修改」
	writeCfg("    - id: dev-b\n      key: \"" + pubB[:len(pubB)-1] + "\"\n")
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(cfgPath, future, future); err != nil {
		t.Fatal(err)
	}

	if _, ok := auth.lookup(signerA.PublicKey()); ok {
		t.Fatal("dev-a 已吊销,应立即失效")
	}
	if id, ok := auth.lookup(signerB.PublicKey()); !ok || id != "dev-b" {
		t.Fatalf("dev-b 应热重载生效,got %q %v", id, ok)
	}
}
