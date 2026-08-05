// sshfwd.go 实现转发-only SSH 层(复刻 claude ssh 的传输形态):
//
//   - 公钥认证:pubkey → device id,这是唯一的门禁;
//   - 只接受 direct-tcpip / direct-streamlocal@openssh.com,且目标必须命中白名单;
//   - session 类型一律 Reject → 无 shell / 无 exec / 无 pty(从结构上不存在);
//   - 连接级与 channel 级请求全部丢弃 → 禁 -R 反向转发与其它扩展;
//   - host key 不存在时首启自动生成(ed25519,0600),客户端靠 known_hosts pin 防 MITM;
//   - authorized_keys 热重载:改 config.yaml 即生效,增删设备无需重启。
//
// 转发 channel 不落地、不拨号:直接包装成携带设备身份的 net.Conn,经 channelListener
// 交给进程内 HTTP Server(ConnContext 把 device id 写进每个请求的 context)。
// 首字节嗅探区分两种客户端形态:TLS(ANTHROPIC_UNIX_SOCKET)与明文 HTTP(ANTHROPIC_BASE_URL)。
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

// forwardTarget 是转发白名单里的一个允许目标(sshd PermitOpen 的等价物)。
type forwardTarget struct {
	network string // "tcp" 或 "unix"
	addr    string // host:port 或 socket 路径
}

func parseForwardTarget(s string) forwardTarget {
	if path, ok := strings.CutPrefix(s, "unix:"); ok {
		return forwardTarget{network: "unix", addr: strings.TrimSpace(path)}
	}
	return forwardTarget{network: "tcp", addr: strings.TrimSpace(s)}
}

func parseForwardTargets(list []string) []forwardTarget {
	out := make([]forwardTarget, 0, len(list))
	for _, s := range list {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, parseForwardTarget(s))
		}
	}
	return out
}

// authorizedKeys 维护「pubkey → device id」映射;path 非空时按 config.yaml 的 mtime 热重载。
type authorizedKeys struct {
	mu    sync.Mutex
	path  string // 热重载来源;空 → 固定列表(env 注入或测试)
	mtime time.Time
	keys  map[string]string // string(pubkey.Marshal()) → device id
}

func newAuthorizedKeys(list []AuthorizedKey, reloadPath string) (*authorizedKeys, error) {
	keys, err := parseKeyList(list)
	if err != nil {
		return nil, err
	}
	return &authorizedKeys{path: reloadPath, keys: keys}, nil
}

func parseKeyList(list []AuthorizedKey) (map[string]string, error) {
	m := make(map[string]string, len(list))
	for _, ak := range list {
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(ak.Key))
		if err != nil {
			return nil, fmt.Errorf("解析设备 %q 的公钥失败: %w", ak.ID, err)
		}
		m[string(pub.Marshal())] = ak.ID
	}
	return m, nil
}

// lookup 按公钥查设备 id;每次认证前检查配置文件是否更新,变了就重载。
func (a *authorizedKeys) lookup(key ssh.PublicKey) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.maybeReload()
	id, ok := a.keys[string(key.Marshal())]
	return id, ok
}

func (a *authorizedKeys) maybeReload() {
	if a.path == "" {
		return
	}
	info, err := os.Stat(a.path)
	if err != nil || info.ModTime().Equal(a.mtime) {
		return
	}
	data, err := os.ReadFile(a.path)
	if err != nil {
		log.Printf("⚠ 重载 %s 失败: %v(沿用旧公钥列表)", a.path, err)
		return
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		log.Printf("⚠ 重载 %s 失败: %v(沿用旧公钥列表)", a.path, err)
		return
	}
	keys, err := parseKeyList(c.SSH.AuthorizedKeys)
	if err != nil {
		log.Printf("⚠ 重载 %s 失败: %v(沿用旧公钥列表)", a.path, err)
		return
	}
	a.keys = keys
	a.mtime = info.ModTime()
	log.Printf("已重载 SSH 可信公钥: %d 台设备", len(keys))
}

// loadOrCreateHostKey 加载服务端 host key;文件不存在则自动生成 ed25519 私钥落盘(0600),
// 并顺手写 .pub 便于用 ssh-keygen -lf 打印指纹给设备比对。
func loadOrCreateHostKey(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		data, err = generateHostKey(path)
	}
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(data)
}

func generateHostKey(path string) ([]byte, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(block)
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return nil, err
	}
	if sshPub, err := ssh.NewPublicKey(pub); err == nil {
		_ = os.WriteFile(path+".pub", ssh.MarshalAuthorizedKey(sshPub), 0o644)
		log.Printf("已生成 SSH host key: %s(指纹 %s)", path, ssh.FingerprintSHA256(sshPub))
	}
	return pemBytes, nil
}

// tunnelAddr 标识一条经 SSH 隧道进来的连接:哪台设备、从哪个远端地址。
type tunnelAddr struct {
	device string
	remote string
}

func (a tunnelAddr) Network() string { return "ssh-tunnel" }
func (a tunnelAddr) String() string  { return a.remote + "/" + a.device }

// channelConn 把一个 SSH 转发 channel 包装成 net.Conn,携带设备身份。
//
// deadline 是 no-op:ssh.Channel 不支持。注意这不是纯粹的形式主义 —— Go 的
// http.Server 在 Hijack 时要靠「把读 deadline 设成过去」来打断自己的后台预读,
// 在这里那一步不起作用,Hijack() 会挂死。所以 CONNECT 在 serveTunnelConn 里
// 就地处理,绝不能丢进 handler 再 Hijack。
type channelConn struct {
	ssh.Channel
	addr tunnelAddr
}

func (c *channelConn) LocalAddr() net.Addr                { return c.addr }
func (c *channelConn) RemoteAddr() net.Addr               { return c.addr }
func (c *channelConn) SetDeadline(t time.Time) error      { return nil }
func (c *channelConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *channelConn) SetWriteDeadline(t time.Time) error { return nil }

// peekConn 让首字节被窥探后仍能被完整读到(用于区分 TLS 与明文 HTTP)。
// 身份透传靠 RemoteAddr:tls.Conn 与本类型都会把它委托给底层 channelConn。
type peekConn struct {
	net.Conn
	r io.Reader
}

func (c *peekConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// peekTimeout 是等客户端说第一句话的上限,防止空闲 channel 永久占着 goroutine。
const peekTimeout = 30 * time.Second

// connectPrefix 是 HTTP 代理形态的开场白。
const connectPrefix = "CONNECT "

// serveTunnelConn 窥探开头几个字节,决定这条隧道连接怎么处理,并把该交给 HTTP Server
// 的那些塞回监听器。三种形态:
//
//	0x16        TLS handshake record —— 老的 ANTHROPIC_UNIX_SOCKET 形态,连上来直接握手;
//	"CONNECT "  HTTP 代理形态(HTTPS_PROXY)—— 就地应答并按需 TLS 终结/盲转发;
//	其余        明文 HTTP(取 CA、调试)。
//
// CONNECT 必须在这一层处理干净,不能丢给 http.Server 的 handler 去 Hijack:
// Go 的 hijack 路径要先 abortPendingRead(),它靠把读 deadline 设成过去来打断后台预读,
// 而 channelConn 的 deadline 是 no-op(ssh.Channel 不支持)—— 那个预读永远打不断,
// Hijack() 会一直阻塞到连接被对端关掉为止。
func (s *sshServer) serveTunnelConn(c net.Conn, device string) {
	guard := time.AfterFunc(peekTimeout, func() { c.Close() })
	br := bufio.NewReader(c)

	first, err := br.Peek(1)
	if err != nil {
		guard.Stop()
		c.Close()
		return
	}
	if first[0] == 0x16 && s.tlsConf != nil {
		guard.Stop()
		s.pushTunnel(tls.Server(replayBuffered(c, br), s.tlsConf))
		return
	}

	if head, err := br.Peek(len(connectPrefix)); err == nil && string(head) == connectPrefix {
		req, err := http.ReadRequest(br)
		guard.Stop()
		if err != nil {
			c.Close()
			return
		}
		s.handleConnect(c, br, req, device)
		return
	}

	guard.Stop()
	s.pushTunnel(replayBuffered(c, br))
}

// pushTunnel 把一条连接交给进程内 HTTP Server;服务正在退出就直接关掉。
func (s *sshServer) pushTunnel(c net.Conn) {
	if !s.tunnels.push(c) {
		c.Close()
	}
}

// replayBuffered 把 bufio 里已经预读的字节接回连接头部,让后续读取看到完整的字节流。
func replayBuffered(c net.Conn, br *bufio.Reader) net.Conn {
	n := br.Buffered()
	if n == 0 {
		return c
	}
	head, err := br.Peek(n)
	if err != nil {
		return c
	}
	// Peek 给的是内部缓冲区的切片,要留着用就得拷一份。
	buf := make([]byte, n)
	copy(buf, head)
	return &peekConn{Conn: c, r: io.MultiReader(bytes.NewReader(buf), c)}
}

// channelListener 把转发 channel 当作 Accept 出来的连接,喂给 http.Server.Serve。
type channelListener struct {
	conns     chan net.Conn
	done      chan struct{}
	closeOnce sync.Once
}

func newChannelListener() *channelListener {
	return &channelListener{conns: make(chan net.Conn), done: make(chan struct{})}
}

func (l *channelListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *channelListener) Close() error {
	l.closeOnce.Do(func() { close(l.done) })
	return nil
}

func (l *channelListener) Addr() net.Addr { return tunnelAddr{device: "*", remote: "ssh"} }

// push 把一条隧道连接交给 Accept 侧;监听器已关闭时返回 false。
func (l *channelListener) push(c net.Conn) bool {
	select {
	case l.conns <- c:
		return true
	case <-l.done:
		return false
	}
}

// deviceCtxKey / deviceConnContext / deviceFrom:把连接上的设备身份传进每个 HTTP 请求的 context。
// 认地址而不认具体类型:tls.Conn / peekConn 都会把 RemoteAddr 委托给底层 channelConn,
// 所以无论隧道连接被包了几层,身份都取得到。
type deviceCtxKey struct{}

func deviceConnContext(ctx context.Context, c net.Conn) context.Context {
	if a, ok := c.RemoteAddr().(tunnelAddr); ok {
		return context.WithValue(ctx, deviceCtxKey{}, a.device)
	}
	return ctx
}

func deviceFrom(ctx context.Context) string {
	s, _ := ctx.Value(deviceCtxKey{}).(string)
	return s
}

// sshServer 是转发-only SSH 服务:唯一对外端口,只当隧道用。
type sshServer struct {
	conf        *ssh.ServerConfig
	addr        string
	permit      []forwardTarget
	fingerprint string
	tunnels     *channelListener // 转发 channel 从这里流向进程内 HTTP Server
	tlsConf     *tls.Config      // TLS 终结(ANTHROPIC_UNIX_SOCKET 形态)
	ca          *certAuthority
}

// permitted 判断客户端声明的转发目标是否在白名单内。
func (s *sshServer) permitted(network, addr string) bool {
	for _, t := range s.permit {
		if t.network == network && t.addr == addr {
			return true
		}
	}
	return false
}

func newSSHServer(sc SSHConfig, reloadPath string) (*sshServer, error) {
	signer, err := loadOrCreateHostKey(sc.HostKey)
	if err != nil {
		return nil, fmt.Errorf("加载 host key %s: %w", sc.HostKey, err)
	}
	auth, err := newAuthorizedKeys(sc.AuthorizedKeys, reloadPath)
	if err != nil {
		return nil, err
	}
	ca, err := loadOrCreateCA(sc.CAKey)
	if err != nil {
		return nil, fmt.Errorf("加载 TLS 终结 CA %s: %w", sc.CAKey, err)
	}
	tlsConf, err := ca.serverTLSConfig()
	if err != nil {
		return nil, fmt.Errorf("签发 %s 叶证书: %w", forgedHost, err)
	}
	conf := &ssh.ServerConfig{
		PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if id, ok := auth.lookup(key); ok {
				return &ssh.Permissions{Extensions: map[string]string{"device": id}}, nil
			}
			audit(map[string]any{"ts": nowMs(), "ok": false, "reason": "ssh_auth",
				"user": meta.User(), "addr": meta.RemoteAddr().String(),
				"fingerprint": ssh.FingerprintSHA256(key)})
			return nil, fmt.Errorf("unknown public key for %q", meta.User())
		},
	}
	conf.AddHostKey(signer)
	return &sshServer{
		conf:        conf,
		addr:        sc.Addr,
		permit:      parseForwardTargets(sc.PermitTargets),
		fingerprint: ssh.FingerprintSHA256(signer.PublicKey()),
		tunnels:     newChannelListener(),
		tlsConf:     tlsConf,
		ca:          ca,
	}, nil
}

func (s *sshServer) listenAndServe() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	return s.serve(ln)
}

func (s *sshServer) serve(ln net.Listener) error {
	for {
		nc, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handleConn(nc)
	}
}

func (s *sshServer) handleConn(nc net.Conn) {
	defer nc.Close()
	sc, chans, reqs, err := ssh.NewServerConn(nc, s.conf)
	if err != nil {
		return // 握手/认证失败已在 PublicKeyCallback 里审计
	}
	defer sc.Close()
	device := sc.Permissions.Extensions["device"]
	audit(map[string]any{"ts": nowMs(), "ok": true, "event": "ssh_connect",
		"user": device, "addr": sc.RemoteAddr().String()})

	// 连接级请求(tcpip-forward 等)全拒 → 禁 -R 反向转发。
	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		switch newCh.ChannelType() {
		case "direct-tcpip":
			var p struct {
				Host     string
				Port     uint32
				OrigHost string
				OrigPort uint32
			}
			if err := ssh.Unmarshal(newCh.ExtraData(), &p); err != nil {
				newCh.Reject(ssh.Prohibited, "bad direct-tcpip payload")
				continue
			}
			target := net.JoinHostPort(p.Host, strconv.Itoa(int(p.Port)))
			if !s.permitted("tcp", target) {
				s.rejectTarget(newCh, device, target)
				continue
			}
			s.acceptForward(newCh, sc, device, target)
		case "direct-streamlocal@openssh.com":
			var p struct {
				Path      string
				Reserved  string
				Reserved2 uint32
			}
			if err := ssh.Unmarshal(newCh.ExtraData(), &p); err != nil {
				newCh.Reject(ssh.Prohibited, "bad direct-streamlocal payload")
				continue
			}
			if !s.permitted("unix", p.Path) {
				s.rejectTarget(newCh, device, p.Path)
				continue
			}
			s.acceptForward(newCh, sc, device, p.Path)
		default:
			// session(shell/exec/pty)与其它一切 channel 都不存在。
			newCh.Reject(ssh.Prohibited, "forwarding only")
		}
	}
}

func (s *sshServer) rejectTarget(newCh ssh.NewChannel, device, target string) {
	audit(map[string]any{"ts": nowMs(), "ok": false, "reason": "ssh_target",
		"user": device, "target": target})
	newCh.Reject(ssh.Prohibited, "target not permitted")
}

// acceptForward 接受一个白名单内的转发 channel,包装成携带设备身份的连接,
// 交给进程内 HTTP Server(不拨号、不出进程)。
func (s *sshServer) acceptForward(newCh ssh.NewChannel, sc *ssh.ServerConn, device, target string) {
	ch, chReqs, err := newCh.Accept()
	if err != nil {
		return
	}
	// channel 级请求同样全拒。
	go ssh.DiscardRequests(chReqs)
	audit(map[string]any{"ts": nowMs(), "ok": true, "event": "ssh_forward",
		"user": device, "target": target})
	conn := &channelConn{Channel: ch, addr: tunnelAddr{device: device, remote: sc.RemoteAddr().String()}}
	// 嗅探要等客户端先说话,放到独立 goroutine,别卡住这条 SSH 连接的 channel 分发循环。
	go s.serveTunnelConn(conn, device)
}
