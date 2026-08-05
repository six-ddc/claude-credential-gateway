// Command claude-credential-gateway 是一个凭证隔离网关(仅订阅模式):
//
// 把 claude ssh 的「占位凭证在外、真凭证在网关注入」做成网关:客户端发占位 token,
// 网关识别设备后透明转发,只把 Authorization 换成你订阅的真 OAuth token。
//
// 同时打印每个请求的 model、token 使用量与订阅限额(从上游响应解析,支持 SSE 流式与普通 JSON)。
//
// 合规底线:注入的是【你自己的】订阅 token、给【你自己的】设备用,不是分给别人。
package main

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/tidwall/gjson"
)

// Usage 是从上游响应解析出的 token 使用量。
type Usage struct {
	Model       string
	Input       int64
	Output      int64
	CacheCreate int64
	CacheRead   int64
}

var (
	cfg         *Config
	upstreamURL *url.URL
	httpClient  *http.Client
	caCertPEM   []byte // TLS 终结 CA 的证书,经 /ca 发给已认证的设备
)

// 逐跳头(hop-by-hop)与不应透传的头,在透明转发时剥掉。
// 注:Authorization 会在注入真凭证时被整个覆盖,无需在此单独剥离。
var stripHeaders = map[string]bool{
	"connection":        true,
	"proxy-connection":  true,
	"keep-alive":        true,
	"transfer-encoding": true,
	"upgrade":           true,
	"content-length":    true, // 由 http.NewRequest 按 body 重新设置
	// 设备上残留的 ANTHROPIC_API_KEY 会让客户端改发 x-api-key。它优先级高于
	// Authorization,不剥掉的话上游拿假 key 校验 → 401 "API key is invalid"。
	// 凭证一律由网关注入,客户端的任何凭证企图都不该到上游。
	"x-api-key": true,
	// 代理形态特有:这是客户端发给【代理】的,不该转给上游。
	"proxy-authorization": true,
}

func main() {
	log.SetFlags(0) // 输出干净,不加时间戳前缀

	c, path, err := loadConfig()
	if err != nil {
		log.Fatalf("✗ 加载配置失败 (%s): %v", path, err)
	}
	cfg = c

	if cfg.Upstream.OAuth == "" {
		log.Fatal("✗ 需要订阅 access token(CLAUDE_GATEWAY_UPSTREAM_OAUTH 或 config.yaml 的 upstream.oauth)")
	}

	u, err := url.Parse(cfg.Upstream.Base)
	if err != nil {
		log.Fatalf("✗ 上游地址无效: %v", err)
	}
	upstreamURL = u

	httpClient = &http.Client{
		Transport: &http.Transport{
			DisableCompression: true, // 不自动解压:逐字节透传给客户端,attestation/编码头不变
			Proxy:              http.ProxyFromEnvironment,
		},
		// 不设全局超时:SSE 流式可能很长
	}

	reloadPath := path
	if os.Getenv("GATEWAY_SSH_AUTHORIZED_KEYS") != "" {
		reloadPath = "" // 公钥来自 env,不做文件热重载
	}
	sshSrv, err := newSSHServer(cfg.SSH, reloadPath)
	if err != nil {
		log.Fatalf("✗ SSH 转发层初始化失败: %v", err)
	}
	if len(cfg.SSH.AuthorizedKeys) == 0 {
		log.Printf("⚠ ssh.authorized_keys 为空:任何设备都连不上,请先登记公钥(改 config.yaml 即生效)")
	}

	// 隧道流量与本地回环共用同一个 HTTP Server;ConnContext 把 SSH 层认证出的
	// device id 写进每个请求的 context —— handler 据此区分「隧道请求」与「本地请求」。
	srv := &http.Server{Handler: http.HandlerFunc(handle), ConnContext: deviceConnContext}

	log.Printf("凭证隔离网关 → %s", upstreamURL.String())
	log.Printf("SSH 转发层(转发-only,唯一对外端口)监听 %s → 白名单 %s",
		cfg.SSH.Addr, strings.Join(cfg.SSH.PermitTargets, ", "))
	log.Printf("SSH host key 指纹: %s(设备首连时比对)", sshSrv.fingerprint)
	log.Printf("TLS 终结 CA: %s(设备经隧道 GET /ca 自取)", sshSrv.ca.certPath)
	caCertPEM = sshSrv.ca.certPEM
	log.Printf("代理: 解密注入 %s;盲转发 %s",
		strings.Join(cfg.Proxy.MITMHosts, ", "), strings.Join(cfg.Proxy.TunnelHosts, ", "))
	log.Printf("注入: 订阅 OAuth token (len=%d)", len(cfg.Upstream.OAuth))
	ids := make([]string, 0, len(cfg.SSH.AuthorizedKeys))
	for _, ak := range cfg.SSH.AuthorizedKeys {
		ids = append(ids, ak.ID)
	}
	log.Printf("可信设备: %s", strings.Join(ids, ", "))

	// 转发 channel 直接进 HTTP Server,全程不监听任何本机 HTTP 端口。
	go func() { log.Fatalf("✗ 隧道 HTTP 退出: %v", srv.Serve(sshSrv.tunnels)) }()
	log.Fatal(sshSrv.listenAndServe())
}

func handle(w http.ResponseWriter, r *http.Request) {
	// 1) 身份来自连接本身:SSH 层公钥认证出的 device id(ConnContext 写入)。
	//    客户端 Authorization 里的占位 token 不参与鉴权,随后会被真凭证整个覆盖。
	device := deviceFrom(r.Context())

	// 唯一入口是 SSH 隧道,所以一切请求都必须带设备身份。
	if device == "" {
		writeError(w, 403, "ssh tunnel required")
		audit(map[string]any{"ts": nowMs(), "ok": false, "reason": "no_tunnel", "path": r.URL.Path})
		return
	}

	// CONNECT 在连接层(serveTunnelConn)就处理掉了,到不了这里 —— 真到了说明
	// 分派逻辑有漏,明说比默默当成普通请求转出去强。
	if r.Method == http.MethodConnect {
		writeError(w, 501, "CONNECT should be handled at the tunnel layer")
		return
	}

	switch r.URL.Path {
	case "/status":
		// 最近采样到的订阅限额快照(5h/7d 还剩多少、几点重置)
		writeStatus(w)
		return
	case "/ca":
		// TLS 终结用的 CA 证书。设备接入时经【已认证的隧道】取它,
		// 就不需要给设备开任何登录网关机的通道(公钥登记由管理员在网关侧做)。
		w.Header().Set("content-type", "application/x-pem-file")
		w.Write(caCertPEM)
		return
	}

	// 明文 HTTP 经代理时是绝对形式请求(GET http://host/path)。目标不是我们打算
	// 解密的主机就拒掉 —— 否则真凭证会被注入到一个跟 Anthropic 无关的目标上。
	// (https 走 CONNECT,在上面就分流了,到不了这里。)
	if r.URL.IsAbs() && !hostInList(cfg.Proxy.MITMHosts, hostnameOf(r.URL.Host)) {
		writeError(w, 403, "host not permitted: "+r.URL.Host)
		audit(map[string]any{"ts": nowMs(), "ok": false, "reason": "proxy_host",
			"user": device, "host": r.URL.Host})
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, 400, "read body failed")
		return
	}
	_ = r.Body.Close()

	// 2) 模型(仅审计;真正的 token 用量从响应解析)
	reqModel := gjson.GetBytes(body, "model").String()

	// 3) 上游 path —— 原样透传。
	//    以前这里把非 /v1/ 的路径一律改写成 /v1/messages,于是 /api/oauth/usage
	//    (/usage 命令查额度用的)会被悄悄换成一个 GET /v1/messages 打到上游,
	//    客户端拿到的报错跟它请求的端点毫无关系,极难排查。代理形态下客户端
	//    要打哪个端点就转哪个。
	path := r.URL.RequestURI()

	// 4) 构造上游请求 —— 注入真凭证,剥掉客户端凭证企图
	upReq, err := http.NewRequest(r.Method, upstreamURL.Scheme+"://"+upstreamURL.Host+path, bytes.NewReader(body))
	if err != nil {
		writeError(w, 502, "build upstream request failed")
		return
	}
	upReq.Host = upstreamURL.Host

	// 透明转发:保留客户端(真 Claude Code)拼好的所有头(betas/版本/UA/attestation 在 body),
	// 只换 Host + Authorization(占位 → 真订阅 token)。
	copyHeaders(upReq.Header, r.Header)
	upReq.Header.Set("authorization", "Bearer "+cfg.Upstream.OAuth)

	// 5) 转发到上游
	upRes, err := httpClient.Do(upReq)
	if err != nil {
		writeError(w, 502, "upstream error: "+err.Error())
		audit(map[string]any{"ts": nowMs(), "ok": false, "reason": "upstream", "user": device, "err": err.Error()})
		return
	}
	defer upRes.Body.Close()

	status := upRes.StatusCode
	audit(map[string]any{"ts": nowMs(), "ok": true, "user": device, "model": reqModel, "status": status})

	// 被动采样订阅限额(5h/7d):每个响应都带这些头,零额外请求。
	logRateLimit(sampleRateLimit(upRes.Header))

	// 复制响应头并写状态码
	for k, vs := range upRes.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(status)

	// tee:一边逐字节透传给客户端(SSE 不破坏流式),一边缓存副本用于解析 token
	buf := teeStream(w, upRes.Body)

	enc := upRes.Header.Get("content-encoding")
	if status >= 400 {
		// 出错时把上游响应体打出来,看真正原因(429/401/400 的 message)
		text := decodeBody(buf.Bytes(), enc)
		if len(text) > 2000 {
			text = text[:2000]
		}
		log.Printf("[upstream %d] %s", status, text)
		return
	}
	if u := extractUsage(decodeBody(buf.Bytes(), enc), upRes.Header.Get("content-type")); u != nil {
		logUsage(device, reqModel, u)
	}
}

// teeStream 把 src 逐块写给客户端(尽量即时 flush 以保留 SSE 流式),
// 同时把全部字节缓存到返回的 buffer 里用于后续解析。
func teeStream(w http.ResponseWriter, src io.Reader) *bytes.Buffer {
	var buf bytes.Buffer
	flusher, _ := w.(http.Flusher)
	chunk := make([]byte, 32*1024)
	for {
		n, err := src.Read(chunk)
		if n > 0 {
			w.Write(chunk[:n])
			if flusher != nil {
				flusher.Flush()
			}
			buf.Write(chunk[:n])
		}
		if err != nil {
			break
		}
	}
	return &buf
}

// decodeBody 按 content-encoding 解压(仅用于打印/解析;转发给客户端的仍是原始字节)。
func decodeBody(raw []byte, enc string) string {
	switch strings.ToLower(enc) {
	case "gzip":
		if r, err := gzip.NewReader(bytes.NewReader(raw)); err == nil {
			if out, err := io.ReadAll(r); err == nil {
				return string(out)
			}
		}
	case "br":
		if out, err := io.ReadAll(brotli.NewReader(bytes.NewReader(raw))); err == nil {
			return string(out)
		}
	case "deflate":
		if r, err := zlib.NewReader(bytes.NewReader(raw)); err == nil {
			if out, err := io.ReadAll(r); err == nil {
				return string(out)
			}
		}
	}
	return string(raw)
}

// extractUsage 用 gjson 从响应体解析 token 使用量(支持 SSE 流 + 普通 JSON)。
func extractUsage(text, contentType string) *Usage {
	if strings.Contains(contentType, "event-stream") {
		// SSE:input/cache 在 message_start.message.usage;最终 output 在最后一个 message_delta.usage
		var u Usage
		found := false
		for _, line := range strings.Split(text, "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "data:") {
				continue
			}
			payload := strings.TrimSpace(line[len("data:"):])
			if payload == "" || payload == "[DONE]" {
				continue
			}
			ev := gjson.Parse(payload)
			switch ev.Get("type").String() {
			case "message_start":
				m := ev.Get("message")
				u.Model = m.Get("model").String()
				u.Input = m.Get("usage.input_tokens").Int()
				u.CacheCreate = m.Get("usage.cache_creation_input_tokens").Int()
				u.CacheRead = m.Get("usage.cache_read_input_tokens").Int()
				u.Output = m.Get("usage.output_tokens").Int()
				found = true
			case "message_delta":
				if usage := ev.Get("usage"); usage.Exists() {
					if ot := usage.Get("output_tokens"); ot.Exists() {
						u.Output = ot.Int()
					}
					if it := usage.Get("input_tokens"); it.Exists() {
						u.Input = it.Int()
					}
					found = true
				}
			}
		}
		if !found {
			return nil
		}
		return &u
	}

	// 普通 JSON 响应
	r := gjson.Parse(text)
	if !r.Get("usage").Exists() && !r.Get("model").Exists() {
		return nil
	}
	return &Usage{
		Model:       r.Get("model").String(),
		Input:       r.Get("usage.input_tokens").Int(),
		CacheCreate: r.Get("usage.cache_creation_input_tokens").Int(),
		CacheRead:   r.Get("usage.cache_read_input_tokens").Int(),
		Output:      r.Get("usage.output_tokens").Int(),
	}
}

func logUsage(device, reqModel string, u *Usage) {
	model := u.Model
	if model == "" {
		model = reqModel
	}
	if model == "" {
		model = "?"
	}
	total := u.Input + u.Output + u.CacheCreate + u.CacheRead
	log.Printf("[usage] user=%s model=%s input=%d output=%d cache_create=%d cache_read=%d total=%d",
		device, model, u.Input, u.Output, u.CacheCreate, u.CacheRead, total)
}

func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		if stripHeaders[strings.ToLower(k)] {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

// writeStatus 输出最近采样到的订阅限额快照(JSON)。还没有任何请求经过时返回空对象。
func writeStatus(w http.ResponseWriter) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(200)
	if s := rateState.Load(); s != nil {
		b, _ := json.Marshal(s)
		w.Write(b)
		return
	}
	w.Write([]byte("{}"))
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(code)
	b, _ := json.Marshal(map[string]string{"error": msg})
	w.Write(b)
}

func audit(e map[string]any) {
	b, _ := json.Marshal(e)
	log.Printf("[audit] %s", b)
}

func nowMs() int64 { return time.Now().UnixMilli() }
