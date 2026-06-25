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
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
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
)

// 逐跳头(hop-by-hop)与不应透传的头,在透明转发时剥掉。
// 注:占位凭证走 Authorization,会在注入真凭证时被整个覆盖,无需在此单独剥离。
var stripHeaders = map[string]bool{
	"connection":        true,
	"proxy-connection":  true,
	"keep-alive":        true,
	"transfer-encoding": true,
	"upgrade":           true,
	"content-length":    true, // 由 http.NewRequest 按 body 重新设置
}

// gatewayKey 取出客户端发来的占位凭证(Authorization: Bearer <占位>),作为前置鉴权的设备 key。
func gatewayKey(r *http.Request) string {
	v := r.Header.Get("authorization")
	if i := strings.IndexByte(v, ' '); i >= 0 { // 去掉 "Bearer " 等 scheme 前缀
		return strings.TrimSpace(v[i+1:])
	}
	return strings.TrimSpace(v)
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

	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	srv := &http.Server{Addr: addr, Handler: http.HandlerFunc(handle)}

	log.Printf("凭证隔离网关 → %s", upstreamURL.String())
	log.Printf("监听 http://%s", addr)
	log.Printf("注入: 订阅 OAuth token (len=%d)", len(cfg.Upstream.OAuth))
	ids := make([]string, 0, len(cfg.Users))
	for _, usr := range cfg.Users {
		ids = append(ids, usr.ID)
	}
	log.Printf("设备/用户 key: %s", strings.Join(ids, ", "))

	log.Fatal(srv.ListenAndServe())
}

func handle(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, 400, "read body failed")
		return
	}
	_ = r.Body.Close()

	// 1) 前置鉴权:客户端发的占位凭证(Authorization: Bearer)就是设备 key。
	//    读完即用于识别设备,随后会被真凭证整个覆盖,绝不外泄。
	user, ok := cfg.Users[gatewayKey(r)]
	if !ok {
		writeError(w, 401, "invalid gateway credential")
		audit(map[string]any{"ts": nowMs(), "ok": false, "reason": "auth", "path": r.URL.Path})
		return
	}

	// 1.5) /status:返回最近采样到的订阅限额快照(5h/7d 还剩多少、几点重置)
	if r.URL.Path == "/status" {
		writeStatus(w)
		return
	}

	// 2) 模型(仅审计;真正的 token 用量从响应解析)
	reqModel := gjson.GetBytes(body, "model").String()

	// 3) 上游 path
	path := "/v1/messages"
	if strings.HasPrefix(r.URL.Path, "/v1/") {
		path = r.URL.RequestURI()
	}

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
		audit(map[string]any{"ts": nowMs(), "ok": false, "reason": "upstream", "user": user.ID, "err": err.Error()})
		return
	}
	defer upRes.Body.Close()

	status := upRes.StatusCode
	audit(map[string]any{"ts": nowMs(), "ok": true, "user": user.ID, "model": reqModel, "status": status})

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
		logUsage(user, reqModel, u)
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

func logUsage(user User, reqModel string, u *Usage) {
	model := u.Model
	if model == "" {
		model = reqModel
	}
	if model == "" {
		model = "?"
	}
	total := u.Input + u.Output + u.CacheCreate + u.CacheRead
	log.Printf("[usage] user=%s model=%s input=%d output=%d cache_create=%d cache_read=%d total=%d",
		user.ID, model, u.Input, u.Output, u.CacheCreate, u.CacheRead, total)
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
