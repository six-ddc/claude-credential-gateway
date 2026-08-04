package main

import (
	"net/http"
	"testing"
)

// 客户端的凭证企图不能到上游:x-api-key 必须剥掉,否则上游拿它校验 → 401。
// (设备上残留 ANTHROPIC_API_KEY 时,claude 就会改发 x-api-key。)
func TestClientCredentialsStripped(t *testing.T) {
	src := http.Header{}
	src.Set("x-api-key", "sk-ant-api03-placeholder")
	src.Set("authorization", "Bearer sk-ant-oat01-placeholder")
	src.Set("anthropic-beta", "oauth-2025-04-20")
	src.Set("content-length", "123")
	src.Set("connection", "keep-alive")

	dst := http.Header{}
	copyHeaders(dst, src)

	if got := dst.Get("x-api-key"); got != "" {
		t.Fatalf("x-api-key 必须被剥掉,实际 %q", got)
	}
	for _, h := range []string{"content-length", "connection"} {
		if got := dst.Get(h); got != "" {
			t.Fatalf("%s 应被剥掉,实际 %q", h, got)
		}
	}
	// 业务头要原样透传(betas 决定上游行为,不能丢)
	if got := dst.Get("anthropic-beta"); got != "oauth-2025-04-20" {
		t.Fatalf("anthropic-beta 应透传,实际 %q", got)
	}
	// Authorization 允许被复制过来,因为随后会被真凭证整个覆盖
	upReq, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", nil)
	copyHeaders(upReq.Header, src)
	upReq.Header.Set("authorization", "Bearer REAL")
	if got := upReq.Header.Get("authorization"); got != "Bearer REAL" {
		t.Fatalf("Authorization 应被真凭证覆盖,实际 %q", got)
	}
}
