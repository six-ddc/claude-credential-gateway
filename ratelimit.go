package main

// 订阅限额(5h/7d)被动采样:
//
// Anthropic 每个成功响应都带 anthropic-ratelimit-unified-* 头,网关本来就经手响应,
// 读几行头即可「白嫖」出额度,零额外请求。单上游凭证 → 一个进程内全局状态就够,不落库。
//
// 头有两套并存,按场景下发,读取时都兜底:
//
//	per-window(信息最全,优先):anthropic-ratelimit-unified-5h-status / -5h-reset / -5h-utilization / -7d-*
//	聚合:                       anthropic-ratelimit-unified-status / -reset

import (
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// RateWindow 是某一刻从响应头采样到的订阅限额快照。
type RateWindow struct {
	Status5h string    `json:"status_5h,omitempty"` // allowed / allowed_warning / rejected
	Util5h   float64   `json:"util_5h"`             // 0–1 已用比例
	Reset5h  time.Time `json:"reset_5h,omitempty"`
	Status7d string    `json:"status_7d,omitempty"`
	Util7d   float64   `json:"util_7d"`
	Reset7d  time.Time `json:"reset_7d,omitempty"`

	UpdatedAt time.Time `json:"updated_at"`
}

// rateState 保存最近一次采样到的限额快照(单上游凭证,全局唯一)。
var rateState atomic.Pointer[RateWindow]

// sampleRateLimit 从一次响应的头里采样订阅限额并更新全局状态。
// 没有任何相关头时(比如非 /v1/messages 响应)返回 nil 且不覆盖旧状态。
func sampleRateLimit(h http.Header) *RateWindow {
	get := func(suffix string) string {
		// 先读 per-window 形式,空了再退回聚合形式。
		if v := h.Get("anthropic-ratelimit-unified-" + suffix); v != "" {
			return v
		}
		return ""
	}

	w := &RateWindow{
		Status5h: firstNonEmpty(get("5h-status"), get("status")),
		Status7d: get("7d-status"),
		Util5h:   parseFloat(get("5h-utilization")),
		Util7d:   parseFloat(get("7d-utilization")),
		Reset5h:  parseResetTime(firstNonEmpty(get("5h-reset"), get("reset"))),
		Reset7d:  parseResetTime(get("7d-reset")),
	}

	// 一个限额头都没有 → 这次响应不携带额度信息,别用空快照覆盖。
	if w.Status5h == "" && w.Status7d == "" &&
		w.Util5h == 0 && w.Util7d == 0 &&
		w.Reset5h.IsZero() && w.Reset7d.IsZero() {
		return nil
	}

	w.UpdatedAt = time.Now()
	rateState.Store(w)
	return w
}

// logRateLimit 把采样到的额度打成日志;status 非 allowed 时升级为醒目告警。
func logRateLimit(w *RateWindow) {
	if w == nil {
		return
	}
	msg := "[ratelimit] 5h=" + pct(w.Util5h) + resetHint(" reset5h=", w.Reset5h) +
		" 7d=" + pct(w.Util7d) + resetHint(" reset7d=", w.Reset7d)
	switch w.Status5h {
	case "", "allowed":
		log.Printf("%s", msg)
	case "allowed_warning":
		log.Printf("⚠ %s status=allowed_warning(接近 5h 限额)", msg)
	case "rejected":
		log.Printf("🛑 %s status=rejected(5h 限额已耗尽)", msg)
	default:
		log.Printf("%s status=%s", msg, w.Status5h)
	}
}

// parseResetTime 把 reset 头解析成时间。Anthropic 既可能下发秒级 Unix 时间戳,
// 也可能下发毫秒级(或 RFC3339 字符串),这里都兜底。
func parseResetTime(v string) time.Time {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		if n > 1e12 { // 毫秒级
			return time.UnixMilli(n)
		}
		return time.Unix(n, 0) // 秒级
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t
	}
	return time.Time{}
}

func parseFloat(v string) float64 {
	f, _ := strconv.ParseFloat(strings.TrimSpace(v), 64)
	return f
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// pct 把 0–1 比例格式化成百分比,例如 0.634 → "63%"。
func pct(f float64) string {
	return strconv.FormatFloat(f*100, 'f', 0, 64) + "%"
}

// resetHint 在重置时间有效时返回 " 前缀=HH:MM",否则空串。
func resetHint(prefix string, t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return prefix + t.Local().Format("15:04")
}
