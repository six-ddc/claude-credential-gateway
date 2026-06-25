package main

import (
	"net/http"
	"testing"
	"time"
)

func TestSampleRateLimit_PerWindow(t *testing.T) {
	rateState.Store(nil)
	h := http.Header{}
	h.Set("anthropic-ratelimit-unified-5h-status", "allowed_warning")
	h.Set("anthropic-ratelimit-unified-5h-utilization", "0.634")
	h.Set("anthropic-ratelimit-unified-5h-reset", "1750000000") // 秒级
	h.Set("anthropic-ratelimit-unified-7d-utilization", "0.21")

	w := sampleRateLimit(h)
	if w == nil {
		t.Fatal("expected a sample, got nil")
	}
	if w.Status5h != "allowed_warning" {
		t.Errorf("Status5h = %q", w.Status5h)
	}
	if w.Util5h != 0.634 || w.Util7d != 0.21 {
		t.Errorf("Util5h=%v Util7d=%v", w.Util5h, w.Util7d)
	}
	if w.Reset5h.Unix() != 1750000000 {
		t.Errorf("Reset5h = %v", w.Reset5h)
	}
	if rateState.Load() != w {
		t.Error("global state not updated")
	}
}

func TestSampleRateLimit_AggregatedFallback(t *testing.T) {
	h := http.Header{}
	h.Set("anthropic-ratelimit-unified-status", "allowed")
	h.Set("anthropic-ratelimit-unified-reset", "1750000000")

	w := sampleRateLimit(h)
	if w == nil || w.Status5h != "allowed" || w.Reset5h.Unix() != 1750000000 {
		t.Fatalf("aggregated fallback failed: %+v", w)
	}
}

func TestSampleRateLimit_NoHeaders(t *testing.T) {
	if w := sampleRateLimit(http.Header{}); w != nil {
		t.Errorf("expected nil for no headers, got %+v", w)
	}
}

func TestParseResetTime(t *testing.T) {
	if got := parseResetTime("1750000000"); got.Unix() != 1750000000 {
		t.Errorf("seconds: %v", got)
	}
	if got := parseResetTime("1750000000000"); got.UnixMilli() != 1750000000000 {
		t.Errorf("millis: %v", got)
	}
	if got := parseResetTime("2026-06-25T14:00:00Z"); got.UTC() != time.Date(2026, 6, 25, 14, 0, 0, 0, time.UTC) {
		t.Errorf("rfc3339: %v", got)
	}
	if got := parseResetTime(""); !got.IsZero() {
		t.Errorf("empty should be zero: %v", got)
	}
}
