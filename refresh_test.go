package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeClaude 造一个假的 claude 可执行文件:校验网关传下来的环境,然后像真的那样
// 把新凭证写进 $CLAUDE_CONFIG_DIR。每次被调用都往 countPath 追加一行,用于数调用次数。
//
// 用假二进制而不是真 claude,才能在没有网络、也不动任何真凭证的前提下测完整条刷新链路。
func fakeClaude(t *testing.T, newToken string, countPath string, exitCode int) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "claude")
	expires := time.Now().Add(8 * time.Hour).UnixMilli()
	refreshExpires := time.Now().Add(30 * 24 * time.Hour).UnixMilli()

	script := fmt.Sprintf(`#!/bin/sh
echo x >> %q
# 网关必须把这些原样传下来,少一个都刷不动
[ "$1" = "auth" ] && [ "$2" = "login" ] || { echo "bad args: $*"; exit 90; }
[ -n "$CLAUDE_CODE_OAUTH_REFRESH_TOKEN" ] || { echo "missing refresh token"; exit 91; }
[ -n "$CLAUDE_CODE_OAUTH_SCOPES" ] || { echo "missing scopes"; exit 92; }
[ "$IS_SANDBOX" = "1" ] || { echo "missing IS_SANDBOX"; exit 93; }
[ -n "$CLAUDE_CONFIG_DIR" ] || { echo "missing config dir"; exit 94; }
# 网关的环境不该被继承下来:代理会让子进程绕回网关自己,API key 会让它走别的鉴权分支
[ -z "$HTTPS_PROXY" ] || { echo "inherited HTTPS_PROXY"; exit 95; }
[ -z "$ANTHROPIC_API_KEY" ] || { echo "inherited ANTHROPIC_API_KEY"; exit 96; }
if [ %d -ne 0 ]; then echo "Login failed: simulated"; exit %d; fi
cat > "$CLAUDE_CONFIG_DIR/.credentials.json" <<EOF
{"claudeAiOauth":{"accessToken":%q,"refreshToken":"sk-ant-ort01-rotated",
"expiresAt":%d,"refreshTokenExpiresAt":%d,
"scopes":["user:inference","user:profile"],"subscriptionType":"max"}}
EOF
echo "Login successful."
`, countPath, exitCode, exitCode, newToken, expires, refreshExpires)

	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return bin
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func readFileString(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func refreshCount(t *testing.T, countPath string) int {
	t.Helper()
	data, err := os.ReadFile(countPath)
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	return len(strings.Fields(string(data)))
}

// newRefreshableTokens 造一份「快过期」的网关专属凭证,并接上假 claude。
func newRefreshableTokens(t *testing.T, remaining time.Duration, newToken string, exitCode int) (ts *tokenSource, countPath, bin string) {
	t.Helper()
	dir := t.TempDir()
	credPath := filepath.Join(dir, ".credentials.json")
	writeCreds(t, credPath, "sk-ant-oat01-old", time.Now().Add(remaining), "user:inference", "user:profile")

	countPath = filepath.Join(dir, "calls.txt")
	bin = fakeClaude(t, newToken, countPath, exitCode)

	ts, err := newTokenSource("", credPath, boolPtr(true), bin)
	if err != nil {
		t.Fatal(err)
	}
	return ts, countPath, bin
}

// 快过期就该自己刷:fork claude auth login,子进程写回凭证,网关重读拿到新 token。
func TestRefreshRunsClaudeAndPicksUpNewToken(t *testing.T) {
	ts, countPath, _ := newRefreshableTokens(t, 5*time.Minute, "sk-ant-oat01-refreshed", 0)

	ts.ensureFresh("")

	if got := ts.get(); got != "sk-ant-oat01-refreshed" {
		t.Fatalf("刷新后 token = %q,想要 sk-ant-oat01-refreshed", got)
	}
	if n := refreshCount(t, countPath); n != 1 {
		t.Fatalf("应当只 fork 一次 claude,实际 %d 次", n)
	}
	// 轮换后的 refresh token 也要跟着进内存,否则下一次刷新会拿废的那个去刷。
	if ts.refreshToken != "sk-ant-ort01-rotated" {
		t.Fatalf("轮换后的 refreshToken 应当被读回,实际 %q", ts.refreshToken)
	}
}

// 还早就别刷:刷新要 fork 进程、还会作废手里的 token,不能每个请求都来一遍。
func TestRefreshSkippedWhenNotExpiringSoon(t *testing.T) {
	ts, countPath, _ := newRefreshableTokens(t, 8*time.Hour, "sk-ant-oat01-refreshed", 0)

	ts.ensureFresh("")

	if got := ts.get(); got != "sk-ant-oat01-old" {
		t.Fatalf("还早不该刷,token 不该变,实际 %q", got)
	}
	if n := refreshCount(t, countPath); n != 0 {
		t.Fatalf("不该 fork claude,实际 %d 次", n)
	}
}

// 刷新是临界区:并发请求全在锁上等,只有一个真去 fork,其余拿到锁后复查即返回。
func TestRefreshIsSingleFlight(t *testing.T) {
	ts, countPath, _ := newRefreshableTokens(t, 5*time.Minute, "sk-ant-oat01-refreshed", 0)

	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ts.ensureFresh("")
		}()
	}
	wg.Wait()

	if n := refreshCount(t, countPath); n != 1 {
		t.Fatalf("12 个并发请求应当只触发一次刷新,实际 %d 次", n)
	}
	if got := ts.get(); got != "sk-ant-oat01-refreshed" {
		t.Fatalf("并发请求都该拿到新 token,实际 %q", got)
	}
}

// 401 兜底:调用方带着刚被拒的那个 token 进来,强制刷一次。
// 但排在后面的请求发现 token 已经换过了,就不该再 fork 一次。
func TestRefreshOn401OnlyOncePerStaleToken(t *testing.T) {
	// 有效期还很长 —— 这条路径靠的是 stale 参数,不是到期判断
	ts, countPath, _ := newRefreshableTokens(t, 8*time.Hour, "sk-ant-oat01-refreshed", 0)

	stale := ts.get()
	ts.ensureFresh(stale)
	if got := ts.get(); got != "sk-ant-oat01-refreshed" {
		t.Fatalf("401 后应当刷出新 token,实际 %q", got)
	}

	ts.ensureFresh(stale) // 后到的请求带着同一个废 token
	if n := refreshCount(t, countPath); n != 1 {
		t.Fatalf("同一个废 token 只该触发一次刷新,实际 %d 次", n)
	}
}

// 回归测试:刷新【成功】但 401 依旧时,也必须被拦住。
//
// 这是最容易漏的一条 —— 退避只管失败,而账号被降级/吊销时刷新会一直「成功」,401 却不消失。
// 那时每个 401 都走「token 变了 → 下一个请求还是 401 → 再刷」,而刷新本身又立即作废上一个
// access token,于是网关一边制造 401、一边被 401 驱动着 fork,凭证反复轮换。
// 实测过没有这道闸门时:并发 3 秒能 fork 出 250+ 个 claude 进程。
func TestRefreshRateLimitedEvenWhenItKeepsSucceeding(t *testing.T) {
	dir := t.TempDir()
	credPath := filepath.Join(dir, ".credentials.json")
	writeCreds(t, credPath, "sk-ant-oat01-old", time.Now().Add(8*time.Hour), "user:profile")
	countPath := filepath.Join(dir, "calls.txt")

	// 假 claude 每次都写一个【不同】的 token,所以每次刷新都算成功、退避永远为零。
	bin := filepath.Join(dir, "claude")
	script := "#!/bin/sh\n" +
		"echo x >> " + countPath + "\n" +
		"n=$(wc -l < " + countPath + " | tr -d ' ')\n" +
		"cat > \"$CLAUDE_CONFIG_DIR/.credentials.json\" <<EOF\n" +
		"{\"claudeAiOauth\":{\"accessToken\":\"sk-ant-oat01-gen$n\",\"refreshToken\":\"sk-ant-ort01-r$n\"," +
		"\"expiresAt\":" + itoa(time.Now().Add(8*time.Hour).UnixMilli()) + "," +
		"\"refreshTokenExpiresAt\":" + itoa(time.Now().Add(30*24*time.Hour).UnixMilli()) + "," +
		"\"scopes\":[\"user:inference\",\"user:profile\"],\"subscriptionType\":\"max\"}}\n" +
		"EOF\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}

	ts, err := newTokenSource("", credPath, boolPtr(true), bin)
	if err != nil {
		t.Fatal(err)
	}

	// 模拟 401 风暴:每次都拿「刚被拒的那个 token」进来,而且每次都确实是最新的。
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ts.ensureFresh(ts.get())
		}()
	}
	wg.Wait()
	for i := 0; i < 20; i++ {
		ts.ensureFresh(ts.get()) // 串行的也一样,不能靠并发去重蒙混过关
	}

	if n := refreshCount(t, countPath); n != 1 {
		t.Fatalf("最小刷新间隔应当把 60 次 401 收敛到 1 次 fork,实际 %d 次", n)
	}
}

// 刷不动的时候要退避:refresh token 真废了的话,不退避就变成每个请求 fork 一个进程。
func TestRefreshBacksOffAfterFailure(t *testing.T) {
	ts, countPath, claudeBin := newRefreshableTokens(t, 5*time.Minute, "sk-ant-oat01-refreshed", 1)

	ts.ensureFresh("")
	if got := ts.get(); got != "sk-ant-oat01-old" {
		t.Fatalf("刷新失败应沿用旧 token,实际 %q", got)
	}
	if ts.currentBackoff() < refreshBackoffMin {
		t.Fatalf("失败后应当进入退避,实际 %v", ts.currentBackoff())
	}

	for i := 0; i < 5; i++ {
		ts.ensureFresh("")
	}
	if n := refreshCount(t, countPath); n != 1 {
		t.Fatalf("退避期内不该反复 fork,实际 %d 次", n)
	}

	// 退避必须能恢复。卡死的退避 = 自刷新永久静默失效,症状和「凭证到期没人管」
	// 一模一样,极难查 —— 所以这条要单独钉住。
	// 让 claude 这次能成功(比如网络恢复了),并把冷却期拨到过去,等价于「等够了」。
	if err := os.WriteFile(claudeBin, []byte(readFileString(t, fakeClaude(t, "sk-ant-oat01-recovered", countPath, 0))), 0o700); err != nil {
		t.Fatal(err)
	}
	ts.mu.Lock()
	ts.lastRefresh = time.Now().Add(-time.Hour)
	ts.mu.Unlock()

	ts.ensureFresh("")
	if got := ts.get(); got != "sk-ant-oat01-recovered" {
		t.Fatalf("退避过去后应当重试成功,实际 token = %q", got)
	}
	if ts.currentBackoff() != 0 {
		t.Fatalf("刷新成功后退避应当归零,实际 %v", ts.currentBackoff())
	}
}

// 三态开关的默认值随凭证来源走。这条最关键:显式 credentials 是网关专属的,
// 没别人会替它续命,所以默认就该开。
func TestRefreshDefaultsOnForExplicitCredentials(t *testing.T) {
	dir := t.TempDir()
	credPath := filepath.Join(dir, ".credentials.json")
	writeCreds(t, credPath, "sk-ant-oat01-old", time.Now().Add(8*time.Hour), "user:profile")
	bin := fakeClaude(t, "sk-ant-oat01-new", filepath.Join(dir, "calls.txt"), 0)

	ts, err := newTokenSource("", credPath, nil, bin) // nil = 没配 upstream.refresh
	if err != nil {
		t.Fatal(err)
	}
	if !ts.refreshEnabled() {
		t.Fatal("显式配了 upstream.credentials 时自刷新应当默认开启")
	}
}

// 回退到本机 claude 的凭证时默认【关】:那份的主人是本机 claude,续命本来就归它,
// 网关去刷会轮换掉它的 refresh token。
func TestRefreshDefaultsOffForFallbackCredentials(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.Mkdir(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeCreds(t, filepath.Join(home, ".claude", ".credentials.json"),
		"sk-ant-oat01-home", time.Now().Add(time.Hour), "user:profile")

	ts, err := newTokenSource("", "", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if ts.refreshEnabled() {
		t.Fatal("回退到本机凭证时自刷新必须默认关闭")
	}
}

// 默认开出来的自刷新是「尽力而为」:前提不满足就降级告警,不能因此拦住启动。
// 显式配 true 则是「说到做到」:同样的情况必须启动失败,不能悄悄不干活。
func TestRefreshDefaultDegradesButExplicitFails(t *testing.T) {
	newCreds := func(t *testing.T) string {
		path := filepath.Join(t.TempDir(), ".credentials.json")
		writeCreds(t, path, "sk-ant-oat01-real", time.Now().Add(time.Hour), "user:profile")
		return path
	}

	t.Run("默认开+找不到claude→降级", func(t *testing.T) {
		ts, err := newTokenSource("", newCreds(t), nil, "/nonexistent/claude-binary")
		if err != nil {
			t.Fatalf("默认开的自刷新不该拦住启动: %v", err)
		}
		if ts.refreshEnabled() {
			t.Fatal("claude 都找不到,不该报告自刷新已启用")
		}
	})

	t.Run("显式开+找不到claude→启动失败", func(t *testing.T) {
		_, err := newTokenSource("", newCreds(t), boolPtr(true), "/nonexistent/claude-binary")
		if err == nil {
			t.Fatal("显式要了自刷新却刷不了,应当启动失败而不是悄悄降级")
		}
		if !strings.Contains(err.Error(), "claude_bin") {
			t.Fatalf("报错要提示怎么修,实际: %v", err)
		}
	})

	t.Run("静态token显式开→启动失败", func(t *testing.T) {
		if _, err := newTokenSource("sk-ant-oat01-static", "", boolPtr(true), ""); err == nil {
			t.Fatal("静态 token 没有 refreshToken,配 refresh 应当报错")
		}
	})
}

// 显式配 false 时,ensureFresh 必须是彻底的 no-op —— 那是「网关只读、别人负责续命」的模式。
func TestRefreshDisabledIsNoop(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".credentials.json")
	writeCreds(t, path, "sk-ant-oat01-old", time.Now().Add(time.Minute), "user:profile")

	ts, err := newTokenSource("", path, boolPtr(false), "")
	if err != nil {
		t.Fatal(err)
	}
	if ts.refreshEnabled() {
		t.Fatal("显式配了 upstream.refresh: false 就不该启用自刷新")
	}
	ts.ensureFresh("")       // 快过期也不该有任何动作
	ts.ensureFresh(ts.get()) // 401 路径同理
	if got := ts.get(); got != "sk-ant-oat01-old" {
		t.Fatalf("只读模式下 token 不该被改动,实际 %q", got)
	}
}
