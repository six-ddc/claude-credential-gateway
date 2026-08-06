package main

import (
	"encoding/json"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeCreds 写一份 Claude Code 形状的凭证文件。expiresAt 传零值表示「无有效期信息」。
// refreshTokenExpiresAt 一律写上(默认 30 天,和实测的真实凭证一致)—— 这样它的 json tag
// 才有测试盖着;不写的话 tag 拼错了没有任何用例会红,而它承载的是整套机制里
// 唯一必须人工介入的那条告警。
func writeCreds(t *testing.T, path, token string, expiresAt time.Time, scopes ...string) {
	t.Helper()
	writeCredsAt(t, path, token, expiresAt, time.Now().Add(30*24*time.Hour), scopes...)
}

// writeCredsAt 同上,但两条到期线都由调用方指定。
func writeCredsAt(t *testing.T, path, token string, expiresAt, refreshExpiresAt time.Time, scopes ...string) {
	t.Helper()
	var c claudeCredentials
	c.ClaudeAIOAuth.AccessToken = token
	c.ClaudeAIOAuth.RefreshToken = "sk-ant-ort01-test"
	c.ClaudeAIOAuth.Scopes = scopes
	c.ClaudeAIOAuth.SubscriptionType = "max"
	if !expiresAt.IsZero() {
		c.ClaudeAIOAuth.ExpiresAt = expiresAt.UnixMilli()
	}
	if !refreshExpiresAt.IsZero() {
		c.ClaudeAIOAuth.RefreshTokenExpiresAt = refreshExpiresAt.UnixMilli()
	}
	data, err := json.Marshal(&c)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// newAccessOnlyWatch 造一个只关心 access token 到期的 tokenSource,用于直接驱动告警阶梯。
func newAccessOnlyWatch(remaining time.Duration) *tokenSource {
	return &tokenSource{
		path:         "/tmp/fake",
		accessExpiry: expiryWatch{at: time.Now().Add(remaining), stages: accessExpiryStages},
	}
}

// 凭证文件里的 accessToken 才是注入用的 token,过期时间与订阅信息也要一并读出来。
func TestTokenSourceFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".credentials.json")
	exp := time.Now().Add(8 * time.Hour)
	writeCreds(t, path, "sk-ant-oat01-real", exp, "user:inference", "user:profile")

	ts, err := newTokenSource("", path, boolPtr(false), "")
	if err != nil {
		t.Fatal(err)
	}
	if got := ts.get(); got != "sk-ant-oat01-real" {
		t.Fatalf("token = %q,想要 sk-ant-oat01-real", got)
	}
	if !ts.accessExpiry.at.Equal(time.UnixMilli(exp.UnixMilli())) {
		t.Fatalf("expiresAt = %v,想要 %v", ts.accessExpiry.at, exp)
	}
	if d := ts.describe(); strings.Contains(d, "sk-ant-oat01-real") {
		t.Fatalf("describe() 不能带上 token 本身: %q", d)
	}
}

// 静态 token 形态:没有文件、没有有效期,也就没有热重载和到期告警可做。
func TestTokenSourceStatic(t *testing.T) {
	ts, err := newTokenSource("sk-ant-oat01-static", "", boolPtr(false), "")
	if err != nil {
		t.Fatal(err)
	}
	if got := ts.get(); got != "sk-ant-oat01-static" {
		t.Fatalf("token = %q", got)
	}
	ts.maybeReload() // path 为空,必须是 no-op 而不是 panic
	ts.checkExpiry()
	if ts.accessExpiry.stage != 0 {
		t.Fatalf("无有效期信息不该产生告警,stage = %d", ts.accessExpiry.stage)
	}
	if hint := ts.expiryHint(); hint != "" {
		t.Fatalf("无有效期信息时 expiryHint 应为空,实际 %q", hint)
	}
}

// 两个来源都配 → 启动就失败。静默择一会让「改了配置却没生效」变成一次线上排查。
func TestTokenSourceBothConfiguredIsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".credentials.json")
	writeCreds(t, path, "sk-ant-oat01-real", time.Now().Add(time.Hour), "user:profile")

	if _, err := newTokenSource("sk-ant-oat01-static", path, boolPtr(false), ""); err == nil {
		t.Fatal("upstream.oauth 与 upstream.credentials 同时配置时应当报错")
	}
}

// 都没配 → 回退到 ~/.claude/.credentials.json;那份也不存在就必须失败,不能静默起空 token。
func TestTokenSourceFallsBackToHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	if _, err := newTokenSource("", "", boolPtr(false), ""); err == nil {
		t.Fatal("没有任何凭证来源时应当报错")
	}

	if err := os.Mkdir(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeCreds(t, filepath.Join(home, ".claude", ".credentials.json"),
		"sk-ant-oat01-home", time.Now().Add(time.Hour), "user:profile")

	ts, err := newTokenSource("", "", boolPtr(false), "")
	if err != nil {
		t.Fatal(err)
	}
	if got := ts.get(); got != "sk-ant-oat01-home" {
		t.Fatalf("回退应当读到本机凭证,实际 %q", got)
	}
}

// accessToken 为空的凭证文件(登录过但凭证不在这里)不能当成可用凭证。
func TestTokenSourceEmptyAccessTokenIsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".credentials.json")
	writeCreds(t, path, "", time.Now().Add(time.Hour), "user:profile")

	if _, err := newTokenSource("", path, boolPtr(false), ""); err == nil {
		t.Fatal("accessToken 为空时应当报错")
	}
}

// 换了凭证文件,网关要自己发现 —— 这是只读模式下唯一的续命通道
// (本机 claude 刷新那份凭证时走的也是这条路)。
func TestTokenSourceReloadsOnMtimeChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".credentials.json")
	writeCreds(t, path, "sk-ant-oat01-old", time.Now().Add(30*time.Minute), "user:profile")

	ts, err := newTokenSource("", path, boolPtr(false), "")
	if err != nil {
		t.Fatal(err)
	}
	ts.checkExpiry() // 先跌破一档,验证重载会把告警阶梯归零
	if ts.accessExpiry.stage == 0 {
		t.Fatal("剩余 30 分钟应当已经触发告警")
	}

	writeCreds(t, path, "sk-ant-oat01-new", time.Now().Add(8*time.Hour), "user:profile")
	// 不靠 sleep 等 mtime 变化:直接把时间戳推到未来,让重载条件确定成立。
	future := time.Now().Add(time.Minute)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}

	ts.maybeReload()
	if got := ts.get(); got != "sk-ant-oat01-new" {
		t.Fatalf("重载后 token = %q,想要 sk-ant-oat01-new", got)
	}
	if ts.accessExpiry.stage != 0 {
		t.Fatalf("换了新凭证后告警阶梯应归零,stage = %d", ts.accessExpiry.stage)
	}
}

// get() 会自己发现别人带外换掉的凭证,但带一秒节流:热路径不该每次都 stat。
// 这两半是一组契约,得一起钉住 —— 只测「能发现」会让节流被悄悄改没,
// 只测「有节流」又可能把「永远不发现」当成通过。
func TestTokenSourceGetPicksUpExternalChangeThrottled(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".credentials.json")
	writeCreds(t, path, "sk-ant-oat01-old", time.Now().Add(8*time.Hour), "user:profile")

	ts, err := newTokenSource("", path, boolPtr(false), "")
	if err != nil {
		t.Fatal(err)
	}
	if got := ts.get(); got != "sk-ant-oat01-old" {
		t.Fatalf("token = %q", got)
	}

	// 别人(本机 claude / cron / 手动)换掉了凭证。
	writeCreds(t, path, "sk-ant-oat01-external", time.Now().Add(8*time.Hour), "user:profile")
	future := time.Now().Add(time.Minute)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}

	// 上一次 stat 就在刚才,节流窗口内不该再去看文件。
	if got := ts.get(); got != "sk-ant-oat01-old" {
		t.Fatalf("节流窗口内不该重复 stat,token 应还是旧的,实际 %q", got)
	}

	// 窗口过去之后,不需要任何人推一把,get() 自己就能发现。
	ts.mu.Lock()
	ts.lastStat = time.Now().Add(-2 * statThrottle)
	ts.mu.Unlock()

	if got := ts.get(); got != "sk-ant-oat01-external" {
		t.Fatalf("节流窗口过后 get() 应当自动读到新凭证,实际 %q", got)
	}
}

// 静态 token 没有文件,节流路径必须是彻底的 no-op(别去 stat 一个空路径)。
func TestTokenSourceGetNoStatForStaticToken(t *testing.T) {
	ts, err := newTokenSource("sk-ant-oat01-static", "", boolPtr(false), "")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if got := ts.get(); got != "sk-ant-oat01-static" {
			t.Fatalf("token = %q", got)
		}
	}
	if !ts.lastStat.IsZero() {
		t.Fatal("静态 token 不该去看文件,lastStat 应当没被动过")
	}
}

// 重载失败要沿用旧 token:手里那份在过期前仍然能用,断服务比用着旧凭证更糟。
func TestTokenSourceKeepsOldTokenWhenReloadFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".credentials.json")
	writeCreds(t, path, "sk-ant-oat01-old", time.Now().Add(time.Hour), "user:profile")

	ts, err := newTokenSource("", path, boolPtr(false), "")
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, []byte("{ 这不是 JSON"), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Minute)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}

	ts.maybeReload()
	if got := ts.get(); got != "sk-ant-oat01-old" {
		t.Fatalf("重载失败后应沿用旧 token,实际 %q", got)
	}
}

// 到期告警按阶梯只打一次,不能让后台巡检每 30 秒刷一条同样的话。
func TestTokenSourceExpiryWarnsOncePerStage(t *testing.T) {
	ts := newAccessOnlyWatch(30 * time.Minute)

	if out := captureEvents(t, ts.checkExpiry); countLines(out) != 1 {
		t.Fatalf("剩余 30 分钟应当告警且只告一行,实际日志: %q", out)
	}
	if out := captureEvents(t, ts.checkExpiry); out != "" {
		t.Fatalf("同一档不应重复告警,实际日志: %q", out)
	}

	// 跌到「已过期」时还要再报一次,并且此后不再重复。
	ts.accessExpiry.at = time.Now().Add(-time.Minute)
	out := captureEvents(t, ts.checkExpiry)
	if countLines(out) != 1 || !strings.Contains(out, "过期") {
		t.Fatalf("已过期应当再报一行,实际日志: %q", out)
	}
	if out := captureEvents(t, ts.checkExpiry); out != "" {
		t.Fatalf("已过期后不应再重复告警,实际日志: %q", out)
	}
}

// 启动时就已经很紧的凭证,只报最紧那一档,不该把中间每一档都刷一遍。
func TestTokenSourceExpiryReportsTightestStageOnly(t *testing.T) {
	ts := newAccessOnlyWatch(5 * time.Minute) // 一次性跌破 6h / 1h / 15m 三档
	out := captureEvents(t, ts.checkExpiry)
	if countLines(out) != 1 {
		t.Fatalf("跌破多档也只该报最紧的那一行,实际日志: %q", out)
	}
	if !strings.Contains(out, "15m") {
		t.Fatalf("报的应当是最紧那档(15m),实际日志: %q", out)
	}
}

func countLines(s string) int {
	if strings.TrimSpace(s) == "" {
		return 0
	}
	return len(strings.Split(strings.TrimRight(s, "\n"), "\n"))
}

// 401 时的提示要能区分「凭证过期了」和「凭证还没过期,401 另有原因」。
func TestTokenSourceExpiryHint(t *testing.T) {
	live := newAccessOnlyWatch(2 * time.Hour)
	if hint := live.expiryHint(); !strings.Contains(hint, "另有原因") {
		t.Fatalf("未过期时应提示 401 另有原因,实际 %q", hint)
	}
	dead := newAccessOnlyWatch(-time.Hour)
	if hint := dead.expiryHint(); !strings.Contains(hint, "已于") {
		t.Fatalf("已过期时应提示更换凭证,实际 %q", hint)
	}
}

// captureLog 抓走 log(启动横幅那一路)的输出供断言。
func captureLog(t *testing.T, fn func()) string {
	t.Helper()
	var buf strings.Builder
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	fn()
	return buf.String()
}

// captureEvents 抓走 slog(运行期事件那一路)的输出供断言。
// 到期告警要保的行为是「打了什么、打了几行」,断言内部计数器只是在重述实现。
func captureEvents(t *testing.T, fn func()) string {
	t.Helper()
	var buf strings.Builder
	prev := events
	events = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{ReplaceAttr: humanize}))
	defer func() { events = prev }()
	fn()
	return buf.String()
}

// refresh token 的死线是整套机制里唯一必须人工介入的时间点(实测每次刷新都不延长它),
// 所以它要独立于 access token 那条线单独告警,而且尺度是天。
// 这里【走文件】而不是手搓 struct —— 否则 refreshTokenExpiresAt 的 json tag 拼错了没人会发现。
func TestTokenSourceWarnsRefreshTokenDeadline(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".credentials.json")
	writeCredsAt(t, path, "sk-ant-oat01-real",
		time.Now().Add(7*time.Hour),    // access token 还早
		time.Now().Add(2*24*time.Hour), // refresh token 只剩 2 天
		"user:inference", "user:profile")

	ts, err := newTokenSource("", path, boolPtr(false), "")
	if err != nil {
		t.Fatal(err)
	}
	if ts.refreshExpiry.at.IsZero() {
		t.Fatal("refreshTokenExpiresAt 没有从文件里读出来(json tag 对不上?)")
	}

	out := captureEvents(t, ts.checkExpiry)
	if !strings.Contains(out, "refresh token") || !strings.Contains(out, "/login") {
		t.Fatalf("refresh token 快到期时应当提示重新登录,实际日志: %q", out)
	}
	if strings.Contains(out, "上游凭证剩余有效期") {
		t.Fatalf("access token 还有 7 小时,不该被这次检查带出告警,实际日志: %q", out)
	}

	if again := captureEvents(t, ts.checkExpiry); strings.Contains(again, "refresh token") {
		t.Fatalf("同一档不应重复告警,实际日志: %q", again)
	}
}

// 开着自刷新时,access token 那条线不该喊人 —— TTL 8h、阶梯 6h/1h、刷新提前量 30min,
// 每个凭证周期必然跌破 6h 和 1h 两档,不静音就是每 8 小时两条假告警,
// 内容还是叫人去手工更换一份网关 30 分钟后自己就要刷掉的凭证。
func TestCheckExpirySilentAboutAccessTokenWhenAutoRefreshing(t *testing.T) {
	dir := t.TempDir()
	credPath := filepath.Join(dir, ".credentials.json")
	writeCredsAt(t, credPath, "sk-ant-oat01-old",
		time.Now().Add(90*time.Minute),  // 已经跌破 6h 档
		time.Now().Add(20*24*time.Hour), // refresh token 那条还早
		"user:profile")
	bin := fakeClaude(t, "sk-ant-oat01-new", filepath.Join(dir, "calls.txt"), 0)

	ts, err := newTokenSource("", credPath, boolPtr(true), bin)
	if err != nil {
		t.Fatal(err)
	}
	if out := captureEvents(t, ts.checkExpiry); strings.Contains(out, "网关不自动刷新") {
		t.Fatalf("自刷新开着时不该喊「网关不自动刷新」,实际日志: %q", out)
	}

	// 只读模式下同一份凭证必须照喊 —— 那时确实没人会替它续命。
	ro, err := newTokenSource("", credPath, boolPtr(false), "")
	if err != nil {
		t.Fatal(err)
	}
	if out := captureEvents(t, ro.checkExpiry); !strings.Contains(out, "网关不自动刷新") {
		t.Fatalf("只读模式下 access token 快过期必须告警,实际日志: %q", out)
	}
}

// 设备侧的占位凭证长得跟真凭证一模一样(scopes 齐全、expiresAt 在 2100 年),
// 混进上游凭证的位置会让每个请求都 401,而启动日志一片祥和。宁可起不来。
// 这份 JSON 照抄 scripts/setup-device.sh 写出来的形状。
func TestTokenSourceRejectsDevicePlaceholder(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".credentials.json")
	placeholder := `{"claudeAiOauth":{"accessToken":"sk-ant-oat01-placeholder",` +
		`"expiresAt":4102444800000,"scopes":["user:inference","user:profile"],` +
		`"subscriptionType":"max"}}`
	if err := os.WriteFile(path, []byte(placeholder), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := newTokenSource("", path, boolPtr(false), "")
	if err == nil {
		t.Fatal("设备侧占位凭证不能被当成上游凭证接受")
	}
	if !strings.Contains(err.Error(), "占位凭证") {
		t.Fatalf("报错要说清是占位凭证,实际: %v", err)
	}
}

// 没有 refreshToken 的凭证到期即死,没人能给它续命 —— 启动时得说一声。
func TestTokenSourceWarnsMissingRefreshToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".credentials.json")
	noRefresh := `{"claudeAiOauth":{"accessToken":"sk-ant-oat01-real",` +
		`"expiresAt":4102444800000,"scopes":["user:inference","user:profile"],` +
		`"subscriptionType":"max"}}`
	if err := os.WriteFile(path, []byte(noRefresh), 0o600); err != nil {
		t.Fatal(err)
	}

	ts, err := newTokenSource("", path, boolPtr(false), "")
	if err != nil {
		t.Fatal(err)
	}
	var buf strings.Builder
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	ts.logCredentialNotes()
	if !strings.Contains(buf.String(), "refreshToken") {
		t.Fatalf("缺 refreshToken 时应当告警,实际日志: %q", buf.String())
	}
}

// 缺 user:profile 是「能推理但 /usage 空着」的根因,启动时必须点名提醒。
func TestTokenSourceWarnsMissingProfileScope(t *testing.T) {
	capture := func(scopes ...string) string {
		path := filepath.Join(t.TempDir(), ".credentials.json")
		writeCreds(t, path, "sk-ant-oat01-real", time.Now().Add(8*time.Hour), scopes...)
		ts, err := newTokenSource("", path, boolPtr(false), "")
		if err != nil {
			t.Fatal(err)
		}
		var buf strings.Builder
		log.SetOutput(&buf)
		defer log.SetOutput(os.Stderr)
		ts.logCredentialNotes()
		return buf.String()
	}

	if out := capture("user:inference"); !strings.Contains(out, "user:profile") {
		t.Fatalf("缺 user:profile 时应当告警,实际日志: %q", out)
	}
	if out := capture("user:inference", "user:profile"); strings.Contains(out, "⚠") {
		t.Fatalf("scopes 齐全时不该告警,实际日志: %q", out)
	}
}

func TestHumanDur(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want string
	}{
		{30 * 24 * time.Hour, "30d"}, // refresh token 那条线按天看才顺眼
		{7*time.Hour + 58*time.Minute, "7h58m"},
		{45 * time.Minute, "45m"},
		{90 * time.Second, "2m"},
		{30 * time.Second, "30s"},
	}
	for _, c := range cases {
		if got := humanDur(c.in); got != c.want {
			t.Errorf("humanDur(%v) = %q,想要 %q", c.in, got, c.want)
		}
	}
}

// boolPtr 让测试能显式表达三态开关的「配了 true / 配了 false」两种情形。
func boolPtr(b bool) *bool { return &b }
