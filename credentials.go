package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// claudeCredentials 对应 Claude Code 的凭证文件 .credentials.json。
// 只取注入需要的字段;refreshToken 网关自己不拿它发请求,只在自刷新时传给 claude 子进程
// (见 refresh.go)。它在不在、什么时候到期决定了这份凭证还能不能被续命,所以两个到期时间都要读。
type claudeCredentials struct {
	ClaudeAIOAuth struct {
		AccessToken  string `json:"accessToken"`
		RefreshToken string `json:"refreshToken"`
		// 毫秒时间戳;<=0 视为「有效期未知」。实测 access token TTL 为 8 小时。
		ExpiresAt int64 `json:"expiresAt"`
		// refresh token 的死线。实测【每次刷新都不会延长它】—— 它锚定在最初那次
		// 交互式登录上(约 30 天),到点必须重新 claude /login,自动刷新救不回来。
		RefreshTokenExpiresAt int64    `json:"refreshTokenExpiresAt"`
		Scopes                []string `json:"scopes"`
		SubscriptionType      string   `json:"subscriptionType"`
	} `json:"claudeAiOauth"`
}

// expiryWatch 盯着一个到期时间,按阶梯只告警一次 —— 避免后台巡检每个周期都刷同样的话。
// access token 和 refresh token 的时间尺度差两个数量级(8 小时 vs 30 天),
// 所以各自带一套阶梯,不能共用。
type expiryWatch struct {
	at     time.Time // 零值 → 未知,不告警
	stages []time.Duration
	stage  int // 已告警到第几档;换了新凭证归零
}

// newlyCrossed 返回本次新跌破的最紧那一档。启动时就已经很紧的话只报最紧的那条,
// 不该把中间每一档都刷一遍。
func (e *expiryWatch) newlyCrossed() (time.Duration, bool) {
	if e.at.IsZero() {
		return 0, false
	}
	remaining := time.Until(e.at)
	hit := -1
	for i := e.stage; i < len(e.stages); i++ {
		if remaining > e.stages[i] {
			break
		}
		hit = i
	}
	if hit < 0 {
		return 0, false
	}
	e.stage = hit + 1
	return e.stages[hit], true
}

// tokenSource 提供注入用的订阅 access token,两种形态:
//
//   - 静态 token(claude setup-token 那种):没有过期信息,不重载、不告警;
//   - 凭证文件(真登录写出的 .credentials.json):按 mtime 热重载,并按剩余有效期分档告警。
//
// 无论哪种形态,网关都【不写】凭证文件。自刷新也是 fork `claude auth login` 让客户端去写,
// 网关只负责读回来 —— 写坏那份文件就得重新交互式登录,是整套机制里唯一不可逆的风险。
//
// 谁负责续命有两种情形,由 claudeBin 是否为空区分:
//   - 自刷新开启:网关自己刷(refresh.go)。前提是这份凭证【网关专属】。
//   - 只读:别人刷(本机 claude 自己、cron、或人工更换),网关靠 mtime 热重载跟上。
//     指向本机 claude 正在用的凭证时走的就是这条 —— 网关绝不能去刷它,
//     refresh token 每次刷新都轮换,刷了就把那次登录顶掉了。
type tokenSource struct {
	mu sync.Mutex
	// reloadMu 串行化整个「stat + 读文件 + 解析 + 提交」。只在最后提交时持 mu 是不够的:
	// 两个并发 reload 交错时,读到旧内容的那个可能后提交,连 mtime 一起写回旧值 ——
	// 于是内存停在已作废的 token 上,而 maybeReload 因为 mtime 也退回去了不会纠正,
	// 要等文件下次变动才恢复。401 风暴下多个请求同时 reloadNow 就能撞上。
	reloadMu sync.Mutex

	// path 与 claudeBin 都是构造期一次性写入、goroutine 起来之前就定死的,
	// 所以 refreshEnabled()/runRefresh() 在锁外读它们不构成竞争。
	// 【将来若加「运行时改凭证来源」的路径,这两个必须一起纳入 mu。】
	path  string // 空 → 静态 token,不重载
	mtime time.Time

	token        string
	refreshToken string // 只传给 claude 子进程用于刷新,网关自己不拿它发请求
	scopes       []string
	sub          string

	// 两条到期线各自的告警状态。名字带 Expiry 后缀是为了和自刷新那组
	// (refreshEnabled / refreshMu / refreshToken)区分开 —— 同一个结构体里
	// 一个 refresh 指「refresh token」、另一个指「自动刷新机制」,读代码时极易看错。
	accessExpiry  expiryWatch // access token 的到期(8 小时量级)
	refreshExpiry expiryWatch // refresh token 的到期(30 天量级,到点必须人工重新登录)
	warnedPerm    os.FileMode // 已就这个权限值告过警,避免频繁重载时刷屏

	// 自刷新(见 refresh.go)。claudeBin 为空 → 只读模式,网关不碰刷新。
	claudeBin   string
	refreshMu   sync.Mutex // 刷新的临界区:同一时刻只有一个子进程在刷,其余请求在这儿等
	lastRefresh time.Time  // 上一次刷新【尝试】的时刻,不论成败
	backoff     time.Duration
}

// 两套告警阶梯(从松到紧,末档 0 表示「已过期」)。
//
// access token 到期只是服务中断,跑一次刷新就活;refresh token 到期才是死线 ——
// 必须有人去 claude /login,所以提前量给到 7 天。
var (
	accessExpiryStages  = []time.Duration{6 * time.Hour, time.Hour, 15 * time.Minute, 0}
	refreshExpiryStages = []time.Duration{7 * 24 * time.Hour, 3 * 24 * time.Hour, 24 * time.Hour, 0}
)

// defaultCredentialsPath 是没配任何凭证时的回退:本机 claude 自己的凭证文件。
func defaultCredentialsPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".claude", ".credentials.json")
}

// newTokenSource 按配置选定凭证来源:显式 credentials 路径、静态 oauth token,
// 两个都没配则回退到本机 ~/.claude/.credentials.json。
//
// 两个都显式配了【直接失败】—— 它们之间没有优先级关系。凭证来源必须唯一且明确,
// 静默择一只会让「我明明改了配置却没生效」变成一次线上排查。
//
// refresh 是三态开关(nil = 没配,取默认):凭证文件形态一律默认【开】,
// 包括回退到 ~/.claude/.credentials.json 那条 —— access token 只活 8 小时,不自刷新
// 就是每 8 小时静默断一次,而「网关正好跑在一台有人天天用 claude 的机器上」并不成立。
// 静态 token 恒关,它没有 refreshToken 可用。
//
// 和本机 claude 共用那份凭证是安全的:刷新走的就是 claude 自己那套(fork auth login),
// 写回同一个文件,客户端会重读。轮换只废掉内存里那份旧的,拿它的一方重读即可恢复。
//
// 默认开出来的自刷新是「尽力而为」:缺 refreshToken、找不到 claude 都只告警降级,不拦启动。
// 显式配 true 则是「说到做到」:同样的情况直接启动失败 —— 你明说要它,它就不该悄悄不干活。
func newTokenSource(static, path string, refresh *bool, claudeBin string) (*tokenSource, error) {
	explicit := refresh != nil && *refresh

	if static != "" && path != "" {
		return nil, fmt.Errorf("upstream.oauth 与 upstream.credentials 只能配一个" +
			"(注意 CLAUDE_GATEWAY_UPSTREAM_OAUTH / CLAUDE_GATEWAY_UPSTREAM_CREDENTIALS 也会填上它们)")
	}
	if static != "" {
		if explicit {
			return nil, fmt.Errorf("upstream.refresh 只能配合 upstream.credentials 用:" +
				"静态 token 没有 refreshToken,刷不了")
		}
		return &tokenSource{token: static}, nil
	}

	fallback := path == ""
	if fallback {
		path = defaultCredentialsPath()
		if path == "" || !fileExists(path) {
			return nil, fmt.Errorf("没有可用的订阅凭证:upstream.credentials(推荐,真登录写出的 .credentials.json)" +
				"或 upstream.oauth / CLAUDE_GATEWAY_UPSTREAM_OAUTH 至少配一个,或让 ~/.claude/.credentials.json 存在")
		}
	}

	ts := &tokenSource{path: path}
	if err := ts.reload(); err != nil {
		return nil, fmt.Errorf("读取凭证文件 %s 失败: %w", path, err)
	}
	if fallback {
		// 回退是隐式行为,必须说出来 —— 否则「我以为在用另一份凭证」没法从日志里发现。
		log.Printf("⚠ 未配置 upstream.oauth / upstream.credentials,回退到本机凭证 %s", path)
	}

	autoRefresh := refresh == nil || *refresh
	if autoRefresh {
		if err := ts.enableRefresh(claudeBin); err != nil {
			if explicit {
				return nil, err
			}
			log.Printf("⚠ 自刷新未启用: %v(凭证到期需要人工更换)", err)
		}
	}
	return ts, nil
}

// enableRefresh 检查自刷新的前提并接上 claude。前提不满足时返回错误,
// 由调用方按「默认开 or 显式开」决定是降级还是启动失败。
func (t *tokenSource) enableRefresh(claudeBin string) error {
	if t.refreshToken == "" {
		return fmt.Errorf("%s 里没有 refreshToken,刷不了", t.path)
	}
	bin, err := resolveClaudeBin(claudeBin)
	if err != nil {
		return err
	}
	t.claudeBin = bin
	return nil
}

// reload 重新读取凭证文件并整体替换内存里的那份。解析失败时不改动任何字段,
// 由调用方决定是启动失败还是沿用旧 token。
func (t *tokenSource) reload() error {
	// 整个读取-提交串行化,见 reloadMu 的说明。
	t.reloadMu.Lock()
	defer t.reloadMu.Unlock()

	info, err := os.Stat(t.path)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(t.path)
	if err != nil {
		return err
	}
	var c claudeCredentials
	if err := json.Unmarshal(data, &c); err != nil {
		return fmt.Errorf("解析 JSON 失败: %w", err)
	}
	o := c.ClaudeAIOAuth
	if o.AccessToken == "" {
		return fmt.Errorf("claudeAiOauth.accessToken 为空(这台机器可能压根没做过交互式登录)")
	}
	// 设备侧的占位凭证长得跟真凭证一模一样(scopes 齐全、expiresAt 在 2100 年),
	// 拿它当上游凭证会让每个请求都 401,而启动日志一片祥和 —— 最难查的那种故障。
	// 宁可起不来:见 scripts/setup-device.sh 写的那份。
	if strings.Contains(o.AccessToken, "placeholder") {
		return fmt.Errorf("这是 ccgw 设备侧的【占位凭证】,不是上游凭证;" +
			"网关要的是真订阅凭证(交互式 /login 写出的那份)")
	}

	t.mu.Lock()
	t.mtime = info.ModTime()
	t.token = o.AccessToken
	t.scopes = o.Scopes
	t.sub = o.SubscriptionType
	t.refreshToken = o.RefreshToken
	// 整体重建两个 watch —— 换了凭证,告警阶梯也跟着重新来过。
	t.accessExpiry = expiryWatch{at: msToTime(o.ExpiresAt), stages: accessExpiryStages}
	t.refreshExpiry = expiryWatch{at: msToTime(o.RefreshTokenExpiresAt), stages: refreshExpiryStages}
	// 权限告警只在权限值变化时打一次:401 兜底会频繁调 reload,不能让它刷屏。
	// 这里只算,日志放到解锁之后打。
	perm := info.Mode().Perm()
	noisy := perm&0o077 != 0 && perm != t.warnedPerm
	t.warnedPerm = perm
	t.mu.Unlock()

	if noisy {
		log.Printf("⚠ 凭证文件 %s 权限是 %#o,同机其他用户可读;建议 chmod 600", t.path, perm)
	}
	return nil
}

// recoverFrom401 在上游 401 之后尽力换到一个可用的 token,返回换到的那个(可能没变)。
// 自刷新模式下强制刷一次;只读模式下退而求其次从盘上重读 —— 外部刷新过的话新的就在那儿。
func (t *tokenSource) recoverFrom401(stale string) string {
	if t.refreshEnabled() {
		t.ensureFresh(stale)
		return t.get()
	}
	return t.reloadNow()
}

// reloadNow 立刻从盘上重读一次凭证(不看 mtime),返回重载后的 token。
// 用在上游 401 之后:外部刷新会【立即】作废旧的 access token,干等后台巡检那一轮
// 就是一个周期的全量 401。静态 token 没得可重载,返回空串。
func (t *tokenSource) reloadNow() string {
	if t.path == "" {
		return ""
	}
	if err := t.reload(); err != nil {
		log.Printf("⚠ 401 后重载凭证文件 %s 失败: %v(沿用旧 token)", t.path, err)
		return ""
	}
	return t.get()
}

// get 返回当前注入用的 token。这是每个请求都要走的热路径,只加一次锁、不碰文件系统 ——
// 文件变更交给后台 watch 循环发现。
func (t *tokenSource) get() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.token
}

// maybeReload 在凭证文件 mtime 变化时热重载。任何失败都只告警不中断:
// 手里那份旧 token 在过期前仍然能用,断服务比用着旧凭证更糟。
func (t *tokenSource) maybeReload() {
	if t.path == "" {
		return
	}
	info, err := os.Stat(t.path)
	if err != nil {
		log.Printf("⚠ 读取凭证文件 %s 失败: %v(沿用旧 token)", t.path, err)
		return
	}
	t.mu.Lock()
	unchanged := info.ModTime().Equal(t.mtime)
	t.mu.Unlock()
	if unchanged {
		return
	}
	if err := t.reload(); err != nil {
		log.Printf("⚠ 重载凭证文件 %s 失败: %v(沿用旧 token)", t.path, err)
		return
	}
	log.Printf("已重载上游凭证: %s", t.describe())
}

// checkExpiry 按阶梯打到期告警 —— 提醒人来处理的通道。
// 两条线严重程度天差地别:access token 到期只是服务中断(刷一次就活),
// refresh token 到期才是死线 —— 自动刷新也救不回来,必须有人重新登录。
func (t *tokenSource) checkExpiry() {
	t.mu.Lock()
	defer t.mu.Unlock()

	// access token 那条线只在【没有自刷新】时才值得喊人。开着自刷新时喊它是纯噪音:
	// TTL 8h、阶梯 6h/1h、refreshMargin 30min,每个凭证周期必然依次跌破 6h 和 1h 两档
	// (reload 后 stage 归零),于是每 8 小时准时两条 WARN,叫人去手工更换一份网关
	// 30 分钟后自己就要刷掉的凭证。真刷不动时 ensureFresh 会自己打 ✗,不靠这里。
	if !t.refreshEnabled() {
		if within, hit := t.accessExpiry.newlyCrossed(); hit {
			if within == 0 {
				log.Printf("✗ 上游凭证已于 %s 过期:上游会开始返回 401。网关不自动刷新,请更换 %s",
					t.accessExpiry.at.Format(time.DateTime), t.path)
			} else {
				log.Printf("⚠ 上游凭证剩余有效期不足 %s(%s 到期)。网关不自动刷新,请及时更换 %s",
					humanDur(within), t.accessExpiry.at.Format(time.DateTime), t.path)
			}
		}
	}

	if within, hit := t.refreshExpiry.newlyCrossed(); hit {
		if within == 0 {
			log.Printf("✗ refresh token 已于 %s 过期:自动刷新救不回来了,"+
				"必须重新 claude /login 并更新 %s", t.refreshExpiry.at.Format(time.DateTime), t.path)
		} else {
			log.Printf("⚠ refresh token 还有不到 %s 到期(%s)。它是硬死线 —— "+
				"每次刷新都不会延长它,到点必须重新 claude /login",
				humanDur(within), t.refreshExpiry.at.Format(time.DateTime))
		}
	}
}

// watch 后台盯着凭证文件:发现 mtime 变化就热重载,并按阶梯发到期告警。
// 只读模式下这是唯一的续命通道 —— 人(或本机 claude)换了文件,网关自己发现。
func (t *tokenSource) watch(interval time.Duration) {
	tk := time.NewTicker(interval)
	defer tk.Stop()
	for range tk.C {
		t.maybeReload()
		// 到期前主动刷,尽量让刷新落在这里而不是某个用户请求的关键路径上。
		t.ensureFresh("")
		t.checkExpiry()
	}
}

// describe 给出可安全打日志的凭证摘要:只有长度、来源、订阅类型和到期时间,不含 token 本身。
func (t *tokenSource) describe() string {
	t.mu.Lock()
	defer t.mu.Unlock()

	var b strings.Builder
	fmt.Fprintf(&b, "订阅 OAuth token (len=%d)", len(t.token))
	if t.path == "" {
		b.WriteString(" ← upstream.oauth(静态 token,无有效期信息)")
		return b.String()
	}
	fmt.Fprintf(&b, " ← %s", t.path)
	if t.sub != "" {
		fmt.Fprintf(&b, ",%s 订阅", t.sub)
	}
	switch at := t.accessExpiry.at; {
	case at.IsZero():
		b.WriteString(",无有效期信息")
	case time.Until(at) <= 0:
		fmt.Fprintf(&b, ",已于 %s 过期", at.Format(time.DateTime))
	default:
		fmt.Fprintf(&b, ",%s 到期(剩余 %s)", at.Format(time.DateTime), humanDur(time.Until(at)))
	}
	return b.String()
}

// logCredentialNotes 在启动时把凭证里「能用但会出怪事」的形状点出来。
// 这两类问题都不该 fatal,但不说一声就得靠 403/401 反推,很费劲。
func (t *tokenSource) logCredentialNotes() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.path == "" {
		return // 静态 token 没有这些信息可查
	}
	if len(t.scopes) > 0 {
		log.Printf("凭证 scopes: %s", strings.Join(t.scopes, ", "))
	}
	if t.claudeBin != "" {
		log.Printf("自刷新: 开 —— 剩余不足 %s 时 fork `%s auth login`(CLAUDE_CONFIG_DIR=%s)",
			humanDur(refreshMargin), t.claudeBin, filepath.Dir(t.path))
	} else {
		log.Printf("自刷新: 关 —— 凭证到期要靠外部续命(本机 claude 自己刷、cron、或人工更换)")
	}

	// refresh token 的死线单独打一行:它是整套机制里唯一必须人工介入的时间点,
	// 而且【每次刷新都不会延长它】—— 刷得再勤也躲不过。
	if !t.refreshExpiry.at.IsZero() {
		log.Printf("refresh token 死线: %s(剩余 %s,到点必须重新 claude /login)",
			t.refreshExpiry.at.Format(time.DateTime), humanDur(time.Until(t.refreshExpiry.at)))
	}

	// 没有 refreshToken 就没人能给它续命:要么是 setup-token 塞进了凭证文件的形状,
	// 要么是哪份「永不过期」的假凭证混了进来。
	if t.refreshToken == "" {
		log.Printf("⚠ 凭证里没有 refreshToken:没有任何人能给它续期。" +
			"确认这是有意为之(比如长期 token),否则检查是不是拿错了凭证文件")
	}

	// 缺 user:profile:推理照常,只有 /usage 和 /api/oauth/* 会 403,
	// 症状是「能用但额度面板空着」,不说一声很难联想到 scope。
	for _, s := range t.scopes {
		if s == "user:profile" {
			return
		}
	}
	log.Printf("⚠ 凭证 scopes 里没有 user:profile:推理不受影响,但设备上 /usage 与 " +
		"/api/oauth/* 会被上游 403(claude setup-token 签的 token 就是这样)")
}

// expiryHint 给 401 日志补一句凭证有效期状态;没有有效期信息时返回空串。
func (t *tokenSource) expiryHint() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.accessExpiry.at.IsZero() {
		return ""
	}
	if remaining := time.Until(t.accessExpiry.at); remaining > 0 {
		return fmt.Sprintf("凭证 %s 才到期(剩余 %s),那 401 多半另有原因",
			t.accessExpiry.at.Format(time.DateTime), humanDur(remaining))
	}
	return fmt.Sprintf("凭证已于 %s 过期,请更换 %s", t.accessExpiry.at.Format(time.DateTime), t.path)
}

// msToTime 把凭证文件里的毫秒时间戳转成 time;<=0 表示「没有这个信息」,返回零值。
func msToTime(ms int64) time.Time {
	if ms <= 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms)
}

// humanDur 把时长打成人看的粗粒度形式(30d / 7h58m / 45m),丢掉更细的位 ——
// 到期提醒不需要那个精度,refresh token 那条线更是按天看才顺眼。
func humanDur(d time.Duration) string {
	switch {
	case d < time.Minute:
		return d.Round(time.Second).String()
	case d >= 48*time.Hour:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
	d = d.Round(time.Minute)
	if h := d / time.Hour; h > 0 {
		return fmt.Sprintf("%dh%dm", h, int((d%time.Hour)/time.Minute))
	}
	return fmt.Sprintf("%dm", int(d/time.Minute))
}
