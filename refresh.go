package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// 刷新用 claude 子进程做,而不是网关自己发 OAuth 请求。
//
// 理由一:刷新协议(端点、client_id、字段名)全是未文档化的,自己实现的那版哪天会静默炸掉;
// 交给客户端则升级 claude 就跟上了。
// 理由二:写回与 refresh token 的轮换持久化一并外包 —— 网关永远不写凭证文件。写坏它就得
// 重新交互式登录,那是这套机制里唯一不可逆的风险,不碰最省心。
//
// 代价是 fork 一个外部进程。实测 `claude auth login` 不加载也不执行 hooks、不起 MCP、
// 不跑推理 —— 它只是个 OAuth 客户端,和 `claude -p` 那种完整 agent 运行时不是一回事。
const (
	// refreshMargin 是提前量:剩余有效期跌破它就刷。给足量,好让刷新几乎永远发生在
	// 后台巡检里,而不是卡在某个用户请求的关键路径上(子进程要跑两三秒)。
	refreshMargin = 30 * time.Minute
	// refreshTimeout 兜住 claude 卡死的情况 —— 它拿着刷新锁,卡住就是全员阻塞。
	// 实测一次刷新 2~3 秒,给到 20 秒足够宽松,又远小于客户端自己的超时。
	refreshTimeout = 20 * time.Second
	// minRefreshInterval 是硬性的最小刷新间隔,【不论上次成功还是失败】都生效。
	//
	// 退避只管失败,挡不住这种情形:刷新成功了、401 却依旧(账号被降级/吊销、
	// 服务端主动作废 token)。那时每个 401 都会走「token 没变 → 退避为零 → 再 fork 一次」,
	// 而刷新本身又【立即】作废上一个 access token,于是网关一边制造 401、一边被 401
	// 驱动着 fork,凭证文件被反复重写、refresh token 被反复轮换 —— 自我强化的进程风暴。
	minRefreshInterval = time.Minute
	// 刷新失败后的退避:refresh token 真废了的话,不退避就会变成每个请求 fork 一个进程。
	refreshBackoffMin = 30 * time.Second
	// 上限刻意小于 refreshMargin:退避退过头的话,凭证会在「还没轮到下次重试」时就过期了。
	refreshBackoffMax = 5 * time.Minute
)

// refreshEnabled 表示这份凭证由网关自己负责刷新。
// 只读模式(指向本机 claude 正在用的凭证)下必须为 false —— 那种情况下网关去刷新
// 会把本机 claude 顶掉,凭证的主人不是它。
func (t *tokenSource) refreshEnabled() bool {
	return t.claudeBin != "" && t.path != ""
}

// ensureFresh 保证手里的 token 不是废的那份,必要时把它刷出来。
//
// stale 传调用方刚用过、并且被上游 401 掉的那个 token;空串表示这只是例行的到期检查。
// 两条路径对「等」的容忍度不同:
//
//   - 401 之后(stale 非空)【阻塞等】。手里那份已经确定是废的,等新 token 比再挨一个 401 强。
//   - 例行检查(stale 为空)【等不到就走】。手里那份还能用几十分钟,而后台巡检本来就会去刷;
//     为它把每个请求都堵在锁上,等于把一次刷新的耗时摊给所有并发请求。
func (t *tokenSource) ensureFresh(stale string) {
	if !t.refreshEnabled() {
		return
	}
	if stale == "" && !t.expiringSoon() {
		return
	}

	// 刷新锁就是那段临界区。排队等在这儿的请求,多半已经被前一个刷新救了 ——
	// 所以拿到锁之后必须复查,不能每人 fork 一次。
	if stale == "" {
		if !t.refreshMu.TryLock() {
			return // 已经有人在刷了,手里这份还够用,别陪着堵
		}
	} else {
		t.refreshMu.Lock()
	}
	defer t.refreshMu.Unlock()

	if stale != "" {
		if t.get() != stale {
			return // 前一个刷新已经换掉了这份废 token
		}
	} else if !t.expiringSoon() {
		return
	}

	if wait := t.refreshCooldown(); wait > 0 {
		return // 刚刷过或刚失败过;别把「刷了也没用」变成每请求一个进程
	}

	err := t.runRefresh()
	backoff := t.noteRefreshDone(err)
	if err != nil {
		log.Printf("✗ 刷新上游凭证失败: %v(沿用旧 token,%s 后再试)", err, humanDur(backoff))
		return
	}
	log.Printf("已刷新上游凭证: %s", t.describe())
}

// runRefresh 跑一次 `claude auth login`,成功后把盘上的新凭证读回内存。
// 凭证由子进程写,网关只负责读 —— 轮换后的 refresh token 也就自动落盘了。
func (t *tokenSource) runRefresh() error {
	t.mu.Lock()
	refreshTok, scopes, bin := t.refreshToken, append([]string(nil), t.scopes...), t.claudeBin
	t.mu.Unlock()

	if refreshTok == "" {
		return fmt.Errorf("凭证里没有 refreshToken,刷不了")
	}
	if len(scopes) == 0 {
		return fmt.Errorf("凭证里没有 scopes,客户端会拒绝(它要求与 refresh token 签发时一致)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), refreshTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, "auth", "login")
	// 环境显式构造,不继承网关进程的 —— 继承下来至少有两个坑:
	// HTTPS_PROXY 之类会让子进程绕回网关自己(自指环路),
	// ANTHROPIC_API_KEY / CLAUDE_CODE_OAUTH_TOKEN 会让客户端走别的鉴权分支,刷了个寂寞。
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		// 决定子进程把刷新后的凭证写回哪里 —— 必须是这份凭证所在的目录。
		"CLAUDE_CONFIG_DIR=" + filepath.Dir(t.path),
		"CLAUDE_CODE_OAUTH_REFRESH_TOKEN=" + refreshTok,
		// 客户端明确要求它与 refresh token 签发时的 scopes 一致,缺了直接报错。
		"CLAUDE_CODE_OAUTH_SCOPES=" + strings.Join(scopes, " "),
		// 没有 tty 时任何交互提示都会把刷新挂死在锁里。
		"IS_SANDBOX=1",
	}
	out, err := cmd.CombinedOutput()
	msg := strings.TrimSpace(string(out))
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("claude auth login 超时(%s): %s", humanDur(refreshTimeout), msg)
		}
		return fmt.Errorf("claude auth login 失败: %v: %s", err, msg)
	}

	// 子进程已经把新凭证写回盘上了,读回来即可 —— 轮换后的 refresh token 一并到手。
	before := t.get()
	if err := t.reload(); err != nil {
		return fmt.Errorf("刷新后重读凭证失败: %w", err)
	}
	// 判据是「token 到底换没换」,不是「换完还剩多久」。上游签发的 TTL 短于 refreshMargin 时,
	// 按剩余时间判会把一次成功的刷新记成失败 —— 而那时 token 其实已经进内存了,
	// 于是既误退避、日志又说反话(「沿用旧 token」)。token 没变才是真出事:
	// 子进程把凭证写去了别处。
	if t.get() == before {
		return fmt.Errorf("刷新后 token 没有变化,检查 CLAUDE_CONFIG_DIR 是不是指向了 %s 所在的目录",
			t.path)
	}
	return nil
}

// expiringSoon 判断是不是该刷了。没有有效期信息(静态 token)就无从判断,一律说不用。
func (t *tokenSource) expiringSoon() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.accessExpiry.at.IsZero() {
		return false
	}
	return time.Until(t.accessExpiry.at) < refreshMargin
}

// refreshCooldown 返回还要等多久才允许下一次刷新;0 表示可以刷了。
// 两道闸门:失败后的指数退避,以及【不论成败】都生效的最小间隔 —— 后者才挡得住
// 「刷新成功但 401 依旧」那种自我强化的 fork 风暴,见 minRefreshInterval。
func (t *tokenSource) refreshCooldown() time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	wait := time.Until(t.lastRefresh.Add(minRefreshInterval))
	if t.backoff > 0 {
		if d := time.Until(t.lastRefresh.Add(t.backoff)); d > wait {
			wait = d
		}
	}
	return wait
}

// noteRefreshDone 记一次刷新尝试的结果,返回失败时的新退避时长(成功时为 0)。
// 无论成败都刷新 lastRefresh —— 最小间隔管的是「刷了多久」,不是「刷成没成」。
func (t *tokenSource) noteRefreshDone(err error) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lastRefresh = time.Now()
	if err == nil {
		t.backoff = 0
		return 0
	}
	switch {
	case t.backoff == 0:
		t.backoff = refreshBackoffMin
	case t.backoff < refreshBackoffMax:
		t.backoff *= 2
	}
	if t.backoff > refreshBackoffMax {
		t.backoff = refreshBackoffMax
	}
	return t.backoff
}

// currentBackoff 只给测试和日志用。
func (t *tokenSource) currentBackoff() time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.backoff
}

// resolveClaudeBin 在启用自刷新时确定用哪个 claude。没配就用裸 "claude" 走 PATH。
//
// 启动时用 LookPath 做一次存在性自检(找不到就让启动失败 —— 等凭证快过期那一刻才发现
// 刷不了就来不及了),但返回的是【配置里那个名字】而不是解析出来的绝对路径:
// claude 会自更新、实际可执行文件的路径会变,每次执行时重新走 PATH 才不会指到旧版本上。
func resolveClaudeBin(bin string) (string, error) {
	if bin == "" {
		bin = "claude"
	}
	if _, err := exec.LookPath(bin); err != nil {
		return "", fmt.Errorf("启用了 upstream.refresh 但找不到 %q(%v);"+
			"装上 Claude Code 或用 upstream.claude_bin 指定路径", bin, err)
	}
	return bin, nil
}
