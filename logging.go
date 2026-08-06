package main

import (
	"log/slog"
	"os"
	"strings"
)

// 日志分两类,故意用两套写法:
//
//   - 启动横幅:给人读一次的中文说明,走 log,不带前缀和时间戳。它是「文档」不是「数据」,
//     套上 time=/level= 只会更难读。
//   - 事件日志:每个请求/连接一条,走 slog。要被 grep、被眼睛快速扫、必要时被采集器吃掉。
//
// 事件日志原来是把 map[string]any 直接 json.Marshal:map 的序列化按 key 字典序,
// 读起来毫无逻辑(model 排在 status 前、ts 排在 user 前),ts 还是人看不懂的毫秒时间戳。
// 换 slog 之后字段按传入顺序输出,顺序问题从根上没了,JSON 输出也不用自己拼。
var events *slog.Logger

// initLogging 装配事件日志。GATEWAY_LOG_FORMAT=json → JSON(给采集器);其余 → key=value(给人)。
func initLogging() {
	if strings.EqualFold(os.Getenv("GATEWAY_LOG_FORMAT"), "json") {
		// 采集器要完整时间戳,所以只丢空字段、不动 time。
		events = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{ReplaceAttr: dropEmpty}))
		return
	}
	events = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{ReplaceAttr: humanize}))
}

// humanize 是人读模式的字段改写:时间砍成时分秒,空字段整条丢掉。
// 网关的事件都是「刚刚」发生的,完整 RFC3339 占掉半行宽度却没人会去读那个年份。
func humanize(groups []string, a slog.Attr) slog.Attr {
	if a.Key == slog.TimeKey && len(groups) == 0 {
		return slog.String(slog.TimeKey, a.Value.Time().Format("15:04:05"))
	}
	return dropEmpty(groups, a)
}

// dropEmpty 丢掉空字符串字段。slog 会老老实实打出 model="",占着一行的宽度却什么也没说 ——
// 非推理端点的 model 恒为空,不丢会淹掉真正有用的字段。返回零值 Attr 即整条略过。
func dropEmpty(_ []string, a slog.Attr) slog.Attr {
	if a.Value.Kind() == slog.KindString && a.Value.String() == "" {
		return slog.Attr{}
	}
	return a
}

// 在 init 里装配而不是等 main 调用:测试也走同一套 handler,
// 「日志长什么样」就不会有两种答案。
func init() { initLogging() }

// logUsage 打一条 token 用量。用量是「数据」,和事件日志同属一类,所以也走 slog。
func logUsage(device, reqModel string, u *Usage) {
	model := u.Model
	if model == "" {
		model = reqModel
	}
	if model == "" {
		model = "?"
	}
	events.Info("usage",
		"user", device, "model", model,
		"input", u.Input, "output", u.Output,
		"cache_create", u.CacheCreate, "cache_read", u.CacheRead,
		"total", u.Input+u.Output+u.CacheCreate+u.CacheRead)
}
