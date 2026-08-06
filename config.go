package main

import (
	"encoding/json"
	"log"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// AuthorizedKey 是一台可信设备的 SSH 公钥登记项。key 是标准 OpenSSH 公钥单行文本。
type AuthorizedKey struct {
	ID  string `yaml:"id" json:"id"`
	Key string `yaml:"key" json:"key"`
}

// SSHConfig 是转发-only SSH 层的配置。SSH 是唯一对外入口,始终启用(默认 :2222)。
type SSHConfig struct {
	Addr           string          `yaml:"addr"`            // 唯一对外端口,默认 ":2222"
	HostKey        string          `yaml:"host_key"`        // 服务端私钥路径(机密,不内联);不存在则自动生成
	CAKey          string          `yaml:"ca_key"`          // TLS 终结 CA(机密);不存在则自动生成,另导出 <path>.crt 供设备信任
	PermitTargets  []string        `yaml:"permit_targets"`  // 转发白名单,每项 host:port 或 unix:/path
	AuthorizedKeys []AuthorizedKey `yaml:"authorized_keys"` // 可信设备公钥,每台一项
}

// Config 是网关的全部配置。真凭证建议用环境变量注入(env 覆盖 YAML)。
// 网关不监听任何 HTTP 端口:转发 channel 在进程内直连 HTTP handler,故没有 host/port 配置。
type Config struct {
	Upstream struct {
		Base string `yaml:"base"`
		// 真凭证,二选一(都配则启动失败):
		OAuth string `yaml:"oauth"` // 静态 access token(setup-token 那种,无过期信息)
		// 凭证文件路径(真登录写出的 .credentials.json);两个都留空则回退
		// 到本机 ~/.claude/.credentials.json。
		Credentials string `yaml:"credentials"`
		// 由网关自己给凭证续命(fork `claude auth login`,见 refresh.go)。
		// 三态:不配 → 按来源取默认(显式 credentials 开、回退到本机凭证关、静态 token 关);
		// 显式 true/false → 照办。
		Refresh *bool `yaml:"refresh"`
		// 刷新用哪个 claude 可执行文件;留空则用裸 "claude" 走 PATH。
		ClaudeBin string `yaml:"claude_bin"`
	} `yaml:"upstream"`
	SSH SSHConfig `yaml:"ssh"`
}

// loadConfig 解析配置文件并应用环境变量覆盖与默认值。
// 路径优先级:GATEWAY_CONFIG > 本地 config.yaml(不进版本库)> config.example.yaml(模板)。
func loadConfig() (*Config, string, error) {
	path, explicit := configFilePath()
	if !explicit {
		log.Printf("⚠ 未找到 config.yaml,回退到 config.example.yaml。建议:cp config.example.yaml config.yaml 后按需修改")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, path, err
	}

	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, path, err
	}

	c.applyEnvOverrides()
	c.applyDefaults()
	return &c, path, nil
}

func configFilePath() (path string, explicit bool) {
	if v := os.Getenv("GATEWAY_CONFIG"); v != "" {
		return v, true
	}
	if fileExists("config.yaml") {
		return "config.yaml", true
	}
	return "config.example.yaml", false
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

// applyEnvOverrides 让环境变量覆盖 YAML —— 真凭证走 env,配置文件可安全提交。
func (c *Config) applyEnvOverrides() {
	if v := os.Getenv("GATEWAY_UPSTREAM_BASE"); v != "" {
		c.Upstream.Base = v
	}
	if v := os.Getenv("CLAUDE_GATEWAY_UPSTREAM_OAUTH"); v != "" {
		c.Upstream.OAuth = v
	}
	if v := os.Getenv("CLAUDE_GATEWAY_UPSTREAM_CREDENTIALS"); v != "" {
		c.Upstream.Credentials = v
	}
	if v := os.Getenv("CLAUDE_GATEWAY_UPSTREAM_REFRESH"); v != "" {
		on := v == "1" || strings.EqualFold(v, "true")
		c.Upstream.Refresh = &on
	}
	if v := os.Getenv("CLAUDE_GATEWAY_CLAUDE_BIN"); v != "" {
		c.Upstream.ClaudeBin = v
	}
	if v := os.Getenv("GATEWAY_SSH_ADDR"); v != "" {
		c.SSH.Addr = v
	}
	if v := os.Getenv("GATEWAY_SSH_HOST_KEY"); v != "" {
		c.SSH.HostKey = v
	}
	if v := os.Getenv("GATEWAY_SSH_CA_KEY"); v != "" {
		c.SSH.CAKey = v
	}
	if v := os.Getenv("GATEWAY_SSH_PERMIT_TARGETS"); v != "" {
		c.SSH.PermitTargets = strings.Split(v, ",")
	}
	if v := os.Getenv("GATEWAY_SSH_AUTHORIZED_KEYS"); v != "" {
		var list []AuthorizedKey
		if err := json.Unmarshal([]byte(v), &list); err == nil {
			c.SSH.AuthorizedKeys = list
		}
	}
}

func (c *Config) applyDefaults() {
	if c.Upstream.Base == "" {
		c.Upstream.Base = "https://api.anthropic.com"
	}
	if c.SSH.Addr == "" {
		c.SSH.Addr = ":2222"
	}
	if c.SSH.HostKey == "" {
		c.SSH.HostKey = "./ssh_host_ed25519_key"
	}
	if c.SSH.CAKey == "" {
		c.SSH.CAKey = "./ccgw_ca_key"
	}
	if len(c.SSH.PermitTargets) == 0 {
		// 代理形态走 tcp(设备侧 -L 出一个本地端口给 HTTPS_PROXY 用);
		// unix 目标留着兼容老设备的 ANTHROPIC_UNIX_SOCKET 形态。
		// 网关并不真监听它们,这里只是校验客户端 -L 声明的目标,防止误以为能转发到别处。
		c.SSH.PermitTargets = []string{"127.0.0.1:8788", "unix:/run/ccgw.sock"}
	}
}
