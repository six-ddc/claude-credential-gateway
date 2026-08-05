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

// ProxyConfig 是正向代理形态(CONNECT)的主机名单。两个名单都支持 "*"、"*.example.com"
// 与精确主机名三种写法。
type ProxyConfig struct {
	// MITMHosts:解密并注入真凭证的主机。只该放 Anthropic API 本身。
	MITMHosts []string `yaml:"mitm_hosts"`
	// TunnelHosts:只做 TCP 盲转发、不解密也不注入凭证的主机。
	// 设了 HTTPS_PROXY 之后客户端的【全部】 https 流量都会经过网关(遥测、WebFetch
	// 抓的任意站点、MCP server),这个名单决定放行到哪儿。默认 "*" 全放行 ——
	// 设备已经过 SSH 公钥认证,且收紧它会直接弄坏 WebFetch。
	TunnelHosts []string `yaml:"tunnel_hosts"`
}

// Config 是网关的全部配置。真凭证建议用环境变量注入(env 覆盖 YAML)。
// 网关不监听任何 HTTP 端口:转发 channel 在进程内直连 HTTP handler,故没有 host/port 配置。
type Config struct {
	Upstream struct {
		Base  string `yaml:"base"`
		OAuth string `yaml:"oauth"` // 你订阅的真 access token
	} `yaml:"upstream"`
	SSH   SSHConfig   `yaml:"ssh"`
	Proxy ProxyConfig `yaml:"proxy"`
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
	if v := os.Getenv("GATEWAY_PROXY_MITM_HOSTS"); v != "" {
		c.Proxy.MITMHosts = strings.Split(v, ",")
	}
	if v := os.Getenv("GATEWAY_PROXY_TUNNEL_HOSTS"); v != "" {
		c.Proxy.TunnelHosts = strings.Split(v, ",")
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
	if len(c.Proxy.MITMHosts) == 0 {
		// 客户端无论上游配到哪儿,URL 里的主机名始终是 api.anthropic.com。
		c.Proxy.MITMHosts = []string{forgedHost}
	}
	if len(c.Proxy.TunnelHosts) == 0 {
		c.Proxy.TunnelHosts = []string{"*"}
	}
}
