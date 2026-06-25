package main

import (
	"encoding/json"
	"log"
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
)

// User 是前置鉴权里一个 per-device key 对应的身份。
type User struct {
	ID string `yaml:"id" json:"id"`
}

// Config 是网关的全部配置。真凭证建议用环境变量注入(env 覆盖 YAML)。
type Config struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Upstream struct {
		Base  string `yaml:"base"`
		OAuth string `yaml:"oauth"` // 你订阅的真 access token
	} `yaml:"upstream"`
	Users map[string]User `yaml:"users"`
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
	if v := os.Getenv("GATEWAY_HOST"); v != "" {
		c.Host = v
	}
	if v := os.Getenv("GATEWAY_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			c.Port = p
		}
	}
	if v := os.Getenv("GATEWAY_UPSTREAM_BASE"); v != "" {
		c.Upstream.Base = v
	}
	if v := os.Getenv("CLAUDE_GATEWAY_UPSTREAM_OAUTH"); v != "" {
		c.Upstream.OAuth = v
	}
	if v := os.Getenv("GATEWAY_USERS"); v != "" {
		m := map[string]User{}
		if err := json.Unmarshal([]byte(v), &m); err == nil {
			c.Users = m
		}
	}
}

func (c *Config) applyDefaults() {
	if c.Host == "" {
		c.Host = "127.0.0.1"
	}
	if c.Port == 0 {
		c.Port = 8788
	}
	if c.Upstream.Base == "" {
		c.Upstream.Base = "https://api.anthropic.com"
	}
}
