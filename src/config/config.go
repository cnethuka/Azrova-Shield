package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

type AppConfig struct {
	Listen                       string   `json:"listen"`
	AdminSessionSecret           string   `json:"adminSessionSecret"`
	ReverseProxyTarget           string   `json:"reverseProxyTarget"`
	StealthMode                  bool     `json:"stealthMode"`
	StrictMode                   bool     `json:"strictMode"`
	FirewallEnabled              bool     `json:"firewallEnabled"`
	ChallengePowDifficulty       int      `json:"challengePowDifficulty"`
	CookieVerificationTTLSeconds int      `json:"cookieVerificationTTLSeconds"`
	NginxAccessLogPath           string   `json:"nginxAccessLogPath"`
	NginxRpsThreshold            int      `json:"nginxRpsThreshold"`
	NginxWindowBanCount          int      `json:"nginxWindowBanCount"`
	ClusterKey                   string   `json:"clusterKey"`
	Peers                        []string `json:"peers"`
	TrustedProxies               []string `json:"trustedProxies"`
	LogFirewallDrops             bool     `json:"logFirewallDrops"`
	L4LogPath                    string   `json:"l4LogPath"`
	L4LogPrefix                  string   `json:"l4LogPrefix"`
	L4RpsThreshold               int      `json:"l4RpsThreshold"`
	L4WindowBanCount             int      `json:"l4WindowBanCount"`
}

type LoginConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type RateLimitConfig struct {
	RequestsPerMinute int `json:"requestsPerMinute"`
	Burst             int `json:"burst"`
	TempBlockSeconds  int `json:"tempBlockSeconds"`
	PermBlockThreshold int `json:"permBlockThreshold"`
}

type WAFRules struct {
	BlockUserAgents []string            `json:"blockUserAgents"`
	BlockReferrers  []string            `json:"blockReferrers"`
	URIPatterns     []string            `json:"uriPatterns"`
	QueryPatterns   []string            `json:"queryPatterns"`
	BodyPatterns    []string            `json:"bodyPatterns"`
	Headers         map[string][]string `json:"headers"`
	BlockedIPs      []string            `json:"blockedIPs"`
	UpdatedAt       time.Time           `json:"-"`
}

type Config struct {
	BaseDir   string
	App       AppConfig
	Login     LoginConfig
	RateLimit RateLimitConfig
	WAF       WAFRules
}

func Load(baseDir string) (*Config, error) {
	c := &Config{BaseDir: baseDir}
	appPath := filepath.Join(baseDir, "configs", "app.json")
	loginPath := filepath.Join(baseDir, "configs", "login.json")
	rlPath := filepath.Join(baseDir, "configs", "ratelimit.json")
	wafPath := filepath.Join(baseDir, "configs", "waf-rules.json")
	if err := readJSON(appPath, &c.App); err != nil {
		return nil, err
	}
	if err := readJSON(loginPath, &c.Login); err != nil {
		return nil, err
	}
	if err := readJSON(rlPath, &c.RateLimit); err != nil {
		return nil, err
	}
	if err := readJSON(wafPath, &c.WAF); err != nil {
		return nil, err
	}
	return c, nil
}

func readJSON(p string, v any) error {
	b, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}