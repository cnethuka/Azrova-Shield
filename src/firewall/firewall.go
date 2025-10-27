package firewall

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

type Controller struct {
	mu       sync.Mutex
	enabled  bool
	baseDir  string
	path     string
	osname   string
	blocked  map[string]struct{}
	temp     map[string]time.Time
	quit     chan struct{}
	ipsetOK  bool
	logDrops bool
}

func New(baseDir string, enabled bool, logDrops bool) *Controller {
	c := &Controller{
		enabled:  enabled,
		baseDir:  baseDir,
		path:     filepath.Join(baseDir, "data", "blocked.json"),
		osname:   runtime.GOOS,
		blocked:  make(map[string]struct{}),
		temp:     make(map[string]time.Time),
		quit:     make(chan struct{}),
		logDrops: logDrops,
	}
	_ = os.MkdirAll(filepath.Join(baseDir, "data"), 0o755)
	c.load()
	if enabled {
		if c.osname == "linux" {
			c.ensureSets()
		}
		for ip := range c.blocked {
			_ = c.applyBlock(ip)
		}
		for ip := range c.temp {
			_ = c.applyTempBlock(ip)
		}
	}
	go c.loop()
	return c
}

func (c *Controller) ensureSets() {
	if c.osname != "linux" {
		return
	}
	_ = exec.Command("ipset", "create", "azrova_drop", "hash:ip", "-exist").Run()
	_ = exec.Command("ipset", "create", "azrova_temp", "hash:ip", "-exist").Run()
	_ = exec.Command("ipset", "create", "azrova_netdrop", "hash:net", "-exist").Run()
	if exec.Command("ipset", "list").Run() == nil {
		c.ipsetOK = true
	}
	if exec.Command("iptables", "-t", "raw", "-C", "PREROUTING", "-m", "set", "--match-set", "azrova_drop", "src", "-j", "DROP").Run() != nil {
		_ = exec.Command("iptables", "-t", "raw", "-I", "PREROUTING", "-m", "set", "--match-set", "azrova_drop", "src", "-j", "DROP").Run()
	}
	if exec.Command("iptables", "-t", "raw", "-C", "PREROUTING", "-m", "set", "--match-set", "azrova_temp", "src", "-j", "DROP").Run() != nil {
		_ = exec.Command("iptables", "-t", "raw", "-I", "PREROUTING", "-m", "set", "--match-set", "azrova_temp", "src", "-j", "DROP").Run()
	}
	if exec.Command("iptables", "-t", "raw", "-C", "PREROUTING", "-m", "set", "--match-set", "azrova_netdrop", "src", "-j", "DROP").Run() != nil {
		_ = exec.Command("iptables", "-t", "raw", "-I", "PREROUTING", "-m", "set", "--match-set", "azrova_netdrop", "src", "-j", "DROP").Run()
	}
	if exec.Command("iptables", "-C", "DOCKER-USER", "-m", "set", "--match-set", "azrova_drop", "src", "-j", "DROP").Run() != nil {
		_ = exec.Command("iptables", "-I", "DOCKER-USER", "-m", "set", "--match-set", "azrova_drop", "src", "-j", "DROP").Run()
	}
	if exec.Command("iptables", "-C", "DOCKER-USER", "-m", "set", "--match-set", "azrova_temp", "src", "-j", "DROP").Run() != nil {
		_ = exec.Command("iptables", "-I", "DOCKER-USER", "-m", "set", "--match-set", "azrova_temp", "src", "-j", "DROP").Run()
	}
	if exec.Command("iptables", "-C", "DOCKER-USER", "-m", "set", "--match-set", "azrova_netdrop", "src", "-j", "DROP").Run() != nil {
		_ = exec.Command("iptables", "-I", "DOCKER-USER", "-m", "set", "--match-set", "azrova_netdrop", "src", "-j", "DROP").Run()
	}
	if exec.Command("iptables", "-C", "INPUT", "-m", "set", "--match-set", "azrova_drop", "src", "-j", "DROP").Run() != nil {
		_ = exec.Command("iptables", "-I", "INPUT", "-m", "set", "--match-set", "azrova_drop", "src", "-j", "DROP").Run()
	}
	if exec.Command("iptables", "-C", "INPUT", "-m", "set", "--match-set", "azrova_temp", "src", "-j", "DROP").Run() != nil {
		_ = exec.Command("iptables", "-I", "INPUT", "-m", "set", "--match-set", "azrova_temp", "src", "-j", "DROP").Run()
	}
	if exec.Command("iptables", "-C", "INPUT", "-m", "set", "--match-set", "azrova_netdrop", "src", "-j", "DROP").Run() != nil {
		_ = exec.Command("iptables", "-I", "INPUT", "-m", "set", "--match-set", "azrova_netdrop", "src", "-j", "DROP").Run()
	}
	if c.logDrops {
		if exec.Command("iptables", "-C", "DOCKER-USER", "-m", "set", "--match-set", "azrova_drop", "src", "-m", "limit", "--limit", "10/second", "--limit-burst", "20", "-j", "LOG", "--log-prefix", "AZR_DROP:").Run() != nil {
			_ = exec.Command("iptables", "-I", "DOCKER-USER", "-m", "set", "--match-set", "azrova_drop", "src", "-m", "limit", "--limit", "10/second", "--limit-burst", "20", "-j", "LOG", "--log-prefix", "AZR_DROP:").Run()
		}
		if exec.Command("iptables", "-C", "DOCKER-USER", "-m", "set", "--match-set", "azrova_temp", "src", "-m", "limit", "--limit", "10/second", "--limit-burst", "20", "-j", "LOG", "--log-prefix", "AZR_TEMP:").Run() != nil {
			_ = exec.Command("iptables", "-I", "DOCKER-USER", "-m", "set", "--match-set", "azrova_temp", "src", "-m", "limit", "--limit", "10/second", "--limit-burst", "20", "-j", "LOG", "--log-prefix", "AZR_TEMP:").Run()
		}
		if exec.Command("iptables", "-C", "DOCKER-USER", "-m", "set", "--match-set", "azrova_netdrop", "src", "-m", "limit", "--limit", "10/second", "--limit-burst", "20", "-j", "LOG", "--log-prefix", "AZR_NET:").Run() != nil {
			_ = exec.Command("iptables", "-I", "DOCKER-USER", "-m", "set", "--match-set", "azrova_netdrop", "src", "-m", "limit", "--limit", "10/second", "--limit-burst", "20", "-j", "LOG", "--log-prefix", "AZR_NET:").Run()
		}
		if exec.Command("iptables", "-C", "INPUT", "-m", "set", "--match-set", "azrova_drop", "src", "-m", "limit", "--limit", "10/second", "--limit-burst", "20", "-j", "LOG", "--log-prefix", "AZR_DROP:").Run() != nil {
			_ = exec.Command("iptables", "-I", "INPUT", "-m", "set", "--match-set", "azrova_drop", "src", "-m", "limit", "--limit", "10/second", "--limit-burst", "20", "-j", "LOG", "--log-prefix", "AZR_DROP:").Run()
		}
		if exec.Command("iptables", "-C", "INPUT", "-m", "set", "--match-set", "azrova_temp", "src", "-m", "limit", "--limit", "10/second", "--limit-burst", "20", "-j", "LOG", "--log-prefix", "AZR_TEMP:").Run() != nil {
			_ = exec.Command("iptables", "-I", "INPUT", "-m", "set", "--match-set", "azrova_temp", "src", "-m", "limit", "--limit", "10/second", "--limit-burst", "20", "-j", "LOG", "--log-prefix", "AZR_TEMP:").Run()
		}
		if exec.Command("iptables", "-C", "INPUT", "-m", "set", "--match-set", "azrova_netdrop", "src", "-m", "limit", "--limit", "10/second", "--limit-burst", "20", "-j", "LOG", "--log-prefix", "AZR_NET:").Run() != nil {
			_ = exec.Command("iptables", "-I", "INPUT", "-m", "set", "--match-set", "azrova_netdrop", "src", "-m", "limit", "--limit", "10/second", "--limit-burst", "20", "-j", "LOG", "--log-prefix", "AZR_NET:").Run()
		}
	}
}

func (c *Controller) loop() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			c.sweep()
		case <-c.quit:
			return
		}
	}
}

func (c *Controller) sweep() {
	now := time.Now()
	c.mu.Lock()
	for ip, exp := range c.temp {
		if now.After(exp) {
			_ = c.applyTempUnblock(ip)
			delete(c.temp, ip)
		}
	}
	c.mu.Unlock()
}

func (c *Controller) Close() {
	close(c.quit)
}

func (c *Controller) SetEnabled(b bool) {
	c.mu.Lock()
	c.enabled = b
	c.mu.Unlock()
	if b {
		c.mu.Lock()
		for ip := range c.blocked {
			_ = c.applyBlock(ip)
		}
		for ip := range c.temp {
			_ = c.applyTempBlock(ip)
		}
		c.mu.Unlock()
	}
}

func (c *Controller) Block(ip string) {
	if ip == "" {
		return
	}
	c.mu.Lock()
	if _, ok := c.blocked[ip]; ok {
		c.mu.Unlock()
		return
	}
	c.blocked[ip] = struct{}{}
	_ = c.persist()
	enabled := c.enabled
	c.mu.Unlock()
	if enabled {
		_ = c.applyBlock(ip)
	}
}

func (c *Controller) Unblock(ip string) {
	if ip == "" {
		return
	}
	c.mu.Lock()
	if _, ok := c.blocked[ip]; ok {
		delete(c.blocked, ip)
		_ = c.persist()
	}
	if _, ok := c.temp[ip]; ok {
		delete(c.temp, ip)
	}
	enabled := c.enabled
	c.mu.Unlock()
	if enabled {
		_ = c.applyUnblock(ip)
		_ = c.applyTempUnblock(ip)
	}
}

func (c *Controller) TempBlock(ip string, d time.Duration) {
	if ip == "" || d <= 0 {
		return
	}
	c.mu.Lock()
	exp := time.Now().Add(d)
	if cur, ok := c.temp[ip]; !ok || exp.After(cur) {
		c.temp[ip] = exp
	}
	enabled := c.enabled
	c.mu.Unlock()
	if enabled {
		_ = c.applyTempBlock(ip)
	}
}

func (c *Controller) load() {
	b, err := os.ReadFile(c.path)
	if err != nil {
		return
	}
	var ips []string
	if json.Unmarshal(b, &ips) != nil {
		return
	}
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			c.blocked[ip] = struct{}{}
		}
	}
}

func (c *Controller) persist() error {
	ips := make([]string, 0, len(c.blocked))
	for ip := range c.blocked {
		ips = append(ips, ip)
	}
	b, _ := json.MarshalIndent(ips, "", "  ")
	return os.WriteFile(c.path, b, 0o644)
}

func (c *Controller) ruleName(ip string) string {
	return "AzrovaShield_Block_" + ip
}

func (c *Controller) tempRuleName(ip string) string {
	return "AzrovaShield_Temp_" + ip
}

func (c *Controller) applyBlock(ip string) error {
	if c.osname == "windows" {
		return exec.Command("netsh", "advfirewall", "firewall", "add", "rule", "name="+c.ruleName(ip), "dir=in", "action=block", "remoteip="+ip).Run()
	}
	if c.ipsetOK {
		return exec.Command("ipset", "add", "azrova_drop", ip, "-exist").Run()
	}
	_ = exec.Command("iptables", "-C", "INPUT", "-s", ip, "-j", "DROP").Run()
	return exec.Command("iptables", "-I", "INPUT", "-s", ip, "-m", "comment", "--comment", "AzrovaShield_Perm", "-j", "DROP").Run()
}

func (c *Controller) applyUnblock(ip string) error {
	if c.osname == "windows" {
		return exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+c.ruleName(ip)).Run()
	}
	if c.ipsetOK {
		return exec.Command("ipset", "del", "azrova_drop", ip).Run()
	}
	err := exec.Command("iptables", "-D", "INPUT", "-s", ip, "-m", "comment", "--comment", "AzrovaShield_Perm", "-j", "DROP").Run()
	if err != nil {
		_ = exec.Command("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP").Run()
	}
	return nil
}

func (c *Controller) applyTempBlock(ip string) error {
	if c.osname == "windows" {
		return exec.Command("netsh", "advfirewall", "firewall", "add", "rule", "name="+c.tempRuleName(ip), "dir=in", "action=block", "remoteip="+ip).Run()
	}
	if c.ipsetOK {
		return exec.Command("ipset", "add", "azrova_temp", ip, "-exist").Run()
	}
	_ = exec.Command("iptables", "-C", "INPUT", "-s", ip, "-m", "comment", "--comment", "AzrovaShield_Temp", "-j", "DROP").Run()
	return exec.Command("iptables", "-I", "INPUT", "-s", ip, "-m", "comment", "--comment", "AzrovaShield_Temp", "-j", "DROP").Run()
}

func (c *Controller) applyTempUnblock(ip string) error {
	if c.osname == "windows" {
		return exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+c.tempRuleName(ip)).Run()
	}
	if c.ipsetOK {
		return exec.Command("ipset", "del", "azrova_temp", ip).Run()
	}
	return exec.Command("iptables", "-D", "INPUT", "-s", ip, "-m", "comment", "--comment", "AzrovaShield_Temp", "-j", "DROP").Run()
}
	
func (c *Controller) BlockNet(cidr string) {
	if cidr == "" {
		return
	}
	if c.osname == "windows" {
		_ = exec.Command("netsh", "advfirewall", "firewall", "add", "rule", "name="+c.ruleName("NET_"+cidr), "dir=in", "action=block", "remoteip="+cidr).Run()
		return
	}
	if c.ipsetOK {
		_ = exec.Command("ipset", "add", "azrova_netdrop", cidr, "-exist").Run()
		return
	}
	_ = exec.Command("iptables", "-I", "INPUT", "-s", cidr, "-j", "DROP").Run()
}
	
func (c *Controller) UnblockNet(cidr string) {
	if cidr == "" {
		return
	}
	if c.osname == "windows" {
		_ = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+c.ruleName("NET_"+cidr)).Run()
		return
	}
	if c.ipsetOK {
		_ = exec.Command("ipset", "del", "azrova_netdrop", cidr).Run()
		return
	}
	_ = exec.Command("iptables", "-D", "INPUT", "-s", cidr, "-j", "DROP").Run()
}
	
func (c *Controller) Snapshot() ([]string, map[string]time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	perms := make([]string, 0, len(c.blocked))
	for ip := range c.blocked {
		perms = append(perms, ip)
	}
	temps := make(map[string]time.Time, len(c.temp))
	for ip, t := range c.temp {
		temps[ip] = t
	}
	return perms, temps
}