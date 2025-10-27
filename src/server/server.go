package server

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
 
	"azrova-shield/src/analytics"
	"azrova-shield/src/config"
	"azrova-shield/src/firewall"
	"azrova-shield/src/middleware"
	"azrova-shield/src/proxy"
	"azrova-shield/src/logs"
	"azrova-shield/src/rules"
	"azrova-shield/src/monitor"
	"github.com/fasthttp/router"
	"github.com/valyala/fasthttp"
)

type Session struct {
	ID      string
	Admin   bool
	Expires time.Time
	CSRF    string
}

type SessionStore struct {
	mu sync.RWMutex
	m  map[string]*Session
}

func NewSessionStore() *SessionStore {
	return &SessionStore{m: make(map[string]*Session)}
}

func (s *SessionStore) Get(id string) (*Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.m[id]
	if !ok {
		return nil, false
	}
	if time.Now().After(v.Expires) {
		return nil, false
	}
	return v, true
}

func (s *SessionStore) Set(sess *Session) {
	s.mu.Lock()
	s.m[sess.ID] = sess
	s.mu.Unlock()
}

type Server struct {
	cfg        *config.Config
	rt         *router.Router
	srv        *fasthttp.Server
	sessions   *SessionStore
	metrics    *analytics.Metrics
	limiter    *middleware.RateLimiter
	waf        *middleware.WAF
	scrub      *middleware.Scrubber
	verifier   *middleware.Verifier
	proxy      *proxy.ReverseProxy
	fw         *firewall.Controller
	secret     []byte
	logger     *logs.Logger
	rules      *rules.Engine
	mon        *monitor.Tailer
	monL4      *monitor.Tailer
	proxies    []*net.IPNet
	peers      []string
	clusterKey []byte
	strikes    map[string]int
	strikesMu  sync.Mutex
}

func New(cfg *config.Config) *Server {
	r := router.New()
	s := &Server{
		cfg:      cfg,
		rt:       r,
		sessions: NewSessionStore(),
		metrics:  analytics.New(),
		secret:   []byte(cfg.App.AdminSessionSecret),
	}
	s.limiter = middleware.NewRateLimiter(cfg.RateLimit, s.metrics)
	s.waf = middleware.NewWAF(cfg.WAF, s.metrics)
	s.scrub = middleware.NewScrubber()
	s.verifier = middleware.NewVerifier(cfg.App.CookieVerificationTTLSeconds, cfg.App.ChallengePowDifficulty, s.metrics)
	s.verifier.SetStrict(cfg.App.StrictMode)
	s.waf.SetStrict(cfg.App.StrictMode)
	s.limiter.SetStrict(cfg.App.StrictMode)
	s.proxy = proxy.New(cfg.App.ReverseProxyTarget, s.metrics)
	s.fw = firewall.New(cfg.BaseDir, cfg.App.FirewallEnabled, cfg.App.LogFirewallDrops)
	s.logger = logs.New(cfg.BaseDir)
	s.rules = rules.New(cfg.BaseDir)
	s.peers = cfg.App.Peers
	if cfg.App.ClusterKey != "" {
		s.clusterKey = []byte(cfg.App.ClusterKey)
	}
	for _, cidr := range cfg.App.TrustedProxies {
		if cidr == "" {
			continue
		}
		if _, ipn, err := net.ParseCIDR(cidr); err == nil {
			s.proxies = append(s.proxies, ipn)
			continue
		}
		if ip := net.ParseIP(cidr); ip != nil {
			mask := net.CIDRMask(32, 32)
			if ip.To4() == nil {
				mask = net.CIDRMask(128, 128)
			}
			s.proxies = append(s.proxies, &net.IPNet{IP: ip, Mask: mask})
		}
	}
	s.verifier.SetIPResolver(s.clientIP)
	s.strikes = make(map[string]int)
	if cfg.App.NginxAccessLogPath != "" {
		s.mon = monitor.New(cfg.App.NginxAccessLogPath, func(ip string, rate int) {
			_, _ = ip, rate
		})
		s.mon.OnWindow(func(counts map[string]int) {
			thr := s.cfg.App.NginxRpsThreshold
			if thr <= 0 {
				return
			}
			winBan := s.cfg.App.NginxWindowBanCount
			if winBan <= 0 {
				winBan = 3
			}
			for ip, c := range counts {
				if c >= thr {
					s.limiter.ReportBad(ip)
					s.strikesMu.Lock()
					s.strikes[ip]++
					n := s.strikes[ip]
					if n >= winBan {
						s.strikes[ip] = 0
						s.strikesMu.Unlock()
						s.limiter.PermBlock(ip)
						s.fw.Block(ip)
						if s.logger != nil {
							s.logger.Log(logs.Entry{Ts: time.Now().Unix(), IP: ip, UA: "", Path: "", Method: "", Status: 0, Action: "nginx_block"})
						}
						s.clusterBlockIP(ip)
					} else {
						s.strikesMu.Unlock()
						s.fw.TempBlock(ip, time.Duration(s.cfg.RateLimit.TempBlockSeconds)*time.Second)
						if s.logger != nil {
							s.logger.Log(logs.Entry{Ts: time.Now().Unix(), IP: ip, UA: "", Path: "", Method: "", Status: 0, Action: "nginx_temp"})
						}
						s.clusterBadIP(ip)
					}
				}
			}
		})
	}
	if cfg.App.L4LogPath != "" {
		prefix := s.cfg.App.L4LogPrefix
		if prefix == "" {
			prefix = "AZR_"
		}
		s.monL4 = monitor.NewWithParser(s.cfg.App.L4LogPath, parseIptablesParser(prefix), func(ip string, rate int) {
			_, _ = ip, rate
		})
		s.monL4.OnWindow(func(counts map[string]int) {
			thr := s.cfg.App.L4RpsThreshold
			if thr <= 0 {
				return
			}
			winBan := s.cfg.App.L4WindowBanCount
			if winBan <= 0 {
				winBan = 3
			}
			for ip, c := range counts {
				if c >= thr {
					s.limiter.ReportBad(ip)
					s.strikesMu.Lock()
					s.strikes[ip]++
					n := s.strikes[ip]
					if n >= winBan {
						s.strikes[ip] = 0
						s.strikesMu.Unlock()
						s.limiter.PermBlock(ip)
						s.fw.Block(ip)
						if s.logger != nil {
							s.logger.Log(logs.Entry{Ts: time.Now().Unix(), IP: ip, UA: "", Path: "", Method: "", Status: 0, Action: "l4_block"})
						}
						s.clusterBlockIP(ip)
					} else {
						s.strikesMu.Unlock()
						s.fw.TempBlock(ip, time.Duration(s.cfg.RateLimit.TempBlockSeconds)*time.Second)
						if s.logger != nil {
							s.logger.Log(logs.Entry{Ts: time.Now().Unix(), IP: ip, UA: "", Path: "", Method: "", Status: 0, Action: "l4_temp"})
						}
						s.clusterBadIP(ip)
					}
				}
			}
		})
	}
	r.GET("/login", s.handleLoginPage)
	r.POST("/login", s.handleLogin)
	r.GET("/dashboard", s.requireAdmin(s.handleDashboard))
	r.GET("/logs", s.requireAdmin(s.handleLogsPage))
	r.GET("/sse/metrics", s.requireAdmin(s.handleSSE))
	r.POST("/api/unblock", s.requireAdmin(s.handleUnblock))
	r.POST("/api/toggles", s.requireAdmin(s.handleToggles))
	r.GET("/api/state", s.requireAdmin(s.handleState))
	r.GET("/api/blocked", s.requireAdmin(s.handleListBlocked))
	r.POST("/api/block", s.requireAdmin(s.handleBlock))
	r.GET("/api/rules", s.requireAdmin(s.handleGetRules))
	r.POST("/api/rules", s.requireAdmin(s.handleSetRules))
	r.GET("/api/logs", s.requireAdmin(s.handleLogs))
	r.POST("/internal/event", s.handleEvent)
	r.ServeFiles("/public/{filepath:*}", "./public")
	s.srv = &fasthttp.Server{
		Handler: s.mainHandler,
		Name:    "Azrova-Shield",
	}
	return s
}

func (s *Server) Start() error {
	return s.srv.ListenAndServe(s.cfg.App.Listen)
}

func (s *Server) mainHandler(ctx *fasthttp.RequestCtx) {
	ip := s.clientIP(ctx)
	if s.scrub.Clean(ctx) {
		s.limiter.ReportBad(ip)
		s.fw.TempBlock(ip, time.Duration(s.cfg.RateLimit.TempBlockSeconds)*time.Second)
		if s.logger != nil {
			s.logger.Log(logs.Entry{Ts: time.Now().Unix(), IP: ip, UA: string(ctx.Request.Header.UserAgent()), Path: string(ctx.Path()), Method: string(ctx.Method()), Status: ctx.Response.StatusCode(), Action: "fw_temp"})
		}
		s.logAction(ctx, ctx.Response.StatusCode(), "scrub")
		return
	}
	path := string(ctx.Path())
	pr := s.rules.Eval(path)
	if pr.Block {
		ctx.SetStatusCode(fasthttp.StatusForbidden)
		s.logAction(ctx, fasthttp.StatusForbidden, "rule_block")
		return
	}
	if pr.ForceChallenge && !s.verifier.Passed(ctx) {
		r := url.QueryEscape(string(ctx.RequestURI()))
		ctx.Redirect("/challenge?r="+r, fasthttp.StatusFound)
		s.logAction(ctx, fasthttp.StatusFound, "rule_challenge")
		return
	}
	if s.cfg.App.StealthMode {
		if !s.isAdmin(ctx) && path != "/login" && path != "/public/" && !strings.HasPrefix(path, "/public/") && !strings.HasPrefix(path, "/challenge") {
			sp := filepath.Join(s.cfg.BaseDir, "public", "stealth.html")
			if b, e := os.ReadFile(sp); e == nil {
				ctx.SetContentType("text/html; charset=utf-8")
				ctx.SetStatusCode(fasthttp.StatusNotFound)
				_, _ = ctx.Write(b)
			} else {
				ctx.SetStatusCode(fasthttp.StatusNotFound)
			}
			s.logAction(ctx, fasthttp.StatusNotFound, "stealth")
			return
		}
	}
	if s.limiter.IsPermBlocked(ip) {
		ctx.SetStatusCode(fasthttp.StatusForbidden)
		s.logAction(ctx, fasthttp.StatusForbidden, "perm_block")
		return
	}
	if !pr.BypassWAF && s.waf.BlockWithIP(ctx, ip) {
		s.metrics.BlockedWAF(ip, string(ctx.Path()))
		s.limiter.ReportBad(ip)
		s.fw.TempBlock(ip, time.Duration(s.cfg.RateLimit.TempBlockSeconds)*time.Second)
		if s.logger != nil {
			s.logger.Log(logs.Entry{Ts: time.Now().Unix(), IP: ip, UA: string(ctx.Request.Header.UserAgent()), Path: string(ctx.Path()), Method: string(ctx.Method()), Status: fasthttp.StatusForbidden, Action: "fw_temp"})
		}
		if s.limiter.ShouldPermBlock(ip) {
			s.fw.Block(ip)
			if s.logger != nil {
				s.logger.Log(logs.Entry{Ts: time.Now().Unix(), IP: ip, UA: string(ctx.Request.Header.UserAgent()), Path: string(ctx.Path()), Method: string(ctx.Method()), Status: fasthttp.StatusForbidden, Action: "fw_block"})
			}
		}
		ctx.SetStatusCode(fasthttp.StatusForbidden)
		s.logAction(ctx, fasthttp.StatusForbidden, "waf_block")
		return
	}
	if !s.verifier.Allowed(ctx) {
		s.logAction(ctx, ctx.Response.StatusCode(), "challenge")
		return
	}
	if !pr.BypassRate && !s.limiter.Allow(ip) {
		s.metrics.RateLimited(ip)
		ctx.Response.Header.Set("Retry-After", "60")
		ctx.SetStatusCode(fasthttp.StatusTooManyRequests)
		s.limiter.ReportBad(ip)
		if s.limiter.ShouldPermBlock(ip) {
			s.fw.Block(ip)
			if s.logger != nil {
				s.logger.Log(logs.Entry{Ts: time.Now().Unix(), IP: ip, UA: string(ctx.Request.Header.UserAgent()), Path: string(ctx.Path()), Method: string(ctx.Method()), Status: fasthttp.StatusTooManyRequests, Action: "fw_block"})
			}
		}
		s.fw.TempBlock(ip, time.Duration(s.cfg.RateLimit.TempBlockSeconds)*time.Second)
		if s.logger != nil {
			s.logger.Log(logs.Entry{Ts: time.Now().Unix(), IP: ip, UA: string(ctx.Request.Header.UserAgent()), Path: string(ctx.Path()), Method: string(ctx.Method()), Status: fasthttp.StatusTooManyRequests, Action: "fw_temp"})
		}
		s.logAction(ctx, fasthttp.StatusTooManyRequests, "rate_limit")
		return
	}
	if s.isAdmin(ctx) {
		ctx.Response.Header.Set("X-CSRF-Token", s.adminCSRF(ctx))
	}
	if path == "/" || path == "" {
		if s.cfg.App.ReverseProxyTarget != "" {
			s.proxy.Serve(ctx)
			s.logAction(ctx, ctx.Response.StatusCode(), "proxy")
			return
		}
		ctx.SetStatusCode(fasthttp.StatusOK)
		_, _ = ctx.WriteString("OK")
		s.logAction(ctx, fasthttp.StatusOK, "ok")
		return
	}
	s.rt.Handler(ctx)
	s.logAction(ctx, ctx.Response.StatusCode(), "route")
}

func (s *Server) handleLoginPage(ctx *fasthttp.RequestCtx) {
	if !s.verifier.Passed(ctx) {
		r := url.QueryEscape("/login")
		ctx.Redirect("/challenge?r="+r, fasthttp.StatusFound)
		return
	}
	p := filepath.Join(s.cfg.BaseDir, "public", "login.html")
	if b, e := os.ReadFile(p); e == nil {
		ctx.SetContentType("text/html; charset=utf-8")
		ctx.SetStatusCode(fasthttp.StatusOK)
		_, _ = ctx.Write(b)
		return
	}
	ctx.SetStatusCode(fasthttp.StatusNotFound)
}

func (s *Server) handleDashboard(ctx *fasthttp.RequestCtx) {
	p := filepath.Join(s.cfg.BaseDir, "public", "dashboard.html")
	if b, e := os.ReadFile(p); e == nil {
		ctx.SetContentType("text/html; charset=utf-8")
		ctx.SetStatusCode(fasthttp.StatusOK)
		_, _ = ctx.Write(b)
		return
	}
	ctx.SetStatusCode(fasthttp.StatusNotFound)
}

func (s *Server) handleLogsPage(ctx *fasthttp.RequestCtx) {
	p := filepath.Join(s.cfg.BaseDir, "public", "logs.html")
	if b, e := os.ReadFile(p); e == nil {
		ctx.SetContentType("text/html; charset=utf-8")
		ctx.SetStatusCode(fasthttp.StatusOK)
		_, _ = ctx.Write(b)
		return
	}
	ctx.SetStatusCode(fasthttp.StatusNotFound)
}

func (s *Server) handleLogs(ctx *fasthttp.RequestCtx) {
	t := strings.ToLower(string(ctx.QueryArgs().Peek("type")))
	if t == "" {
		t = "system"
	}
	lim := 200
	if v := string(ctx.QueryArgs().Peek("limit")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 5000 {
			lim = n
		}
	}
	es := s.readLogEntries(lim)
	var out []logs.Entry
	switch t {
	case "ip":
		for _, e := range es {
			a := e.Action
			if a == "perm_block" || a == "rate_limit" || a == "waf_block" || a == "scrub" || a == "rule_block" || a == "nginx_temp" || a == "nginx_block" || a == "l4_temp" || a == "l4_block" {
				out = append(out, e)
			}
		}
	case "access":
		for _, e := range es {
			a := e.Action
			if a == "ok" || a == "proxy" || a == "route" {
				out = append(out, e)
			}
		}
	default:
		out = es
	}
	b, _ := json.Marshal(out)
	ctx.SetContentType("application/json")
	ctx.SetStatusCode(fasthttp.StatusOK)
	_, _ = ctx.Write(b)
}

func (s *Server) readLogEntries(limit int) []logs.Entry {
	fp := filepath.Join(s.cfg.BaseDir, "logs", "azrova-"+time.Now().Format("20060102")+".log")
	f, err := os.Open(fp)
	if err != nil {
		return nil
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	buf := make([]byte, 0, 1024)
	sc.Buffer(buf, 1<<20)
	out := make([]logs.Entry, 0, limit)
	for sc.Scan() {
		var e logs.Entry
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			out = append(out, e)
			if len(out) > limit {
				out = out[1:]
			}
		}
	}
	return out
}

func (s *Server) handleSSE(ctx *fasthttp.RequestCtx) {
	ctx.Response.Header.Set("Content-Type", "text/event-stream")
	ctx.Response.Header.Set("Cache-Control", "no-cache")
	ctx.Response.Header.Set("Connection", "keep-alive")
	ctx.SetBodyStreamWriter(func(w *bufio.Writer) {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				snap := s.metrics.Snapshot()
				b, _ := json.Marshal(snap)
				_, _ = w.WriteString("data: ")
				_, _ = w.Write(b)
				_, _ = w.WriteString("\n\n")
				_ = w.Flush()
			
			}
		}
	})
}

func (s *Server) handleUnblock(ctx *fasthttp.RequestCtx) {
	if !s.checkCSRF(ctx) {
		ctx.SetStatusCode(fasthttp.StatusForbidden)
		return
	}
	var req struct {
		IP string `json:"ip"`
	}
	_ = json.Unmarshal(ctx.PostBody(), &req)
	if req.IP != "" {
		s.limiter.UnblockIP(req.IP)
		s.fw.Unblock(req.IP)
	}
	ctx.SetStatusCode(fasthttp.StatusOK)
}

func (s *Server) handleToggles(ctx *fasthttp.RequestCtx) {
	if !s.checkCSRF(ctx) {
		ctx.SetStatusCode(fasthttp.StatusForbidden)
		return
	}
	var req struct {
		Stealth               *bool `json:"stealth"`
		Firewall              *bool `json:"firewall"`
		Strict                *bool `json:"strict"`
		NginxRpsThreshold     *int  `json:"nginxRpsThreshold"`
		NginxWindowBanCount   *int  `json:"nginxWindowBanCount"`
	}
	_ = json.Unmarshal(ctx.PostBody(), &req)
	changed := false
	if req.Stealth != nil {
		s.cfg.App.StealthMode = *req.Stealth
		changed = true
	}
	if req.Firewall != nil {
		s.cfg.App.FirewallEnabled = *req.Firewall
		s.fw.SetEnabled(*req.Firewall)
		changed = true
	}
	if req.Strict != nil {
		s.cfg.App.StrictMode = *req.Strict
		s.verifier.SetStrict(*req.Strict)
		s.waf.SetStrict(*req.Strict)
		s.limiter.SetStrict(*req.Strict)
		s.clusterStrict(*req.Strict)
		changed = true
	}
	if req.NginxRpsThreshold != nil {
		if *req.NginxRpsThreshold < 0 {
			*req.NginxRpsThreshold = 0
		}
		s.cfg.App.NginxRpsThreshold = *req.NginxRpsThreshold
		changed = true
	}
	if req.NginxWindowBanCount != nil {
		if *req.NginxWindowBanCount < 0 {
			*req.NginxWindowBanCount = 0
		}
		s.cfg.App.NginxWindowBanCount = *req.NginxWindowBanCount
		changed = true
	}
	if changed {
		p := filepath.Join(s.cfg.BaseDir, "configs", "app.json")
		b, _ := json.MarshalIndent(s.cfg.App, "", "  ")
		_ = os.WriteFile(p, b, 0o644)
	}
	ctx.SetStatusCode(fasthttp.StatusOK)
}

func (s *Server) handleLogin(ctx *fasthttp.RequestCtx) {
	if !s.verifier.Passed(ctx) {
		ctx.SetStatusCode(fasthttp.StatusForbidden)
		return
	}
	ct := string(ctx.Request.Header.ContentType())
	var u, p string
	if strings.Contains(ct, "application/json") {
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		_ = json.Unmarshal(ctx.PostBody(), &body)
		u, p = body.Username, body.Password
	} else {
		u = string(ctx.FormValue("username"))
		p = string(ctx.FormValue("password"))
	}
	if u == s.cfg.Login.Username && p == s.cfg.Login.Password {
		sess := &Session{
			ID:      s.randomID(),
			Admin:   true,
			Expires: time.Now().Add(24 * time.Hour),
			CSRF:    s.sign(s.randomID()),
		}
		s.sessions.Set(sess)
		c := fasthttp.Cookie{}
		c.SetKey("azv_sid")
		c.SetValue(sess.ID)
		c.SetHTTPOnly(true)
		c.SetPath("/")
		c.SetMaxAge(86400)
		c.SetSameSite(fasthttp.CookieSameSiteLaxMode)
		ctx.Response.Header.SetCookie(&c)
		cs := fasthttp.Cookie{}
		cs.SetKey("azv_csrf")
		cs.SetValue(sess.CSRF)
		cs.SetPath("/")
		cs.SetMaxAge(86400)
		cs.SetSameSite(fasthttp.CookieSameSiteLaxMode)
		ctx.Response.Header.SetCookie(&cs)
		ctx.SetStatusCode(fasthttp.StatusOK)
		_, _ = ctx.WriteString(`{"ok":true}`)
		return
	}
	ctx.SetStatusCode(fasthttp.StatusUnauthorized)
}

func (s *Server) requireAdmin(h fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		if !s.isAdmin(ctx) {
			ctx.Redirect("/login", fasthttp.StatusFound)
			return
		}
		h(ctx)
	}
}

func (s *Server) isAdmin(ctx *fasthttp.RequestCtx) bool {
	id := string(ctx.Request.Header.Cookie("azv_sid"))
	if id == "" {
		return false
	}
	se, ok := s.sessions.Get(id)
	if !ok {
		return false
	}
	return se.Admin
}

func (s *Server) adminCSRF(ctx *fasthttp.RequestCtx) string {
	id := string(ctx.Request.Header.Cookie("azv_sid"))
	se, ok := s.sessions.Get(id)
	if !ok {
		return ""
	}
	return se.CSRF
}

func (s *Server) checkCSRF(ctx *fasthttp.RequestCtx) bool {
	got := string(ctx.Request.Header.Peek("X-CSRF-Token"))
	if got == "" {
		got = string(ctx.Request.Header.Cookie("azv_csrf"))
	}
	id := string(ctx.Request.Header.Cookie("azv_sid"))
	if id == "" || got == "" {
		return false
	}
	se, ok := s.sessions.Get(id)
	if !ok {
		return false
	}
	return hmac.Equal([]byte(got), []byte(se.CSRF))
}

func (s *Server) clientIP(ctx *fasthttp.RequestCtx) string {
	remote := ctx.RemoteIP()
	trusted := false
	for _, n := range s.proxies {
		if n.Contains(remote) {
			trusted = true
			break
		}
	}
	if trusted {
		h := string(ctx.Request.Header.Peek("X-Forwarded-For"))
		if h != "" {
			if i := strings.IndexByte(h, ','); i >= 0 {
				return strings.TrimSpace(h[:i])
			}
			return strings.TrimSpace(h)
		}
	}
	return remote.String()
}

func (s *Server) randomID() string {
	b := make([]byte, 32)
	_, _ = io.ReadFull(rand.Reader, b)
	return hex.EncodeToString(b)
}

func (s *Server) sign(x string) string {
	m := hmac.New(sha256.New, s.secret)
	_, _ = m.Write([]byte(x))
	return hex.EncodeToString(m.Sum(nil))
}

func (s *Server) logAction(ctx *fasthttp.RequestCtx, status int, action string) {
	if s.logger == nil {
		return
	}
	s.logger.Log(logs.Entry{
		Ts:     time.Now().Unix(),
		IP:     s.clientIP(ctx),
		UA:     string(ctx.Request.Header.UserAgent()),
		Path:   string(ctx.Path()),
		Method: string(ctx.Method()),
		Status: status,
		Action: action,
	})
}

func (s *Server) handleState(ctx *fasthttp.RequestCtx) {
	type state struct {
		Stealth               bool `json:"stealth"`
		Firewall              bool `json:"firewall"`
		Strict                bool `json:"strict"`
		NginxRpsThreshold     int  `json:"nginxRpsThreshold"`
		NginxWindowBanCount   int  `json:"nginxWindowBanCount"`
	}
	b, _ := json.Marshal(state{
		Stealth:              s.cfg.App.StealthMode,
		Firewall:             s.cfg.App.FirewallEnabled,
		Strict:               s.cfg.App.StrictMode,
		NginxRpsThreshold:    s.cfg.App.NginxRpsThreshold,
		NginxWindowBanCount:  s.cfg.App.NginxWindowBanCount,
	})
	ctx.SetContentType("application/json")
	ctx.SetStatusCode(fasthttp.StatusOK)
	_, _ = ctx.Write(b)
}

func (s *Server) handleListBlocked(ctx *fasthttp.RequestCtx) {
	p := filepath.Join(s.cfg.BaseDir, "data", "blocked.json")
	var ips []string
	if b, err := os.ReadFile(p); err == nil {
		_ = json.Unmarshal(b, &ips)
	}
	resp := struct {
		Blocked []string `json:"blocked"`
	}{Blocked: ips}
	b, _ := json.Marshal(resp)
	ctx.SetContentType("application/json")
	ctx.SetStatusCode(fasthttp.StatusOK)
	_, _ = ctx.Write(b)
}

func (s *Server) handleBlock(ctx *fasthttp.RequestCtx) {
	if !s.checkCSRF(ctx) {
		ctx.SetStatusCode(fasthttp.StatusForbidden)
		return
	}
	var req struct {
		IP string `json:"ip"`
	}
	_ = json.Unmarshal(ctx.PostBody(), &req)
	if req.IP != "" {
		s.limiter.PermBlock(req.IP)
		s.fw.Block(req.IP)
	}
	ctx.SetStatusCode(fasthttp.StatusOK)
}

func (s *Server) handleGetRules(ctx *fasthttp.RequestCtx) {
	p := filepath.Join(s.cfg.BaseDir, "configs", "page-rules.json")
	b, err := os.ReadFile(p)
	if err != nil {
		ctx.SetContentType("application/json")
		ctx.SetStatusCode(fasthttp.StatusOK)
		_, _ = ctx.WriteString(`{}`)
		return
	}
	ctx.SetContentType("application/json")
	ctx.SetStatusCode(fasthttp.StatusOK)
	_, _ = ctx.Write(b)
}

func (s *Server) handleSetRules(ctx *fasthttp.RequestCtx) {
	if !s.checkCSRF(ctx) {
		ctx.SetStatusCode(fasthttp.StatusForbidden)
		return
	}
	body := ctx.PostBody()
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		return
	}
	p := filepath.Join(s.cfg.BaseDir, "configs", "page-rules.json")
	_ = os.WriteFile(p, body, 0o644)
	ctx.SetStatusCode(fasthttp.StatusOK)
}

func (s *Server) handleEvent(ctx *fasthttp.RequestCtx) {
	if len(s.clusterKey) == 0 {
		ctx.SetStatusCode(fasthttp.StatusForbidden)
		return
	}
	sig := string(ctx.Request.Header.Peek("X-Azrova-Signature"))
	body := ctx.PostBody()
	if sig == "" || sig != s.signEvent(body) {
		ctx.SetStatusCode(fasthttp.StatusForbidden)
		return
	}
	var ev struct {
		Type   string `json:"type"`
		IP     string `json:"ip"`
		Strict *bool  `json:"strict"`
	}
	if json.Unmarshal(body, &ev) != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		return
	}
	switch ev.Type {
	case "bad_ip":
		if ev.IP != "" {
			s.limiter.ReportBad(ev.IP)
			s.fw.TempBlock(ev.IP, time.Duration(s.cfg.RateLimit.TempBlockSeconds)*time.Second)
		}
	case "block_ip":
		if ev.IP != "" {
			s.limiter.PermBlock(ev.IP)
			s.fw.Block(ev.IP)
		}
	case "strict":
		if ev.Strict != nil {
			s.cfg.App.StrictMode = *ev.Strict
			s.verifier.SetStrict(*ev.Strict)
			s.waf.SetStrict(*ev.Strict)
			s.limiter.SetStrict(*ev.Strict)
		}
	}
	ctx.SetStatusCode(fasthttp.StatusOK)
}

func (s *Server) clusterBadIP(ip string) {
	if len(s.clusterKey) == 0 || len(s.peers) == 0 || ip == "" {
		return
	}
	payload, _ := json.Marshal(map[string]any{"type": "bad_ip", "ip": ip})
	sig := s.signEvent(payload)
	for _, peer := range s.peers {
		req := fasthttp.AcquireRequest()
		resp := fasthttp.AcquireResponse()
		req.Header.SetMethod("POST")
		req.SetRequestURI(strings.TrimRight(peer, "/") + "/internal/event")
		req.Header.Set("X-Azrova-Signature", sig)
		req.Header.SetContentType("application/json")
		req.SetBody(payload)
		_ = fasthttp.Do(req, resp)
		fasthttp.ReleaseRequest(req)
		fasthttp.ReleaseResponse(resp)
	}
}

func (s *Server) clusterBlockIP(ip string) {
	if len(s.clusterKey) == 0 || len(s.peers) == 0 || ip == "" {
		return
	}
	payload, _ := json.Marshal(map[string]any{"type": "block_ip", "ip": ip})
	sig := s.signEvent(payload)
	for _, peer := range s.peers {
		req := fasthttp.AcquireRequest()
		resp := fasthttp.AcquireResponse()
		req.Header.SetMethod("POST")
		req.SetRequestURI(strings.TrimRight(peer, "/") + "/internal/event")
		req.Header.Set("X-Azrova-Signature", sig)
		req.Header.SetContentType("application/json")
		req.SetBody(payload)
		_ = fasthttp.Do(req, resp)
		fasthttp.ReleaseRequest(req)
		fasthttp.ReleaseResponse(resp)
	}
}

func (s *Server) clusterStrict(on bool) {
	if len(s.clusterKey) == 0 || len(s.peers) == 0 {
		return
	}
	payload, _ := json.Marshal(map[string]any{"type": "strict", "strict": on})
	sig := s.signEvent(payload)
	for _, peer := range s.peers {
		req := fasthttp.AcquireRequest()
		resp := fasthttp.AcquireResponse()
		req.Header.SetMethod("POST")
		req.SetRequestURI(strings.TrimRight(peer, "/") + "/internal/event")
		req.Header.Set("X-Azrova-Signature", sig)
		req.Header.SetContentType("application/json")
		req.SetBody(payload)
		_ = fasthttp.Do(req, resp)
		fasthttp.ReleaseRequest(req)
		fasthttp.ReleaseResponse(resp)
	}
}

func parseIptablesParser(prefix string) func(string) (string, bool) {
	return func(line string) (string, bool) {
		p := prefix
		if p == "" {
			p = "AZR_"
		}
		if !strings.Contains(line, p) {
			return "", false
		}
		i := strings.Index(line, "SRC=")
		if i < 0 {
			return "", false
		}
		i += 4
		j := i
		for j < len(line) {
			c := line[j]
			if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
				break
			}
			j++
		}
		ip := strings.TrimSpace(line[i:j])
		if ip == "" {
			return "", false
		}
		if net.ParseIP(ip) == nil {
			return "", false
		}
		return ip, true
	}
}

func (s *Server) signEvent(b []byte) string {
	m := hmac.New(sha256.New, s.clusterKey)
	_, _ = m.Write(b)
	return hex.EncodeToString(m.Sum(nil))
}