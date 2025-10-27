package middleware

import (
	"sync"
	"time"

	"azrova-shield/src/analytics"
	"azrova-shield/src/config"
)

type ipState struct {
	tokens    float64
	last      time.Time
	tempUntil time.Time
	perm      bool
	bad       int
	rlHits    int
	rlWindow  time.Time
}

type RateLimiter struct {
	mu                   sync.Mutex
	perSec               float64
	burst                float64
	tempBlock            time.Duration
	permThreshold        int
	ips                  map[string]*ipState
	metrics              *analytics.Metrics
	basePerSec           float64
	baseBurst            float64
	baseTempBlock        time.Duration
	basePermThreshold    int
	rlHitsThreshold      int
	baseRlHitsThreshold  int
}

func NewRateLimiter(cfg config.RateLimitConfig, metrics *analytics.Metrics) *RateLimiter {
	perSec := float64(cfg.RequestsPerMinute) / 60.0
	if perSec <= 0 {
		perSec = 1
	}
	if cfg.Burst <= 0 {
		cfg.Burst = 1
	}
	if cfg.TempBlockSeconds <= 0 {
		cfg.TempBlockSeconds = 300
	}
	if cfg.PermBlockThreshold <= 0 {
		cfg.PermBlockThreshold = 10
	}
	rlHits := 5
	return &RateLimiter{
		perSec:               perSec,
		burst:                float64(cfg.Burst),
		tempBlock:            time.Duration(cfg.TempBlockSeconds) * time.Second,
		permThreshold:        cfg.PermBlockThreshold,
		ips:                  make(map[string]*ipState),
		metrics:              metrics,
		basePerSec:           perSec,
		baseBurst:            float64(cfg.Burst),
		baseTempBlock:        time.Duration(cfg.TempBlockSeconds) * time.Second,
		basePermThreshold:    cfg.PermBlockThreshold,
		rlHitsThreshold:      rlHits,
		baseRlHitsThreshold:  rlHits,
	}
}

func (l *RateLimiter) Allow(ip string) bool {
	now := time.Now()
	l.mu.Lock()
	st := l.ips[ip]
	if st == nil {
		st = &ipState{tokens: l.burst, last: now}
		l.ips[ip] = st
	}
	if st.perm {
		l.mu.Unlock()
		return false
	}
	if now.Before(st.tempUntil) {
		l.mu.Unlock()
		return false
	}
	elapsed := now.Sub(st.last).Seconds()
	if elapsed > 0 {
		st.tokens += elapsed * l.perSec
		if st.tokens > l.burst {
			st.tokens = l.burst
		}
		st.last = now
	}
	if st.tokens >= 1.0 {
		st.tokens -= 1.0
		l.mu.Unlock()
		return true
	}
	if now.Sub(st.rlWindow) > time.Minute {
		st.rlWindow = now
		st.rlHits = 0
	}
	st.rlHits++
	if st.rlHits >= l.rlHitsThreshold {
		st.tempUntil = now.Add(l.tempBlock)
		st.rlHits = 0
	}
	l.mu.Unlock()
	return false
}

func (l *RateLimiter) ReportBad(ip string) {
	l.mu.Lock()
	st := l.ips[ip]
	if st == nil {
		st = &ipState{tokens: l.burst, last: time.Now()}
		l.ips[ip] = st
	}
	st.bad++
	l.mu.Unlock()
}

func (l *RateLimiter) ShouldPermBlock(ip string) bool {
	l.mu.Lock()
	st := l.ips[ip]
	if st == nil {
		st = &ipState{tokens: l.burst, last: time.Now()}
		l.ips[ip] = st
	}
	if st.bad >= l.permThreshold {
		st.perm = true
		l.mu.Unlock()
		return true
	}
	l.mu.Unlock()
	return false
}

func (l *RateLimiter) IsPermBlocked(ip string) bool {
	l.mu.Lock()
	st := l.ips[ip]
	blocked := st != nil && st.perm
	l.mu.Unlock()
	return blocked
}

func (l *RateLimiter) UnblockIP(ip string) {
	l.mu.Lock()
	delete(l.ips, ip)
	l.mu.Unlock()
}

func (l *RateLimiter) PermBlock(ip string) {
	l.mu.Lock()
	st := l.ips[ip]
	if st == nil {
		st = &ipState{tokens: l.burst, last: time.Now()}
		l.ips[ip] = st
	}
	st.perm = true
	l.mu.Unlock()
}

func (l *RateLimiter) SetStrict(on bool) {
	l.mu.Lock()
	if on {
		ps := l.basePerSec * 0.5
		if ps < 0.25 {
			ps = 0.25
		}
		l.perSec = ps
		bb := l.baseBurst * 0.5
		if bb < 1 {
			bb = 1
		}
		l.burst = bb
		l.tempBlock = l.baseTempBlock * 2
		pt := l.basePermThreshold - 2
		if pt < 3 {
			pt = 3
		}
		l.permThreshold = pt
		rht := l.baseRlHitsThreshold - 2
		if rht < 2 {
			rht = 2
		}
		l.rlHitsThreshold = rht
	} else {
		l.perSec = l.basePerSec
		l.burst = l.baseBurst
		l.tempBlock = l.baseTempBlock
		l.permThreshold = l.basePermThreshold
		l.rlHitsThreshold = l.baseRlHitsThreshold
	}
	l.mu.Unlock()
}