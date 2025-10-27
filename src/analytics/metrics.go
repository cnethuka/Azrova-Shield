package analytics

import (
	"sort"
	"sync"
	"time"
)

type Stat struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

type Snapshot struct {
	Ts                int64  `json:"ts"`
	UptimeSeconds     int64  `json:"uptimeSeconds"`
	BlockedWAF        uint64 `json:"blockedWAF"`
	RateLimited       uint64 `json:"rateLimited"`
	ChallengeIssued   uint64 `json:"challengeIssued"`
	ChallengePassed   uint64 `json:"challengePassed"`
	TopBlockedIPs     []Stat `json:"topBlockedIPs"`
	TopRateLimitedIPs []Stat `json:"topRateLimitedIPs"`
}

type Metrics struct {
	mu              sync.Mutex
	start           time.Time
	blockedWAF      uint64
	rateLimited     uint64
	challengeIssued uint64
	challengePassed uint64
	blockedByIP     map[string]int
	rlByIP          map[string]int
}

func New() *Metrics {
	return &Metrics{
		start:       time.Now(),
		blockedByIP: make(map[string]int),
		rlByIP:      make(map[string]int),
	}
}

func (m *Metrics) BlockedWAF(ip, path string) {
	m.mu.Lock()
	m.blockedWAF++
	if ip != "" {
		m.blockedByIP[ip]++
	}
	m.mu.Unlock()
}

func (m *Metrics) RateLimited(ip string) {
	m.mu.Lock()
	m.rateLimited++
	if ip != "" {
		m.rlByIP[ip]++
	}
	m.mu.Unlock()
}

func (m *Metrics) ChallengeIssued(kind string) {
	m.mu.Lock()
	m.challengeIssued++
	m.mu.Unlock()
}

func (m *Metrics) ChallengePassed(kind string) {
	m.mu.Lock()
	m.challengePassed++
	m.mu.Unlock()
}

func (m *Metrics) Snapshot() Snapshot {
	m.mu.Lock()
	tb := topN(m.blockedByIP, 10)
	tr := topN(m.rlByIP, 10)
	snap := Snapshot{
		Ts:                time.Now().Unix(),
		UptimeSeconds:     int64(time.Since(m.start) / time.Second),
		BlockedWAF:        m.blockedWAF,
		RateLimited:       m.rateLimited,
		ChallengeIssued:   m.challengeIssued,
		ChallengePassed:   m.challengePassed,
		TopBlockedIPs:     tb,
		TopRateLimitedIPs: tr,
	}
	m.mu.Unlock()
	return snap
}

type kv struct {
	k string
	v int
}

func topN(m map[string]int, n int) []Stat {
	kvs := make([]kv, 0, len(m))
	for k, v := range m {
		kvs = append(kvs, kv{k: k, v: v})
	}
	sort.Slice(kvs, func(i, j int) bool {
		if kvs[i].v == kvs[j].v {
			return kvs[i].k < kvs[j].k
		}
		return kvs[i].v > kvs[j].v
	})
	if n > len(kvs) {
		n = len(kvs)
	}
	out := make([]Stat, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, Stat{Key: kvs[i].k, Count: kvs[i].v})
	}
	return out
}