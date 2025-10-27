package rules

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

type cfg struct {
	BlockPaths            []string `json:"blockPaths"`
	ChallengePaths        []string `json:"challengePaths"`
	BypassWAFPaths        []string `json:"bypassWAFPaths"`
	BypassRateLimitPaths  []string `json:"bypassRateLimitPaths"`
}

type ruleset struct {
	block []*regexp.Regexp
	chal  []*regexp.Regexp
	bwaf  []*regexp.Regexp
	brl   []*regexp.Regexp
}

type Result struct {
	Block          bool
	ForceChallenge bool
	BypassWAF      bool
	BypassRate     bool
}

type Engine struct {
	mu    sync.RWMutex
	path  string
	rs    ruleset
	mtime time.Time
}

func New(baseDir string) *Engine {
	p := filepath.Join(baseDir, "configs", "page-rules.json")
	e := &Engine{path: p}
	e.reload()
	go e.loop()
	return e
}

func (e *Engine) loop() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for range t.C {
		e.reload()
	}
}

func (e *Engine) reload() {
	fi, err := os.Stat(e.path)
	if err != nil {
		return
	}
	mt := fi.ModTime()
	e.mu.RLock()
	same := e.mtime.Equal(mt)
	e.mu.RUnlock()
	if same {
		return
	}
	b, err := os.ReadFile(e.path)
	if err != nil {
		return
	}
	var c cfg
	if json.Unmarshal(b, &c) != nil {
		return
	}
	rs := ruleset{
		block: compileAll(c.BlockPaths),
		chal:  compileAll(c.ChallengePaths),
		bwaf:  compileAll(c.BypassWAFPaths),
		brl:   compileAll(c.BypassRateLimitPaths),
	}
	e.mu.Lock()
	e.rs = rs
	e.mtime = mt
	e.mu.Unlock()
}

func compileAll(ps []string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(ps))
	for _, p := range ps {
		if r, err := regexp.Compile(p); err == nil {
			out = append(out, r)
		}
	}
	return out
}

func (e *Engine) Eval(path string) Result {
	e.mu.RLock()
	rs := e.rs
	e.mu.RUnlock()
	var r Result
	for _, re := range rs.block {
		if re.MatchString(path) {
			r.Block = true
			return r
		}
	}
	for _, re := range rs.chal {
		if re.MatchString(path) {
			r.ForceChallenge = true
			break
		}
	}
	for _, re := range rs.bwaf {
		if re.MatchString(path) {
			r.BypassWAF = true
			break
		}
	}
	for _, re := range rs.brl {
		if re.MatchString(path) {
			r.BypassRate = true
			break
		}
	}
	return r
}