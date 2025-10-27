package monitor

import (
	"bufio"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

type Tailer struct {
	path    string
	cb      func(string, int)
	parser  func(string) (string, bool)
	mu      sync.Mutex
	offset  int64
	buf     strings.Builder
	winCb   func(map[string]int)
	winStart time.Time
	counts  map[string]int
	quit    chan struct{}
	wg      sync.WaitGroup
}

func New(path string, cb func(string, int)) *Tailer {
	return NewWithParser(path, parseFirstToken, cb)
}

func NewWithParser(path string, parser func(string) (string, bool), cb func(string, int)) *Tailer {
	t := &Tailer{
		path:     path,
		cb:       cb,
		parser:   parser,
		counts:   make(map[string]int),
		winStart: time.Now(),
		quit:     make(chan struct{}),
	}
	t.wg.Add(1)
	go t.run()
	return t
}

func (t *Tailer) Close() {
	close(t.quit)
	t.wg.Wait()
}

func (t *Tailer) OnWindow(cb func(map[string]int)) {
	t.mu.Lock()
	t.winCb = cb
	t.mu.Unlock()
}

func (t *Tailer) run() {
	defer t.wg.Done()
	t.initOffset()
	readTicker := time.NewTicker(500 * time.Millisecond)
	defer readTicker.Stop()
	winTicker := time.NewTicker(time.Second)
	defer winTicker.Stop()

	for {
		select {
		case <-readTicker.C:
			t.readNew()
		case <-winTicker.C:
			t.rotateWindow()
		case <-t.quit:
			return
		}
	}
}

func (t *Tailer) initOffset() {
	fi, err := os.Stat(t.path)
	if err == nil {
		t.offset = fi.Size()
	}
}

func (t *Tailer) readNew() {
	f, err := os.Open(t.path)
	if err != nil {
		return
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return
	}
	if fi.Size() < t.offset {
		t.offset = 0
		t.buf.Reset()
	}
	if _, err = f.Seek(t.offset, io.SeekStart); err != nil {
		return
	}
	r := bufio.NewReaderSize(f, 64*1024)
	for {
		chunk, err := r.ReadString('\n')
		if len(chunk) > 0 {
			t.feed(chunk)
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			break
		}
	}
	if pos, err := f.Seek(0, io.SeekCurrent); err == nil {
		t.offset = pos
	}
}

func (t *Tailer) feed(s string) {
	t.buf.WriteString(s)
	for {
		str := t.buf.String()
		i := strings.IndexByte(str, '\n')
		if i < 0 {
			break
		}
		line := str[:i]
		rest := str[i+1:]
		t.buf.Reset()
		t.buf.WriteString(rest)
		t.handleLine(line)
	}
}

func (t *Tailer) handleLine(line string) {
	if t.parser == nil {
		return
	}
	ip, ok := t.parser(strings.TrimSpace(line))
	if !ok || ip == "" {
		return
	}
	t.mu.Lock()
	t.counts[ip]++
	rate := t.counts[ip]
	t.mu.Unlock()
	if t.cb != nil {
		t.cb(ip, rate)
	}
}

func parseFirstToken(line string) (string, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", false
	}
	sp := strings.IndexByte(line, ' ')
	if sp <= 0 {
		return "", false
	}
	ip := line[:sp]
	if !likelyIP(ip) {
		return "", false
	}
	return ip, true
}

func (t *Tailer) rotateWindow() {
	now := time.Now()
	if now.Sub(t.winStart) >= time.Minute {
		var snap map[string]int
		var cb func(map[string]int)
		t.mu.Lock()
		if len(t.counts) > 0 {
			snap = make(map[string]int, len(t.counts))
			for k, v := range t.counts {
				snap[k] = v
			}
		} else {
			snap = make(map[string]int)
		}
		cb = t.winCb
		t.counts = make(map[string]int)
		t.winStart = now
		t.mu.Unlock()
		if cb != nil {
			cb(snap)
		}
	}
}

func likelyIP(s string) bool {
	if len(s) < 3 {
		return false
	}
	if strings.Contains(s, ":") {
		if strings.Count(s, ":") >= 2 {
			return true
		}
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '.' && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}