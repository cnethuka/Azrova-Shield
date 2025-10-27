package logs

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Entry struct {
	Ts     int64  `json:"ts"`
	IP     string `json:"ip"`
	UA     string `json:"ua"`
	Path   string `json:"path"`
	Method string `json:"method"`
	Status int    `json:"status"`
	Action string `json:"action"`
}

type Logger struct {
	mu      sync.Mutex
	baseDir string
	ch      chan Entry
	quit    chan struct{}
	f       *os.File
	w       *bufio.Writer
	curDate string
}

func New(baseDir string) *Logger {
	l := &Logger{
		baseDir: baseDir,
		ch:      make(chan Entry, 4096),
		quit:    make(chan struct{}),
	}
	go l.run()
	return l
}

func (l *Logger) filePathFor(date string) string {
	dir := filepath.Join(l.baseDir, "logs")
	_ = os.MkdirAll(dir, 0o755)
	return filepath.Join(dir, "azrova-"+date+".log")
}

func (l *Logger) rotateIfNeeded(now time.Time) error {
	date := now.Format("20060102")
	if l.f != nil && l.curDate == date {
		return nil
	}
	if l.w != nil {
		_ = l.w.Flush()
	}
	if l.f != nil {
		_ = l.f.Close()
	}
	fp := l.filePathFor(date)
	f, err := os.OpenFile(fp, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	l.f = f
	l.w = bufio.NewWriterSize(f, 1<<20)
	l.curDate = date
	return nil
}

func (l *Logger) run() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case e := <-l.ch:
			now := time.Now()
			l.mu.Lock()
			if l.rotateIfNeeded(now) == nil {
				b, _ := json.Marshal(e)
				_, _ = l.w.Write(b)
				_ = l.w.WriteByte('\n')
				_ = l.w.Flush()
			}
			l.mu.Unlock()
		case <-l.quit:
			l.mu.Lock()
			if l.w != nil {
				_ = l.w.Flush()
			}
			if l.f != nil {
				_ = l.f.Close()
			}
			l.mu.Unlock()
			return
		}
	}
}

func (l *Logger) Log(e Entry) {
	select {
	case l.ch <- e:
	default:
	}
}

func (l *Logger) Close() {
	close(l.quit)
}