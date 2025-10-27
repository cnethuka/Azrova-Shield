package middleware

import (
	"net"
	"net/url"
	"strings"

	"github.com/valyala/fasthttp"
)

type Scrubber struct {
	maxPath         int
	maxQuery        int
	maxHeaders      int
	maxHeaderName   int
	maxHeaderValue  int
	maxHeaderBytes  int
	maxArgs         int
	maxArgSize      int
	dropBodyOnSafe  bool
	maxBody         int
}

func NewScrubber() *Scrubber {
	return &Scrubber{
		maxPath:        4096,
		maxQuery:       8192,
		maxHeaders:     96,
		maxHeaderName:  64,
		maxHeaderValue: 4096,
		maxHeaderBytes: 64 * 1024,
		maxArgs:        256,
		maxArgSize:     2048,
		dropBodyOnSafe: true,
		maxBody:        8 * 1024 * 1024,
	}
}

func (s *Scrubber) Clean(ctx *fasthttp.RequestCtx) bool {
	m := string(ctx.Method())
	switch m {
	case "GET", "POST", "HEAD", "PUT", "PATCH", "DELETE", "OPTIONS":
	default:
		ctx.SetStatusCode(fasthttp.StatusMethodNotAllowed)
		return true
	}

	host := string(ctx.Request.Header.Host())
	if host == "" {
		host = string(ctx.Host())
	}
	if !validHost(host) {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		return true
	}

	te := strings.ToLower(strings.TrimSpace(string(ctx.Request.Header.Peek("Transfer-Encoding"))))
	cl := ctx.Request.Header.ContentLength()
	if te != "" && cl >= 0 {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		return true
	}
	if te != "" && te != "chunked" {
		if !strings.Contains(te, "chunked") {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			return true
		}
	}
	if strings.Count(te, "chunked") > 1 {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		return true
	}
	exp := strings.ToLower(strings.TrimSpace(string(ctx.Request.Header.Peek("Expect"))))
	if exp != "" && exp != "100-continue" {
		ctx.SetStatusCode(fasthttp.StatusExpectationFailed)
		return true
	}
	if v := ctx.Request.Header.Peek("X-HTTP-Method-Override"); len(v) > 0 {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		return true
	}
	ce := strings.ToLower(strings.TrimSpace(string(ctx.Request.Header.Peek("Content-Encoding"))))
	if ce != "" && ce != "gzip" && ce != "br" && ce != "deflate" && ce != "identity" {
		ctx.SetStatusCode(fasthttp.StatusUnsupportedMediaType)
		return true
	}
	rng := strings.TrimSpace(string(ctx.Request.Header.Peek("Range")))
	if strings.Contains(rng, ",") {
		ctx.SetStatusCode(fasthttp.StatusRequestedRangeNotSatisfiable)
		return true
	}

	ae := strings.ToLower(strings.TrimSpace(string(ctx.Request.Header.Peek("Accept-Encoding"))))
	if ae != "" {
		okAE := true
		for _, t := range strings.Split(ae, ",") {
			tt := strings.TrimSpace(t)
			if tt == "" {
				continue
			}
			switch tt {
			case "gzip", "br", "deflate", "identity", "*":
			default:
				okAE = false
			}
			if !okAE {
				break
			}
		}
		if !okAE {
			ctx.Request.Header.Del("Accept-Encoding")
		}
	}

	if cl > s.maxBody && s.maxBody > 0 {
		ctx.SetStatusCode(fasthttp.StatusRequestEntityTooLarge)
		return true
	}
	if m == fasthttp.MethodPost || m == fasthttp.MethodPut || m == fasthttp.MethodPatch || cl > 0 {
		ct := strings.ToLower(strings.TrimSpace(string(ctx.Request.Header.ContentType())))
		if ct == "" {
			ct = "application/octet-stream"
		}
		if !strings.HasPrefix(ct, "application/json") &&
			!strings.HasPrefix(ct, "application/x-www-form-urlencoded") &&
			!strings.HasPrefix(ct, "multipart/form-data") &&
			!strings.HasPrefix(ct, "text/plain") {
			ctx.SetStatusCode(fasthttp.StatusUnsupportedMediaType)
			return true
		}
	}

	delHop(ctx)

	hc := 0
	total := 0
	bad := false
	ctx.Request.Header.VisitAll(func(k, v []byte) {
		if bad {
			return
		}
		hc++
		total += len(k) + len(v)
		if hc > s.maxHeaders || total > s.maxHeaderBytes {
			bad = true
			return
		}
		if len(k) > s.maxHeaderName || len(v) > s.maxHeaderValue {
			bad = true
			return
		}
		if hasCtl(k) || hasCtl(v) {
			bad = true
			return
		}
		for _, c := range k {
			if !isTokenChar(c) {
				bad = true
				return
			}
		}
	})
	if bad {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		return true
	}

	if (m == fasthttp.MethodGet || m == fasthttp.MethodHead) && s.dropBodyOnSafe && cl > 0 {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		return true
	}

	q := string(ctx.URI().QueryString())
	if len(q) > s.maxQuery {
		ctx.SetStatusCode(fasthttp.StatusRequestURITooLong)
		return true
	}
	args := ctx.URI().QueryArgs()
	if args.Len() > s.maxArgs {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		return true
	}
	badv := false
	args.VisitAll(func(k, v []byte) {
		if badv {
			return
		}
		if len(k)+len(v) > s.maxArgSize {
			badv = true
			return
		}
		if hasCtl(k) || hasCtl(v) {
			badv = true
			return
		}
	})
	if badv {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		return true
	}
	if strings.Contains(q, "%") {
		if dq, err := url.QueryUnescape(q); err == nil {
			if len(dq) > s.maxQuery || hasCtl([]byte(dq)) {
				ctx.SetStatusCode(fasthttp.StatusBadRequest)
				return true
			}
			ctx.URI().SetQueryString(dq)
		}
	}

	p := string(ctx.Path())
	orig := p
	if p == "" {
		p = "/"
	}
	lp := strings.ToLower(p)
	if strings.HasPrefix(lp, "http://") || strings.HasPrefix(lp, "https://") {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		return true
	}
	if oc := strings.ToLower(orig); strings.Contains(oc, "%2f") || strings.Contains(oc, "%5c") {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		return true
	}
	p = strings.ReplaceAll(p, "\\", "/")
	ok := true
	if strings.Contains(p, "%") {
		p, ok = decodePathLoop(p, 4, s.maxPath*2)
		if !ok {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			return true
		}
	}
	if strings.Contains(p, ";") {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		return true
	}
	p = collapseSlashes(p)
	p = removeDotSegments(p)
	if p == "" {
		p = "/"
	}
	for _, seg := range strings.Split(p, "/") {
		if len(seg) > 255 {
			ctx.SetStatusCode(fasthttp.StatusRequestURITooLong)
			return true
		}
	}
	if len(p) > s.maxPath || hasCtl([]byte(p)) {
		ctx.SetStatusCode(fasthttp.StatusRequestURITooLong)
		return true
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	ctx.URI().SetPath(p)

	return false
}

func hasCtl(b []byte) bool {
	for _, c := range b {
		if c < 32 || c == 127 {
			return true
		}
	}
	return false
}

func isTokenChar(r byte) bool {
	if r >= 'a' && r <= 'z' {
		return true
	}
	if r >= 'A' && r <= 'Z' {
		return true
	}
	if r >= '0' && r <= '9' {
		return true
	}
	switch r {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	}
	return false
}

func validHost(h string) bool {
	if h == "" || len(h) > 255 {
		return false
	}
	if strings.ContainsAny(h, " \t\r\n") {
		return false
	}
	if strings.HasPrefix(h, "[") && strings.Contains(h, "]") {
		return true
	}
	if strings.Count(h, ":") > 1 && !strings.HasPrefix(h, "[") {
		return false
	}
	host := h
	if i := strings.LastIndexByte(h, ':'); i > 0 && !strings.Contains(h, "]") {
		host = h[:i]
	}
	if strings.HasSuffix(host, ".") {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	for _, c := range host {
		if !(c == '-' || c == '.' || (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
			return false
		}
	}
	return true
}

func decodePathLoop(p string, iters int, limit int) (string, bool) {
	s := p
	for i := 0; i < iters; i++ {
		if !strings.Contains(s, "%") {
			return s, true
		}
		u, err := url.PathUnescape(s)
		if err != nil {
			return s, true
		}
		if len(u) > limit {
			return s, false
		}
		if u == s {
			return s, true
		}
		s = u
	}
	return s, true
}

func collapseSlashes(p string) string {
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	return p
}

func removeDotSegments(p string) string {
	if p == "" {
		return "/"
	}
	segs := strings.Split(p, "/")
	stack := make([]string, 0, len(segs))
	for _, s := range segs {
		if s == "" || s == "." {
			continue
		}
		if s == ".." {
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			continue
		}
		stack = append(stack, s)
	}
	return "/" + strings.Join(stack, "/")
}

func delHop(ctx *fasthttp.RequestCtx) {
	h := &ctx.Request.Header
	h.Del("Connection")
	h.Del("Proxy-Connection")
	h.Del("Keep-Alive")
	h.Del("TE")
	h.Del("Trailer")
	h.Del("Transfer-Encoding")
	h.Del("Upgrade")
	h.Del("X-Original-URL")
	h.Del("X-Rewrite-URL")
	h.Del("X-HTTP-Method-Override")
}