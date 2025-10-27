package middleware

import (
	"regexp"
	"strings"

	"azrova-shield/src/analytics"
	"azrova-shield/src/config"
	"github.com/valyala/fasthttp"
)

type WAF struct {
	ua      []*regexp.Regexp
	ref     []*regexp.Regexp
	uri     []*regexp.Regexp
	qp      []*regexp.Regexp
	body    []*regexp.Regexp
	headers map[string][]*regexp.Regexp
	ipb     map[string]struct{}
	metrics *analytics.Metrics
	strict  bool
}

func NewWAF(rules config.WAFRules, m *analytics.Metrics) *WAF {
	w := &WAF{
		ua:      compileAll(rules.BlockUserAgents),
		ref:     compileAll(rules.BlockReferrers),
		uri:     compileAll(rules.URIPatterns),
		qp:      compileAll(rules.QueryPatterns),
		body:    compileAll(rules.BodyPatterns),
		headers: make(map[string][]*regexp.Regexp),
		ipb:     make(map[string]struct{}),
		metrics: m,
	}
	for k, v := range rules.Headers {
		w.headers[strings.ToLower(k)] = compileAll(v)
	}
	for _, ip := range rules.BlockedIPs {
		w.ipb[ip] = struct{}{}
	}
	return w
}

func (w *WAF) SetStrict(on bool) {
	w.strict = on
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

func (w *WAF) Block(ctx *fasthttp.RequestCtx) bool {
	return w.BlockWithIP(ctx, ctx.RemoteIP().String())
}

func (w *WAF) BlockWithIP(ctx *fasthttp.RequestCtx, ip string) bool {
	if _, ok := w.ipb[ip]; ok {
		return true
	}
	if w.blockUA(ctx) {
		return true
	}
	if w.blockRef(ctx) {
		return true
	}
	if w.blockURI(ctx) {
		return true
	}
	if w.blockQuery(ctx) {
		return true
	}
	if w.blockHeaders(ctx) {
		return true
	}
	if w.strictHeaders(ctx) {
		return true
	}
	if w.blockBody(ctx) {
		return true
	}
	return false
}

func (w *WAF) blockUA(ctx *fasthttp.RequestCtx) bool {
	ua := strings.ToLower(string(ctx.Request.Header.UserAgent()))
	if ua == "" {
		return true
	}
	for _, r := range w.ua {
		if r.MatchString(ua) {
			return true
		}
	}
	return false
}

func (w *WAF) blockRef(ctx *fasthttp.RequestCtx) bool {
	ref := strings.ToLower(string(ctx.Request.Header.Peek("Referer")))
	for _, r := range w.ref {
		if r.MatchString(ref) {
			return true
		}
	}
	return false
}

func (w *WAF) blockURI(ctx *fasthttp.RequestCtx) bool {
	p := string(ctx.Path())
	for _, r := range w.uri {
		if r.MatchString(p) {
			return true
		}
	}
	return false
}

func (w *WAF) blockQuery(ctx *fasthttp.RequestCtx) bool {
	q := strings.ToLower(string(ctx.URI().QueryString()))
	for _, r := range w.qp {
		if r.MatchString(q) {
			return true
		}
	}
	return false
}

func (w *WAF) blockHeaders(ctx *fasthttp.RequestCtx) bool {
	for k, rs := range w.headers {
		v := strings.ToLower(string(ctx.Request.Header.Peek(k)))
		if v == "" {
			continue
		}
		for _, r := range rs {
			if r.MatchString(v) {
				return true
			}
		}
	}
	return false
}

func (w *WAF) strictHeaders(ctx *fasthttp.RequestCtx) bool {
	if !w.strict {
		return false
	}
	ac := strings.ToLower(strings.TrimSpace(string(ctx.Request.Header.Peek("Accept"))))
	if ac == "" {
		return true
	}
	if !strings.Contains(ac, "text/html") && !strings.Contains(ac, "application/json") && !strings.Contains(ac, "*/*") {
		return true
	}
	al := strings.TrimSpace(string(ctx.Request.Header.Peek("Accept-Language")))
	if al == "" || len(al) > 64 {
		return true
	}
	return false
}

func (w *WAF) blockBody(ctx *fasthttp.RequestCtx) bool {
	m := ctx.IsPost() || ctx.IsPut() || ctx.IsPatch()
	if !m {
		return false
	}
	b := ctx.PostBody()
	if len(b) == 0 {
		return false
	}
	if len(b) > 65536 {
		b = b[:65536]
	}
	s := strings.ToLower(string(b))
	for _, r := range w.body {
		if r.MatchString(s) {
			return true
		}
	}
	return false
}