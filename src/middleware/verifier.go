package middleware

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"azrova-shield/src/analytics"
	"github.com/valyala/fasthttp"
)

type Verifier struct {
	ttl        time.Duration
	diff       int
	metrics    *analytics.Metrics
	mu         sync.Mutex
	challenges map[string]*challenge
	secret     []byte
	baseTTL    time.Duration
	baseDiff   int
	strict     bool
	ipResolver func(*fasthttp.RequestCtx) string
}

type challenge struct {
	cid        string
	seed       string
	bits       int
	exp        time.Time
	ip         string
	captchaSum int
}

func NewVerifier(ttlSeconds int, diff int, m *analytics.Metrics) *Verifier {
	if ttlSeconds <= 0 {
		ttlSeconds = 86400
	}
	if diff <= 0 {
		diff = 16
	}
	s := make([]byte, 32)
	_, _ = rand.Read(s)
	d := time.Duration(ttlSeconds) * time.Second
	v := &Verifier{
		ttl:        d,
		diff:       diff,
		metrics:    m,
		challenges: make(map[string]*challenge),
		secret:     s,
		baseTTL:    d,
		baseDiff:   diff,
	}
	return v
}

func (v *Verifier) SetIPResolver(f func(*fasthttp.RequestCtx) string) {
	v.mu.Lock()
	v.ipResolver = f
	v.mu.Unlock()
}

func (v *Verifier) Allowed(ctx *fasthttp.RequestCtx) bool {
	p := string(ctx.Path())
	if strings.HasPrefix(p, "/public/") {
		return true
	}
	if strings.HasPrefix(p, "/challenge") {
		v.handleChallenge(ctx)
		return false
	}
	if v.validCookie(ctx) {
		return true
	}
	v.metrics.ChallengeIssued("captcha")
	if string(ctx.Method()) == fasthttp.MethodGet || string(ctx.Method()) == fasthttp.MethodHead {
		r := url.QueryEscape(string(ctx.RequestURI()))
		ctx.Redirect("/challenge?r="+r, fasthttp.StatusFound)
		return false
	}
	ctx.SetStatusCode(fasthttp.StatusForbidden)
	ctx.SetContentType("text/html; charset=utf-8")
	ctx.Response.SetBodyString(`<html><head><meta charset="utf-8"></head><body><a href="/challenge">Challenge</a></body></html>`)
	return false
}

func (v *Verifier) validCookie(ctx *fasthttp.RequestCtx) bool {
	c := string(ctx.Request.Header.Cookie("azv_v"))
	if c == "" {
		return false
	}
	i := strings.IndexByte(c, ':')
	if i <= 0 {
		return false
	}
	expStr := c[:i]
	mac := c[i+1:]
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil {
		return false
	}
	if time.Now().Unix() >= exp {
		return false
	}
	expect := v.sign(v.verifString(ctx, exp))
	return hmac.Equal([]byte(mac), []byte(expect))
}

func (v *Verifier) verifString(ctx *fasthttp.RequestCtx, exp int64) string {
	ip := v.clientIP(ctx)
	ua := string(ctx.Request.Header.UserAgent())
	return ip + "|" + ua + "|" + fmt.Sprint(exp) + "|v1"
}

func (v *Verifier) handleChallenge(ctx *fasthttp.RequestCtx) {
	if string(ctx.Method()) == fasthttp.MethodGet {
		v.getChallenge(ctx)
		return
	}
	if string(ctx.Method()) == fasthttp.MethodPost {
		v.postChallenge(ctx)
		return
	}
	ctx.Error("method not allowed", fasthttp.StatusMethodNotAllowed)
}

func (v *Verifier) getChallenge(ctx *fasthttp.RequestCtx) {
	cid := hexRand(16)
	seed := hexRand(16)
	bits := v.diff
	a := int(randByte()%10) + 2
	b := int(randByte()%10) + 2
	sum := a + b
	ch := &challenge{
		cid:        cid,
		seed:       seed,
		bits:       bits,
		exp:        time.Now().Add(2 * time.Minute),
		ip:         v.clientIP(ctx),
		captchaSum: sum,
	}
	v.mu.Lock()
	v.challenges[cid] = ch
	v.mu.Unlock()
	r := string(ctx.QueryArgs().Peek("r"))
	if r == "" {
		r = "/dashboard"
	}
	html := v.page(seed, cid, bits, r, a, b)
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetContentType("text/html; charset=utf-8")
	_, _ = ctx.WriteString(html)
}

func (v *Verifier) postChallenge(ctx *fasthttp.RequestCtx) {
	ct := strings.ToLower(string(ctx.Request.Header.ContentType()))
	type reqBody struct {
		CID    string `json:"cid"`
		Suffix string `json:"suffix"`
		Answer string `json:"answer"`
		R      string `json:"r"`
	}
	var rb reqBody
	if strings.Contains(ct, "application/json") {
		_ = json.Unmarshal(ctx.PostBody(), &rb)
	} else {
		rb.CID = string(ctx.FormValue("cid"))
		rb.Answer = string(ctx.FormValue("answer"))
		rb.R = string(ctx.FormValue("r"))
	}
	if rb.CID == "" {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		return
	}
	v.mu.Lock()
	ch, ok := v.challenges[rb.CID]
	if ok && time.Now().After(ch.exp) {
		ok = false
		delete(v.challenges, rb.CID)
	}
	if ok && ch.ip != v.clientIP(ctx) {
		ok = false
	}
	if ok && rb.Suffix != "" {
		zeros := (ch.bits + 3) / 4
		h := sha256Hex(ch.seed + rb.Suffix)
		if !strings.HasPrefix(h, strings.Repeat("0", zeros)) {
			ok = false
		}
	}
	if ok && rb.Suffix == "" {
		ans, err := strconv.Atoi(rb.Answer)
		if err != nil || ans != ch.captchaSum {
			ok = false
		}
	}
	if ok {
		delete(v.challenges, rb.CID)
	}
	v.mu.Unlock()
	if !ok {
		ctx.SetStatusCode(fasthttp.StatusForbidden)
		return
	}
	exp := time.Now().Add(v.ttl).Unix()
	val := fmt.Sprintf("%d:%s", exp, v.sign(v.verifString(ctx, exp)))
	c := fasthttp.Cookie{}
	c.SetKey("azv_v")
	c.SetValue(val)
	c.SetPath("/")
	c.SetHTTPOnly(true)
	c.SetMaxAge(int(v.ttl / time.Second))
	c.SetSameSite(fasthttp.CookieSameSiteLaxMode)
	ctx.Response.Header.SetCookie(&c)
	if rb.Suffix != "" {
		v.metrics.ChallengePassed("pow")
	} else {
		v.metrics.ChallengePassed("captcha")
	}
	r := rb.R
	if r == "" {
		r = "/dashboard"
	}
	u, _ := url.QueryUnescape(r)
	if !strings.HasPrefix(u, "/") {
		u = "/"
	}
	if strings.Contains(ct, "application/json") {
		ctx.SetStatusCode(fasthttp.StatusOK)
		ctx.SetContentType("application/json; charset=utf-8")
		_, _ = ctx.WriteString(`{"ok":true,"redirect":"` + u + `"}`)
		return
	}
	ctx.Redirect(u, fasthttp.StatusFound)
}

func (v *Verifier) page(_ string, cid string, _ int, r string, a, b int) string {
	return `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<script src="https://cdn.tailwindcss.com"></script>
<title>Verification</title>
</head>
<body class="min-h-screen bg-gradient-to-b from-black via-zinc-950 to-black text-gray-100 flex items-center justify-center">
<div class="w-full max-w-md p-6 rounded-xl bg-zinc-900 border border-zinc-800">
<div class="text-2xl font-semibold mb-2">Verification</div>
<div class="text-sm text-zinc-400 mb-4">Enter the code to continue</div>
<form method="post" action="/challenge" class="space-y-3">
<input type="hidden" name="cid" value="` + cid + `">
<input type="hidden" name="r" value="` + htmlEscape(r) + `">
<div class="text-sm">` + strconv.Itoa(a) + ` + ` + strconv.Itoa(b) + ` =</div>
<input class="w-full px-3 py-2 rounded bg-zinc-800 border border-zinc-700 outline-none" name="answer" autocomplete="off" inputmode="numeric" pattern="[0-9]*" required>
<button class="w-full px-3 py-2 bg-emerald-600 rounded hover:bg-emerald-500">Verify</button>
</form>
</div>
</body>
</html>`
}

func (v *Verifier) sign(x string) string {
	m := hmac.New(sha256.New, v.secret)
	_, _ = m.Write([]byte(x))
	return hex.EncodeToString(m.Sum(nil))
}

func (v *Verifier) SetStrict(on bool) {
	v.mu.Lock()
	v.strict = on
	if on {
		v.ttl = v.baseTTL / 2
		if v.ttl < 5*time.Minute {
			v.ttl = 5 * time.Minute
		}
		v.diff = v.baseDiff + 6
	} else {
		v.ttl = v.baseTTL
		v.diff = v.baseDiff
	}
	v.mu.Unlock()
}

func (v *Verifier) Passed(ctx *fasthttp.RequestCtx) bool {
	return v.validCookie(ctx)
}

func (v *Verifier) clientIP(ctx *fasthttp.RequestCtx) string {
	if v.ipResolver != nil {
		return v.ipResolver(ctx)
	}
	return ctx.RemoteIP().String()
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func hexRand(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func randByte() byte {
	var b [1]byte
	_, _ = rand.Read(b[:])
	return b[0]
}

func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;")
	return r.Replace(s)
}

func jsEscape(s string) string {
	r := strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "\n", "", "\r", "")
	return r.Replace(s)
}