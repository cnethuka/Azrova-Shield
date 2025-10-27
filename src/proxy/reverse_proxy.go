package proxy

import (
	"net/url"
	"strings"
	"time"

	"azrova-shield/src/analytics"
	"github.com/valyala/fasthttp"
)

type ReverseProxy struct {
	target  string
	base    *url.URL
	hc      *fasthttp.HostClient
	metrics *analytics.Metrics
}

func New(target string, m *analytics.Metrics) *ReverseProxy {
	if target == "" {
		return &ReverseProxy{target: "", metrics: m}
	}
	u, _ := url.Parse(target)
	host := u.Host
	if !strings.Contains(host, ":") {
		if u.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	hc := &fasthttp.HostClient{
		Addr:         host,
		IsTLS:        u.Scheme == "https",
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		MaxConns:     1024,
	}
	return &ReverseProxy{target: target, base: u, hc: hc, metrics: m}
}

func (p *ReverseProxy) Serve(ctx *fasthttp.RequestCtx) {
	if p.hc == nil {
		ctx.SetStatusCode(fasthttp.StatusServiceUnavailable)
		return
	}
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)
	ctx.Request.CopyTo(req)
	req.URI().SetScheme(p.base.Scheme)
	req.URI().SetHost(p.base.Host)
	req.URI().SetPathBytes(ctx.Path())
	req.URI().SetQueryStringBytes(ctx.URI().QueryString())
	req.Header.SetHost(p.base.Host)
	h := string(req.Header.Peek("X-Forwarded-For"))
	ip := ctx.RemoteIP().String()
	if h == "" {
		req.Header.Set("X-Forwarded-For", ip)
	} else {
		req.Header.Set("X-Forwarded-For", h+", "+ip)
	}
	if ctx.IsTLS() {
		req.Header.Set("X-Forwarded-Proto", "https")
	} else {
		req.Header.Set("X-Forwarded-Proto", "http")
	}
	req.Header.Set("X-Forwarded-Host", string(ctx.Host()))
	req.Header.Del("Connection")
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Keep-Alive")
	req.Header.Del("Proxy-Authenticate")
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Te")
	req.Header.Del("Trailer")
	req.Header.Del("Transfer-Encoding")
	err := p.hc.DoDeadline(req, resp, time.Now().Add(30*time.Second))
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadGateway)
		return
	}
	resp.Header.Del("Connection")
	resp.Header.Del("Proxy-Connection")
	resp.CopyTo(&ctx.Response)
}