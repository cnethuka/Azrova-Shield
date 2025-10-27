Azrova-Shield

Overview
Azrova‑Shield is a high‑performance Layer 7 DDoS protection gateway built on fasthttp. It provides a WAF, JavaScript challenge with CAPTCHA fallback, cookie-based verification, rate limiting with escalation to firewall blocks, real-time analytics, custom page rules, stealth mode, and admin controls.

Architecture
- Core entry: src/main.go
- HTTP server and routes: src/server/server.go
- Configuration loader: src/config/config.go
- Middlewares
  - WAF: src/middleware/waf.go
  - Rate limiting: src/middleware/rate_limit.go
  - Challenge and verification: src/middleware/verifier.go
- Reverse proxy: src/proxy/reverse_proxy.go
- Firewall integration: src/firewall/firewall.go
- Metrics/analytics: src/analytics/metrics.go
- Rule engine (page rules): src/rules/engine.go
- Structured logs: src/logs/logger.go
- Public UI
  - Login: public/login.html
  - Dashboard: public/dashboard.html
  - Stealth page: public/stealth.html
- Configs
  - configs/app.json
  - configs/login.json
  - configs/waf-rules.json
  - configs/ratelimit.json
  - configs/page-rules.json

Features
- Web Application Firewall with regex-driven URI/header/body rules and UA/referrer blocking
- JavaScript proof-of-work challenge with fallback numeric CAPTCHA (noscript) and verification cookie
- Cookie-based verification with HMAC and TTL binding IP and UA
- Per-IP token bucket rate limiting with temporary quarantine and permanent escalation
- Header and URI pattern filtering
- Layer 7 challenge-response flow with redirect and stealth-aware behavior
- Blocking invalid/malicious User-Agents and Referrers
- SQLi/XSS/bad payload filtering via configurable patterns
- Anti-bypass via IP+UA bound verification cookies and challenge enforcement
- Real-time attack analytics via Server-Sent Events
- Custom page rules (block, force challenge, bypass WAF, bypass rate limiting)
- Invisible mode/Stealth page for non-admin visitors
- Scanner deterrence (Censys, Shodan, etc.) via WAF rules
- Firewall integration using iptables (Linux) and netsh advfirewall (Windows) to drop IPs
- Structured JSON logs with daily rotation

Requirements
- Go 1.21+
- Linux or Windows
- Linux: iptables for firewall integration
- Windows: Administrator privileges for netsh firewall rules

Quick start
1) Clone
- Ensure you are in an empty folder containing this repository.

2) Config
- All default configs are provided under configs/. Change credentials and secrets before production.
  - configs/login.json controls dashboard authentication.
  - configs/app.json contains listen address, session secret, stealth mode, challenge difficulty, and firewall toggle.

3) Build and run
- Linux/macOS:
  - go mod tidy
  - go run ./src
- Windows:
  - go mod tidy
  - go run .\src

4) Access
- Login: http://localhost:8080/login
- Dashboard: http://localhost:8080/dashboard

Configuration
configs/app.json
- listen: Address to bind, e.g. ":8080"
- adminSessionSecret: A long random string (32+ bytes). Change immediately for production.
- reverseProxyTarget: Optional upstream, e.g. "http://127.0.0.1:3000" or "https://origin.example.com"
- stealthMode: When true, non-admin requests receive the stealth page except login, public assets, and the challenge path
- firewallEnabled: When true, permanent blocks also apply at OS firewall level
- challengePowDifficulty: Bits for POW difficulty (higher = harder)
- cookieVerificationTTLSeconds: TTL for verification cookie

configs/login.json
- username: Admin username for dashboard
- password: Admin password for dashboard

configs/ratelimit.json
- requestsPerMinute: Refill rate per IP
- burst: Burst capacity per IP
- tempBlockSeconds: Temporary quarantine duration when hitting repeated rate limits
- permBlockThreshold: Number of WAF/bad events to trigger a permanent block

configs/waf-rules.json
- blockUserAgents: Regex strings for UAs to block
- blockReferrers: Regex strings for referrers to block
- uriPatterns: Regex strings to reject requests by path
- bodyPatterns: Regex strings to reject requests by body content
- headers: Regex rules keyed by header name (match rejects)
- blockedIPs: Static IP block list

configs/page-rules.json
- blockPaths: Regex list to hard-block by path
- challengePaths: Regex list that forces a challenge if verification not yet passed
- bypassWAFPaths: Regex list to bypass WAF checks
- bypassRateLimitPaths: Regex list to bypass rate limiting
Notes
- Regexes are standard Go regex, case-insensitive examples use (?i)
- Page rules hot-reload approximately every 5 seconds

Admin dashboard
- Login: /login (uses configs/login.json)
- Dashboard: /dashboard
- Toggles
  - Stealth: Enables/disables stealth mode
  - Firewall: Enables/disables firewall integration
- Unblock IP: Submit an IP to remove from local/permanent block
- Live metrics: Uptime, WAF blocked, rate-limited, challenges issued/passed, and top IPs

Admin APIs
- GET /api/state
  - Returns {"stealth": bool, "firewall": bool}
- POST /api/toggles
  - Body: {"stealth": bool?, "firewall": bool?}
  - Requires admin session and CSRF token (dashboard handles this automatically)
- POST /api/unblock
  - Body: {"ip": "x.x.x.x"}
  - Requires admin session and CSRF token

Challenge and verification
- First-time visitors get redirected to /challenge for a JavaScript POW. Noscript users see a simple CAPTCHA form.
- On success, a verification cookie (azv_v) is set with HMAC binding to IP and UA and a TTL (configurable).
- Admin sessions (azv_sid) bypass the challenge flow.

Reverse proxy
- If app.json reverseProxyTarget is set, the gateway will forward unmatched routes upstream.
- Adds X-Forwarded-For, X-Forwarded-Proto, and X-Forwarded-Host.
- High-performance fasthttp HostClient is used.

Firewall integration
- Permanent block escalation triggers iptables (Linux) or netsh advfirewall (Windows).
- Persistence path: data/blocked.json
- Requires root (Linux) or Administrator (Windows).
- Enable with app.json firewallEnabled: true
- Temporary rate-limit quarantine is in-memory. Permanent block is OS firewall enforced. Use dashboard to unblock.

Logs
- Location: ./logs/azrova-YYYYMMDD.log
- Structured JSON lines including ts, ip, ua, path, method, status, action

Security hardening
- Change configs/login.json credentials.
- Change configs/app.json adminSessionSecret to a high-entropy value.
- Run behind a TLS terminator or enable TLS at an upstream/load balancer.
- Increase challengePowDifficulty during attacks.
- Enable stealthMode during sensitive events or active scanning.
- Populate waf-rules.json and page-rules.json with organization-specific rules.
- Prefer dedicated users and service files; restrict filesystem permissions around data/ and configs/.

Production notes
- Linux: Ensure iptables present. If using nftables-only systems, adapt firewall rules or run a compatibility layer.
- Windows: netsh firewall commands require Admin.
- Ensure enough file descriptors and OS tuning for high concurrency (ulimits, TCP backlog, etc.) when deploying at scale.

Build
- Development:
  - go mod tidy
  - go run ./src
- Production:
  - go build -o azrova-shield ./src
  - ./azrova-shield

File map
- Server: src/server/server.go
- Main: src/main.go
- WAF: src/middleware/waf.go
- Rate limit: src/middleware/rate_limit.go
- Challenge: src/middleware/verifier.go
- Reverse proxy: src/proxy/reverse_proxy.go
- Firewall: src/firewall/firewall.go
- Rules: src/rules/engine.go
- Analytics: src/analytics/metrics.go
- Login page: public/login.html
- Dashboard: public/dashboard.html
- Stealth: public/stealth.html
- Configs: configs/*.json

Defaults
- The repository includes sane defaults for configs. Update for production use and commit private overrides to your own secrets management rather than VCS.

License
- For internal or permitted usage. Review organizational policies before deploying to production.
Cluster deployment and attack migration

Overview
Azrova‑Shield supports multi-node clusters. Nodes share detection signals and mitigation decisions using an HMAC-signed internal event channel. When any node detects abusive IPs (WAF, rate limit, or Nginx access log tail), it quarantines locally, optionally escalates to OS firewall, and broadcasts the bad IP to peers. Strict mode can also be toggled cluster-wide.

Configuration keys reference
Add these keys in configs/app.json:
- clusterKey: Shared secret used to HMAC-sign cluster events.
- peers: Array of base URLs for other nodes, e.g. ["http://10.0.0.2:8080","http://10.0.0.3:8080"].
- trustedProxies: CIDR/IP list of load balancers or reverse proxies whose X-Forwarded-For should be trusted.
- nginxAccessLogPath: Full path to the Nginx access log on this node.
- nginxRpsThreshold: Per-IP requests-per-minute threshold derived from the access log that triggers mitigation.
- strictMode: When true, verification TTL shortens and POW difficulty increases cluster-wide.
- firewallEnabled: When true, permanent blocks apply at OS firewall level.

Example configs/app.json
{
  "listen": ":8080",
  "adminSessionSecret": "REPLACE_WITH_LONG_RANDOM_SECRET",
  "reverseProxyTarget": "http://127.0.0.1:3000",
  "stealthMode": false,
  "firewallEnabled": true,
  "challengePowDifficulty": 16,
  "cookieVerificationTTLSeconds": 86400,
  "strictMode": false,
  "clusterKey": "REPLACE_WITH_64_HEX_BYTES",
  "peers": ["http://10.0.0.2:8080","http://10.0.0.3:8080"],
  "trustedProxies": ["10.0.0.0/24","192.168.0.0/16"],
  "nginxAccessLogPath": "/var/log/nginx/access.log",
  "nginxRpsThreshold": 600
}

Windows example for nginxAccessLogPath
Use escaped backslashes:
"C:\\nginx\\logs\\access.log"

Cluster event channel
- Endpoint: POST /internal/event
- Header: X-Azrova-Signature: hex(HMAC-SHA256(clusterKey, body))
- Body examples:
  {"type":"bad_ip","ip":"203.0.113.5"}
  {"type":"block_ip","ip":"203.0.113.5"}
  {"type":"strict","strict":true}

Multi-node setup
1) Build the binary on each node.
2) Copy public/, configs/, and the binary to each node.
3) Set the same clusterKey across all nodes.
4) Populate peers on each node with the other nodes’ base URLs.
5) Set trustedProxies to include your load balancer CIDRs and any edge proxies in front of Azrova‑Shield.
6) Point nginxAccessLogPath to the local Nginx access log file and set nginxRpsThreshold to an appropriate per-IP RPM threshold.
7) Start Azrova‑Shield on all nodes.
8) Open /dashboard to verify live metrics on each node.

Attack migration across servers
- Load shift: Reweight traffic at your load balancer to shed load from saturated nodes. Azrova‑Shield continues to broadcast bad_ip events so remaining nodes preemptively quarantine abusive IPs.
- Strict mode: Toggle Strict in one dashboard; the change propagates to all peers. Strict increases proof-of-work difficulty and reduces verification TTL to harden during spikes.
- Edge drop: Abuse detected on any node triggers OS firewall temp blocks immediately, reducing local pressure while events propagate.

Nginx integration
1) Ensure access log is enabled:
log_format azrova '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"';
access_log /var/log/nginx/access.log azrova;

2) If Nginx is behind a load balancer, restore client IP and align trustedProxies:
set_real_ip_from 10.0.0.0/24;
real_ip_header X-Forwarded-For;

3) Set configs/app.json nginxAccessLogPath to your access log path on each node.

Client IP resolution and verification
- Verification cookies bind to client IP and User-Agent.
- X-Forwarded-For is trusted only when the remote address is in trustedProxies. Otherwise, the remote socket IP is used.
- Ensure trustedProxies includes your load balancer/proxy networks to avoid binding cookies to proxy IPs.

Firewall enforcement
- Linux: iptables required for OS-level drops when firewallEnabled is true.
- Windows: netsh advfirewall is used for OS-level blocking.
- Temporary quarantine is in-memory; permanent blocks persist at data/blocked.json and are reapplied on restart.

Service installation (Linux systemd)
[Unit]
Description=Azrova Shield
After=network-online.target

[Service]
User=root
WorkingDirectory=/opt/azrova-shield
ExecStart=/opt/azrova-shield/azrova-shield
Restart=always
LimitNOFILE=200000

[Install]
WantedBy=multi-user.target

Custom VAC deployment outline
- Anycast IPs announced from scrubbing POPs.
- On-POP scrubbing using iptables/ipset or XDP paths to shed volumetric layer 7 floods.
- GRE or IP-in-IP tunnels from scrubbing POPs back to origin or private DC.
- Router flowspec to drop obvious bad prefixes during spikes.
- Deploy Azrova‑Shield on scrubbing POPs to enforce Layer 7 policies. Use shared clusterKey and peers among POP nodes to propagate detections.
- Use trustedProxies to trust POP addresses so verification binds to real client IP restored at the POP.
- Use nginxAccessLogPath on each POP to feed local detection and propagate to the cluster.

Operational guidance
- Credentials: Update configs/login.json before first run.
- Secrets: Change adminSessionSecret and clusterKey to long random values.
- Thresholds: Start nginxRpsThreshold at 400–800 RPM for public sites, adjust per traffic profile.
- POW difficulty: Increase challengePowDifficulty and enable strictMode during attacks.
- Stealth: Enable stealthMode during sensitive maintenance or when scanning is detected.
- Unblocking: Use the dashboard Unblock IP form to remove permanent blocks swiftly.

API notes
- GET /api/state returns stealth, firewall, strict.
- POST /api/toggles accepts stealth, firewall, strict.
- POST /api/unblock removes an IP from permanent block lists.

Troubleshooting
- Verification page stuck: Ensure time is correct on client and server, and that browsers allow WebCrypto. A numeric CAPTCHA fallback is displayed automatically when WebCrypto is unavailable.
- Client IP seems wrong: Verify trustedProxies and Nginx real_ip settings and that your load balancer preserves X-Forwarded-For.
- OS blocks not applied: Confirm iptables is present on Linux or Administrator rights on Windows for netsh advfirewall.

Security and performance
- Run behind TLS.
- Pin configs directory permissions.
- Raise file descriptor limits and tune TCP backlog for high concurrency.
- Keep public/ assets and dashboard reachable only for verified users; the login page itself is gated by verification.
