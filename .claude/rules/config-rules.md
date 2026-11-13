# Configuration Rules (PART 5, PART 6, PART 12)

⚠️ **These rules are NON-NEGOTIABLE. Violations are bugs.** ⚠️

## CRITICAL - NEVER DO
- **PART 5:** *CRITICAL: ALL comments in YAML files MUST go ABOVE the setting, NEVER inline.**
- **PART 5:** *Exception:** GitHub Actions SHA-pin version annotations stay inline — `uses: owner/action@{40-char-sha}  # vX.Y.Z` — Renovate reads and rewrites the same-line comment when bumping pins; never move it above the `uses:` line.
- **PART 5:** *Configuration is stored in `server.yml` only; the database never holds operator-editable configuration.**
- **PART 5:** `server.yml` is the sole source of truth for configuration. The SQLite (or remote libsql/Turso) database stores resource state, owner tokens, audit log entries, etc. — never user accounts or operator-editable configuration.
- **PART 5:** *All write operations return HTTP `503 Service Unavailable` with the canonical error body (see PART 14 → "Error Response"). Maintenance-specific context goes in `details` and in response headers — never in ad-hoc top-level fields.**
- **PART 5:** *`mode` always reports the configured MODE (`production`/`development`/`debug`) — maintenance is a state carried by `status`, never a mode. HTTP code: `503 Service Unavailable`.**
- **PART 5:** | `sure` | `never` |
- **PART 5:** *NEVER use `strconv.ParseBool()` directly** - it only accepts `true/false/1/0/t/f`. Always use `config.ParseBool()` for consistent behavior across the application.
- **PART 5:** *Directory variables are applied on EVERY startup, never "once".** Precedence: flag, then environment variable, then the platform default (PART 4). They locate `server.yml` and the rest of the app's files, so they cannot live inside `server.yml` and are never written to it.
- **PART 5:** | ❌ No | Never needs escalation/auth |
- **PART 5:** [ ] Boolean handling uses `config.ParseBool()` - NEVER `strconv.ParseBool()`
- **PART 6:** *`debug` mode:** `--mode debug` / `MODE=debug` selects debug mode — explicit opt-in only, NEVER implied or auto-enabled. It defaults the debug flag to on; an explicit `--debug` flag or `DEBUG` env var still wins — `MODE=debug DEBUG=false` runs debug mode with the `/debug/*` endpoints off.
- **PART 6:** | Sensitive data | Never shown |
- **PART 6:** *Explicit opt-in only — NEVER implied or auto-enabled. Selecting it defaults the debug flag to on (an explicit `--debug`/`DEBUG` still wins).**
- **PART 6:** | Security checks | Never disabled — authentication and authorization fully enforced |
- **PART 6:** *Enables ALL debug diagnostics regardless of mode. Debug mode affects verbosity and diagnostics ONLY — it NEVER disables authentication or security checks, in any mode, including production. Use sparingly in production.**
- **PART 6:** | **Operator token (`server.token`) auth** | **NEVER bypassed** — all auth and security checks remain fully enforced |
- **PART 6:** *Debug endpoints are ONLY available when `--debug` flag or `DEBUG=true` is set. Otherwise returns 404. When enabled, EVERY `/debug/*` endpoint (including pprof and expvar) additionally requires the operator token (`server.token`) as a Bearer credential — `--debug` turns the endpoints on, it never replaces authentication.**
- **PART 12:** *If config setting is invalid, warn and replace with default. Never fail startup.**
- **PART 12:** | **Never crash on config** | Server must start with sane defaults |
- **PART 12:** *Middleware ordering — preserve the original TCP peer.** Any real-IP middleware that rewrites `r.RemoteAddr` with the resolved client IP MUST first store the original TCP peer address in the request context. `isTrustedPeer()` — and every `trusted_proxies` gate in the spec (`BuildURL(r, ...)`, `X-Forwarded-Prefix` handling, domain learning, CORS/CSP origin learning) — MUST evaluate that preserved original peer, never the rewritten value. Client-IP consumers (rate limiting, blocklists, access logs, GeoIP) use the resolved client IP. Rewriting first and trust-checking later makes every later gate judge the end client's public IP: proxy headers are silently dropped and `{proto}` downgrades to `http` behind a working proxy.
- **PART 12:** **Port:** always stripped (never appended)
- **PART 12:** 1. **Clearnet-identifying data is swapped or omitted** — absolute URLs use `tor.onion_address`; the clearnet FQDN and clearnet contact email never appear (see "Tor Privacy Rules" below).
- **PART 12:** 2. **Operations genuinely impossible over Tor fail loudly, never silently** — when a feature cannot work for a Tor request (an OAuth provider that rejects `.onion` redirect URIs, a third-party API with no `.onion` while outbound Tor is disabled, etc.), return a clear error/warning whose message is written for that specific context and names the Tor-specific reason. Never degrade silently, never fall back to a clearnet URL, never report false success.
- **PART 12:** Tor hidden services are always plain `http://` — the `.onion` address is itself the cryptographic identity and the Tor circuit provides end-to-end encryption, so TLS/HTTPS semantics do not apply. For every request detected as a Tor request:
- **PART 12:** | **HTTP→HTTPS redirect** | Never issued — there is no HTTPS endpoint to redirect to; a redirect would break the hidden service. |
- **PART 12:** | **`Strict-Transport-Security` (HSTS)** | Never sent — HSTS would make the browser refuse the `http://` onion, taking the site offline. |
- **PART 12:** | **Clearnet HTTPS-only mode** | Never inherited — a clearnet port-443 / HTTPS-only configuration does NOT propagate to the onion; the onion stays `http://` regardless. |
- **PART 12:** | **Canonical / `Location` / absolute links** | Built via `BuildURL(r, path)` → `http://{onion_address}`; never `https://`, never the clearnet host. |
- **PART 12:** These are concrete cases of parity-principle point 2 — features that cannot work, or must adapt, for a Tor request. The list is illustrative, not exhaustive; whenever one is reached on a Tor request, either substitute a Tor-appropriate behavior or fail loudly with a context-specific message — never silently, and never by reaching out to a clearnet endpoint.
- **PART 12:** | **Client IP address / geolocation** | Onion routing hides the client; the request arrives from the local Tor daemon, so the connection's remote address is loopback (`127.0.0.1`). The real client IP and its country are unknowable by design. | Never log or display a "real" IP for Tor requests; skip GeoIP; derive locale from the `Accept-Language` header, never from IP geolocation. |
- **PART 12:** | **IP-based rate limiting / allow-deny lists / abuse blocking** | Every Tor request appears to come from loopback, so per-IP counters and CIDR rules collapse into a single bucket. | Rate-limit Tor traffic by session, account, API token, or a global onion-wide limit instead of by IP; if Tor's `HiddenServiceExportCircuitID haproxy` is enabled, key limits on the exported per-circuit ID (an opaque PROXY-protocol token, not an IP) for a per-session bucket without deanonymization; never apply clearnet IP allow/deny lists to Tor requests. |
- **PART 12:** | **HTTP/3 (QUIC)** | QUIC runs over UDP; Tor carries TCP only. | Serve HTTP/1.1 or HTTP/2 over the onion; never advertise `Alt-Svc: h3` to a Tor request. |
- **PART 12:** | **Third-party OAuth / SSO login** | Many providers reject `.onion` redirect URIs and will not federate to a hidden service. | Offer local or onion-native auth for Tor; if an external provider is required and unavailable, show a clear "not available over Tor" message — never redirect to a clearnet callback. |
- **PART 12:** For a Tor request the connection's remote address is the local Tor daemon (loopback), so it is meaningless as a client identifier and misleading in logs — it collides with genuine localhost traffic and looks like an identifier when it is not. Wherever the app would record or display a client IP — access logs, audit trails, admin UI, rate-limit keys — substitute the **Tor circuit ID** exported via `HiddenServiceExportCircuitID haproxy` (read from the PROXY-protocol header), clearly marked as a Tor circuit (e.g. `tor:{circuit_id}`). When circuit-ID export is not enabled, use the literal sentinel `tor` instead. **Never** log or display `127.0.0.1` for a Tor request.
- **PART 12:** User-facing timestamps normally render the server's local timezone (`%B %d, %Y at %H:%M:%S %Z` → e.g. `EST`). Served over the onion that leaks the operator's timezone, and thus their rough location — a server-side deanonymization vector. For Tor requests, render all user-facing timestamps in **UTC** (force the zone to `UTC`, never the server's local zone). Audit any other locale-, timezone-, or `Accept-Language`-derived output for the same operator-location leak and normalize or omit it for Tor requests.
- **PART 12:** Send `Onion-Location: http://{onion_address}{request_path}` on clearnet **HTML document** responses only (2xx, top-level navigations) — never on the onion's own responses, never on API/JSON responses, never on static assets or redirects.
- **PART 12:** The value is built from `tor.onion_address` (never the clearnet host) and always uses `http://` (see "Tor HTTP Semantics"); construct it with `BuildURL` against the onion host so the request path and query are preserved.
- **PART 12:** An equivalent `<meta http-equiv="onion-location" content="http://{onion_address}{request_path}">` in the HTML `<head>` is acceptable where a response header cannot be set; do not send both.
- **PART 12:** This is the only Tor-related header that appears on **clearnet** responses; the onion's own responses never carry `Onion-Location`.
- **PART 12:** | **Email** | Show `tor.contact_email` only; if unset, omit email entirely from all responses (security.txt, contact pages, error pages, footers). Never fall back to the clearnet contact email. |
- **PART 12:** | **URLs** | All absolute URLs in responses must use `tor.onion_address`. Never embed clearnet FQDN. Applies to: `security.txt`, `llms.txt`, OpenAPI `servers[0].url`, GraphQL endpoint, OAuth redirect URIs, email verification links, pagination links. |
- **PART 12:** | **CORS** | The onion address is added to the CORS allow-list automatically when `tor.onion_address` is set. The clearnet origin must NOT appear in Tor response CORS headers. |
- **PART 12:** `{tor_contact_line}` = `Contact: mailto:{tor.contact_email}` — **omitted entirely if `tor.contact_email` is unset**; never falls back to the clearnet contact email
- **PART 12:** Served per-request via `BuildURL(r, path)`; never cached or frozen at startup
- **PART 12:** Rate limiting is the primary abuse defense. Anonymous requests are limited per IP; requests carrying a valid Bearer token (REST and MCP alike) are limited per token, so clients that share an egress IP (hosted assistants, NAT) never throttle one another, and failed authentication is always counted per IP. Counters use a sliding window stored in `server.db` by default; when an external cache (Valkey/Redis) is configured, the counters live in the cache instead (see the cache usage table in PART 12).
- **PART 12:** *Response when limited:** `429 Too Many Requests` with `Retry-After` header set to seconds until the window resets. Body: `{"ok":false,"error":"RATE_LIMITED","message":"Too many requests"}` — the wait time is conveyed via the `Retry-After` header only, never as a top-level body field (see PART 14 error-response rules).
- **PART 12:** | `abuse` | `server.contact.abuse.email` if set → else `server.contact.general.email` if set → else `server.contact.admin.email`. Same fallback chain for webhooks. Never defaults to `abuse@{fqdn}` automatically — RFC 2142 recommends that address, but the operator must opt in (an unprovisioned mailbox would bounce reports). |
- **PART 12:** | `admin` | Server-internal events: error rate spike, panic, backup failure, cert renewal, security report received (summary only) | Subject + body + severity. NEVER includes user content. |
- **PART 12:** | `server.contact.admin.email` | NEVER public | Server-internal recipient only. |
- **PART 12:** | Any `webhooks.*` | NEVER public | URLs contain secrets / chat IDs / etc. |
- **PART 12:** Do NOT introduce flat aliases, duplicate names, or migration shims for contact recipients unless the user explicitly requests a migration feature.
- **PART 12:** *Tracking MUST NOT weaken the CSP (`script-src 'self'`, no `'unsafe-inline'`).** The snippets below are shown in HTML form for readability, but they are never written inline into pages:
- **PART 12:** **Tor and I2P:** tracking is never rendered for requests served through the onion or I2P address — provider scripts are clearnet endpoints and calling them leaks the request off Tor — and `/server/tracking.js` returns `404` there.
- **PART 12:** | **Consent message** | "...never sold" | "...may be shared with or sold..." |
- **PART 12:** | **Analytics description** | "...anonymized and never sold" | "...may be shared with third parties" |
- **PART 12:** | **Data usage content** | `data_usage` (never sold) | `data_usage_if_sold` (may be sold) |
- **PART 12:** | **Privacy page summary** | "We never sell your data" | "Your data may be sold" |
- **PART 12:** | **CCPA compliance** | "We do not sell" notice | "Do Not Sell" opt-out toggle |

## CRITICAL - ALWAYS DO
- **PART 5:** *All paths MUST be normalized and validated. This is a GLOBAL security rule for all binaries (server, cli) and applies to:**
- **PART 5:** *This middleware MUST run early in the chain — immediately after URL normalization and request-ID attachment (execution position #3, see Middleware Order below), and always before auth and routing.**
- **PART 5:** *When constructing file paths from user input, ALWAYS validate the result stays within bounds:**
- **PART 5:** *All other errors are recoverable. The server ALWAYS attempts self-healing.**
- **PART 5:** *ALL boolean parsing in the application MUST use `config.ParseBool()` or `config.IsTruthy()`.**
- **PART 5:** | **No root required** | Ports >1024 don't need root privileges |
- **PART 5:** *Default rule:** server/service processes MUST run as a dedicated system user/group whenever the project supports privilege drop.
- **PART 5:** *Project-specific exception:** a project may run permanently as root/Administrator only when its core function requires ongoing OS-level privileges and privilege drop would break the app. This exception MUST be explicitly justified in IDEA.md.
- **PART 5:** *The binary MUST:**
- **PART 5:** 1. **Platform-independent privilege detection (REQUIRED):**
- **PART 5:** | Operation | Danger | Authorization Required |
- **PART 5:** | Always show others | Show port for all non-standard ports |
- **PART 6:** | Credentials | Keys, tokens, passwords, secrets ALWAYS redacted — no exceptions |
- **PART 12:** *I2P exception:** identical to the Tor exception. When I2P is opt-in enabled and `i2p.b32_address` is set, a request whose `Host` matches it is resolved from `i2p.*` config — always `http://`, no proxy header inspection, no IP check (the eepsite backend is a plain loopback listener with no PROXY header). When I2P is disabled or the address is unset, `.b32.i2p` Host headers are treated like any other host. See **PART 31.2 → "I2P Eepsite"**.
- **PART 12:** | Always trusted (no config required) | Reason |
- **PART 12:** **Proto:** `http://` — Tor hidden services are always HTTP; TLS terminates in the Tor layer
- **PART 12:** This check is **priority 0** in the FQDN resolution table — evaluated before reverse proxy headers, always trusted, no IP check against `trusted_proxies` required.
- **PART 12:** *Tor parity principle:** a Tor request MUST behave **exactly like the equivalent clearnet request** — same routes, same features, same responses — with only two classes of difference:
- **PART 12:** | **Clearnet links** | Any link that would normally point to the clearnet site must use the onion address or be omitted entirely. |
- **PART 12:** | **OAuth / external auth** | Redirect URIs must use the onion address. If the OAuth provider does not support `.onion` redirect URIs, that provider is disabled for Tor requests with a `503` error. |
- **PART 12:** > **Full I2P implementation:** the same overlay HTTP semantics apply to `.b32.i2p` (always `http://`, no cert, no HSTS, no upgrade). For the opt-in eepsite provider lifecycle (i2pd process or SAM bridge), `i2pd.conf` generation, and destination-key persistence, see **PART 31.2 → "I2P Eepsite"**.
- **PART 12:** | `admin` | Required. Empty → startup warning. Auto-populated from the operator's email on first install if unset. |
- **PART 12:** | Type | Name | ID Format | URL Required | Notes |
- **PART 12:** | `google` | Must match `UA-\d+-\d+` or `G-[A-Z0-9]+` | N/A |
- **PART 12:** | `matomo` | Must be integer | Must be valid URL |
- **PART 12:** | `piwik` | Must be integer | Must be valid URL |
- **PART 12:** | `owa` | Non-empty string | Must be valid URL |
- **PART 12:** | `umami` | Valid UUID format | Must be valid URL |
- **PART 12:** | **Essential** | No | Sessions, CSRF tokens, security - required |

## Key Rules Summary

### PART 5 — CONFIGURATION
- YAML Comment Style
- Path Normalization & Validation
- Configuration Storage
- Boolean Handling
- Environment Variables
- Configuration File
- Port Rules

### PART 6 — APPLICATION MODES
- Mode and Debug Detection Priority
- Six Operational States
- Production Mode (Default)
- Development Mode
- Debug Mode (`MODE=debug`)
- Debug Flag (`--debug` / `DEBUG=true`)
- Mode Shortcuts
- Debug Endpoints (`--debug` / `DEBUG=true` Only)

### PART 12 — SERVER CONFIGURATION
- Config Validation Rule
- Base URL
- Request Limits
- Response Compression
- Trusted Proxies
- Tor Hidden Service Configuration
- Rate Limiting
- Internationalization (i18n)
- Contact Configuration (Server Notification Recipients)
- Analytics Tracking
- Privacy & Consent
- Cache Configuration
- Settings Configuration (config file)

For complete details, see AI.md PART 5, PART 6, PART 12.

<!-- AI.md source: 03cc45ec58df -->
