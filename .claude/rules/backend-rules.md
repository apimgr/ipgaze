# Backend Rules (PART 9, 10, 11, 31)

⚠️ **These rules are NON-NEGOTIABLE. Violations are bugs.** ⚠️

## CRITICAL - NEVER DO
- Never use `SELECT *` in application code — always name columns explicitly
- Never build SQL via string concatenation — parameterized queries only
- Never reveal internals in error responses (stack traces, DB structure, internal hostnames/ports, dependency versions)
- Never weaken rate limiting, caching correctness, or logging fidelity to simplify implementation
- Never let the error-page/error-handling path itself be the thing that breaks a request — a panic/recover
  middleware and a template-render failure MUST both fall back to a minimal hardcoded error response
  (correct status code, short body, content-negotiation-aware) instead of a blank body, dropped connection,
  or leaked stack trace — the backend mirror of the service worker's guaranteed-`Response` rule
- Never use `github.com/mattn/go-sqlite3` (CGO) — `modernc.org/sqlite` only, `CGO_ENABLED=0`
- Never write a migrations/version table or a destructive `ALTER TABLE` — schema changes are idempotent
  `CREATE TABLE IF NOT EXISTS` / additive `ALTER TABLE ADD COLUMN` only, applied on every startup
- Never cache an HTML document response — HTML is always `no-store`; only static assets are cacheable
- Never compare secrets/tokens/CSRF values with `==` or `bytes.Equal` — timing-safe
  `crypto/subtle.ConstantTimeCompare` only
- Never trust `X-Forwarded-For`/`X-Real-IP`/proxy headers from an untrusted peer — client-IP extraction
  and rate-limit/audit-log keys must go through the trusted-proxy resolver, never a raw header read
- Never put the wait time of a `429` in the JSON body — it belongs in the `Retry-After` header only
- Never log secrets, raw tokens, passwords, or full credentials — hash or redact before writing to any log

## CRITICAL - ALWAYS DO
- Validate and sanitize all input for its destination context (HTML-encode for HTML, parameterize for SQL)
- Follow the canonical error-response format and audience-specific detail levels (user/operator/console/log/audit)
- Log structured errors with request IDs and full context server-side, while returning minimal messages to clients
- Every request MUST terminate in a rendered response, no exceptions
- Return the canonical JSON error envelope `{"ok":false,"error":"UPPER_SNAKE_CODE","message":"..."}` with the
  correct HTTP status; render the themed HTML error page for browser clients using the same status/message
- Apply per-IP sliding-window rate limiting by endpoint class (read/write/health) plus a global burst ceiling;
  on rejection set `Retry-After` and log a fail2ban-consumable line to `security.log`
- Run schema setup (`EnsureSchema`) once at startup before accepting requests; every statement must be safe
  to re-run against an existing database
- Apply the full security-header set (CSP, HSTS when TLS, X-Content-Type-Options, X-Frame-Options,
  Referrer-Policy, Permissions-Policy, COOP/COEP/CORP) on every response, config-overridable per directive
- Use double-submit-cookie CSRF on all cookie-authenticated, state-changing browser requests — never bypass
  it based on `Origin`/`Referer` alone, since those can be absent or spoofed

## Key Rules Summary

### PART 9 — Error Handling & Caching
- Canonical error body: `{"ok": false, "error": "CODE", "message": "text"}`; `error` is always
  UPPERCASE_SNAKE_CASE, mapped 1:1 from the HTTP status (`NOT_FOUND`, `RATE_LIMITED`, `SERVER_ERROR`, etc.)
- Content negotiation: `/api/**` defaults to JSON except a `.txt` path suffix, `Accept: text/plain`, or a
  detected non-interactive tool (curl/wget/httpie); everything else gets the themed HTML error page
- 5xx errors are always logged server-side with request_id, status, method, path, and client IP — the
  client only ever receives the sanitized message, never the internal `error.Error()` value
- Error-page rendering must go into a buffer first; only swap it into the live response on success, so a
  template failure falls straight through to the guaranteed plain-text fallback instead of corrupting a
  partially-written response
- HTML documents: `Cache-Control: no-store` + a build-stamp `ETag`, paired with the version-change
  Clear-Site-Data purge so intermediaries that ignore `no-store` still revalidate
- A panic anywhere in a handler must be recovered by dedicated middleware, logged to `error.log` with full
  context, and answered with the guaranteed fallback response — never a dropped connection
- `RecoverMiddleware` is the OUTERMOST middleware, registered before routing, logging, or any other layer
  that could itself panic; its fallback uses plain strings only (no template engine, no theme system, no
  state that can panic) and is skipped only when the handler already wrote a status line

### PART 10 — Database
- Driver: `modernc.org/sqlite` (local, `CGO_ENABLED=0`) or `tursodatabase/libsql-client-go` (remote/libsql);
  never `mattn/go-sqlite3`, never `lib/pq`
- SQLite DSN is a bare file path — `modernc.org/sqlite` ignores `mattn`-style `?_journal=...` query params;
  WAL mode, `foreign_keys`, and `busy_timeout` must be set via explicit `PRAGMA` statements after opening
- Connection pool: SQLite is pinned to 1 open/1 idle connection (single-writer); libsql/remote uses the
  configured pool size. Lifetime/idle-time ceilings apply to every driver
- No migrations table, no version tracking — every schema change is an idempotent `CREATE TABLE IF NOT
  EXISTS` / `CREATE INDEX IF NOT EXISTS` / additive `ALTER TABLE ADD COLUMN`, safe to run on every startup
  against a database that may already have the object; "already exists" errors are swallowed, not fatal
- Parameterized queries only, explicit column lists always — no `SELECT *`, no string-built SQL
- Every query carries a context timeout, sized by class: simple SELECT 5s, JOIN-heavy SELECT 15s,
  INSERT/UPDATE/DELETE 10s, bulk 60s, reports 2m; a multi-statement transaction is bounded at 30s across
  the whole `BeginTx`…`Commit`/`Rollback` span, not per statement — always the `*Context` call variants
- Core self-managed tables include `config`/`config_meta` (with version-bump triggers), `rate_limits`,
  `audit_log`, `scheduler_tasks`/`scheduler_history`, `backups`, `api_tokens`, `app_secrets`, `pgp_keypairs`
  — `server.yml` remains the sole source of truth for configuration; the DB never stores user credentials
  or settings, only resource state, tokens, and audit trails

### PART 11 — Security & Logging
- Constant-time comparison (`crypto/subtle.ConstantTimeCompare`) for every secret/token/CSRF comparison;
  pad failed-auth timing to a shared floor so rejection reason isn't observable via latency
- Root secrets (`installation_secret`, `cookie_signing_key`, `csrf_token_secret`) live in `app_secrets` with
  independent rotation lifecycles and a grace-overlap window (`previous_value`/`previous_until`)
- Security headers are emitted on every response from a default set, overridable per-directive via
  `web.*` config (CSP mode + `*_extra`/`*_override` per directive, HSTS, Permissions-Policy, NEL, COOP/
  COEP/CORP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy); reporting directives are dropped
  entirely when `reports_enabled` is false
- CSRF: double-submit cookie, validated on every state-changing cookie-authenticated request; bypassed only
  for safe methods (GET/HEAD/OPTIONS), Bearer/API-token auth, WebSocket upgrades, and an explicit
  `exempt_paths` allow-list (webhooks, browser report endpoints, debug routes) — never bypassed on Origin
  match alone
- Client IP extraction for rate limiting, audit logs, and CSRF failure records must go through the
  trusted-proxy resolver — reading `X-Forwarded-For` unconditionally lets any client forge the IP a
  fail2ban integration bans on
- Every log file is raw text, one event per line, CR/LF-and-control-character stripped before write
  (prevents log-line injection); console output may be pretty and respects `NO_COLOR`
- Audit log is JSON Lines, append-only, tamper-evident; never logs secrets/credentials/PII in raw form;
  separate log files exist per concern (access.log, server.log, error.log, app.log, auth.log, audit.log,
  security.log, debug.log)
- Rate limiting is per-IP sliding window by endpoint class (read/write/health) plus a global burst ceiling;
  429 responses set `Retry-After` and `X-RateLimit-*` headers, and the JSON body never carries the wait
  time as a top-level field
- IP allow/block lists are config-file only (no web/API management route); the allowlist bypasses IP
  blocklist/rate-limit/GeoIP/auto-block but never bypasses CSRF, path-security, or TLS

### PART 31 — Overlay Networks (Tor & I2P)
- Tor hidden service is REQUIRED functionality — auto-enabled whenever the `tor` binary is found on the
  host, no explicit opt-in flag needed
- I2P eepsite support is OPTIONAL and strictly opt-in via `features.i2p.enabled` in `server.yml`
- Full lifecycle, request-detection, and privacy-rule details are owned by another PART/agent — read
  AI.md PART 31 directly before touching Tor/I2P-specific code

For complete details, see AI.md PART 9, PART 10, PART 11, PART 31.
