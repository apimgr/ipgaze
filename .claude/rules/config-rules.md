# Configuration Rules (PART 5, 6, 12)

⚠️ **These rules are NON-NEGOTIABLE. Violations are bugs.** ⚠️

## CRITICAL - NEVER DO

- NEVER name the config file `server.yaml` — it is always `server.yml`
- NEVER use `strconv.ParseBool()` for config/env booleans — use
  `config.ParseBool()` / `config.IsTruthy()` (handles yes/no, oui/non,
  si/no, da/net, and other locale truthy/falsy forms)
- NEVER store user accounts, credentials, or settings in the database —
  `server.yml` is the sole source of truth for configuration; the
  database only holds resource state, tokens, and audit logs
- NEVER put inline YAML comments — comments always go on the line above
  the setting
- NEVER let `--debug`/`DEBUG=true` bypass auth or security checks —
  debug mode only unlocks `/debug/*`, `/debug/pprof/*`, `/debug/vars`
- NEVER read Init-Only env vars (`CONFIG_DIR`, `DATA_DIR`, `LOG_DIR`,
  `DATABASE_DIR`, `BACKUP_DIR`, `PID_FILE`, `CACHE_DIR`, `PORT`,
  `LISTEN`, `APPLICATION_NAME`, `APPLICATION_TAGLINE`) after first-run —
  they seed `server.yml` once and are ignored on every later start
- NEVER fail startup on an invalid config value — warn and replace with
  the built-in default (PART 12 Config Validation Rule); the server
  MUST always start with sane defaults, never crash on bad config
- NEVER honor `X-Forwarded-*` / real-IP headers from a peer that is not
  in `trusted_proxies` (private ranges + `additional` allow-list) —
  forged headers from an untrusted peer must be dropped before any
  FQDN/proto/port/base-path resolution runs
- NEVER apply the `trusted_proxies` IP gate to Tor/I2P requests — those
  are resolved from `tor.*`/`i2p.*` config with no header inspection and
  no IP check (priority 0, evaluated before reverse-proxy headers)
- NEVER introduce flat aliases or duplicate names for the canonical
  `server.contact.{admin,security,abuse,general}.email` keys
- NEVER expose `server.contact.admin.email` or any `webhooks.*` URL
  publicly — admin email and webhook URLs (secrets/chat IDs) are
  server-internal only

## CRITICAL - ALWAYS DO

- ALWAYS re-check Runtime env vars every start (`NO_COLOR`, `TERM`,
  `DOMAIN`, `MODE`, `DATABASE_DRIVER`, `DATABASE_URL`, `CACHE_URL`,
  `SMTP_*`, `DEBUG`, `HOST_IPV4`, `HOST_IPV6`, `LANG`/`LC_ALL`, `TZ`)
- ALWAYS resolve mode via priority: `--mode` flag > `MODE` env > default
  production; resolve debug via `--debug` flag > `DEBUG` env (truthy) >
  `MODE=debug`/`--mode debug` alias > default false — explicit
  `--debug`/`DEBUG` always overrides the `MODE=debug` alias, including
  an explicit `--debug=false`/`DEBUG=false`
  ALWAYS support all six operational states: Production, Production+
  Debug, Development, Development+Debug, Debug (`MODE=debug
  DEBUG=false`), Debug+Endpoints (`MODE=debug`, `DEBUG` unset)
- ALWAYS default to a random unused port in the 64000-64999 range on
  first run, then persist it to `server.yml`; once persisted, the
  config value wins over the `PORT` env on every later start
- ALWAYS follow the privileged-port (<1024) bind-then-drop-privilege
  pattern rather than running the whole process as root
- ALWAYS trigger maintenance mode / self-healing on critical errors
  (DB connection failure, disk write failure) instead of crashing
- ALWAYS preserve the original TCP peer address in request context
  before any real-IP middleware rewrites `r.RemoteAddr` — every
  `trusted_proxies` gate must evaluate the original peer, never the
  rewritten client IP
- ALWAYS sign outbound webhook POSTs (`X-Webhook-Signature`,
  `X-Webhook-Timestamp`, `X-Webhook-ID`, `X-Webhook-Event`) and retry
  non-2xx responses with exponential backoff (1m, 5m, 15m, 1h, 6h, 24h)
  reusing the same `X-Webhook-ID`
- ALWAYS resolve contact roles through their fallback chain: `security`
  → `admin` if unset; `abuse` → `general` → `admin`; `general` → `admin`
  — computed per-dispatch, never cached across requests
- ALWAYS keep the cookie-consent default opt-out model (`default_enabled:
  true`, essential cookies always on, decline disables
  preferences/analytics) and switch privacy-page/consent copy on
  `server.privacy.data.sold`

## Key Rules Summary

`server.yml` is authoritative for configuration; env vars only seed it
on first run (Init-Only) or override at runtime for a fixed allow-list
(Runtime). Mode/Debug resolution has a strict precedence order already
implemented in `src/mode/mode.go`. Boolean parsing must go through
`src/config/bool.go`'s `ParseBool`/`IsTruthy`, already implemented
correctly.

**PART 12 additions (Server Configuration):**
- `server.baseurl` — URL path prefix for all routes, default `/`;
  resolution order is `X-Forwarded-Prefix` > `X-Forwarded-Path` >
  `X-Script-Name` > config/`--baseurl` flag > default `/`
- `server.limits.*` — `max_body_size` (10MB), `read_timeout`/
  `write_timeout` (30s), `idle_timeout` (120s)
- `server.compression.*` — gzip/deflate toggle, level 1-9, MIME type list
- `server.trusted_proxies.additional` — extra IPs/CIDRs/DNS names beyond
  the always-trusted private ranges; gates every `X-Forwarded-*`-based
  resolution (FQDN, proto, port, base path, client IP)
- `tor.onion_address` / `tor.contact_email` — Tor hidden-service
  detection and privacy rules (no HTTPS upgrade/HSTS, UTC timestamps,
  onion-only URLs, `Onion-Location` header on clearnet HTML responses
  only); I2P (`i2p.b32_address`) follows the same overlay-HTTP semantics
- `server.rate_limit.*` — read/write/health buckets + `global_burst`
  ceiling, sliding window counters in DB or external cache; `429` with
  `Retry-After` header, error body has no top-level wait-time field
- `server.i18n.default_language`/`supported` — locale configuration
- `server.contact.{admin,security,abuse,general}` — unified
  email+webhooks recipient tree with per-role fallback chains; webhook
  transports (telegram/discord/slack/mattermost/pushover/gotify/generic)
  are all HMAC-signed
- `server.tracking.{type,id,url}` — pluggable analytics (google, matomo,
  piwik, owa, fathom, plausible, umami, simple, cloudflare); empty/`none`
  disables; URL requirement depends on `type`
- `server.privacy.*` — GDPR/CCPA cookie-consent banner, data-handling
  policy, retention, and privacy-page content; behavior branches on
  `server.privacy.data.sold`
- `server.cache.*` — optional; `none`/`memory` (default)/`valkey`/
  `redis`; `url` takes precedence over discrete `host`/`port`/etc. when
  both are set; used by sessions and rate limiting

Cross-checked against `src/config/config.go`: all PART 5/6/12 struct
fields, yaml tags, and defaults listed above are present and match the
spec. No missing keys found in this pass.

For complete details, see AI.md PART 5, PART 6, PART 12.
