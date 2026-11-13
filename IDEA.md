# ipgaze

## Project description

IPGaze is a self-hosted alternative to services such as ifconfig.me, ipinfo.io, whatismyip.com, ipchicken.com, and iplocation.net — providing full parity and then some. It returns the visitor's public IP address along with comprehensive GeoIP information, VPN/proxy detection, Tor exit-node detection, and EU membership status.

It implements the echoip-compatible API (https://github.com/mpolden/echoip) — same routes, same response formats, same CLI user-agent detection — so existing echoip integrations require zero changes. It extends the echoip API surface with VPN/proxy detection, Tor detection, PWA support, GraphQL, OpenAPI, and Prometheus metrics.

IPGaze supports both IPv4 and IPv6 (curl -4 and curl -6), provides JSON, plain text, and HTML output formats, and includes a full-stack web frontend using server-side rendered Go templates. Container deployments can supply HOST_IPV4 and HOST_IPV6 environment variables to advertise the host's public IPs in curl command examples shown in the web UI.

## Project variables

project_name:      ipgaze
project_org:       apimgr
internal_org:      apimgr
internal_name:     ipgaze
app_name:          IPGaze
official_site:     https://ifcfg.us
maintainer_name:   apimgr
maintainer_email:  apimgr@casjay.pro
license:           MIT
repository:        https://github.com/apimgr/ipgaze

## Business logic

### Product scope & non-goals

**In scope:**
- Visitor's own public IP address lookup (IPv4 and IPv6 via curl -4 / curl -6)
- Specific IP address lookup by any client
- GeoIP information: country, city, region, postal code, coordinates, timezone, ASN, EU membership
- VPN/proxy detection (checked against known VPN/hosting ASNs and ip2proxy-compatible data)
- Tor exit-node detection (cross-referenced against Tor exit node list)
- echoip-compatible API surface (same routes, response formats, user-agent detection behavior)
- Multiple output formats per endpoint: JSON, plain text, HTML (content negotiation)
- Guest UI preferences for theme, language, and the default landing-page curl example widget; built-in UI and CLI locales are English, Spanish, French, German, Italian, Chinese, Arabic, and Japanese. Preferences are stored in cookies and never used to alter echoip-compatible API responses
- CLI user-agent detection: curl, wget, HTTPie, Go HTTP client, Mikrotik, ddclient, xh → plain text response
- Reverse DNS hostname lookup (always enabled, no flag)
- Port reachability testing (always enabled, no flag)
- Built-in scheduler for automatic periodic maintenance (GeoIP updates, blocklist sync, CVE feed, cert renewal, token cleanup, log rotation, backups, self-health checks)
- Email/notification delivery via SMTP (operator-configured; HTML + plain text multipart)
- Configurable IPv4/IPv6 allowlists and permanent blocks, with persisted temporary request-flood blocks and optional security alerts
- IP/domain threat blocklist downloads (daily, auto-applied to incoming requests)
- CVE/security database sync (daily, for vulnerability reporting)
- PWA support: web app manifest and service worker for offline caching
- Prometheus metrics (internal only, not public)
- GraphQL endpoint for flexible queries
- OpenAPI/Swagger interactive documentation
- Stateless Streamable HTTP MCP endpoint that exposes the registered public versioned API operations as tools. Example user prompts: “What is my public IP address?”, “Look up 8.8.8.8 and summarize its GeoIP data”, and “Which ASN announces 1.1.1.1?” MCP clients use anonymous public access; results depend on configured GeoIP databases. The endpoint is POST-only, sessionless, rate-limited, audited, and validates `Origin`.
- CLI client binary (`ipgaze-cli`) for querying any ipgaze-compatible server with token-based auth
- Tor hidden service (auto-enabled when Tor binary is present) with optional server-originated outbound Tor routing
- I2P eepsite (opt-in via `server.i2p.enabled`; i2pd process preferred, external SAM bridge as fallback)
- HOST_IPV4 / HOST_IPV6 env vars: container deployments supply the host's public IPv4/IPv6 for web UI curl examples; invalid values are silently ignored; unset = normal detection

**Non-goals:**
- WebSocket real-time updates (future)
- Multi-tenant or SaaS features
- Feature gating or premium tiers — all functionality is free

### Roles & permissions

| Role | Description | Capabilities |
|------|-------------|-------------|
| **Anonymous** | Any visitor or API client | All public IP/GeoIP endpoints, GraphQL, OpenAPI, PWA — no authentication required |

There is exactly one role. ipgaze is a public, anonymous service with no user accounts, no admin web UI, and no login.

### Data model & sensitivity

**Public data (no authentication required):**
- Visitor's public IP address (IPv4 or IPv6)
- Derived GeoIP fields: country, city, region, ASN, coordinates, timezone, EU membership, postal code
- User-agent product/version when parsed

**On-disk data:**
- Config: `{config_dir}/server.yml` (operator-only, not public)
- GeoIP databases: `{data_dir}/security/geoip/` (downloaded at runtime, public data source)
- Blocklists: `{data_dir}/security/blocklists/` (IP/domain, downloaded daily)
- Threat lists: `{data_dir}/security/threat/` (VPN/proxy/Tor exit-node CIDRs, downloaded daily)
- CVE database: `{data_dir}/security/cve/` (downloaded daily)
- Operator tokens: `{data_dir}/db/server.db` (cleaned by `token_cleanup` scheduler task)
- Backups: `{data_dir}/backups/` (`.tar.gz` archives)
- TLS certs: `{data_dir}/certs/`
- Tor keys: `{data_dir}/tor/`
- Logs: `{log_dir}/` (access logs in Apache CLF format, no PII beyond IP)

No user accounts, passwords, or user sessions. Security reports may retain reporter contact details and vulnerability content in encrypted form for coordinated disclosure; plaintext report content is never stored in the database.
CLI operator tokens are stored server-side (DB) and cleaned up by the `token_cleanup` scheduler task. The CLI client stores its own token in `{config_dir}/cli.yml`. Public IP/GeoIP endpoints require no authentication.

### Trust boundaries & external services

| External dependency | Trust level | Failure mode |
|--------------------|-------------|-------------|
| sapics/ip-location-db via jsDelivr CDN | Trusted source for GeoIP DB downloads; no API key required | GeoIP features disabled if download fails; server continues without GeoIP |
| MMDB binary format | Trusted format, validated on load by maxminddb-golang | Error logged; GeoIP disabled if DB corrupt |
| Proxy client-IP headers | UNTRUSTED unless the immediate peer matches the operator-configured `trusted_proxies`; only then are the configured proxy headers honored | Untrusted headers are ignored and `r.RemoteAddr` is used; `server.trusted_proxies.client_ip_header` selects `auto` order or one pinned header |
| Tor network | Optional, no trust required | Hidden service silently disabled if Tor binary not found |
| jsDelivr CDN (https://cdn.jsdelivr.net) | Trusted delivery channel for ip-location-db MMDB files | Download retried; GeoIP disabled if unavailable |
| Official site (https://ifcfg.us) | Production endpoint embedded as default server in CLI binary | CLI falls back to manual `--server` flag |
| Blocklist source (configured in server.yml) | Operator-trusted; content applied to rate limiting and abuse detection | Blocklist update skipped; previously downloaded list retained |
| Tor Project exit list (check.torproject.org) | Trusted; official Tor Project bulk exit list | Threat update skipped; previously downloaded list retained |
| X4BNet VPN lists (github.com/X4BNet/lists_vpn) | Community-maintained; covers major VPN provider CIDRs | Threat update skipped; previously downloaded list retained |
| firehol proxy lists (github.com/firehol/blocklist-ipsets) | Community-maintained; socks_proxy_7d + http_proxy_7d | Threat update skipped; previously downloaded list retained |
| CVE feed source (configured in server.yml) | Operator-trusted; downloaded and stored for vulnerability reporting | CVE update skipped; previously downloaded data retained |
| SMTP server (operator-configured) | Operator-trusted; used for email notifications | Notifications silently dropped if SMTP is unreachable |

### Threat model & abuse cases

**Primary assets being protected:**
- GeoIP database integrity (downloaded from trusted source, validated before use)
- Service availability (rate limiting, resource limits)

**Trusted inputs:**
- GeoIP databases downloaded from sapics/ip-location-db via jsDelivr CDN

**Untrusted inputs:**
- All inbound HTTP requests: IP headers, query parameters, request body, user-agent string
- Any IP address submitted for lookup via path or query parameter
- X-Forwarded-For / X-Real-IP headers (unless the immediate peer is trusted and the header is selected by `server.trusted_proxies.client_ip_header`)

**Attacker/abuser goals:**
- Trigger SSRF via IP lookup of internal/RFC1918 addresses
- Abuse the GeoIP lookup as a DoS amplifier (high-volume requests)
- Inject malformed IP addresses or path traversal via query strings
- Scrape GeoIP data at volume to exhaust download quotas

**Required defenses:**
- All IP inputs validated against allowed formats before any lookup
- Specific IP lookups (`/{ip}`) restricted to GeoIP database lookup only — no outbound connections triggered
- Parameterized queries for all database access
- Per-IP rate limiting (see AI.md PART 11)

**Intentional non-defenses (documented):**
- GeoIP data is inherently approximate; it is not used for access control
- Country blocking may be configured as an advisory deny-only signal; it is never authoritative because GeoIP accuracy is limited and VPNs trivially bypass country checks

### Security decisions & exceptions

| Decision | Reason |
|----------|--------|
| echoip-compatible API routes preserved | External route compatibility (AI.md line 212) — ipgaze is its own product but preserves the echoip wire format so existing integrations require zero changes |
| GeoIP country blocking is advisory and deny-only, never the sole access-control gate | GeoIP accuracy is limited; VPNs trivially bypass country-based blocks, so other security checks must always run |
| `unsafe` Go package: NOT used | CGO_ENABLED=0, pure Go static binary — no unsafe memory operations |
| Tor binary in container but not started by entrypoint | Binary controls Tor lifecycle per AI.md PART 31; entrypoint only sets env vars and execs binary |
| Proxy client-IP headers are gated by `trusted_proxies` | Trusting headers from arbitrary peers enables IP spoofing; only a configured trusted proxy may supply the client IP, with `r.RemoteAddr` as fallback |
| Coordinated disclosure defaults to the official `ifcfg.us` service and a 90-day window | Keep third-party and self-hosted systems outside the project's authority; exclude disruptive or non-technical testing and protect good-faith research |

---

### echoip Compatibility

ipgaze implements the complete echoip-compatible API. All echoip routes, response field names, response formats, and CLI user-agent detection behaviors are preserved identically so existing echoip integrations require zero changes. This is a core product feature — not a fork, not a drop-in replacement, but an independent implementation of the same public API contract.

ipgaze enhancements on top of the echoip-compatible surface:
- VPN/proxy detection (`is_vpn`, `is_proxy` fields) via X4BNet + firehol lists, updated daily
- Tor exit-node detection (`is_tor` field) via Tor Project bulk exit list, updated daily
- PWA support (web app manifest, service worker, offline caching)
- Empty Atom and RSS syndication feeds, ready for a future public item stream
- GraphQL endpoint for flexible queries
- OpenAPI/Swagger interactive documentation
- Prometheus metrics (internal only)
- Standard pages: security.txt, robots.txt, privacy, terms, contact
- Public contact-form metadata and safe operator-token validation for CLI/GUI server setup
- Coordinated vulnerability reporting for the official service, with encrypted submissions, private status tracking, configurable disclosure policy, selectable contact-form CAPTCHA, and researcher acknowledgments
- Public DPO contact page/API and consent-gated, same-origin analytics loading

---

### Binaries

This project produces two binaries:

| Binary | Purpose |
|--------|---------|
| `ipgaze` | IP lookup web server — serves all public endpoints |
| `ipgaze-cli` | CLI client for querying any ipgaze-compatible server |

Both binaries are built together. See AI.md PART 7, 8, 32, 33 for build, flag, and packaging rules.

---

### Core Features

**IP Address Detection**
- Returns the visitor's public IP address (IPv4 and IPv6)
- Lookup any specific IP address
- Handles proxy headers only from trusted peers, using configured automatic selection or a pinned `server.trusted_proxies.client_ip_header`
- IP decimal representation alongside dotted-decimal

**GeoIP Information** (from sapics/ip-location-db, downloaded at runtime)
- Country name, ISO code, EU membership status
- City name, region/state name and code, postal code, metro code
- Latitude and longitude coordinates
- IANA timezone identifier
- ASN number and organization name

**Content Negotiation**
- Browsers receive HTML pages
- CLI tools (curl, wget, HTTPie, etc.) receive plain text
- API clients with `Accept: application/json` receive JSON
- All field endpoints support `.txt` extension for explicit plain text

**TLS / ACME** (AI.md PART 15)

Certificates issued via Let's Encrypt using `go-acme/lego`. Supported challenge types: HTTP-01 (default), TLS-ALPN-01, and DNS-01. DNS-01 is provider-agnostic — any lego-supported DNS provider (all providers under `lego/providers/dns`) can be selected by name in `server.yml` (`server.ssl.letsencrypt.dns_provider` + `dns_credentials` block, encrypted at rest with `server.security.encryption_key`), with no per-provider Go code required. Credentials are decrypted only at the point of use and validated on startup and before every certificate request; `dns_credentials.validated_at` records the last successful check. ACME account key/registration persisted under `{config_dir}/ssl/letsencrypt/account/`.

**Scheduler** (AI.md PART 18)

All tasks run continuously; state persists across restarts. Jobs are registered at startup; graceful shutdown drains running jobs.

| Task | Schedule | Description |
|------|----------|-------------|
| `ssl_renewal` | Daily 03:00 | Renew TLS certs when ≤ 7 days from expiry |
| `geoip_update` | Weekly (Sun 03:00) | Download GeoIP databases from sapics/ip-location-db |
| `blocklist_update` | Daily 04:00 | Download IP/domain blocklists for abuse detection |
| `threat_update` | Daily 04:30 | Download VPN/proxy/Tor exit-node lists for detection |
| `cve_update` | Daily 05:00 | Download CVE/security databases |
| `token_cleanup` | Every 15 min | Remove expired CLI operator tokens |
| `log_rotation` | Daily 00:00 | Rotate and compress old logs |
| `backup_daily` | Daily 02:00 | Cumulative daily incremental plus a verified full backup; keeps the incremental's base full |
| `backup_hourly` | Hourly | Incremental backup — disabled by default |
| `healthcheck_self` | Every 5 min | Self-health verification |
| `tor_health` | Every 10 min | Check Tor connectivity — registered only when Tor is detected |

**Email & Notifications** (AI.md PART 17)
- SMTP configuration in `server.yml` under `notifications.smtp`
- HTML + plain text multipart emails
- Templates embedded in binary via `embed.FS`; operator can override by placing templates in `{config_dir}/template/email/`
- Credentials never logged

**Tor Hidden Service** (AI.md PART 31)
- Auto-enabled when `tor` binary is found in PATH
- v3 onion address (ed25519)
- Operator sees the onion address in startup output

**Docker non-root exception** (AI.md PART 26 "Dockerfile Requirements",
documented per its own exception clause)
- `docker/Dockerfile` and `docker/Dockerfile.dev` intentionally contain
  no `USER` directive — the container starts and stays root
- Reason: the binary manages a system service (Tor, PART 31/23) and
  must create its own dedicated system user and take ownership of
  `/config`, `/data`, and their subdirectories on every normal startup
  (AI.md PART 23 "Server Startup Sequence" steps 8a/8c and "System User
  Requirements"), including recovering from host bind mounts owned
  `root:root`. It creates the `ipgaze` system user, chowns its
  directories, binds ports, then calls `dropPrivileges()` before
  serving any request — verified via container logs
  ("Dropped privileges to user ipgaze") and a live healthz check
- The Trivy `DS-0002` ("Specify at least 1 USER command") finding is
  suppressed inline in both Dockerfiles with a comment pointing back to
  this section, per AI.md's own "document any exception in IDEA.md"
  instruction

**PWA Support**
- Web app manifest for mobile installation
- Service worker for offline caching of static assets

**Database**
- Default: SQLite via `modernc.org/sqlite` (pure Go, CGO_ENABLED=0, local file)
- Alternate: libSQL/Turso remote via `tursodatabase/libsql-client-go` (remote Turso cloud or self-hosted sqld)
- Driver selected in `server.yml` under `server.database.driver` (sqlite | libsql | turso)
- Config aliases: sqlite2/sqlite3 → sqlite; turso → libsql

**Cache Backends**
- `none` (disabled), `memory` (default, in-process), `valkey`/`redis` (shared), `memcache`
- Configured under `server.cache.type`; `CACHE_URL` overrides the connection
  string and upgrades a `none`/`memory` type to `valkey`

**Operator Commands** (server binary flags)
- `--service start|stop|restart|reload|status|--install|--uninstall|--disable` — systemd/launchd/Windows service management
- `--maintenance backup|restore` — backup/restore (`--include-ssl`, `--include-data` widen the archive)
- `--maintenance update|mode|setup` — self-update alias, maintenance-mode toggle, re-run first-run setup
- `--maintenance pgp generate|rotate|publish|export|import|delete` — server PGP keypair lifecycle
- `--maintenance secret rotate` — rotate `server.security.encryption_key` with a 30-day grace period
- `--maintenance token list|revoke` — operator API token management
- `--maintenance data export` — JSON inventory of stored operational data and the configured privacy policy
- `--maintenance data delete` — interactively erase rate-limit and audit-log history
- `--maintenance compliance report` — show enabled standards and configured privacy/security controls; enabled standards require encrypted backups
- `--shell completions|init [SHELL]` — shell completions and init snippet
- `--update check|yes|branch {stable|beta|devel}` — binary self-update from GitHub Releases; rolling-channel aliases normalize to `devel`
- Backup format: `.tar.gz` (or `.tar.gz.enc` when encryption is enabled); SSL keys and the full data directory are excluded unless explicitly included
