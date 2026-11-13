# Features Rules (PART 17, PART 18, PART 19, PART 20, PART 21, PART 22)

⚠️ **These rules are NON-NEGOTIABLE. Violations are bugs.** ⚠️

## CRITICAL - NEVER DO
- **PART 17:** *Display Note:** Detected SMTP `{host}:{port}` is shown in console/logs (exempt from "never show localhost" rules - users need to see the actual detected server for troubleshooting).
- **PART 17:** *Encryption is always negotiated per `smtp.tls`; certificate verification is skipped only when the configured `smtp.host` is an IP literal in a private range.** A relay on the operator's own network (for example the Docker bridge `172.17.0.1`) almost never has a certificate with an IP SAN, so verification there always fails with `x509: cannot validate certificate for {ip} because it doesn't contain any IP SAN`. The operator is handing mail to a local relay inside their own infrastructure, so TLS stays on (traffic is still encrypted) and only chain and name verification are relaxed.
- **PART 17:** **Keyed on the configured host string, never on DNS results** — a hostname that resolves to a private address is still verified, so DNS answers can never downgrade verification
- **PART 17:** **Go:** classify with `netip.Addr` (`IsPrivate()`, `IsLoopback()`, `IsLinkLocalUnicast()`, plus the `100.64.0.0/10` range); set `tls.Config{ServerName: host, InsecureSkipVerify: true}` only for those addresses and never for any other path. **Rust:** classify with `std::net::IpAddr` and the same ranges, and apply the relaxed verifier only for those addresses
- **PART 17:** **One info line at startup and on config change:** `SMTP host {ip} is a private address: TLS certificate verification skipped` — never per message
- **PART 17:** The startup connection test (EHLO) and every send use the same policy, so a relay that passes the test never fails later on verification
- **PART 17:** | `To` | One valid `addr-spec` per message; recipients are never exposed to each other and never placed in `Bcc` headers |
- **PART 17:** | Header safety | Any value taken from user input is rejected if it contains CR or LF — header injection is never possible |
- **PART 17:** **Tests required:** every message carries all headers above; a non-ASCII subject and display name round-trip through RFC 2047; a CR/LF in a recipient, subject or name is rejected before sending; the plain-text part is never empty
- **PART 17:** *DO NOT:**
- **PART 17:** *Translation:** this engine does plain substitution only — it cannot call functions, so `{{t "key"}}`/`{{tf "key" ...}}` do NOT work here. Per PART 30's i18n mandate, resolve every translated string server-side (`i18n.Translate`/`i18n.TranslateFormat`) BEFORE rendering, then pass the already-translated result as a plain `{variable}` value — see PART 30 § "Email Template Translation" for the full pattern.
- **PART 17:** *Three notification channels. The public WebUI serves visitors; operators are reached via logs and email — API projects have no admin UI, so operator events NEVER render in the WebUI.**
- **PART 17:** *Operator events (backups, SSL, updates, scheduler failures, abuse detection) never appear here — see "Operator Notifications" below.**
- **PART 17:** *API projects have no admin UI — operator events surface via structured logs (always), email (when SMTP is configured), and CLI output (`--status`, `--update check`). Never via the public WebUI.**
- **PART 17:** **Delivery:** the recipient is the admin role (PART 12 → "Contact Configuration"). The shutdown email is best effort with a 5-second send timeout and never delays process exit beyond that.
- **PART 17:** | Banner dismissals | `dismissed_announcements` cookie (client-side, keyed on announcement id, visitor-clearable — same store as theme/language preferences; server-readable so dismissed banners are never rendered) |
- **PART 18:** *A single scheduled task MUST NEVER be able to crash the scheduler or the server process.**
- **PART 18:** | **No cross-task impact** | A panic in one task MUST NOT skip, delay, or corrupt the state of any other task |
- **PART 18:** *The built-in scheduler handles ALL scheduled tasks. NEVER use external schedulers.**
- **PART 18:** | Platform | NEVER Use | Reason |
- **PART 18:** Task activity is logged to log files only — the scheduler NEVER prints to the console (see Console vs Logs → Runtime Console Silence).
- **PART 19:** GeoIP databases are NEVER embedded in the binary — they are downloaded on first run and kept updated via the built-in scheduler (see PART 18: SCHEDULER). First run works with zero config: GeoIP defaults to enabled with no country blocking (`deny_countries`/`allow_countries` both empty).
- **PART 19:** *GeoIP MUST be treated as one risk signal among many — never as the sole access-control gate.** GeoIP is a deny-only layer: it can reject a request but never grant access. A request from an allowed, unknown or unlooked-up country MUST still pass through every other layer of the security pipeline (authentication, authorization, input validation, audit logging) and MUST NOT skip any check on the assumption that "the country is trusted". A request from a blocked country is rejected with `403` at the GeoIP step after the blocklist and the rate limiter, so it consumes rate-limit budget and is logged with its source IP; authentication is not evaluated for it because it is already denied.
- **PART 19:** | **Never sole gate** | Country / ASN / city signals can raise risk score, trigger MFA, lower rate-limit thresholds, or feed audit logs — they MUST NOT be the only thing standing between an attacker and a resource. |
- **PART 19:** | **Always alongside, not instead of** | The country check runs after the blocklist and the rate limiter and before authentication (PART 5 → "Middleware Order", positions 6–8 then 9). It only denies; it never replaces authentication or authorization for any request that passes it. |
- **PART 19:** | **GeoIP-only auth is forbidden** | "Allow if country = US" is not authentication. Login, API keys, session cookies, and tokens are still required regardless of source country. |
- **PART 19:** | **Failure mode** | If a GeoIP database is missing, stale, or the lookup fails, the request MUST be processed by the rest of the pipeline normally (fail-open for GeoIP, fail-closed for real auth). Never block a request because a GeoIP lookup errored. |
- **PART 19:** | **Private/internal IPs** | RFC 1918 / RFC 4193 / loopback addresses are never looked up or country-blocked. |
- **PART 19:** *No separate "WHOIS" database.** Earlier drafts of this spec described a combined WHOIS lookup exposing a `registrant_org` field — no such dataset exists in ip-location-db. The `geo-whois-asn-country` package name is misleading: despite the name, it exposes only `country_code` (merged from RIR geofeed, whois, and ASN data at the NRO's publishing layer — the merge happens upstream, not in the file this project consumes). Organization-name data available to this project comes solely from the ASN database's `autonomous_system_organization` field (a BGP/RIR-derived AS holder name, not an RDAP/WHOIS registrant record) — use that field directly and do not label it "WHOIS" anywhere in code, config, or docs.
- **PART 19:** *Do not use MaxMind GeoLite2 as an alternative or fallback.** GeoLite2 requires acceptance of the MaxMind GeoLite2 EULA in addition to CC BY-SA 4.0 attribution — stricter terms (e.g. redistribution and update-frequency restrictions) than the CC BY 4.0 sources above. It is not zero-config-compatible with this project's "first run works with zero config, no account required" rule.
- **PART 19:** If a future database swap changes the license (e.g. adding a PDDL-only source), update this section — do not carry stale attribution for a database no longer in use, and do not drop attribution for one still in use
- **PART 19:** Private/internal IPs (RFC 1918, RFC 4193, loopback) are never looked up or country-blocked
- **PART 19:** *No preset ships pre-populated, and this project MUST NOT bundle a
- **PART 19:** A preset is only ever a name plus the country codes the operator entered — the project never fetches, infers, or auto-suggests preset contents from any external source
- **PART 19:** Referencing a preset only pre-fills `deny_countries`/`allow_countries` for the operator to review and save in `server.yml`; it is never applied automatically or silently
- **PART 19:** If an operator needs a compliance-driven blocklist, they build and save it themselves as a preset, sourced from their own current legal/compliance review — never from a template default
- **PART 19:** Presets are a pure config-reuse convenience; the actually-enforced behavior is always driven by `deny_countries`/`allow_countries` at the time of the request, never by the preset name itself
- **PART 20:** | `/metrics[/{service}]` | GET | Same per-service token | Root alias, gated on `server.metrics.root.enabled: true` (default **true** — Prometheus scrapers default to `/metrics`); same handler, NEVER a redirect |
- **PART 20:** All alias routes invoke the SAME handler — never redirect (redirects break scrapers), same rule as the healthz root alias.
- **PART 20:** | **Behind reverse proxy** | Proxy config | Do NOT proxy `/server/metrics` or `/metrics` to public |
- **PART 20:** | **Per-service tokens** | Each service (`prometheus`, `grafana`, `loki`) has its own token in `server.yml` — rotating one service's token never breaks the others |
- **PART 20:** | **Header only** | `Authorization: Bearer {token}` — query-string tokens are FORBIDDEN (they leak into access logs and proxies) |
- **PART 20:** | **Never logged, always redacted** | Tokens never appear in logs, error messages, `/server/healthz`, or any config dump — display as `xxxxx` |
- **PART 20:** | **Still INTERNAL** | Metrics remain internal/operational endpoints — never advertised, never in FeaturesInfo, firewall/proxy rules still apply as defense in depth |
- **PART 20:** *Cardinality note:** `per_ip` is a `limit` label *value*, never a per-address label. Never use a raw client IP as a metric label — per-IP labels are unbounded-cardinality and a memory-DoS vector. The rate limiter must cap the set of tracked IPs (e.g., a fixed-size LRU) or aggregate; never emit one label value per unique client IP. Log per-IP details to structured logs instead; metrics answer "how many?" while logs answer "which IPs?"
- **PART 21:** | Password Storage | Held only as the `server.backup.encryption_password` config value, so scheduled backups can run unattended. Never written to the database, a log, a manifest or an archive; never returned by any API; never hashed (it is key material, not a login verifier). Restore never reads it: the operator supplies the password |
- **PART 21:** 5. Unencrypted archive never touches disk
- **PART 21:** Do NOT delete any existing backups
- **PART 21:** Never re-resolve the path at cleanup time.
- **PART 21:** *Decision: incrementals are cumulative (differential), never a chain. Restore always needs exactly one full + at most one incremental.**
- **PART 21:** | **Base protection** | Retention never deletes a full that is the `base_backup` of a retained incremental |
- **PART 22:** *Channels are cumulative — a less-stable channel never leaves you older than a more-stable one.**
- **PART 22:** | `beta` | Beta pre-releases (`*-beta`) + all stable releases | Newest of both — beta users are never stuck behind a stable release |
- **PART 22:** | Devel channel ignores `defer_days` | The rolling `devel` release is deleted and recreated nightly, so its `published_at` is always fresh — an age-based gate could never pass and would permanently block the devel channel. Devel selection instead compares the release's `published_at` against the running binary's embedded `BUILD_EPOCH` (see Channel Semantics above), with no deferral window applied |
- **PART 22:** | `auto_install: false` (default) | Notify only — fires the `update_available` event; never touches the binary |
- **PART 22:** *Surfacing rules (API projects have no admin UI — operator events never render in the public WebUI):**
- **PART 22:** NEVER inject update notices into API responses, headers, or any public endpoint — running-version and update status are Tier 3 information (Public Endpoint Safety Principle, PART 11), and update prompts are operator concerns, not client concerns

## CRITICAL - ALWAYS DO
- **PART 17:** *ALL projects MUST have customizable email templates.**
- **PART 17:** | Any public IP literal | Verified against the system roots; the certificate must carry an IP SAN |
- **PART 17:** **Tests required:** each private range above skips verification; a public IP literal and every hostname verify; a hostname resolving to a private address verifies; `starttls` against a server without STARTTLS fails instead of falling back to plaintext
- **PART 17:** *Every message the app sends MUST be a well-formed RFC 5322 / MIME message, whatever relay it goes through.**
- **PART 17:** *ALL email templates MUST have sensible defaults that work immediately without configuration.**
- **PART 17:** *ALL server notification emails MUST include:**
- **PART 17:** | **Public WebUI (Toast/Banner)** | Visitors | Always (client-side) | Feedback for the visitor's own actions and service announcements |
- **PART 17:** | **Logs** | Operators | Always | Every operator event gets a structured, leveled log line |
- **PART 17:** **Defaults:** both switches default to off (`server.notifications.email.events.startup` and `shutdown`). Every occurrence is always logged at INFO whatever the switches say.
- **PART 18:** *ALL projects MUST have a built-in scheduler that is ALWAYS RUNNING.**
- **PART 18:** | **Always Running** | Scheduler starts with application and runs until shutdown |
- **PART 18:** Every task run MUST execute inside its own panic/`recover` boundary, isolated from the scheduler's own control loop and from every other task:
- **PART 18:** | **Scheduler loop survives** | A panicking task MUST be logged and marked `failed` for that run — the scheduler loop itself MUST keep running and MUST still fire the task's next scheduled occurrence |
- **PART 18:** | **Same guarantee as HTTP handlers** | This is the same non-negotiable guarantee as the per-request panic/`recover` requirement in "Error Pages (MUST Match Theme)" — a background job is not exempt just because no browser is watching it |
- **PART 18:** Every project MUST include these scheduled tasks:
- **PART 18:** | Verify | Yes | All checks must pass |
- **PART 18:** 1. **Use Go's time/ticker** - No external cron libraries required
- **PART 19:** *ALL server-capable projects MUST have built-in GeoIP support using sapics/ip-location-db.**
- **PART 19:** All databases come from [sapics/ip-location-db](https://github.com/sapics/ip-location-db), distributed via the jsDelivr CDN under the `@ip-location-db` npm scope — no API key, account, or license agreement required at download time.
- **PART 19:** *Required, verbatim, on `/server/about` (see "Standard Pages" → /server/about) AND in `LICENSE.md`'s third-party attribution section (see PART 2):**
- **PART 19:** Attribution MUST be visible on the page — not hidden behind a click-through, tooltip, or collapsed section
- **PART 19:** Both notices are required together; the DB-IP notice alone does not cover the NRO-sourced country data, and vice versa
- **PART 19:** Allowlisted IPs (`server.security.allowlist`) always bypass country blocking
- **PART 19:** *Operators MUST be able to save the current `deny_countries` or
- **PART 20:** *ALL projects MUST have built-in Prometheus-compatible metrics support for production monitoring.**
- **PART 20:** | `prometheus` | `text/plain; version=0.0.4` | Full Prometheus text exposition — all required + project metrics |
- **PART 20:** | `loki` | `application/json` | Recent structured log entries in Loki push-API stream format: `{"streams":[{"stream":{labels},"values":[["<ns-timestamp>","<line>"],...]}]}` — bounded by `loki.max_entries`/`loki.max_age`, same sanitization as log files (credentials ALWAYS redacted) |
- **PART 20:** *All metrics MUST follow Prometheus naming conventions.**
- **PART 20:** *Every project MUST expose these core metrics at minimum.**
- **PART 20:** | `{project_name}_app_info` | Gauge | `version`, `commit`, `build_date`, `go_version` | Always 1, labels carry info |
- **PART 20:** | `app_info` | Gauge | `version`, `commit`, `build_date`, `go_version` | Always 1, labels carry build info |
- **PART 21:** | `server.yml` | ✓ Always | Configuration file |
- **PART 21:** | `server.db` | ✓ Always | Main database (settings, rate limits, audit log) |
- **PART 21:** | **Enabled** | Set | Encrypted backups (required) |
- **PART 21:** Every backup is verified **immediately after creation** - backups must be 100% working:
- **PART 21:** *All checks must pass. If ANY check fails:**
- **PART 21:** *Validation (warn, don't error - server must start):**
- **PART 21:** | `{project_name}-daily.tar.gz[.enc]` | Daily incremental (cumulative changes since the previous full - see Incremental Backup Contract) | Always 1 (replaced each run) |
- **PART 21:** | `{project_name}-hourly.tar.gz[.enc]` | Hourly incremental (if enabled) | Always 1 (replaced each run) |
- **PART 21:** *Daily incremental is NOT counted** in retention - it's always exactly 1 file that gets replaced. A full backup that is the `base_backup` of a retained incremental is exempt from pruning until that incremental is replaced (at most one extra full on disk).
- **PART 21:** *If backup is encrypted (`.tar.gz.enc`), backup password is required (separate from `server.token`).**
- **PART 22:** | `check` | Check for updates without installing (no privileges required) |
- **PART 22:** *Channel names:** `devel` is the canonical name of the rolling channel. `daily`, `rolling`, `dev`, and `development` are accepted anywhere a channel is read (`--update branch`, `update.branch`, `cli.yml`) and normalized to `devel` before it is stored or compared, so a stored value is always `stable`, `beta`, or `devel`. `stable` follows the version tags with or without a `v` prefix (`v1.0.1` and `1.0.1`); `beta` follows the `*-beta` tags.
- **PART 22:** | Gates the scheduled task only | `update_check` skips ineligible releases for BOTH notification and auto-install; manual `--update check` / `--update yes` always see and install the true latest — an explicit operator action overrides the defer window |
- **PART 22:** *When running as a service, update must coordinate with service manager:**
- **PART 22:** *All downloads MUST be verified against checksums from the release:**

## Key Rules Summary

### PART 17 — EMAIL & NOTIFICATIONS
- Overview
- Template Storage
- SMTP Configuration
- Default Templates
- Sane Defaults
- Template Format
- Global Variables (Available in All Templates)
- Server Email Requirements
- Template-Specific Variables
- Email Template Configuration
- Notification Systems
- Public WebUI Notification System
- Operator Notifications
- Log vs Email Decision Matrix
- Notification Storage
- Operator Notification Preferences
- Configuration

### PART 18 — SCHEDULER
- Built-in Scheduler
- NEVER Use External Schedulers

### PART 19 — GEOIP
- Overview
- GeoIP Is a Risk Signal — Never the Sole Access Gate (NON-NEGOTIABLE)
- Database Sources (ip-location-db) — Canonical, Single Source Per Category
- License & Attribution (NON-NEGOTIABLE)
- Configuration
- Country Blocking Presets (Operator-Defined, Never Auto-Applied)

### PART 20 — METRICS
- Overview
- Endpoints
- Service Semantics
- Access Control
- Authentication
- Configuration
- Metrics Categories
- Metric Naming Conventions
- Required Metrics
- Complete Metrics Reference
- Metrics Output Example
- Metrics Implementation
- Metrics Endpoint Output
- Alerting Rules (Prometheus)
- Grafana Dashboard
- Metrics Configuration (config file)

### PART 21 — BACKUP & RESTORE
- Backup Command
- Incremental Backup Contract
- Restore Command

### PART 22 — UPDATE COMMAND
- --update Command
- Commands
- Update Configuration
- Self-Update Implementation

For complete details, see AI.md PART 17, PART 18, PART 19, PART 20, PART 21, PART 22.

<!-- AI.md source: 03cc45ec58df -->
