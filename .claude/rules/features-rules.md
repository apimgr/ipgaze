# Features Rules (PART 17-22)

⚠️ **These rules are NON-NEGOTIABLE. Violations are bugs.** ⚠️

## CRITICAL - NEVER DO
- Never add a notification/scheduler/backup/update feature that isn't documented in IDEA.md
- Never guess default schedule intervals, retention windows, or metrics namespaces — check spec or ask
- Never use `strconv.ParseBool()`/ad hoc parsing for `SMTP_TLS`/`events.*`/feature toggles — use `config.ParseBool()`
- Never send email when SMTP is unconfigured — "No SMTP = No emails. Don't even try."
- Never use `github.com/oschwald/geoip2-golang` — it rejects ip-location-db's non-MaxMind `database_type`
  strings; decode `.mmdb` files with `github.com/oschwald/maxminddb-golang` into project-defined structs
- Never embed GeoIP databases in the binary or use MaxMind GeoLite2 (EULA-restricted, not zero-config)
- Never use an external scheduler (cron, systemd timers, launchd, K8s CronJob) — the built-in scheduler
  (PART 18) is mandatory and exclusive
- Never expose metrics via a query-string token — `Authorization: Bearer {token}` header only
- Never let a metrics alias route (`/metrics`, `/api/metrics`, `/api/{api_version}/server/metrics`)
  redirect — every alias calls the identical handler
- Never skip mandatory post-backup verification or SHA-256 checksum verification before an update
  replaces the running binary
- Never accept a `--update`/self-update CLI flag for the backup/restore password — password prompt only

## CRITICAL - ALWAYS DO
- Translate all user-facing notification and scheduler text (`{{t .Lang "key"}}` / template vars)
- Verify features by exercising them (trigger the scheduled job, hit `/server/metrics`, run a
  backup/restore cycle, run `--update check`) before reporting done
- Suppress the generic `scheduler_error` email when a more specific failure event
  (`backup_failed`, `ssl_renewal_failed`) already fired for the same execution
- Probe SMTP auto-detect hosts/ports in the exact priority order below; ports per host in ascending order
  `25, 465, 587`
- Prefix every Prometheus metric with `{project_name}_`; counters end `_total`; base units only
  (`_seconds`, `_bytes`, never ms/KB); labels stay low-cardinality (never raw IP/user ID)
- Attribute GeoIP data: CC BY 4.0 / NRO / DB-IP, verbatim, on `/server/about` and in `LICENSE.md`

## Key Rules Summary

### PART 17 — Email & Notifications
- SMTP auto-detect priority order: `127.0.0.1` → `172.17.0.1` (Docker bridge) → `{gateway_ip}` →
  `{fqdn}` → `{global_ipv4}` → `mail.{fqdn}` → `smtp.{fqdn}`; each tried on ports 25, 465, 587 in order;
  first successful EHLO wins, saved to `server.yml`, email enabled
- Config: `server.notifications.email.smtp.{host,port,username,password,tls}` (`tls`: auto/starttls/tls/none,
  default `auto`); `from.{name,email}` (default `no-reply@{fqdn}`); env overrides `SMTP_HOST`, `SMTP_PORT`
  (default 587), `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_TLS`, `SMTP_FROM_NAME`, `SMTP_FROM_EMAIL`
- 10 default templates (embedded, overridable in `{config_dir}/template/email/`): `backup_complete`,
  `backup_failed`, `scheduler_error`, `security_alert`, `ssl_expiring`, `ssl_renewal_failed`,
  `ssl_renewed`, `test`, `update_available`, `update_installed`
- 11 per-event toggles under `server.notifications.email.events.*`: `startup`, `shutdown`,
  `backup_complete`, `backup_failed`, `ssl_expiring`, `ssl_renewed`, `ssl_renewal_failed`,
  `security_alert`, `scheduler_error`, `update_available`, `update_installed`
- No account emails ever (no signup/password-reset/verification flows) — operator notifications only

### PART 18 — Scheduler
- Built-in scheduler only, no external cron/systemd-timer/K8s-CronJob equivalents, ever
- Required tasks and defaults: `ssl_renewal` `0 3 * * *`; `geoip_update` `0 3 * * 0` (weekly, Sunday);
  `blocklist_update` `0 4 * * *`; `cve_update` `0 5 * * *`; `update_check` `0 6 * * *`;
  `token_cleanup` `@every 15m`; `log_rotation` `0 0 * * *`; `backup_daily` `0 2 * * *`;
  `backup_hourly` `@hourly` (disabled by default); `healthcheck_self` `@every 5m`;
  `tor_health` `@every 10m`; `i2p_health` `@every 10m`
- Every task schedule/enabled state is overridable via `server.schedule.tasks.{id}` in `server.yml`

### PART 19 — GeoIP
- Source: sapics/ip-location-db via jsDelivr CDN (`@ip-location-db` npm scope), no API key/account
- Three canonical `.mmdb` databases only — ASN (`asn-mmdb`), Country (`geo-whois-asn-country-mmdb`),
  City IPv4/IPv6 (`dbip-city-mmdb`); no separate "WHOIS" dataset exists
- License: CC BY 4.0 (NRO / DB-IP) — attribution mandatory, not optional
- Downloaded on first run (never embedded in binary), refreshed weekly via `geoip_update` (Sunday 03:00)
- Defaults to enabled with zero config, `deny_countries`/`allow_countries` both empty; fail-open on
  lookup failure; GeoIP is a risk signal only, never a sole access-control gate

### PART 20 — Metrics
- Endpoint family under `/server` namespace: `/server/metrics` (= `/server/metrics/prometheus`),
  `/server/metrics/grafana`, `/server/metrics/loki`; mirrored at
  `/api/{api_version}/server/metrics[/{service}]`, `/api/metrics[/{service}]`, and root
  `/metrics[/{service}]` (gated by `server.metrics.root.enabled`, default true) — all aliases call the
  identical handler, never a redirect
- Per-service bearer token (`prometheus`, `grafana`, `loki`); `Authorization: Bearer {token}` header only;
  constant-time comparison (`crypto/subtle`); `auth.allow_unauthenticated: true` (default false) is a
  firewalled-network-only escape hatch
- Library: `github.com/prometheus/client_golang`; metric prefix `{project_name}_` (e.g. `ipgaze_`)
- Required metric families include `app_info`/`app_uptime_seconds`/`app_start_timestamp`,
  `http_requests_total`/`http_request_duration_seconds`/`http_request_size_bytes`/
  `http_response_size_bytes`/`http_active_requests`, `db_queries_total`/`db_query_duration_seconds`/
  `db_connections_open`/`db_connections_in_use`/`db_errors_total`, `auth_attempts_total`/
  `auth_sessions_active`, plus cache/scheduler/system/business categories per the full metric tables
- Label rules: snake_case, lowercase, no units in label names, low cardinality (method/status/path with
  IDs normalized to `:id` — never raw user IDs or IPs)

### PART 21 — Backup & Restore
- Format: `tar.gz`, optionally `.enc`; manual/timestamped filenames
  `{project_name}_backup_YYYY-MM-DD_HHMMSS.tar.gz[.enc]`; scheduled daily fulls
  `{project_name}_backup_YYYY-MM-DD.tar.gz[.enc]`
- Encryption (compliance mode: mandatory): AES-256-GCM, key derived via Argon2id from an
  operator-supplied password (never a CLI flag — password prompt only)
- Retention (`server.backup.retention.*`): `max_backups` (default 1, ≥1, daily fulls to keep),
  `keep_weekly` (default 0 = disabled, Sunday backups), `keep_monthly` (default 0, 1st-of-month),
  `keep_yearly` (default 0, Jan 1st), `max_total_size` (default `"10%"` of backup volume or an absolute
  size like `"50G"`; `0` disables; overrides count limits when set)
- `backup_daily` flow (02:00): disk-space pre-check → create daily incremental → run mandatory
  post-creation verification (all checks fatal) → apply retention sweep → audit log
  (`backup.daily_updated`, `backup.retention_cleanup`)

### PART 22 — Update Command
- CLI: `--update {check|yes|branch {stable|beta|daily}}` and `--maintenance update` alias
- Source: GitHub Releases API; mandatory SHA-256 verification against the release's `sha256.txt` asset
  (`"{sha256}  {filename}"` lines) before the running binary is ever touched — abort on missing checksum
  asset or mismatch
- Channels are cumulative: `stable` ⊆ `beta` ⊆ `daily` (daily is a single rolling release retagged nightly)
- `defer_days` gates only the scheduled `update_check` task — manual `--update yes`/`branch` bypasses it
- Platform-specific binary replacement: Unix atomic rename + `syscall.Exec`; Windows rename-to-`.old` +
  deferred `MoveFileEx` deletion

For complete details, see AI.md PART 17, PART 18, PART 19, PART 20, PART 21, PART 22.
