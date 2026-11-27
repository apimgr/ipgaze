# Configuration

Complete configuration reference for **ipgaze**.

## Configuration File

ipgaze creates `server.yml` with sane defaults on first run. Ordered files in
`yaml.d/` override it, and `secrets.yml` is merged last for credentials. The
database stores operational state and issued API token records; `audit.log` is
the authoritative audit record, with database rows as a queryable mirror.
Operator settings never live in the database. Optional public-page content lives in
`yaml.d/branding.yml`.

### Default Location

| User Type | Path |
|-----------|------|
| Root | `/etc/apimgr/ipgaze/server.yml` |
| Regular user | `~/.config/apimgr/ipgaze/server.yml` (XDG `$XDG_CONFIG_HOME` honored) |
| Docker container | `/config/ipgaze/server.yml` |

The `--config` flag or the `CONFIG_DIR` environment variable (first run only)
can override the configuration directory.

### Drop-in Files

For large configurations, place `*.yml` or `*.yaml` files in
`{config_dir}/yaml.d/`. The server reads them after `server.yml` in
byte-wise filename order, so a later file overrides an earlier value.
Mappings merge recursively; later scalar and list values replace earlier
values, and lists are never appended. Explicit `null` values, duplicate keys,
and drop-ins writable by group or other users are rejected.

Hidden files, backups (`*.bak`, `*~`, `*.orig`), other file extensions, and
subdirectories are ignored. Symlinks are read only when their target remains
inside `yaml.d/`. Changes to `server.yml`, this directory, or `secrets.yml` are
merged and reloaded; an invalid result leaves the last valid configuration
active. Generated settings are written to `server.yml`; generated credentials
are written only to `secrets.yml`. Backups include `yaml.d/` and `secrets.yml`
when they exist. The archived copy blanks `server.token` and
`server.backup.encryption_password`; restore keeps the target host's operator
token.

### Operator Page Content

Optional `server.branding.content` entries in
`{config_dir}/yaml.d/branding.yml` customize About, privacy, terms, header,
and footer content. Markdown, HTML, and text are supported where specified;
HTML output is sanitized, each body is limited to 256 KiB, and edits are
hot-reloaded.

Startup logs list loaded drop-ins at info level. Debug logs identify the source
files when a later setting overrides an earlier one; configuration values are
not included in those override messages.

### Migration

If a legacy `server.yaml` is found next to the expected `server.yml` path,
it is automatically renamed to `server.yml` on startup.

### Example Configuration

Most configuration keys are grouped under `server:` and `web:`. Page
configuration uses the top-level `pages:` section.

```yaml
# IPGaze Server Configuration
server:
  port: "64123"
  fqdn: "ip.example.com"
  address: "[::]"
  mode: production

  healthz:
    root:
      enabled: false

  logs:
    level: warn

  geoip:
    enabled: true

  rate_limit:

  seo:
    feed:
      max_items: 50
      title: ""

  database:
    driver: sqlite

  restore:
    max_archive_size: 1G
    max_expanded_size: 4G
    max_files: 10000
    max_file_size: 512M
    max_ratio: 100

  compliance:
    enabled: false
    gdpr: false
    ccpa: false
    hipaa: false
    soc2: false
    pci_dss: false
    iso27001: false
    fedramp: false
    lgpd: false
    pipeda: false
    appi: false
    pdpa: false

web:
  ui:
    theme: dark
  cors: "*"
```

Enabling `server.compliance.enabled` or any individual standard requires
encrypted backups. `ipgaze --maintenance compliance report` prints enabled
standards and effective retention settings, owner/token/open-report counts,
retained compliance events from the last 30 days, the last backup time, and
the audit-chain integrity result. A standard flag records the operator's
configured scope; it does not certify that the deployment meets that standard.

## WebUI Toasts

Visitor-facing success and information toasts default to three seconds;
warnings default to five seconds, and errors always require manual dismissal.
Configure placement and durations under `server.notifications.webui`:

```yaml
server:
  notifications:
    webui:
      position: top-right # top-right, top-left, bottom-right, bottom-left
      duration: 3 # success and information; 0 disables auto-dismiss
      warning_duration: 5 # warnings; 0 disables auto-dismiss
```

`server.security.encryption_key` is generated and stored in `secrets.yml` on
first run. It protects sensitive data stored by the application, including
security report contents and researcher credit names. Keep the secrets file
private and preserve its backup with the database.

Closed security reports are removed by the daily `security_cleanup` task
after `server.security.reports.retention_days` days from `closed_at` (default
365). Open reports are retained. Rotated PGP keys used for in-flight reports
are pruned after their 30-day grace period.

```yaml
server:
  security:
    reports:
      retention_days: 365
```

## Configuration Precedence

For values that can come from a CLI flag, an environment variable, and
`server.yml`, the precedence (highest wins) is:

1. CLI flag (e.g. `--port`, `--address`)
2. `server.yml` (once a value has been persisted there)
3. Environment variable — for `PORT`/`LISTEN` this only applies on first
   run (see "Init-Only Variables" below); for the Runtime variables it
   is re-checked every start
4. Built-in default

Once a value is resolved (e.g. the port on first run), it is written back
into `server.yml` and persists across restarts — later runs read it from
the file unless a flag overrides it (or, for Runtime variables, the
matching env var overrides it again every start).

## Environment Variables

### Runtime Variables (always checked)

These are re-read on every start and take priority over `server.yml`:

| Variable | Description |
|----------|-------------|
| `DOMAIN` | FQDN override (highest priority for hostname resolution) |
| `MODE` | `production` (default), `development` or explicit `debug`; `prod`/`dev`/`devel` accepted. Development keeps sanitization enforced; debug behavior follows PART 6 and never exposes credentials |
| `PORT` | Listener port; `--port` wins, then `PORT`, then config/default according to the server startup precedence |
| `LISTEN` | Listener address; `--address` wins, then `LISTEN`, then config/default according to the server startup precedence |
| `PID_FILE` | PID file path; `--pid` wins, then `PID_FILE`, then the platform default |
| `I2P_ENABLED` | I2P eepsite activation; `--i2p` wins, then `I2P_ENABLED`, then config/computed default (on in containers, off elsewhere) |
| `CACHE_DIR` | Cache directory; environment value overrides the platform default on every start |
| `DATABASE_DRIVER` | `sqlite` (+ `sqlite2`, `sqlite3` aliases) or `libsql` (+ `turso` alias) |
| `DATABASE_URL` | Database connection string (libsql/Turso only) |
| `CACHE_URL` | Cache backend connection string (`valkey://`/`redis://`/`rediss://`); overrides `server.cache.url` and upgrades `server.cache.type` to `valkey` when it was `none`/`memory` |
| `SMTP_HOST` | SMTP server hostname (skips autodetect when set) |
| `SMTP_PORT` | SMTP server port (default: `587`) |
| `SMTP_USERNAME` | SMTP authentication username |
| `SMTP_PASSWORD` | SMTP authentication password |
| `SMTP_FROM_NAME` | Sender display name (default: app title; `SMTP_FROM` also accepted) |
| `SMTP_FROM_EMAIL` | Sender email (default: `no-reply@{fqdn}`) |
| `SMTP_TLS` | TLS mode: `auto`, `starttls`, `tls`, `none` (default: `auto`) |
| `DEBUG` | Enable debug mode (truthy value); unlocks `/debug/*`, `/debug/pprof/*`, and `/debug/vars` only — never bypasses auth. Overridden by `--debug` |
| `NO_COLOR` | Disable ANSI color output when set to any non-empty value |
| `TERM` | Terminal type; `TERM=dumb` disables ANSI escapes and forces CLI mode |
| `HOST_IPV4` | Host's public IPv4 address, reported instead of the container's internal address when the server runs behind Docker NAT |
| `HOST_IPV6` | Host's public IPv6 address, same purpose as `HOST_IPV4` |
| `LANG` / `LC_ALL` | Locale used to auto-detect the output language when `--lang` is not passed (`LC_ALL` wins) |
| `TZ` | Timezone used for log timestamps and scheduler run times |

Boolean-like values from any of these are parsed via the server's own
truthy-value parser (`config.ParseBool` / `config.IsTruthy`), not Go's
`strconv.ParseBool` — accepted truthy values include `true`, `1`, `yes`,
`on` (case-insensitive), and their falsy counterparts.

### Init-Only Variables (first run only)

These seed `server.yml` and OS-specific directories the first time the
server starts; on subsequent starts they are ignored in favor of the
persisted config:

| Variable | Description |
|----------|-------------|
| `CONFIG_DIR` | Configuration directory |
| `DATA_DIR` | Data directory |
| `LOG_DIR` | Log directory |
| `DATABASE_DIR` | SQLite database directory (changeable) |
| `BACKUP_DIR` | Backup directory (changeable) |
| `PORT` | Server port |
| `LISTEN` | Listen address |
| `APPLICATION_NAME` | Application title |
| `APPLICATION_TAGLINE` | Application description |

### Port and Address Resolution

The `--port`/`--address` CLI flags resolve in this order:

- Port: `--port` flag → `server.port` in config (once persisted) → `PORT` env (first run only) → random `64xxx` default
- Address: `--address` flag → `server.address` in config (once persisted, seeded from `LISTEN` on first run) → default `[::]`

### Docker Environment

```yaml
environment:
  - PORT=80
  - LISTEN=::
  - DATA_DIR=/data
```

## Port Selection

The default port is a random unused port in the `64000`-`64999` range,
chosen on first run and then saved to `server.yml`, where it persists
across restarts. Setting `server.port` explicitly always takes priority
over random selection.

## GeoIP Databases

Configuration lives under `server.geoip`:

```yaml
server:
  geoip:
    enabled: true
    deny_countries: []
    allow_countries: []
    presets: {}
```

`deny_countries` and `allow_countries` are mutually exclusive —
`allow_countries` takes precedence when both are set.

### Automatic Download

GeoIP databases auto-download on first run from
[sapics/ip-location-db](https://github.com/sapics/ip-location-db) and are
stored under `{data_dir}/security/geoip`. ASN (`iptoasn-asn.mmdb`) and Country
(`iptoasn-country.mmdb`) data come from iptoasn.com and are PDDL. City data
(`dbip-city-ipv4.mmdb` and `dbip-city-ipv6.mmdb`) comes from DB-IP under
CC BY 4.0. Each download is checked against its published SHA-256 before the
live file is replaced. The required DB-IP attribution appears on
`/server/about` and in `LICENSE.md`. Databases are refreshed by the
`geoip_update` task (weekly by default).

## Tor

The Tor hidden service starts automatically when the `tor` binary is
available; there is no hidden-service enable or disable flag. The optional
`server.tor.use_network` setting defaults to `false`. When enabled, the
managed Tor process exposes its SOCKS listener only on loopback for
server-originated HTTP connections selected to use Tor. Requests from inbound
hidden-service visitors cannot choose outbound destinations. This includes
app-selected update, threat-data, GeoIP, notification, keyserver, and ACME
HTTP requests. User-supplied remote URLs remain outside the Tor client. If Tor
cannot provide the configured route, routed requests fail instead of falling
back to a direct connection.

```yaml
server:
  tor:
    binary: ""          # Empty means auto-detect
    expose: false        # Publish the onion address in /api/autodiscover
    use_network: false  # Route supported server-originated HTTP requests via Tor
    startup_timeout: 60  # Control-port file wait, 10-300 seconds
    contact_email: ""   # Optional address shown only in Tor responses
  update:
    cli_min_version: "" # Empty means no minimum CLI version is enforced
```

The Tor contact address is `server.tor.contact_email`. If it is empty, Tor
responses omit email contact details and never fall back to the clearnet
contact address. Legacy top-level `tor.contact_email` values are read as a
compatibility fallback.

In the standard Docker layout, Tor stores the onion hostname at
`/data/ipgaze/tor/site/hostname`.

### CLI Release Distribution

The server does not build or download client binaries. Provision release files
in the configured directory; the server reads `version.txt` and `sha256.txt`,
recomputes each binary's SHA-256, and advertises only matching files from
`/api/autodiscover`. A missing directory, metadata file, or binary returns an
empty version map, so clients see no available update. Directory changes are
picked up on the next autodiscover request.

The default directory is `{data_dir}/cli`. These settings belong in
`yaml.d/maintenance.yml`:

```yaml
cli:
  binary_download:
    dir: "{data_dir}/cli"
    require_auth: false
```

Set `require_auth: true` to require an operator bearer token for binary
downloads. See the [CLI reference](cli.md#client-binary-distribution) for the
release filenames and update endpoint.

### Request Flood Detection and Permanent IP Blocks

Flood detection counts every request, including `429` responses, by client IP
and endpoint class. Defaults detect a count greater than 10 times the class
limit in a rolling 60-second window, block the IP for one hour, and send a
security alert. Allowlisted addresses bypass IP blocklists, request rate
limits, GeoIP country blocking, and automatic flood blocks. Authentication,
CSRF, path-security, and TLS checks still apply. Temporary blocks persist in
the database and expire automatically. Permanent blocks and allowlists accept
IPv4/IPv6 addresses or CIDRs; a bare address is treated as `/32` or `/128`.
Invalid entries and overly broad allowlist ranges (IPv4 `/0` through `/7`, IPv6
`/0` through `/15`) are skipped with a warning, without failing startup or
config reload. Allowlist entries are managed through the configuration files;
there is no allowlist API. If a block overlaps an allowlist entry, the
allowlist takes precedence.

```yaml
server:
  security:
    abuse_detection:
      request_flood:
        multiplier: 10
        window: 60s
        block_duration: 1h
      auto_block_ip: true
      auto_alert: true
    blocked_ips:
      - cidr: 198.51.100.0/24
        reason: "Abusive network"
      - cidr: "2001:db8::/32"
        reason: "Abusive IPv6 range"
    allowlist:
      - cidr: 192.0.2.10
        description: "Monitoring host"
      - cidr: "2001:db8:1::/48"
        description: "Trusted monitoring network"
```

## I2P

I2P hosting starts by default in application containers such as Docker and
Podman. It is disabled by default on bare metal, in VMs, and in Incus/LXC
system containers. Set `server.i2p.enabled` to `true` to enable an eepsite on
those hosts or `false` to disable it in an application container. Overlay startup
runs in the background so it does not delay the HTTP listener. Health reports
`starting`, `healthy`, or `unavailable`; an overlay failure does not stop or
restart the clearnet server. IPGaze manages an
`i2pd` process when its binary is available; otherwise it connects to an
external SAMv3 bridge. Tunnel lengths
and quantities apply to the managed `i2pd` provider. `bootstrap_timeout` is
expressed in seconds and must be between 30 and 600. The managed provider
uses an isolated `i2pd.conf`, disables unrelated router services, and creates
the eepsite through a private SAM port; it does not load server tunnels from
other configuration locations. External SAM bridges must support SAM 3.1 or
newer.

Set `server.i2p.expose: true` to publish the active `.b32.i2p` address in
`/api/autodiscover`. Both overlay exposure settings default to `false`.

```yaml
server:
  i2p:
    enabled: false
    expose: false               # Publish the .b32.i2p address in autodiscover
    binary: ""                   # Empty means auto-detect i2pd
    sam_address: "127.0.0.1:7656" # External SAMv3 bridge fallback
    virtual_port: 80
    inbound_length: 3
    outbound_length: 3
    inbound_quantity: 5
    outbound_quantity: 5
    signature_type: 7
    bootstrap_timeout: 300         # Seconds; 5 minutes
```

The I2P data directory and keys are stored under
`/data/ipgaze/i2p/site/`; see [I2P integration](integrations.md#i2p-eepsite)
for provider behavior and the persistent destination.

## Reverse Proxy

When behind a reverse proxy, the built-in proxy-header detection uses
client-IP headers only when the immediate peer is trusted. IPv4-mapped IPv6
addresses are unmapped, IPv6 zones and transport ports are stripped, and all
consumers use the canonical full address. IPv6 addresses are not grouped by
prefix for rate limits or bans. Rate-limit state is bounded and expires.

Standard URL-forwarding headers (`X-Forwarded-Proto`, `X-Forwarded-Port`,
`X-Forwarded-Prefix`) are also accepted from trusted peers. Additional trusted
proxy CIDRs (beyond the private ranges, which are always trusted) can be added under
`server.trusted_proxies`:

```yaml
server:
  trusted_proxies:
    client_ip_header: auto
    additional:
      - "203.0.113.0/24"
```

`client_ip_header: auto` selects the first present client address header in this
order: `X-Forwarded-For`, `Forwarded`, `CF-Connecting-IP`, `True-Client-IP`,
`X-Real-IP`, then `X-Client-IP`. Set it to one of those header names to read only
that header. The default chain headers combine repeated header fields, examine
at most the rightmost 32 hops, and walk from the nearest proxy toward the
client using the configured trusted proxy ranges. Invalid or obfuscated hops
stop the walk at the nearest valid address. Production deployments should pin
the header to the one their front proxy controls.

### nginx

```nginx
location / {
    proxy_pass http://172.17.0.1:64580;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header X-Forwarded-Port $server_port;
    proxy_set_header X-Forwarded-Prefix $http_x_forwarded_prefix;
    proxy_connect_timeout 3600s;
    proxy_send_timeout 3600s;
    proxy_read_timeout 3600s;
}
```

### Caddy

```
example.com {
    reverse_proxy 172.17.0.1:64580
}
```

### Traefik

```yaml
labels:
  - "traefik.enable=true"
  - "traefik.http.routers.ipgaze.rule=Host(`example.com`)"
  - "traefik.http.services.ipgaze.loadbalancer.server.port=80"
```

## MCP Endpoint

The Streamable HTTP MCP endpoint is always available at `/api/v1/server/mcp`,
with aliases at `/api/mcp` and `/mcp`. MCP requires an owner or operator Bearer token, while the REST API remains publicly accessible. Issue an owner token from the tokens page or API, then use a linked token for each MCP client. The
endpoint is stateless, accepts POST requests, validates the `Origin` header,
and applies the server's rate limits. It does not accept cookies or issue
MCP-specific tokens.

## Caching

Response/lookup caching is configured under `server.cache`:

```yaml
server:
  cache:
    # type: none, memory (default), valkey, redis, or memcache
    type: memory
    url: ""
    host: localhost
    port: 6379
    username: ""
    password: ""
    db: 0
    tls: false
    tls_skip_verify: false
    pool_size: 10
    min_idle: 2
    timeout: "5s"
    prefix: "ipgaze:"
    ttl: "1h"
```

Set `type: none` to disable caching entirely. `memcache` uses `host`/`port`
(default port `11211`) and ignores the Redis-only auth, TLS, and pool keys.

## Rate Limiting

Rate limiting is always enabled and bucketed by request class under
`server.rate_limit`:

```yaml
server:
  rate_limit:
    # Read: GET/HEAD requests
    read:
      requests: 120
      window: 60
    # Write: POST/PUT/PATCH/DELETE requests
    write:
      requests: 10
      window: 60
    # Health checks: /server/healthz and its configured aliases
    health:
      requests: 120
      window: 60
    # Token reveal, rotation, restore, and issue operations
    strict:
      requests: 10
      window: 900
    # Invalid, revoked, or expired Bearer credentials; lockout is per IP
    auth_failures:
      requests: 5
      window: 900
    # Absolute per-minute ceiling across endpoint classes
    global_burst: 240
```

Counters use sliding windows persisted in `server.db` by default. When
`server.cache.type` is `valkey` or `redis`, the counters use that external
cache instead, so rate limits are shared across server instances. Anonymous
requests use the normalized client IP; authenticated requests use the
validated token, and strict token actions use the owner identity.
Authentication failures are counted per IP and do not reset after a
successful request.

## Owner and Linked Token Settings

Owner tokens can be issued from `/server/preferences/tokens` or the API without
creating an IP lookup resource. The primary token identifies its owner; linked
tokens provide separate credentials for MCP clients.

```yaml
server:
  tokens:
    max_linked: 25
    cookie_max_age: 1y
    idle_purge_days: 0
```

`cookie_max_age` is a sliding lifetime refreshed when the primary owner cookie
is used. `idle_purge_days: 0` keeps owners indefinitely. A positive value
deletes idle owners that have no owned resources, along with their tokens.

## CORS

`web.cors` is a single string value (not a nested object): an allowed
origin, `*` for any origin, or a comma-separated list of origins.

```yaml
web:
  cors: "*"
```

## Analytics Tracking

Configure an analytics provider under `server.tracking`. Supported types are
`google`, `matomo`, `piwik`, `owa`, `fathom`, `plausible`, `umami`, `simple`,
and `cloudflare`; set `type: none` to disable tracking.

```yaml
server:
  tracking:
    type: plausible
    id: "example.com"
    url: ""
```

The `id` and `url` values depend on the provider. Self-hosted Matomo, Piwik,
OWA, and Umami require a URL; Fathom and Plausible accept an optional
self-hosted URL. Other provider requirements are validated at startup. The
generated same-origin `/server/tracking.js` endpoint waits for explicit
analytics consent, respects the CCPA opt-out and Global Privacy Control
signal, and checks the enforced CSP script allowlist. It returns 404 when
tracking is disabled, consent is absent, or the request is served over Tor or
I2P.
Simple Analytics also uses its no-script pixel only when consent is present
and `img-src` permits its host. For a third-party provider, add its script
host to `web.csp.script_src_extra`.
Clearnet tracking scripts and pixels are never loaded over Tor or I2P.

### Contact CAPTCHA and Disclosure Policy

The contact and security report forms share `pages.contact.captcha`. The
built-in `simple` challenge is the default and works without JavaScript. To use
an external provider, configure both keys; a missing key logs one warning and
falls back to `simple` without preventing startup. Provider hosts are added
only for the selected provider, and Tor/I2P requests always use the built-in
challenge. The built-in challenge stores only an answer hash with a
32-character challenge ID, expires after 10 minutes, and is consumed on the
first verification attempt. The report form handles abuse, DMCA, privacy, and
security reports. Each submission first returns a server-rendered review; the
second confirmed submission delivers it. Public form submissions use a 256 KiB
request limit, a hidden honeypot, single-use signed form and review tokens,
same-origin checks for browser posts, markup and link checks, blocked-word and
domain filters, duplicate detection, and in-memory IP, email, and global rate
limits. Repeated honeypot, CAPTCHA, content, origin, replay, or duplicate
rejections temporarily ban the source IP. Tor and I2P submissions skip per-IP
limits and strike bans.

```yaml
pages:
  contact:
    enabled: true
    captcha: simple # simple, recaptcha, or hcaptcha
    captcha_site_key: ""
    captcha_secret_key: ""
    antispam:
      honeypot: true
      min_fill_seconds: 3
      max_age_seconds: 43200
      per_ip: 5
      per_email: 3
      global: 60
      window: 1h
      max_links: 10
      reject_markup: true
      blocked_words: []
      blocked_email_domains: []
      blocked_link_domains: []
      strikes: 3
      ban_hours: 24
      review_min_seconds: 2
      review_max_seconds: 900
      duplicate_window_hours: 24

web:
  security:
    policy: "" # Optional public disclosure policy in Markdown

server:
  contact:
    dpo:
      name: ""
      email: ""
```

The DPO page uses `server.contact.dpo.email`, falling back to the general
contact address only. The page links to the privacy policy and security page;
it publishes an email address only when one is configured. If neither
address is available, it explains that no DPO email is configured.
`web.security.policy` replaces the default disclosure policy text when
non-empty.

### Security Headers

Security headers are automatically added from secure defaults. HSTS, CSP, and
other headers can be adjusted under `web.hsts`, `web.csp`, and `web.headers`.
Permissions-Policy is fixed by the project and always emitted:

- The default Content-Security-Policy uses `script-src 'self'`; inline scripts
  are blocked. Add a provider host to `web.csp.script_src_extra` only when the
  service is intentionally configured. Analytics loads only after analytics
  consent, and clearnet providers are suppressed for onion requests.
- HSTS is emitted for TLS-enabled service endpoints.
- Permissions Policy and the remaining response headers use the defaults in
  `AI.md` PART 11; per-header configuration can extend or override them.

## Server Administration

ipgaze has no admin web UI and no runtime configuration API. Settings are
managed by editing `server.yml` and the appropriate `yaml.d/` drop-in;
credentials are stored in `secrets.yml`. See
[Server Administration](admin.md) for details.

## Logging

Logging is configured under `server.logs`, with a global level plus
per-file settings for `access`, `server`, `error`, `app`, `auth`,
`audit`, `security`, and `debug` logs:

```yaml
server:
  logs:
    # level: debug, info, warn, error
    level: warn
    defaults:
      custom: ""
      rotate: weekly,50MB
      keep: none
    access:
      format: apache
      rotate: monthly
    audit:
      format: json
      rotate: daily
      compress: false
      include_user_agent: true
      events:
        configuration: true
        security: true
        backup: true
        server: true
```

Each log kind inherits `custom`, `rotate`, and `keep` from `defaults`; a kind
can override those values. Filenames are derived from the kind, such as
`access.log` and `audit.log`.

## Backups

The scheduled daily task snapshots the application once, then creates and
verifies a cumulative daily incremental against the newest earlier full backup
before writing the new full backup. The incremental contains changed files
since that base, plus deletion records; it is not a chain of hourly or daily
deltas. Keep its referenced full in the backup directory. Restore from an
incremental verifies the base, overlays changed files, and applies deletions.
Restore size and file-count limits apply to the combined result. The first
scheduled run has no previous full, so it creates only a full backup.

The optional hourly task is disabled by default and creates one replaceable
cumulative incremental based on the newest full. Scheduled backups are verified
before retention cleanup. Manual `--maintenance backup` creates a timestamped
full archive. Configure retention under `server.backup.retention`:

```yaml
server:
  backup:
    retention:
      max_backups: 1
      keep_weekly: 0
      keep_monthly: 0
      keep_yearly: 0
      max_total_size: "10%"
```

Retention protects a full backup referenced by the current daily or hourly
incremental. `max_total_size`, when set above zero, may override count-based
retention. The archive encryption password and compliance requirements are
described in the backup and restore configuration generated in `server.yml`.

## Database

```yaml
server:
  database:
    # driver: sqlite (default; also accepts sqlite2, sqlite3) or libsql (also accepts turso)
    driver: sqlite
    # url and token are only used when driver is libsql/turso
    url: ""
    token: ""
```

For remote libSQL, the optional SQLite replica is disabled by default. Enable it
only when a persistent local cache is useful:

```yaml
server:
  database:
    driver: libsql
    url: "${DATABASE_URL}"
    cache:
      enabled: true
      path: "${DATA_DIR}/db/cache.db"
      sync_interval: 30s
      offline_mode: true
      max_age: 1h
```

The remote database remains authoritative. Successful remote writes refresh the
local replica; a failed refresh bypasses the cache until synchronization
succeeds. With `offline_mode: true`, fresh cached reads continue while writes
are rejected during a remote outage. The cache is a separate SQLite file with
mode `0600` in a directory with mode `0700`; it omits application secrets,
audit records, and per-request rate-limit counters. Tables with `updated_at`
use a watermark and reconcile deletions; other cached tables are reread in
full on each synchronization. Reads older than `max_age` use the remote while
it is reachable.

## Representative Example

```yaml
# server.yml - representative configuration example

server:
  port: "64123"
  fqdn: "ip.example.com"
  address: "[::]"
  mode: production

  healthz:
    root:
      enabled: false

  database:
    driver: sqlite

  schedule:
    enabled: true
    geoip_update: weekly
    timezone: America/New_York

  geoip:
    enabled: true
    deny_countries: []
    allow_countries: []

  rate_limit:
    read:
      requests: 120
      window: 60
    write:
      requests: 10
      window: 60

  logs:
    level: warn
    defaults:
      custom: ""
      rotate: weekly,50MB
      keep: none

  branding:
    title: "IPGaze"
    tagline: "IP intelligence, self-hosted"
    description: ""
    favicon: ""
    logo: ""

  ssl:
    enabled: false
    cert: ""
    key: ""
    min_version: "TLS1.2"
    letsencrypt:
      enabled: false

web:
  ui:
    theme: dark
  cors: "*"
```

### Other top-level settings

These top-level settings are part of the supported configuration surface in
addition to the `server`, `web`, and `pages` settings described above.

| Key | Type | Default | Behavior |
|-----|------|---------|----------|
| `output.color` | boolean, optional | automatic | Selects color output for CLI commands. An explicit CLI flag takes precedence, then this setting, then `NO_COLOR`, then terminal autodetection. |
| `output.emoji` | boolean, optional | automatic | Selects emoji output for CLI commands. When explicitly enabled, emoji output remains enabled even when `NO_COLOR` disables color; `TERM=dumb` always disables emoji. |
| `data.cve.source` | URL string | NVD CVE API 2.0 endpoint | Selects the source for the CVE feed. An empty string uses the compiled-in NVD API endpoint. |
| `data.cve.filter_by_cpe` | boolean | `false` | Enables CPE filtering. The default remains false because dependency-to-CPE mappings are not verified and could hide applicable CVEs. |
| `tor.onion_address` | string, optional | empty | Published onion address for clearnet `Onion-Location`. Publication requires this value and `server.tor.expose: true`. |
| `tor.contact_email` | string (legacy) | empty | Migrated to `server.tor.contact_email` when a legacy file is loaded. |

The complete reference is the settings described throughout this page,
including the nested `server`, `web`, `pages`, `data`, `output`, and legacy
`tor` keys. Generated `server.yml` is a defaults file, not a substitute for
this operator reference.

### TLS and Let's Encrypt

Set `server.ssl.enabled: true` to serve HTTPS when the configured listener
includes an HTTPS port. `server.ssl.cert` and `server.ssl.key` are an optional
manual certificate/key pair; configure both or leave both empty for automatic
certificate discovery. With no explicit pair, ipgaze checks system certbot
paths under `/etc/letsencrypt/live/`, then
`{config_dir}/ssl/letsencrypt/{fqdn}/`, then
`{config_dir}/ssl/local/{fqdn}/`. Certificates must match the configured FQDN
and be unexpired. The `min_version` setting accepts `TLS1.2` (default) or
`TLS1.3`.

Changes to the TLS listener settings (`enabled`, `cert`, `key`, and
`min_version`) require a process restart. Changes under
`server.ssl.letsencrypt.*` are picked up by the ACME client at its next
issuance or renewal and do not require a restart.

To request and renew certificates automatically, set
`server.ssl.letsencrypt.enabled: true` and configure the contact `email`.
Challenges include `http-01` (default), `tls-alpn-01`, and `dns-01`; staging
can be enabled while testing. DNS-01 accepts every provider supported by lego
v5: set `server.ssl.letsencrypt.dns_provider` to its lowercase provider
identifier and put that provider's lego environment variable names and values
in the flat `server.ssl.letsencrypt.dns_credentials` map. The credential map
is encrypted at rest with `server.security.encryption_key` and validated on
startup and before certificate requests. Values are never logged or returned
by the API.

For RFC 2136, use `rfc2136` (or its `dnsupdate` alias) with
`DNSUPDATE_NAMESERVER`; lego v5 also accepts the legacy `RFC2136_*` variable
prefix. TSIG credentials use `DNSUPDATE_TSIG_KEY`,
`DNSUPDATE_TSIG_SECRET`, and optionally `DNSUPDATE_TSIG_ALGORITHM`. A TSIG key
file must be named relative to `{config_dir}/ssl/` with
`DNSUPDATE_TSIG_FILE`; absolute paths and paths outside that directory are
rejected. Without TSIG credentials, the update is unsigned and accepted only
by a DNS server configured to trust the sender. The provider removes only the
TXT record it created after challenge validation. App-managed ACME account
state and certificates are stored under `{config_dir}/ssl/`.
