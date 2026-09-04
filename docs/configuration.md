# Configuration

Complete configuration reference for **ipgaze**.

## Configuration File

ipgaze uses `server.yml` for configuration. The file is auto-created with
sane defaults on first run. `server.yml` is the sole source of truth for
operator configuration — the database only stores resource state, tokens,
and the audit log, never operator settings.

### Default Location

| User Type | Path |
|-----------|------|
| Root | `/etc/apimgr/ipgaze/server.yml` |
| Regular user | `~/.config/apimgr/ipgaze/server.yml` (XDG `$XDG_CONFIG_HOME` honored) |
| Docker container | `/config/ipgaze/server.yml` |

The `--config` flag or the `CONFIG_DIR` environment variable (first run only)
can override the configuration directory.

### Migration

If a legacy `server.yaml` is found next to the expected `server.yml` path,
it is automatically renamed to `server.yml` on startup.

### Example Configuration

All configuration keys are nested under `server:` and `web:`.

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

  logging:
    level: warn

  geoip:
    enabled: true

  rate_limit:
    enabled: true

  database:
    driver: sqlite

web:
  ui:
    theme: dark
  cors: "*"
```

## Configuration Precedence

For values that can come from a CLI flag, an environment variable, and
`server.yml`, the precedence (highest wins) is:

1. CLI flag (e.g. `--port`, `--address`)
2. Project-prefixed environment variable (e.g. `IPGAZE_PORT`, `IPGAZE_LISTEN`)
3. Generic environment variable (e.g. `PORT`, `LISTEN`, `ADDRESS`)
4. `server.yml`
5. Built-in default

Once a value is resolved (e.g. the port on first run), it is written back
into `server.yml` and persists across restarts — later runs read it from
the file unless a flag or env var overrides it again.

## Environment Variables

### Runtime Variables (always checked)

These are re-read on every start and take priority over `server.yml`:

| Variable | Description |
|----------|-------------|
| `DOMAIN` | FQDN override (highest priority for hostname resolution) |
| `MODE` | `production` (default) or `development`; `prod`/`dev`/`devel` accepted; `debug` implies development + debug unless `DEBUG` is explicitly set |
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
| `CACHE_DIR` | Cache directory |
| `PID_FILE` | PID file path |
| `DATABASE_DIR` | SQLite database directory (changeable) |
| `BACKUP_DIR` | Backup directory (changeable) |
| `PORT` | Server port (generic alias; `IPGAZE_PORT` takes priority) |
| `LISTEN` | Listen address (generic alias; `IPGAZE_LISTEN` takes priority) |
| `APPLICATION_NAME` | Application title |
| `APPLICATION_TAGLINE` | Application description |

### Port and Address Aliases

The `--port`/`--address` CLI flags and their env-var aliases resolve in
this order:

- Port: `--port` flag → `IPGAZE_PORT` → `PORT` → `server.port` in config → random `64xxx` default
- Address: `--address` flag → `IPGAZE_LISTEN` → `LISTEN` → `IPGAZE_ADDRESS` → `ADDRESS` → `server.address` in config → default `[::]`

### Docker Environment

```yaml
environment:
  - PORT=80
  - ADDRESS=::
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
    # dir defaults to {data_dir}/security/geoip when empty
    dir: ""
    deny_countries: []
    allow_countries: []
    databases:
      asn: true
      country: true
      city: true
      whois: true
```

`deny_countries` and `allow_countries` are mutually exclusive —
`allow_countries` takes precedence when both are set.

### Automatic Download

GeoIP databases auto-download on first run from
[sapics/ip-location-db](https://github.com/sapics/ip-location-db) and are
refreshed on the schedule set by `server.schedule.geoip_update`
(default: `weekly`).

## Reverse Proxy

When behind a reverse proxy, the built-in proxy-header detection trusts
standard forwarding headers automatically (`X-Real-IP`,
`X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Port`,
`X-Forwarded-Prefix`). Additional trusted proxy CIDRs (beyond the
private ranges, which are always trusted) can be added under
`server.trusted_proxies`:

```yaml
server:
  trusted_proxies:
    additional:
      - "203.0.113.0/24"
```

### nginx

```nginx
location / {
    proxy_pass http://127.0.0.1:64123;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

### Caddy

```
example.com {
    reverse_proxy localhost:64123
}
```

### Traefik

```yaml
labels:
  - "traefik.enable=true"
  - "traefik.http.routers.ipgaze.rule=Host(`example.com`)"
  - "traefik.http.services.ipgaze.loadbalancer.server.port=64123"
```

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

Rate limiting is bucketed by request class under `server.rate_limit`:

```yaml
server:
  rate_limit:
    enabled: true
    # Read: GET/HEAD requests
    read:
      requests: 120
      window: 60
    # Write: POST/PUT/PATCH/DELETE requests
    write:
      requests: 10
      window: 60
    # Health: /healthz, /readyz, /livez
    health:
      requests: 120
      window: 60
    # GlobalBurst: absolute per-IP ceiling across all classes (req/min)
    global_burst: 240
```

## CORS

`web.cors` is a single string value (not a nested object): an allowed
origin, `*` for any origin, or a comma-separated list of origins.

```yaml
web:
  cors: "*"
```

### Security Headers

Security headers are automatically added:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: SAMEORIGIN`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'`
- `Permissions-Policy: geolocation=(), microphone=(), camera=()`

## Server Administration

ipgaze has no admin web UI and no runtime configuration API. All settings
are managed by editing `server.yml`. See
[Server Administration](admin.md) for details.

## Logging

Logging is configured under `server.logging`, with a global level plus
per-file settings for `access`, `server`, `error`, `app`, `auth`,
`audit`, `security`, and `debug` logs:

```yaml
server:
  logging:
    # level: debug, info, warn, error
    level: warn
    access:
      enabled: true
      filename: access.log
      format: apache
      rotate: monthly
      keep: none
    audit:
      enabled: true
      filename: audit.log
      format: json
      rotate: daily
      keep: none
      compress: false
      include_user_agent: true
      events:
        configuration: true
        security: true
        backup: true
        server: true
```

Each per-file block supports `rotate` (`daily`, `weekly`, `monthly`, or a
size like `100MB`, combinable) and `keep` (`none`, `N`, `Nd`, `Nw`, `Nm`,
`forever`) retention settings.

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

## Complete Example

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
    enabled: true
    read:
      requests: 120
      window: 60
    write:
      requests: 10
      window: 60

  logging:
    level: warn

  branding:
    title: "IPGaze"
    tagline: "IP intelligence, self-hosted"

  ssl:
    enabled: false
    letsencrypt:
      enabled: false

web:
  ui:
    theme: dark
  cors: "*"
```

See `server.yml` itself for the full, always-current set of keys — it is
regenerated with every default field present on first run.
