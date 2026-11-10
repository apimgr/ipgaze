# Integrations

ipgaze exposes several standard protocol surfaces that allow integration with external tools, clients, and platforms.

---

## echoip-Compatible API

ipgaze implements the same routes and response formats used by echoip-compatible services (such as `ifconfig.co` and `ifconfig.me`). Any tool or script already targeting those endpoints can point to an ipgaze instance with no client changes.

**Compatible routes:**

| Route | Response |
|-------|----------|
| `GET /` | Content negotiation: JSON / plain text / HTML |
| `GET /json` | Full JSON response |
| `GET /ip` | Plain text IP address |
| `GET /{ip}` | Lookup specific IP |
| `GET /country` | Country name |
| `GET /country-iso` | ISO 3166-1 alpha-2 code |
| `GET /city` | City name |
| `GET /coordinates` | `latitude,longitude` |
| `GET /asn` | ASN number |
| `GET /asn-org` | ASN organization name |

**CLI user-agent detection:** `curl`, `wget`, `HTTPie`, `xh`, `Go-http-client`, `Mikrotik`, `ddclient` — all receive plain text automatically.

---

## OpenAPI / Swagger

ipgaze publishes a machine-readable OpenAPI 3 schema and an interactive Swagger UI:

| Endpoint | Format |
|----------|--------|
| `GET /server/docs/swagger` | Interactive Swagger UI (HTML) |
| `GET /api/swagger` | OpenAPI 3 schema (JSON) |

Use `/api/swagger` to generate client SDKs with `openapi-generator`,
`oapi-codegen`, or any OpenAPI-compatible toolchain.

---

## GraphQL

ipgaze exposes a GraphQL endpoint for flexible IP lookup queries:

| Endpoint | Methods |
|----------|---------|
| `/server/docs/graphql` | Interactive GraphiQL UI |
| `/api/graphql` | GraphQL query endpoint (`GET` or `POST`) |

Example query:

```graphql
{
  lookup(ip: "1.1.1.1") {
    ip
    country
    country_iso
    city
    asn
    asn_org
    latitude
    longitude
  }
}
```

---

## Model Context Protocol (MCP)

When `server.mcp.enabled` is true, IPGaze exposes its registered public API
operations as tools over stateless Streamable HTTP:

| Endpoint | Purpose |
|----------|---------|
| `POST /api/v1/server/mcp` | Canonical MCP endpoint |
| `POST /api/mcp`, `POST /mcp` | Direct aliases |
| `GET /server/help/mcp` | Client setup guide, available tools, and troubleshooting |
| `GET /api/v1/server/help/mcp` | MCP help data as JSON |

IPGaze exposes public lookup operations, so MCP clients can connect without a
token. There is no MCP-specific token. The guide at `/server/help/mcp` shows
the resolved endpoint URL, available tools, and a client initialization
example.

---

## Prometheus Metrics

When enabled in configuration, ipgaze exposes internal metrics endpoints
under `/server/metrics` and `/api/v1/server/metrics`, with `/metrics` and
`/api/metrics` aliases. Every service endpoint requires its own bearer token
by default; keep these routes on a trusted monitoring network.

| Endpoint | Purpose |
|----------|---------|
| `GET /server/metrics/prometheus` | Prometheus text exposition format |
| `GET /server/metrics/grafana` | Importable Grafana dashboard JSON |
| `GET /server/metrics/loki` | Recent logs in Loki stream JSON format |

**Enable in `server.yml`:**
```yaml
server:
  metrics:
    enabled: true
    auth:
      tokens:
        prometheus: "replace-with-a-long-random-token"
        grafana: "replace-with-a-long-random-token"
        loki: "replace-with-a-long-random-token"
```

Send the matching token in `Authorization: Bearer <token>`. An empty token
disables that service endpoint. `server.metrics.auth.allow_unauthenticated`
can disable token checks for a firewalled internal network, but must not be
enabled on a publicly reachable server. See the
[metrics configuration](configuration.md) and AI.md PART 20 for the full
access-control requirements.

**Available metrics:**

| Metric | Type | Description |
|--------|------|-------------|
| `ipgaze_app_info` | Gauge | Application version and build information |
| `ipgaze_app_uptime_seconds` | Gauge | Application uptime |
| `ipgaze_http_requests_total` | Counter | HTTP requests by method, normalized route, and status |
| `ipgaze_http_request_duration_seconds` | Histogram | HTTP request latency by method and normalized route |
| `ipgaze_http_request_size_bytes` | Histogram | HTTP request size by method and normalized route |
| `ipgaze_http_response_size_bytes` | Histogram | HTTP response size by method and normalized route |
| `ipgaze_http_active_requests` | Gauge | Requests currently being processed |
| `ipgaze_db_queries_total` | Counter | Database queries by operation and known table |
| `ipgaze_db_query_duration_seconds` | Histogram | Database query latency by operation and known table |
| `ipgaze_db_connections_open` | Gauge | Open database connections |
| `ipgaze_db_connections_in_use` | Gauge | Database connections currently in use |
| `ipgaze_db_errors_total` | Counter | Database errors by operation and error category |
| `ipgaze_auth_attempts_total` | Counter | Authentication attempts by mechanism and outcome |
| `ipgaze_ratelimit_requests_total` | Counter | Rate-limiter requests by limit type and outcome |
| `ipgaze_ratelimit_blocked_total` | Counter | Requests blocked by the rate limiter |

Cache, scheduler, Tor, Go runtime, and host system metrics are also available
when their related features are enabled. Host CPU, memory, and data-directory
disk metrics require `server.metrics.include_system: true`; Go runtime metrics
require `server.metrics.include_runtime: true`. The system metrics use the
`ipgaze_system_*` prefix and runtime metrics use `ipgaze_go_*`.

`ipgaze_auth_sessions_active` is listed in AI.md PART 20, but that PART also
states that this project has no user sessions. Its meaning is unresolved in
the source specification, so consumers should not use this gauge until the
template contract is clarified.

Scrape interval recommendation: `15s` or `30s`.

---

## Tor Hidden Service

ipgaze automatically enables a Tor hidden service when the `tor` binary is available (included in the Docker image). In the standard Docker layout, the `.onion` address is written to `/data/ipgaze/tor/site/hostname` on startup.

No explicit configuration is required — the binary fully manages the Tor lifecycle.

Tor starts when its binary is available. The project does not expose an
enable/disable toggle; installing Tor changes this behavior.

Optional outbound Tor routing is controlled by `server.tor.use_network` and
defaults to `false`. When enabled, the managed Tor process opens a loopback-only
SOCKS listener for app-selected outbound HTTP requests. Requests arriving over
the hidden service cannot choose or influence outbound destinations. If Tor
is unavailable, routed requests fail instead of using the clearnet directly.
App-selected update, threat-data, GeoIP, notification, keyserver, and ACME
requests use this route; caller-supplied remote URLs remain outside it.

---

## I2P Eepsite

I2P eepsite hosting is optional and disabled by default. Enable it explicitly
in `server.yml`:

```yaml
server:
  i2p:
    enabled: true
```

When enabled, IPGaze manages a dedicated `i2pd` process when the binary is
available, or connects to an existing SAMv3 bridge at `127.0.0.1:7656`.
The resulting `.b32.i2p` address is shown in the server information page when
the destination is ready. I2P is used for inbound eepsite hosting only.
Requests on the I2P listener share a dedicated global rate-limit bucket. The
server treats the loopback connection as one I2P client and never applies
per-IP blocks to `127.0.0.1` for those requests.
All server-side I2P options and defaults are listed in
[Configuration: I2P](configuration.md#i2p).

---

## PWA (Progressive Web App)

ipgaze ships PWA assets for installation as a home-screen app on mobile and desktop:

| Endpoint | Purpose |
|----------|---------|
| `GET /manifest.json` | Web App Manifest (name, icons, theme color) |
| `GET /sw.js` | Service worker (offline support) |

These endpoints are public and do not require authentication. The service
worker and manifest are served with revalidation headers so browsers can
detect deployed asset updates.

---

## Native App Association

No native app association files (`apple-app-site-association`, `assetlinks.json`) are currently published. ipgaze is a web-only service with no companion native applications.

---

## Autodiscovery

No autodiscovery or federation protocols (e.g. WebFinger, ActivityPub, OAuth provider metadata) are currently implemented.
