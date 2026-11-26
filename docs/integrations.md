# Integrations

ipgaze exposes several standard protocol surfaces that allow integration with external tools, clients, and platforms.

---

## echoip-Compatible API

ipgaze implements the same routes and response formats used by echoip-compatible services (such as `ifconfig.co` and `ifconfig.me`). Any tool or script already targeting those endpoints can point to an ipgaze instance with no client changes.

**Compatible routes:**

| Route | Response |
|-------|----------|
| `GET https://ifcfg.us/` | Content negotiation: JSON / plain text / HTML |
| `GET https://ifcfg.us/json` | Full JSON response |
| `GET https://ifcfg.us/ip` | Plain text IP address |
| `GET https://ifcfg.us/{ip}` | Lookup specific IP |
| `GET https://ifcfg.us/country` | Country name |
| `GET https://ifcfg.us/country-iso` | ISO 3166-1 alpha-2 code |
| `GET https://ifcfg.us/city` | City name |
| `GET https://ifcfg.us/coordinates` | `latitude,longitude` |
| `GET https://ifcfg.us/asn` | ASN number |
| `GET https://ifcfg.us/asn-org` | ASN organization name |

**CLI user-agent detection:** `curl`, `wget`, `HTTPie`, `xh`, `Go-http-client`, `Mikrotik`, `ddclient` — all receive plain text automatically.

---

## OpenAPI / Swagger

ipgaze publishes a machine-readable OpenAPI 3 schema and an interactive Swagger UI:

| Endpoint | Format |
|----------|--------|
| `GET https://ifcfg.us/server/docs/swagger` | Interactive Swagger UI (HTML) |
| `GET https://ifcfg.us/api/v1/server/swagger` | Canonical OpenAPI 3 schema (JSON) |
| `GET https://ifcfg.us/api/swagger` | Direct alias for the current version's OpenAPI schema |

Use `/api/v1/server/swagger` to generate client SDKs with
`openapi-generator`, `oapi-codegen`, or any OpenAPI-compatible toolchain.

---

## GraphQL

ipgaze exposes a GraphQL endpoint for flexible IP lookup queries:

| Endpoint | Methods |
|----------|---------|
| `/server/docs/graphql` | Interactive GraphiQL UI |
| `/api/v1/server/graphql` | Canonical GraphQL endpoint (`GET` or `POST`) |
| `/api/graphql` | Direct alias for the current version's GraphQL endpoint |

GraphQL is query-only. Its `authCheck` field validates the caller's operator
Bearer token without returning it; invalid tokens produce a GraphQL error.
The REST contact-form description is available through
`GET https://ifcfg.us/api/v1/server/contact`.

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

IPGaze exposes its registered public API operations as tools over stateless
Streamable HTTP:

| Endpoint | Purpose |
|----------|---------|
| `POST https://ifcfg.us/api/v1/server/mcp` | Canonical MCP endpoint |
| `POST https://ifcfg.us/api/mcp`, `POST https://ifcfg.us/mcp` | Direct aliases |
| `GET https://ifcfg.us/server/help/mcp` | Client setup guide, available tools, and troubleshooting |
| `GET https://ifcfg.us/api/v1/server/help/mcp` | MCP help data as JSON |

MCP requires an owner or operator Bearer token; the REST API's public lookup
operations remain anonymous. Issue an owner token from `/server/preferences/tokens`
or `POST https://ifcfg.us/api/v1/server/preferences/tokens/primary`, then create one linked
token per MCP client. Operator-only API tools are listed only when the request
carries a valid `server.token` bearer credential. Token-management operations
are never exposed as MCP tools. Use a linked token for each client; do not put
the primary owner token or operator token in an MCP client's configuration.
The public [MCP setup guide](https://ifcfg.us/server/help/mcp) describes the
client configuration and verification request.

---

## Prometheus Metrics

When enabled in configuration, ipgaze exposes internal metrics endpoints
under `/server/metrics` and `/api/v1/server/metrics`, with `/metrics` and
`/api/metrics` aliases. Every service endpoint requires its own bearer token
by default; keep these routes on a trusted monitoring network.

| Endpoint | Purpose |
|----------|---------|
| `GET https://ifcfg.us/server/metrics/prometheus` | Prometheus text exposition format |
| `GET https://ifcfg.us/server/metrics/grafana` | Importable Grafana dashboard JSON |
| `GET https://ifcfg.us/server/metrics/loki` | Recent logs in Loki stream JSON format |

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
| `ipgaze_owner_tokens_active` | Gauge | Active owner tokens by token kind (`primary` or `linked`); remains zero until a visitor issues a token |
| `ipgaze_ratelimit_requests_total` | Counter | Rate-limiter requests by limit type and outcome |
| `ipgaze_ratelimit_blocked_total` | Counter | Requests blocked by the rate limiter |

Cache, scheduler, Tor, Go runtime, and host system metrics are also available
when their related features are enabled. Host CPU, memory, and data-directory
disk metrics require `server.metrics.include_system: true`; Go runtime metrics
require `server.metrics.include_runtime: true`. The system metrics use the
`ipgaze_system_*` prefix and runtime metrics use `ipgaze_go_*`.

Scrape interval recommendation: `15s` or `30s`.

---

## Atom and RSS Feeds

The server provides `/feed.xml` (Atom 1.0) and `/rss.xml` (RSS 2.0), including valid empty feeds when there are no public items. IPGaze currently has no public item stream, so these feeds contain no entries. Both routes accept `GET` and `HEAD`, use request-derived absolute URLs, and support conditional caching. They are available by convention and are not advertised in page markup.

The feed title and entry limit can be configured in `server.yml`:

```yaml
server:
  seo:
    feed:
      max_items: 50
      title: ""
```

`max_items` is reserved for projects with a public item stream; IPGaze currently serves empty feeds. The endpoints are always available.

## Tor Hidden Service

ipgaze automatically enables a Tor hidden service when the `tor` binary is available (included in the Docker image). In the standard Docker layout, the `.onion` address is written to `/data/ipgaze/tor/site/hostname` on startup.

No explicit configuration is required — the binary fully manages the Tor lifecycle.

Set `server.tor.contact_email` to publish a contact address in Tor-specific
responses. An empty value omits the address; the server never substitutes its
clearnet contact address.

Tor starts when its binary is available. The project does not expose an
enable/disable toggle; installing Tor changes this behavior.
The address is omitted from `/api/autodiscover` by default. Set
`server.tor.expose: true` to advertise it to clients.

Optional outbound Tor routing is controlled by `server.tor.use_network` and
defaults to `false`. When enabled, the managed Tor process opens a loopback-only
SOCKS listener for app-selected outbound HTTP requests. Requests arriving over
the hidden service cannot choose or influence outbound destinations. If Tor
is unavailable, routed requests fail instead of using the clearnet directly.
App-selected update, threat-data, GeoIP, notification, keyserver, and ACME
requests use this route; caller-supplied remote URLs remain outside it.

---

## I2P Eepsite

I2P eepsite hosting is optional. It starts by default in application
containers such as Docker and Podman. It is disabled by default on bare metal,
in VMs, and in Incus/LXC system containers. Enable or disable it explicitly in
`server.yml`:

```yaml
server:
  i2p:
    enabled: true
    expose: false # Set true to advertise the address in /api/autodiscover
```

When enabled, IPGaze starts overlay setup in the background so it does not
delay the HTTP listener. Health reports `starting`, `healthy`, or
`unavailable`; provider failures do not stop or restart the clearnet server.
IPGaze manages a dedicated `i2pd` process when the binary is
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
| `GET https://ifcfg.us/manifest.json` | Web App Manifest (name, icons, theme color) |
| `GET https://ifcfg.us/sw.js` | Service worker (offline support) |

These endpoints are public and do not require authentication. The service
worker and manifest are served with revalidation headers so browsers can
detect deployed asset updates. New worker versions wait for user approval,
then activate and reload the page once. Navigation requests fall back after
an eight-second network timeout. Only responses explicitly marked public can
be cached for offline navigation; private pages and forms are removed from the
cache. When there is no cached public page, the worker synthesizes a translated
offline response from the strings stored by the last loaded page. There is no
static `/offline.html` route. Redirects and error responses are never stored
in the service worker cache.

---

## Native App Association

No native app association files (`apple-app-site-association`, `assetlinks.json`) are currently published. ipgaze is a web-only service with no companion native applications.

---

## Autodiscovery

`GET https://ifcfg.us/api/autodiscover` returns the service name and version, current API
version, public endpoint URLs, and available CLI versions. Onion and I2P
addresses are included only while the corresponding overlay is running and
its `expose` setting is enabled. See [API Documentation and Discovery](api.md#api-documentation-and-discovery)
for the response details. ipgaze does not implement federation protocols such
as WebFinger or ActivityPub, or OAuth provider metadata.
