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
| `GET /openapi` | Interactive Swagger UI (HTML) |
| `GET /openapi.json` | OpenAPI 3 schema (JSON) |

Use `/openapi.json` to generate client SDKs with `openapi-generator`, `oapi-codegen`, or any OpenAPI-compatible toolchain.

---

## GraphQL

ipgaze exposes a GraphQL endpoint for flexible IP lookup queries:

| Endpoint | Methods |
|----------|---------|
| `/graphql` | `GET` (query via `?query=`), `POST` (JSON body) |

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

## Prometheus Metrics

When enabled in configuration, ipgaze exposes a Prometheus-compatible metrics endpoint:

| Endpoint | Purpose |
|----------|---------|
| `GET /metrics` | Prometheus text exposition format |

**Enable in `server.yml`:**
```yaml
server:
  metrics:
    enabled: true
    endpoint: /metrics
```

**Available metrics:**

| Metric | Type | Description |
|--------|------|-------------|
| `ipgaze_requests_total` | Counter | Total HTTP requests by method and route |
| `ipgaze_request_duration_seconds` | Histogram | Request latency by route |
| `ipgaze_geoip_cache_hits_total` | Counter | GeoIP cache hits |
| `ipgaze_geoip_cache_misses_total` | Counter | GeoIP cache misses |
| `process_goroutines` | Gauge | Active goroutines |
| `process_resident_memory_bytes` | Gauge | Resident memory usage |

Scrape interval recommendation: `15s` or `30s`.

---

## Tor Hidden Service

ipgaze automatically enables a Tor hidden service when the `tor` binary is available (included in the Docker image). The `.onion` address is written to `/data/ipgaze/tor/hostname` on startup.

No explicit configuration is required — the binary fully manages the Tor lifecycle.

To disable Tor in the AIO container: set `TOR_ENABLED=false` in the environment.

---

## PWA (Progressive Web App)

ipgaze ships PWA assets for installation as a home-screen app on mobile and desktop:

| Endpoint | Purpose |
|----------|---------|
| `GET /manifest.json` | Web App Manifest (name, icons, theme color) |
| `GET /sw.js` | Service worker (offline support) |

These endpoints are served unconditionally with no authentication.

---

## Native App Association

No native app association files (`apple-app-site-association`, `assetlinks.json`) are currently published. ipgaze is a web-only service with no companion native applications.

---

## Autodiscovery

No autodiscovery or federation protocols (e.g. WebFinger, ActivityPub, OAuth provider metadata) are currently implemented.
