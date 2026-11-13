# API Reference

IPGaze accepts requests at the configured server URL. The public service is
available at `https://ifcfg.us`. All lookup endpoints are anonymous. A
deployment may apply rate limits and block abusive traffic.

When deployed behind a trusted proxy, caller identity uses the configured
`server.trusted_proxies.client_ip_header` selection and validates forwarded
chains against trusted proxy ranges. Addresses are normalized before lookup,
logging, and per-client enforcement; IPv4-mapped IPv6 addresses share their
IPv4 identity. See [Trusted Proxies](configuration.md#reverse-proxy) for the
automatic header order, pinning, and chain-walk behavior.

## Address Lookup

| Request | Result |
|---------|--------|
| `GET /` | The caller's address and lookup data, negotiated as HTML, JSON, or plain text |
| `GET /json` | The caller's lookup data as JSON |
| `GET /ip` | The caller's IP address as plain text |
| `GET /country` | Country name |
| `GET /country-iso` | ISO country code |
| `GET /city` | City |
| `GET /coordinates` | Latitude and longitude |
| `GET /asn` | Autonomous system number |
| `GET /asn-org` | Autonomous system organization |
| `GET /{ip}` | Lookup the supplied IPv4 or IPv6 address |
| `GET /port/{port}` | Check TCP reachability for a port |

GeoIP field routes require the corresponding database to be enabled and
available. A `.txt` suffix forces plain text for supported field and API
routes. The root route chooses a response based on the request's `Accept`
header and User-Agent.

```bash
# Caller IP as text
curl -q -LSsf https://ifcfg.us/ip

# Caller information as JSON
curl -q -LSsf https://ifcfg.us/json

# Force JSON at the root
curl -q -LSsf -H 'Accept: application/json' https://ifcfg.us/

# Lookup an address
curl -q -LSsf https://ifcfg.us/8.8.8.8
```

## Versioned API

The current API version is `v1`. API routes return JSON by default; appending
`.txt` requests plain text where that operation supports it.

Successful JSON responses use the `{ "ok": true, "data": ... }` envelope.
Errors use `{ "ok": false, "error": "CODE", "message": "..." }`.
Health endpoints are the exception and return the bare health document.

| Request | Description |
|---------|-------------|
| `GET /api/v1` | Caller lookup information |
| `GET /api/v1/json` | Caller lookup information (JSON alias) |
| `GET /api/v1/ip` | Caller IP |
| `GET /api/v1/ip/{ip}` | Lookup a specific IP address |
| `GET /api/v1/country` | Caller country name |
| `GET /api/v1/country-iso` | Caller ISO country code |
| `GET /api/v1/city` | Caller city |
| `GET /api/v1/coordinates` | Caller latitude and longitude |
| `GET /api/v1/asn` | Caller autonomous system number |
| `GET /api/v1/asn-org` | Caller autonomous system organization |
| `GET /api/v1/port/{port}` | Check TCP reachability for a port |
| `GET /api/v1/server/healthz` | Server health |
| `GET /api/v1/version` | Version, commit, and build date |
| `GET /api/v1/server/about` | Application information |
| `GET /api/v1/server/help` | Help sections |
| `GET /server/help/mcp` | MCP setup guide when MCP is enabled |
| `GET /api/v1/server/help/mcp` | MCP setup data in the standard JSON envelope |
| `GET /api/v1/server/privacy` | Current privacy and tracking configuration |
| `GET /server/dpo` | Public Data Protection Officer contact page |
| `GET /api/v1/server/dpo` | DPO contact JSON (`name`, `email`, `privacy_url`) |
| `GET /server/tracking.js` | Consent-gated tracking script generated from live configuration; returns 404 without analytics consent or over Tor/I2P |
| `GET /api/v1/server/terms` | Terms sections |
| `GET /api/v1/server/security` | Security contact information |
| `GET /server/security/policy` | Coordinated disclosure policy |
| `GET /api/v1/server/security/policy` | Disclosure policy in the standard JSON envelope |
| `GET /server/security/thanks` | Public researcher acknowledgments |
| `GET /api/v1/server/security/thanks` | Acknowledgments in the standard JSON envelope |
| `GET /server/security/report/{tracking_id}` | Researcher status page; requires the one-shot token when an acknowledgment email was delivered |
| `GET /api/v1/server/preferences` | Current guest preferences |
| `POST /api/v1/server/preferences` | Update guest preferences |
| `GET /api/v1/server/preferences/export` | Export guest preferences |
| `GET /api/v1/server/preferences/import` | Import guest preferences |
| `POST /api/v1/server/contact` | Submit the contact form |
| `POST /api/v1/server/consent` | Save cookie consent choices |
| `POST /api/v1/server/ccpa` | Record a CCPA data-sale opt-out |
| `POST /api/v1/announcements/dismiss` | Dismiss a site announcement |
| `POST /api/v1/server/reports/csp` | Submit a Content Security Policy browser report |
| `POST /api/v1/server/reports/nel` | Submit a Network Error Logging browser report |
| `POST /api/v1/server/reports/deprecation` | Submit a browser deprecation report |
| `POST /api/v1/server/reports/intervention` | Submit a browser intervention report |
| `POST /api/v1/server/reports/crash` | Submit a browser crash report |
| `POST /api/v1/server/reports/error` | Submit a browser error report |
| `POST /api/v1/server/reports/default` | Submit a generic browser report |
| `GET /api/v1/server/swagger` | OpenAPI document |
| `GET` or `POST /api/v1/server/graphql` | GraphQL endpoint when enabled |
| `POST /api/v1/server/mcp` | MCP Streamable HTTP endpoint when enabled |

When an active PGP report-encryption key is configured, the security status
response includes its full SHA-256 fingerprint and the public-key URL.
Security report submission persists the encrypted report and returns its
tracking ID even when SMTP is unavailable or delivery fails. In that case the
researcher acknowledgment is skipped; use the returned tracking ID for follow-up.

GeoIP field endpoints are registered when their database is available; port
reachability is always enabled. Some protocol endpoints depend on their
feature configuration. See the live
[OpenAPI document](https://ifcfg.us/api/swagger) for the deployed route
inventory and request schemas.

## Health Checks

- `GET /server/healthz` is the canonical public route. Browsers receive the
  health page; recognized non-interactive HTTP clients without an explicit
  `Accept` header and `Accept: text/plain` receive localized, human-readable
  text; `Accept: application/json` returns the bare health JSON.
- `GET /api/v1/server/healthz` returns bare JSON by default. It returns
  machine-readable dot-notation text for `.txt`, `Accept: text/plain`, or a
  non-interactive client without an explicit `Accept` header. Explicit
  `Accept: application/json` overrides User-Agent detection.
- `GET /api/healthz` is a direct, versionless alias using the same API
  negotiation rules.
- `GET /healthz` is available only when `server.healthz.root.enabled` is true;
  it directly uses the canonical frontend handler and never redirects.

Every health route reports the status code from the health state: healthy,
degraded, and restart-required return `200`; unhealthy, maintenance, and
shutting-down return `503`. The public response reports version/build/runtime
information, enabled features, subsystem checks, and aggregate statistics. It
includes cached per-database GeoIP and per-list blocklist checks when enabled.
Those checks expose only `ok`, `degraded`, or `error` and refresh at least
every 60 seconds and after a data update. The response does not expose private
configuration, credentials, internal addresses, or filesystem paths.

## API Documentation and Discovery

| Request | Description |
|---------|-------------|
| `GET /server/docs/swagger` | Interactive Swagger UI |
| `GET /api/swagger` | OpenAPI JSON, direct alias for the current API version |
| `GET` or `POST /server/docs/graphql` | GraphiQL UI when GraphQL is enabled |
| `GET` or `POST /api/graphql` | GraphQL direct alias when enabled |
| `GET /api/autodiscover` | Server and client configuration discovery |
| `GET /llms.txt` | Machine-readable service and API summary |
| `GET /.well-known/llms.txt` | Well-known alias for the same summary |

## Errors and Limits

Invalid IP addresses return a client error. Rate-limited requests return
`429 Too Many Requests`; retry behavior may include a `Retry-After` header.
Detailed error response fields and schemas are defined by the live OpenAPI
document.
