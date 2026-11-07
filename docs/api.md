# API Reference

IPGaze accepts requests at the configured server URL. The public service is
available at `https://ifcfg.us`. All lookup endpoints are anonymous. A
deployment may apply rate limits and block abusive traffic.

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
| `GET /port/{port}` | Check TCP reachability for a port when port lookup is enabled |

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
| `GET /api/v1/ip` | Caller IP |
| `GET /api/v1/ip/{ip}` | Lookup a specific IP address |
| `GET /api/v1/server/healthz` | Server health |
| `GET /api/v1/version` | Version, commit, and build date |
| `GET /api/v1/server/about` | Application information |
| `GET /api/v1/server/help` | Help sections |
| `GET /server/help/mcp` | MCP setup guide when MCP is enabled |
| `GET /api/v1/server/help/mcp` | MCP setup data in the standard JSON envelope |
| `GET /api/v1/server/privacy` | Current privacy and tracking configuration |
| `GET /api/v1/server/terms` | Terms sections |
| `GET /api/v1/server/security` | Security contact information |
| `GET /server/security/policy` | Coordinated disclosure policy |
| `GET /api/v1/server/security/policy` | Disclosure policy in the standard JSON envelope |
| `GET /server/security/thanks` | Public researcher acknowledgments |
| `GET /api/v1/server/security/thanks` | Acknowledgments in the standard JSON envelope |
| `GET /server/security/report/{tracking_id}` | Researcher status page; requires the one-shot token from the acknowledgment email |
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

The GeoIP lookup endpoints, port check, and some protocol endpoints are
registered only when their backing feature is available. See the live
[OpenAPI document](https://ifcfg.us/api/swagger) for the deployed route
inventory and request schemas.

## Health Checks

- `GET /server/healthz` serves the health page using normal content negotiation.
- `GET /api/v1/server/healthz` returns the API health response.
- `GET /api/healthz` is the direct versionless JSON health alias.
- `GET /healthz` is available only when `server.healthz.root.enabled` is true.

The health response reports status, version/build/runtime information, enabled
features, subsystem checks, and public-safe statistics. It does not expose
private configuration or credentials.

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
