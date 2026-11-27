# API Reference

IPGaze accepts requests at the configured server URL. The public service is
available at `https://ifcfg.us`. All lookup endpoints are anonymous. A
deployment may apply rate limits and block abusive traffic.

The REST API is public. MCP uses the same API but requires an `Authorization:
Bearer` token. Visitors can issue an owner token from the tokens page or
`POST https://ifcfg.us/api/v1/server/preferences/tokens/primary`; use a linked token for each
MCP client. Every MCP request must carry a valid owner, linked, or operator
Bearer token; cookies are not accepted by MCP. The public lookup API does not
require authentication.

When deployed behind a trusted proxy, caller identity uses the configured
`server.trusted_proxies.client_ip_header` selection and validates forwarded
chains against trusted proxy ranges. Addresses are normalized before lookup,
logging, and per-client enforcement; IPv4-mapped IPv6 addresses share their
IPv4 identity. See [Trusted Proxies](configuration.md#reverse-proxy) for the
automatic header order, pinning, and chain-walk behavior.

## Address Lookup

| Request | Result |
|---------|--------|
| `GET https://ifcfg.us/` | The caller's address and lookup data, negotiated as HTML, JSON, or plain text |
| `GET https://ifcfg.us/json` | The caller's lookup data as JSON |
| `GET https://ifcfg.us/ip` | The caller's IP address as plain text |
| `GET https://ifcfg.us/country` | Country name |
| `GET https://ifcfg.us/country-iso` | ISO country code |
| `GET https://ifcfg.us/city` | City |
| `GET https://ifcfg.us/coordinates` | Latitude and longitude |
| `GET https://ifcfg.us/asn` | Autonomous system number |
| `GET https://ifcfg.us/asn-org` | Autonomous system organization |
| `GET https://ifcfg.us/{ip}` | Lookup the supplied IPv4 or IPv6 address |
| `GET https://ifcfg.us/port/{port}` | Check TCP reachability for a port |

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
| `GET https://ifcfg.us/api/v1` | Caller lookup information |
| `GET https://ifcfg.us/api/v1/json` | Caller lookup information (JSON alias) |
| `GET https://ifcfg.us/api/v1/ip` | Caller IP |
| `GET https://ifcfg.us/api/v1/ip/{ip}` | Lookup a specific IP address |
| `GET https://ifcfg.us/api/v1/country` | Caller country name |
| `GET https://ifcfg.us/api/v1/country-iso` | Caller ISO country code |
| `GET https://ifcfg.us/api/v1/city` | Caller city |
| `GET https://ifcfg.us/api/v1/coordinates` | Caller latitude and longitude |
| `GET https://ifcfg.us/api/v1/asn` | Caller autonomous system number |
| `GET https://ifcfg.us/api/v1/asn-org` | Caller autonomous system organization |
| `GET https://ifcfg.us/api/v1/port/{port}` | Check TCP reachability for a port |
| `GET https://ifcfg.us/api/v1/server/healthz` | Server health |
| `GET https://ifcfg.us/api/v1/version` | Version, commit, and build date |
| `GET https://ifcfg.us/api/v1/server/about` | Application information |
| `GET https://ifcfg.us/api/v1/server/help` | Help sections |
| `GET https://ifcfg.us/server/help/mcp` | MCP setup guide |
| `GET https://ifcfg.us/api/v1/server/help/mcp` | MCP setup data in the standard JSON envelope |
| `GET https://ifcfg.us/api/v1/server/privacy` | Current privacy and tracking configuration |
| `GET https://ifcfg.us/server/dpo` | Public Data Protection Officer contact page |
| `GET https://ifcfg.us/api/v1/server/dpo` | DPO contact JSON (`name`, `email`, `privacy_url`) |
| `GET https://ifcfg.us/server/tracking.js` | Consent-gated tracking script generated from live configuration; returns 404 without analytics consent or over Tor/I2P |
| `GET https://ifcfg.us/api/v1/server/terms` | Terms sections |
| `GET https://ifcfg.us/api/v1/server/security` | Security contact information |
| `GET https://ifcfg.us/server/security/policy` | Coordinated disclosure policy |
| `GET https://ifcfg.us/api/v1/server/security/policy` | Disclosure policy in the standard JSON envelope |
| `GET https://ifcfg.us/server/security/thanks` | Public researcher acknowledgments |
| `GET https://ifcfg.us/api/v1/server/security/thanks` | Acknowledgments in the standard JSON envelope |
| `GET https://ifcfg.us/api/v1/server/contact` | Public report-form definition, CAPTCHA challenge, security URL, and abuse contact |
| `GET https://ifcfg.us/api/v1/server/auth/check` | Validate an operator Bearer token; returns `data.kind = "operator"` or 401 |
| `GET https://ifcfg.us/server/security/report/{tracking_id}` | Researcher status page; requires the one-shot token when an acknowledgment email was delivered |
| `GET https://ifcfg.us/api/v1/server/preferences` | Current guest preferences |
| `GET https://ifcfg.us/server/preferences/tokens` | Public owner-token management page; lists tokens only with a valid owner cookie |
| `POST https://ifcfg.us/server/preferences/token/create` | Issue an owner token without creating a resource; sets the owner cookie |
| `POST https://ifcfg.us/server/preferences/token/restore` | Restore a primary owner token into this browser |
| `POST https://ifcfg.us/server/preferences/token/reveal` | Reveal the primary token; requires the owner cookie and CSRF token |
| `POST https://ifcfg.us/server/preferences/token/rotate` | Rotate the primary token; requires the owner cookie and CSRF token |
| `POST https://ifcfg.us/server/preferences/token/revoke` | Revoke the primary token and delete its owner, linked tokens, and owned resources; requires typing the primary token's last four characters and a CSRF token |
| `POST https://ifcfg.us/server/preferences/token/forget` | Clear this browser's saved owner token without revoking it |
| `POST https://ifcfg.us/server/preferences/tokens` | Create a linked token; requires the primary owner cookie and CSRF token |
| `POST https://ifcfg.us/server/preferences/tokens/{id}/reveal` | Reveal one linked token; requires the primary owner cookie and CSRF token |
| `POST https://ifcfg.us/server/preferences/tokens/{id}/rotate` | Rotate one linked token; requires the primary owner cookie and CSRF token |
| `POST https://ifcfg.us/server/preferences/tokens/{id}/update` | Rename a linked token or change its expiry; requires the primary owner cookie and CSRF token |
| `POST https://ifcfg.us/server/preferences/tokens/{id}/revoke` | Revoke a linked token; requires the primary owner cookie and CSRF token |
| `GET https://ifcfg.us/api/v1/server/preferences/tokens` | List masked owner and linked token metadata; requires the primary Bearer token |
| `POST https://ifcfg.us/api/v1/server/preferences/tokens/primary` | Issue a primary owner token without other credentials |
| `POST https://ifcfg.us/api/v1/server/preferences/tokens/primary/reveal` | Reveal the primary token; requires the primary Bearer token |
| `POST https://ifcfg.us/api/v1/server/preferences/tokens/primary/rotate` | Rotate the primary token; requires the primary Bearer token |
| `DELETE https://ifcfg.us/api/v1/server/preferences/tokens/primary` | Revoke the primary token and delete its owner; requires the primary Bearer token and `{"confirm":"<last4>"}` |
| `POST https://ifcfg.us/api/v1/server/preferences/tokens` | Create a linked token; requires the primary Bearer token |
| `POST https://ifcfg.us/api/v1/server/preferences/tokens/{id}/reveal` | Reveal a linked token; requires the primary Bearer token |
| `POST https://ifcfg.us/api/v1/server/preferences/tokens/{id}/rotate` | Rotate a linked token; requires the primary Bearer token |
| `PATCH https://ifcfg.us/api/v1/server/preferences/tokens/{id}` | Rename or change linked-token expiry; requires the primary Bearer token |
| `DELETE https://ifcfg.us/api/v1/server/preferences/tokens/{id}` | Revoke a linked token; requires the primary Bearer token |
| `POST https://ifcfg.us/api/v1/server/preferences` | Update guest preferences |
| `GET https://ifcfg.us/server/preferences/sync` | Export guest preferences as a URL and base64url code; negotiates HTML, text, and JSON. Consent and credentials are excluded |
| `POST https://ifcfg.us/server/preferences/sync` | Import guest preferences from the form's `code` field |
| `GET https://ifcfg.us/server/preferences/sync/import` | Apply guest preferences from direct query parameters or a code |
| `GET https://ifcfg.us/api/v1/server/preferences/sync` | Export guest preferences, including the full URL and code |
| `GET https://ifcfg.us/api/v1/server/preferences/sync/import` | Import guest preferences and return applied/ignored fields |
| `POST https://ifcfg.us/api/v1/server/contact` | Submit a report for review, then repeat its fields with the review token and confirmation to deliver it |
| `POST https://ifcfg.us/server/contact` | Submit a report for review and confirm delivery; the browser form is CSRF-protected |
| `POST https://ifcfg.us/announcements/dismiss` | Dismiss a site announcement |
| `POST https://ifcfg.us/api/v1/server/reports/csp` | Submit a Content Security Policy browser report |
| `POST https://ifcfg.us/api/v1/server/reports/nel` | Submit a Network Error Logging browser report |
| `POST https://ifcfg.us/api/v1/server/reports/deprecation` | Submit a browser deprecation report |
| `POST https://ifcfg.us/api/v1/server/reports/intervention` | Submit a browser intervention report |
| `POST https://ifcfg.us/api/v1/server/reports/crash` | Submit a browser crash report |
| `POST https://ifcfg.us/api/v1/server/reports/error` | Submit a browser error report |
| `POST https://ifcfg.us/api/v1/server/reports/default` | Submit a generic browser report |
| `GET https://ifcfg.us/api/v1/server/swagger` | OpenAPI document |
| `GET` or `POST https://ifcfg.us/api/v1/server/graphql` | GraphQL endpoint |
| `POST https://ifcfg.us/api/v1/server/mcp` | MCP Streamable HTTP endpoint |

The `{id}` path value and `id` fields in token responses are opaque UUIDs. The database integer key stays private.

The owner-token list response contains `data.primary`, `data.linked`, and
`data.max_linked`. Token objects use `token_masked` and UTC RFC 3339 timestamps;
raw tokens appear only in issue, create, reveal, or rotate responses. Linked-token
create, reveal, and rotate responses name the raw credential `linked_token`.
Token objects expose `scope`: primary tokens use `global`; linked tokens use
`read` or `read-write`. Linked-token creation accepts an optional `scope` field
(default `read-write`), and the browser token page offers the same choices.
Insufficient scope is rejected with `403` and
`WWW-Authenticate: Bearer error="insufficient_scope"`. Create and update
requests accept `expires` (`never`, `7d`, `30d`, `90d`, or
`1y`) or `expires_on` (`YYYY-MM-DD`), but not both.


Token list responses contain masked values and metadata only. The raw value is
returned only by a token issuance or reveal action; reveal responses disable
caching. Token-management APIs accept the primary owner's Bearer token, while
linked tokens cannot manage other tokens. Token-management routes are not
exposed as MCP tools.

Contact submissions enforce the `max_length` values returned by the form
definition, counting Unicode characters after trimming. Over-limit requests
return `400 VALIDATION_FAILED` with `details.field`, `details.rule`, and
`details.max_length`. A researcher's pasted key has `max_length: 16384`; an
HTTPS key URL has a separate 2048-character validation cap. The metadata keeps
one `max_length` value per field.

When an active PGP report-encryption key is configured, the security status
response includes its 40-character OpenPGP v4 fingerprint and the public-key URL.
Security report submission persists the encrypted report and returns its
tracking ID even when SMTP is unavailable or delivery fails. In that case the
researcher acknowledgment is skipped; use the returned tracking ID for follow-up.

GeoIP field endpoints are registered when their database is available; port
reachability is always enabled. Some protocol endpoints depend on their
feature configuration. See the live
[OpenAPI document](https://ifcfg.us/api/swagger) for the deployed route
inventory and request schemas.

## Health Checks

- `GET https://ifcfg.us/server/healthz` is the canonical public route. Browsers receive the
  health page; recognized non-interactive HTTP clients without an explicit
  `Accept` header and `Accept: text/plain` receive localized, human-readable
  text; `Accept: application/json` returns the bare health JSON.
- `GET https://ifcfg.us/api/v1/server/healthz` returns bare JSON by default. It returns
  machine-readable dot-notation text for `.txt`, `Accept: text/plain`, or a
  non-interactive client without an explicit `Accept` header. Explicit
  `Accept: application/json` overrides User-Agent detection.
- `GET https://ifcfg.us/api/healthz` is a direct, versionless alias using the same API
  negotiation rules.
- `GET https://ifcfg.us/healthz` is available only when `server.healthz.root.enabled` is true;
  it directly uses the canonical frontend handler and never redirects.

Every health route reports the status code from the health state: healthy,
degraded, and restart-required return `200`; unhealthy, maintenance, and
shutting-down return `503`. The public response reports version/build/runtime
information, enabled features, subsystem checks, and aggregate statistics. It
includes cached per-database GeoIP and per-list blocklist checks when enabled.
Those checks expose only `ok`, `degraded`, or `error` and refresh at least
every 60 seconds and after a data update. A blocklist source becomes `degraded`
when its last good copy is older than 72 hours; its last good entries remain
active, and a source that has never loaded reports `error`. The response does
not expose private configuration, credentials, internal addresses, or
filesystem paths.

## API Documentation and Discovery

| Request | Description |
|---------|-------------|
| `GET https://ifcfg.us/server/docs/swagger` | Interactive Swagger UI |
| `GET https://ifcfg.us/api/swagger` | OpenAPI JSON, direct alias for the current API version |
| `GET https://ifcfg.us/server/docs/graphql` | GraphiQL UI |
| `GET` or `POST https://ifcfg.us/api/graphql` | GraphQL direct alias |
| `GET https://ifcfg.us/api/autodiscover` | Unversioned `{ok,data}` discovery document containing `name`, `version`, `api.current_version`, public `urls`, and CLI `cli_versions` / `cli_min_version`; `onion` and `i2p` appear only when their overlay is running and `server.tor.expose` or `server.i2p.expose` is true |
| `GET https://ifcfg.us/llms.txt` | Machine-readable service and API summary |
| `GET https://ifcfg.us/.well-known/llms.txt` | Well-known alias for the same summary |

`llms.txt` includes the API rate limit, public endpoints, the MCP endpoint and
canonical API/security contact addresses. Operators can disable generated
endpoint and schema sections or append up to ten validated Markdown sections
with `web.llms` configuration. Custom HTML is escaped and links are limited to
HTTPS and relative paths.

## Server-Rendered Pages

These public pages render HTML for browsers and use the same frontend content
negotiation as the lookup pages. Forms submit through server routes, so their
core flows work without JavaScript.

| Page | Purpose |
|------|---------|
| `GET https://ifcfg.us/` | Look up the visitor's address and show the lookup interface |
| `GET https://ifcfg.us/server` | Redirect to the server About page |
| `GET https://ifcfg.us/server/about` | Application and service information |
| `GET https://ifcfg.us/server/help` | Usage help |
| `GET https://ifcfg.us/server/help/mcp` | MCP client setup instructions |
| `GET https://ifcfg.us/server/healthz` | Public server health page |
| `GET https://ifcfg.us/server/privacy` | Privacy and tracking information |
| `GET https://ifcfg.us/server/terms` | Terms of service |
| `GET https://ifcfg.us/server/contact` | Contact and typed report forms; submissions use `POST https://ifcfg.us/server/contact` |
| `GET https://ifcfg.us/server/dpo` | Data protection contact information |
| `GET https://ifcfg.us/server/security` | Security overview and reporting links |
| `GET https://ifcfg.us/server/security/policy` | Coordinated disclosure policy |
| `GET https://ifcfg.us/server/security/thanks` | Public researcher acknowledgments |
| `GET https://ifcfg.us/server/security/report/{tracking_id}` | Private researcher report status |
| `GET https://ifcfg.us/server/preferences` | Guest theme, language, consent, and lookup preferences |
| `GET https://ifcfg.us/server/preferences/tokens` | Owner and linked token management; credentials gate actions |
| `GET https://ifcfg.us/server/preferences/sync` | Export or import portable guest preferences |
| `GET https://ifcfg.us/server/docs/swagger` | Interactive REST API documentation |
| `GET https://ifcfg.us/server/docs/graphql` | Interactive GraphQL explorer |

`GET https://ifcfg.us/theme.css` serves the shared, build-versioned theme variables as an
external stylesheet. The Swagger and GraphQL theme stylesheets are served at
`GET https://ifcfg.us/server/docs/swagger/theme.css` and
`GET https://ifcfg.us/server/docs/graphql/theme.css`; both use the selected theme. These are
page assets rather than navigable pages. `/server/tracking.js` is a
consent-gated script endpoint, not a page. The service worker and other static
or machine-readable resources are listed in the relevant API and integration
sections.

## Errors and Limits

Invalid IP addresses return a client error. Rate-limited requests return
`429 Too Many Requests`; retry behavior may include a `Retry-After` header.
Detailed error response fields and schemas are defined by the live OpenAPI
document.
