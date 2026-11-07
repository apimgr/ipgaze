# Security

## Security Model

ipgaze is designed with security-first principles. This page covers the security model, public and protected endpoints, authentication, and how to report security issues.

---

## Authentication

ipgaze is a public, anonymous IP lookup service. No login is required for public
lookup endpoints. The service does not create user accounts or persistent
lookup-result ownership records. Operator-protected endpoints use scoped
bearer tokens stored as SHA-256 hashes.

Security practices applied throughout:

- **Token storage:** SHA-256 hashed before storage — raw tokens are never persisted
- **Rate limiting:** All endpoints are rate-limited; abuse triggers automatic IP blocking
- **Constant-time comparison:** All token checks use timing-safe comparison to prevent timing attacks

---

## Public Endpoints

The following endpoints are accessible without authentication:

| Endpoint | Purpose |
|----------|---------|
| `GET /` | IP lookup for caller (content negotiation: JSON/text/HTML) |
| `GET /ip` | Caller IP address (plain text) |
| `GET /json` | Full JSON lookup for caller |
| `GET /{ip}` | Lookup a specific IP address |
| `GET /country` | Country name for caller |
| `GET /country-iso` | ISO country code for caller |
| `GET /city` | City for caller |
| `GET /coordinates` | Latitude/longitude for caller |
| `GET /asn` | ASN number for caller |
| `GET /asn-org` | ASN organization for caller |
| `GET /server/healthz` | Health check (content negotiation) |
| `GET /api/v1/server/healthz` | Versioned health check |
| `GET /api/healthz` | Direct JSON health alias |
| `GET /healthz` | Optional health alias when enabled in `server.yml` |
| `GET /server/security` | Security overview and reporting links |
| `GET /server/security/policy` | Coordinated disclosure policy |
| `GET /server/security/thanks` | Public researcher acknowledgments |
| `GET /server/security/report/{tracking_id}` | Researcher report status using the one-shot token in the private acknowledgment link |
| `GET /.well-known/security.txt` | RFC 9116 security contact information |
| `GET /.well-known/pgp-key.asc` | Public report encryption key when configured |
| `GET /server/metrics/...` | Metrics (when enabled; service-specific bearer token may be required) |
| `GET /robots.txt` | Robots policy |
| `GET /favicon.ico` | Site favicon |
| `GET /manifest.json` | PWA manifest |
| `GET /sw.js` | Service worker |
| `GET /server/docs/swagger` | OpenAPI documentation (HTML) |
| `GET /api/swagger` | OpenAPI schema (JSON) |
| `GET /server/docs/graphql` | GraphiQL UI when enabled |
| `GET /api/graphql` | GraphQL endpoint when enabled |

---

## Well-Known Namespace

ipgaze serves the following well-known endpoints:

| Endpoint | Purpose |
|----------|---------|
| `GET /.well-known/security.txt` | RFC 9116 security contact |
| `GET /.well-known/pgp-key.asc` | Public PGP key when configured |
| `GET /.well-known/llms.txt` | Service and API summary |

The canonical security contact file is `/.well-known/security.txt` and follows
[RFC 9116](https://www.rfc-editor.org/rfc/rfc9116). `/security.txt` is not a
supported canonical route. Unknown `/.well-known/*` paths return `404`.
When a PGP key is active, the file also includes its full SHA-256 fingerprint
as a comment; `GET /api/v1/server/security` returns the same fingerprint with
the public-key URL.

---

## Input Validation & Output Safety

- All IP addresses are validated before GeoIP lookup — invalid input is rejected with a `400`
- All SQL queries use parameterized statements — no string interpolation
- HTML output is escaped via Go's `html/template` package — XSS is structurally prevented
- All untrusted input is size-capped before buffering — no unbounded reads from network streams
- GeoIP lookup uses local databases. Optional port reachability checks perform
  network connections and are controlled by the server configuration.

---

## Enumeration Mitigation

- Resource IDs (when used by the CLI for owner-token operations) are opaque, non-sequential identifiers
- Per-IP rate limiting is uniform across endpoints to avoid timing-based discovery

---

## Audit Logging

ipgaze logs request-level events using Apache Combined Log Format. Logged fields:

- Client IP, timestamp, method, path, status code, response bytes, referer, user-agent

Logs never contain raw tokens. Operator and API token values are not written to
log output.

---

## Reporting a Security Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report repository vulnerabilities privately:

1. **GitHub Private Reporting:** Use [GitHub Security Advisories](https://github.com/apimgr/ipgaze/security/advisories/new). This is the preferred channel for repository vulnerabilities.

The coordinated disclosure policy applies to the official `ifcfg.us` service.
For issues against that deployed service, use the security report link in
[`security.txt`](https://ifcfg.us/.well-known/security.txt), which opens the
security mode of the contact form. The ordinary contact mode remains for
general questions. Repository vulnerabilities should use GitHub private
reporting. Researcher acknowledgments are shown at
[`/server/security/thanks`](https://ifcfg.us/server/security/thanks) when
consented credits are available. The report form asks separately for a public
handle when the researcher chooses handle credit. The private acknowledgment
email provides a one-shot status link; the public status page does not expose
report contents.

Security report contents and researcher names or handles chosen for credit are
encrypted at rest. Public credit is displayed only after a report is marked
disclosed and the researcher opted in.
