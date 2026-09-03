# Security

## Security Model

ipgaze is designed with security-first principles. This page covers the security model, public and protected endpoints, authentication, and how to report security issues.

---

## Authentication

ipgaze is a public, anonymous IP lookup service. No login is required for any public
endpoint. Resource ownership (for managing lookup results) uses short-lived bearer tokens
stored client-side and validated via SHA-256 hash.

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
| `GET /healthz` | Health check (content negotiation) |
| `GET /api/v1/healthz` | Health check (always JSON) |
| `GET /metrics` | Prometheus metrics (if enabled) |
| `GET /robots.txt` | Robots policy |
| `GET /manifest.json` | PWA manifest |
| `GET /sw.js` | Service worker |
| `GET /openapi` | OpenAPI documentation (HTML) |
| `GET /openapi.json` | OpenAPI schema (JSON) |
| `GET /graphql` | GraphQL endpoint |

---

## Well-Known Namespace

ipgaze serves the following well-known endpoints:

| Endpoint | Purpose |
|----------|---------|
| `GET /security.txt` | Security contact and policy |
| `GET /.well-known/security.txt` | RFC 9116 security contact |

The `security.txt` file follows [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116) and points to the security reporting channel.

---

## Input Validation & Output Safety

- All IP addresses are validated before GeoIP lookup — invalid input is rejected with a `400`
- All SQL queries use parameterized statements — no string interpolation
- HTML output is escaped via Go's `html/template` package — XSS is structurally prevented
- All untrusted input is size-capped before buffering — no unbounded reads from network streams
- SSRF is not possible: IP lookups call only the local in-process GeoIP database, with no outbound requests

---

## Enumeration Mitigation

- Resource IDs (when used by the CLI for owner-token operations) are opaque, non-sequential identifiers
- Per-IP rate limiting is uniform across endpoints to avoid timing-based discovery

---

## Audit Logging

ipgaze logs request-level events using Apache Combined Log Format. Logged fields:

- Client IP, timestamp, method, path, status code, response bytes, referer, user-agent

Logs never contain raw tokens. The server.token (when present) is stored as a SHA-256
hash and is never written to log output.

---

## Reporting a Security Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities privately:

1. **GitHub Private Reporting:** Use [GitHub Security Advisories](https://github.com/apimgr/ipgaze/security/advisories/new) (preferred)
2. **Email:** Contact the maintainer at `apimgr@casjay.pro` with `[SECURITY]` in the subject line

We aim to acknowledge reports within 48 hours and provide a fix timeline within 7 days for confirmed issues.

See our [Security Policy](https://github.com/apimgr/ipgaze/security/policy) for the full disclosure process.
