# Security

## Security Model

ipgaze is designed with security-first principles. This page covers the security model, public and protected endpoints, authentication, and how to report security issues.

---

## Authentication

ipgaze is a public, anonymous IP lookup service. No login is required for public
lookup endpoints. The service does not create user accounts or persistent
lookup-result ownership records. Operator-protected endpoints use the
server-wide `server.token` bearer credential stored in `secrets.yml`. This
product has no user accounts. Visitors may issue owner tokens without creating
a resource; those tokens link later resources to the visitor and are required
for MCP. Linked tokens are intended for individual MCP clients. The CLI can
access public lookup operations without a token; protected operator operations
require the operator credential.

Security practices applied throughout:

- **Operator token:** Stored in `secrets.yml` and compared using its SHA-256 hash cached in memory; never stored in the database
- **Issued API tokens:** Owner tokens may be issued without creating a resource. They identify resources a caller creates and are required for MCP access. Primary tokens have `global` scope. Linked tokens have `read` or `read-write` scope, defaulting to `read-write`, and provide separate, revocable credentials for MCP clients. Insufficient scope returns `403` with a `WWW-Authenticate` challenge.
- **Rate limiting:** Requests use persisted sliding windows, keyed by client IP for anonymous traffic and token for authenticated traffic; failed authentication is tracked per IP
- **Client address identity:** Trusted proxy headers are validated and normalized to one canonical IP; IPv6 limits and bans use the full address, and rate-limit state is bounded and expires
- **Constant-time comparison:** All token checks use timing-safe comparison to prevent timing attacks

---

## Public Endpoints

The following endpoints are accessible without authentication:

| Endpoint | Purpose |
|----------|---------|
| `GET https://ifcfg.us/` | IP lookup for caller (content negotiation: JSON/text/HTML) |
| `GET https://ifcfg.us/ip` | Caller IP address (plain text) |
| `GET https://ifcfg.us/json` | Full JSON lookup for caller |
| `GET https://ifcfg.us/{ip}` | Lookup a specific IP address |
| `GET https://ifcfg.us/country` | Country name for caller |
| `GET https://ifcfg.us/country-iso` | ISO country code for caller |
| `GET https://ifcfg.us/city` | City for caller |
| `GET https://ifcfg.us/coordinates` | Latitude/longitude for caller |
| `GET https://ifcfg.us/asn` | ASN number for caller |
| `GET https://ifcfg.us/asn-org` | ASN organization for caller |
| `GET https://ifcfg.us/server/healthz` | Health check (content negotiation) |
| `GET https://ifcfg.us/api/v1/server/healthz` | Versioned health check |
| `GET https://ifcfg.us/api/healthz` | Direct JSON health alias |
| `GET https://ifcfg.us/healthz` | Optional health alias when enabled in `server.yml` |
| `GET https://ifcfg.us/server/security` | Security overview and reporting links |
| `GET https://ifcfg.us/server/dpo` | Public DPO contact details, privacy link, and security page link |
| `GET https://ifcfg.us/server/security/policy` | Coordinated disclosure policy |
| `GET https://ifcfg.us/server/security/thanks` | Public researcher acknowledgments |
| `GET https://ifcfg.us/server/security/report/{tracking_id}` | Researcher report status using the one-shot token in the private acknowledgment link |
| `GET https://ifcfg.us/server/preferences` | Guest preferences hub |
| `GET https://ifcfg.us/server/preferences/tokens` | Public token page; token lists/actions require the primary owner cookie |
| `POST https://ifcfg.us/server/preferences` | Update guest preference cookies; CSRF-protected browser form |
| `GET https://ifcfg.us/server/preferences/sync` | Export guest preferences |
| `POST https://ifcfg.us/server/preferences/sync` | Import guest preferences; CSRF-protected browser form |
| `GET https://ifcfg.us/server/preferences/sync/import` | Apply preferences from a shared link |
| `GET https://ifcfg.us/api/v1/server/preferences` | Read guest preference state |
| `POST https://ifcfg.us/api/v1/server/preferences` | Update guest preference cookies without browser-session authority |
| `GET https://ifcfg.us/api/v1/server/preferences/sync` | Export guest preferences |
| `GET https://ifcfg.us/api/v1/server/preferences/sync/import` | Apply preferences from a code or query |
| `GET https://ifcfg.us/.well-known/security.txt` | RFC 9116 security contact information |
| `GET https://ifcfg.us/.well-known/pgp-key.asc` | Public report encryption key while a keypair exists |
| `GET https://ifcfg.us/robots.txt` | Robots policy |
| `GET https://ifcfg.us/favicon.ico` | Site favicon |
| `GET https://ifcfg.us/manifest.json` | PWA manifest |
| `GET https://ifcfg.us/sw.js` | Service worker |
| `GET https://ifcfg.us/server/docs/swagger` | OpenAPI documentation (HTML) |
| `GET https://ifcfg.us/api/v1/server/swagger` | Canonical OpenAPI schema (JSON) |
| `GET https://ifcfg.us/api/swagger` | Direct alias for the current version's OpenAPI schema |
| `GET` or `POST https://ifcfg.us/server/docs/graphql` | GraphiQL UI |
| `GET` or `POST https://ifcfg.us/api/v1/server/graphql` | Canonical GraphQL endpoint |
| `GET` or `POST https://ifcfg.us/api/graphql` | Direct alias for the current version's GraphQL endpoint |

The `cookie_consent` cookie stores compact JSON percent-encoded for a cookie
value. The server decodes it with path-unescaping; malformed values count as
missing consent, so analytics stays disabled and the consent banner appears.
The browser writer uses `encodeURIComponent` for the same format.

Metrics endpoints are internal operational interfaces, not public endpoints.
When enabled, every service route requires its service-specific bearer token
unless `server.metrics.auth.allow_unauthenticated` is enabled for a firewalled
internal network. Do not expose these routes through a public reverse proxy.

---

## Well-Known Namespace

ipgaze serves the following well-known endpoints:

| Endpoint | Purpose |
|----------|---------|
| `GET https://ifcfg.us/.well-known/security.txt` | RFC 9116 security contact |
| `GET https://ifcfg.us/.well-known/pgp-key.asc` | Public PGP key while a keypair exists |
| `GET https://ifcfg.us/.well-known/llms.txt` | Service and API summary |

The canonical security contact file is `/.well-known/security.txt` and follows
[RFC 9116](https://www.rfc-editor.org/rfc/rfc9116). `/security.txt` is not a
supported canonical route. Unknown `/.well-known/*` paths return `404`.
When a PGP key is active, the file also includes its 40-character OpenPGP v4
fingerprint as a comment; `GET https://ifcfg.us/api/v1/server/security` returns the same
fingerprint with the public-key URL.

---

## Input Validation & Output Safety

- All IP addresses are validated before GeoIP lookup — invalid input is rejected with a `400`
- All SQL queries use parameterized statements — no string interpolation
- HTML output is escaped via Go's `html/template` package — XSS is structurally prevented
- All untrusted input is size-capped before buffering — no unbounded reads from network streams
- GeoIP lookup uses local databases. Port reachability checks are always
  enabled and only test the requested TCP port.

---

## Enumeration Mitigation

- Per-IP rate limiting is uniform across endpoints to avoid timing-based discovery

---

## Audit Logging

ipgaze logs request-level events using Apache Combined Log Format. Logged fields:

- Client IP, timestamp, method, path, status code, response bytes, referer, user-agent

Logs never contain raw tokens. Operator and API token values are not written to
log output.

## IP Blocks and Request Floods

Permanent blocks and allowlists accept both IPv4 and IPv6 addresses or CIDRs.
Allowlisted addresses bypass IP blocks, request rate limits, GeoIP country
blocking, and automatic flood blocks. Authentication, CSRF, path-security, and
TLS checks still apply. Automatic flood blocks are stored in the database with
an expiry and survive restarts; expired blocks are removed automatically. The
default trigger is more than 10 times the endpoint-class rate limit in a
60-second window, and the default block lasts one hour. Invalid entries and
overly broad allowlist ranges are skipped with a warning. Allowlist entries are
configuration-only and have no API. Operators can tune the threshold,
duration, alerts, and permanent blocks under `server.security` in the ordered
`yaml.d/security.yml` drop-in; see the
[configuration reference](configuration.md#request-flood-detection-and-permanent-ip-blocks).

The built-in contact CAPTCHA stores only a keyed answer hash, expires after 10
minutes, and is consumed on the first verification attempt. Contact form
submissions are rate-limited per client IP. Optional reCAPTCHA and hCaptcha
providers fail closed if verification is unavailable; requests over Tor or I2P
always use the built-in challenge.

---

## Reporting a Security Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

### Coordinated disclosure scope

The public policy at [`/server/security/policy`](https://ifcfg.us/server/security/policy)
and the versioned JSON endpoint at `/api/v1/server/security/policy` describe
the official service's coordinated disclosure terms. By default, the in-scope
asset is the official IPGaze service at `https://ifcfg.us`; self-hosted
installations and services operated by third parties are out of scope. The
default request is a 90-day coordinated disclosure period from acknowledgment.
Denial-of-service testing, spam, social engineering, physical attacks,
disruption, access to another person's data, and third-party vulnerabilities
without demonstrated impact on the official service are excluded. The policy
includes a good-faith safe-harbor statement for research within that scope.
Operators can replace the hosted policy using `web.security.policy`; the API
then returns the configured Markdown policy. See the
[configuration reference](configuration.md#contact-captcha-and-disclosure-policy).

Report repository vulnerabilities privately:

1. **GitHub Private Reporting:** Use [GitHub Security Advisories](https://github.com/apimgr/ipgaze/security/advisories/new). This is the preferred channel for repository vulnerabilities.

The coordinated disclosure policy applies to the official `ifcfg.us` service.
For issues against that deployed service, use the security report link in
[`security.txt`](https://ifcfg.us/.well-known/security.txt), which opens the
security mode of the contact form. For abuse, DMCA, and privacy reports, use
the corresponding typed form linked from [`/server/security`](https://ifcfg.us/server/security).
The form does not accept general questions, support requests, bug reports, or
feature requests. Repository vulnerabilities should use GitHub private
reporting. Researcher acknowledgments are shown at
[`/server/security/thanks`](https://ifcfg.us/server/security/thanks) when
consented credits are available. The report form asks separately for a public
handle when the researcher chooses handle credit. The private acknowledgment
email provides a one-shot status link; the public status page does not expose
report contents.

Security report contents and researcher names or handles chosen for credit are
encrypted at rest. Public credit is displayed only after a report is marked
disclosed and the researcher opted in.

The disclosure policy can be customized in `web.security.policy` using
Markdown in the `yaml.d/web.yml` drop-in. Security report records are stored
encrypted before email delivery; if SMTP is unavailable or delivery fails, the
submission still returns its tracking ID and skips the researcher
acknowledgment. Invalid `security_id` values are logged only as an eight-character
SHA-256 prefix, alongside the request IP and user agent. The one-shot status
response sets `Referrer-Policy: no-referrer`.
