# ipgaze

## Project description

IPGaze is a self-hosted alternative to services such as ifconfig.me, ipinfo.io, whatismyip.com, ipchicken.com, and iplocation.net — providing full parity and then some. It returns the visitor's public IP address along with comprehensive GeoIP information, VPN/proxy detection, Tor exit-node detection, and EU membership status.

It implements the echoip-compatible API (https://github.com/mpolden/echoip) — same routes, same response formats, same CLI user-agent detection — so existing echoip integrations require zero changes. It extends the echoip API surface with VPN/proxy detection, Tor detection, PWA support, GraphQL, OpenAPI, and Prometheus metrics.

IPGaze supports both IPv4 and IPv6 (curl -4 and curl -6), provides JSON, plain text, and HTML output formats, and includes a full-stack web frontend using server-side rendered Go templates. Container deployments can supply HOST_IPV4 and HOST_IPV6 environment variables to advertise the host's public IPs in curl command examples shown in the web UI.

## Project variables

project_name:      ipgaze
project_org:       apimgr
internal_org:      apimgr
internal_name:     ipgaze
owner_token:       ipgaze_owner_token_qzmtkvha
resource_label_plural: items
app_name:          IPGaze
official_site:     https://ifcfg.us
maintainer_name:   apimgr
maintainer_email:  apimgr@casjay.pro
license:           MIT
repository:        https://github.com/apimgr/ipgaze

## Business logic

### Product scope & non-goals

**In scope:**
- Visitor's own public IP address lookup (IPv4 and IPv6 via curl -4 / curl -6)
- Specific IP address lookup by any client
- GeoIP information: country, city, region, postal code, coordinates, timezone, ASN, EU membership
- VPN/proxy detection (checked against known VPN/hosting ASNs and ip2proxy-compatible data)
- Tor exit-node detection (cross-referenced against Tor exit node list)
- echoip-compatible API surface (same routes, response formats, user-agent detection behavior)
- Multiple output formats per endpoint: JSON, plain text, HTML (content negotiation)
- Guest UI preferences for theme, language, and the default landing-page curl example widget; built-in UI and CLI locales are English, Spanish, French, German, Italian, Chinese, Arabic, and Japanese. Preferences are stored in cookies, can be moved between browsers through a dedicated sync page using a portable URL or code, and never alter echoip-compatible API responses
- CLI user-agent detection: curl, wget, HTTPie, Go HTTP client, Mikrotik, ddclient, xh → plain text response
- Reverse DNS hostname lookup (always enabled, no flag)
- Port reachability testing (always enabled, no flag)
- Automatic maintenance that keeps lookup data, threat data, certificates, tokens, logs, backups, and service health current
- Operator notifications by email
- IPv4/IPv6 allowlists and permanent blocks, with temporary protections against request floods and optional security alerts
- IP/domain threat intelligence that informs request protection
- Blocklist health degrades after 72 hours without a successful source update;
  the last good entries remain active, and never-loaded sources report an error
- Current vulnerability information for security reporting
- PWA support: web app manifest and service worker for offline caching
- Prometheus metrics (internal only, not public)
- GraphQL endpoint for flexible queries
- OpenAPI/Swagger interactive documentation
- MCP tools for public IP and GeoIP lookups; visitors can issue owner tokens and separate linked tokens for MCP clients. Public REST lookups remain available without a token.
- CLI client (`ipgaze-cli`) for querying ipgaze-compatible servers with token-based access
- Optional onion and I2P addresses for reaching the service through privacy networks
- Public abuse, DMCA, privacy, and security reporting, including private status tracking and researcher acknowledgments
- About, privacy, terms, contact, DPO, and security information pages
- Consent-controlled, same-origin analytics

**Non-goals:**
- WebSocket real-time updates (future)
- Multi-tenant or SaaS features
- Feature gating or premium tiers — all functionality is free

### Roles & permissions

| Role | Description | Capabilities |
|------|-------------|-------------|
| **Anonymous** | Any visitor or API client | All public IP/GeoIP endpoints, GraphQL, OpenAPI, PWA — no authentication required |

There is exactly one role. ipgaze is a public service with no user accounts, no admin web UI, and no login. Anonymous callers can use the REST API; owner tokens identify resources a caller creates and are required for MCP access.

### Data model & sensitivity

**Public data (no authentication required):**
- Visitor's public IP address (IPv4 or IPv6)
- Derived GeoIP fields: country, city, region, ASN, coordinates, timezone, EU membership, postal code
- User-agent product/version when parsed

**Entities and sensitivity:**
- Owner identity: an opaque identifier associated with resources and issued API tokens; it does not represent a user account.
- API token: a secret credential used for owner or operator access. Raw token values are sensitive and are not exposed after issuance.
- Guest preferences: a visitor's theme, language, and landing-page example choices.
- Contact and security reports: submissions may contain reporter contact details and vulnerability information. Security reports are confidential and protected for coordinated disclosure.
- Lookup results: public IP and derived GeoIP information may be sensitive personal data when associated with a visitor.

The product has no user accounts, passwords, or login sessions. Public lookup endpoints do not require authentication. Operators can customize public site information and page content.

### Trust boundaries & external services

| External dependency | Trust boundary | User-visible behavior on failure |
|--------------------|---------------|----------------------------------|
| GeoIP data publisher and delivery network | Supplies public lookup data; downloaded data is validated before use | IP lookup remains available without GeoIP fields while data is unavailable |
| Client-IP forwarding metadata | Untrusted unless supplied by a configured trusted proxy | Untrusted forwarding values do not replace the caller address |
| Tor and I2P networks | Optional external access networks | The service remains available at its regular address if an overlay is unavailable |
| Threat intelligence publishers | External sources for VPN, proxy, Tor, and abuse indicators | Previously available protection data remains in use when an update fails |
| Vulnerability data publishers | External sources for vulnerability reporting | Previously available vulnerability data remains available when an update fails |
| Operator-selected mail service | Sends operator notifications and report acknowledgments | Email delivery may be delayed or unavailable while the service is unreachable |
| Official service endpoint | Default destination for CLI use | The CLI can be configured to use another compatible server |

### Threat model & abuse cases

**Primary assets being protected:**
- GeoIP database integrity (downloaded from trusted source, validated before use)
- Service availability (rate limiting, resource limits)

**Trusted inputs:**
- GeoIP databases downloaded from sapics/ip-location-db via jsDelivr CDN

**Untrusted inputs:**
- All inbound HTTP requests: IP headers, query parameters, request body, user-agent string
- Any IP address submitted for lookup via path or query parameter
- X-Forwarded-For / X-Real-IP headers (unless the immediate peer is trusted and the header is selected by `server.trusted_proxies.client_ip_header`)

**Attacker/abuser goals:**
- Trigger SSRF via IP lookup of internal/RFC1918 addresses
- Abuse the GeoIP lookup as a DoS amplifier (high-volume requests)
- Inject malformed IP addresses or path traversal via query strings
- Scrape GeoIP data at volume to exhaust download quotas

**Required defenses:**
- All IP inputs validated against allowed formats before any lookup
- Specific IP lookups (`/{ip}`) restricted to GeoIP database lookup only — no outbound connections triggered
- Parameterized queries for all database access
- Per-IP rate limiting (see AI.md PART 11)

**Intentional non-defenses (documented):**
- GeoIP data is inherently approximate; it is not used for access control
- Country blocking may be configured as an advisory deny-only signal; it is never authoritative because GeoIP accuracy is limited and VPNs trivially bypass country checks

### Security decisions & exceptions

| Decision | Product reason |
|----------|----------------|
| Preserve echoip-compatible request and response behavior | Existing echoip integrations continue to work without changes |
| Treat GeoIP country restrictions as advisory and deny-only | GeoIP is approximate and can be bypassed, so it must not decide access by itself |
| Accept forwarded client addresses only from configured trusted proxies | Untrusted request headers must not let callers impersonate another address |
| Keep security reports private and support coordinated disclosure | Researchers can report vulnerabilities without publishing sensitive details prematurely |

### API routes

IPGaze's project-defined lookup API is public and requires no authentication.
The compatibility routes preserve echoip request and response behavior; the
versioned routes expose the same lookup operations under `/api/v1`.

| Method | Path | Auth | Purpose and request/response summary |
|--------|------|------|--------------------------------------|
| `GET` | `/` | None | Look up the caller's public IP; negotiate HTML, JSON, or plain text and return available address and GeoIP fields. |
| `GET` | `/json` | None | Return the caller's address and lookup fields as JSON. |
| `GET` | `/ip` | None | Return the caller's IP address as plain text. |
| `GET` | `/country` | None | Return the caller's country name when GeoIP data is available. |
| `GET` | `/country-iso` | None | Return the caller's ISO country code when GeoIP data is available. |
| `GET` | `/city` | None | Return the caller's city when GeoIP data is available. |
| `GET` | `/coordinates` | None | Return the caller's latitude and longitude when GeoIP data is available. |
| `GET` | `/asn` | None | Return the caller's autonomous system number when GeoIP data is available. |
| `GET` | `/asn-org` | None | Return the caller's autonomous system organization when GeoIP data is available. |
| `GET` | `/{ip}` | None | Look up the supplied IPv4 or IPv6 address from the path and return its available address and GeoIP fields; invalid addresses are rejected. |
| `GET` | `/port/{port}` | None | Check TCP reachability for the requested port and return the result. |
| `GET` | `/api/v1` | None | Return the caller's address and available lookup fields in the standard JSON envelope. |
| `GET` | `/api/v1/json` | None | Return the caller's address and lookup fields as JSON. |
| `GET` | `/api/v1/ip` | None | Return the caller's IP address. |
| `GET` | `/api/v1/ip/{ip}` | None | Look up a supplied IPv4 or IPv6 address and return its available address and GeoIP fields; invalid addresses are rejected. |
| `GET` | `/api/v1/country` | None | Return the caller's country name when GeoIP data is available. |
| `GET` | `/api/v1/country-iso` | None | Return the caller's ISO country code when GeoIP data is available. |
| `GET` | `/api/v1/city` | None | Return the caller's city when GeoIP data is available. |
| `GET` | `/api/v1/coordinates` | None | Return the caller's latitude and longitude when GeoIP data is available. |
| `GET` | `/api/v1/asn` | None | Return the caller's autonomous system number when GeoIP data is available. |
| `GET` | `/api/v1/asn-org` | None | Return the caller's autonomous system organization when GeoIP data is available. |
| `GET` | `/api/v1/port/{port}` | None | Check TCP reachability for the requested port and return the result. |
| `GET` | `/api/v1/server/graphql` | None | Serve the GraphQL explorer. |
| `POST` | `/api/v1/server/graphql` | None | Accept a GraphQL query, optional variables and operation name; return the query result in the GraphQL response shape. |

The compatibility endpoints preserve echoip request and response behavior.
GeoIP-dependent fields are available when lookup data is available. The
versioned lookup routes return the same product information through JSON,
plain text, or HTML as appropriate; GraphQL keeps its standard response shape.

### Client applications

The server binary provides the public lookup service. The companion `ipgaze-cli`
client can query any compatible server and present lookup results to operators
and scripts. See AI.md PARTS 7, 8, and 32 for the required implementation and
packaging details.
