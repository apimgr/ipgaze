# ipgaze

## Project description

IPGaze is a self-hosted alternative to services such as ifconfig.me, ipinfo.io, whatismyip.com, ipchicken.com, and iplocation.net — providing full parity and then some. It returns the visitor's public IP address along with comprehensive GeoIP information, VPN/proxy detection, Tor exit-node detection, and EU membership status.

It implements the echoip-compatible API (https://github.com/mpolden/echoip) — same routes, same response formats, same CLI user-agent detection — so existing echoip integrations require zero changes. It extends the echoip API surface with VPN/proxy detection, Tor detection, PWA support, GraphQL, OpenAPI, and Prometheus metrics.

IPGaze supports both IPv4 and IPv6 (curl -4 and curl -6), provides JSON, plain text, and HTML output formats, and includes a web interface. The landing page can show the service's public addresses in its example commands when those addresses are known.

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
- VPN/proxy detection using public threat intelligence
- Tor exit-node detection using the Tor exit-node list
- echoip-compatible API surface (same routes, response formats, user-agent detection behavior)
- Multiple output formats per endpoint: JSON, plain text, HTML (content negotiation)
- Guest preferences for theme, language, and the default landing-page curl example; the UI and CLI support English, Spanish, French, German, Italian, Chinese, Arabic, and Japanese. Visitors can carry preferences between browsers, and these choices never alter echoip-compatible API responses
- CLI user-agent detection: curl, wget, HTTPie, Go HTTP client, Mikrotik, ddclient, xh → plain text response
- Reverse DNS hostname lookup
- TCP port reachability testing
- Automatic maintenance that keeps lookup data, threat data, certificates, tokens, logs, backups, and service health current
- Operator notifications by email
- IPv4/IPv6 allowlists and permanent blocks, with temporary protections against request floods and optional security alerts
- IP/domain threat intelligence that informs request protection
- Blocklist health degrades after 72 hours without a successful source update;
  the last good entries remain active, and never-loaded sources report an error
- Current vulnerability information for security reporting
- Installable web app support with offline access to static assets
- Private operator metrics for service monitoring
- GraphQL endpoint for flexible queries
- OpenAPI/Swagger interactive documentation
- MCP tools for public IP and GeoIP lookups; visitors can issue owner tokens and separate linked tokens for MCP clients. Public REST lookups remain available without a token.
- CLI client (`ipgaze-cli`) for querying ipgaze-compatible servers with token-based access
- Optional onion and I2P addresses for reaching the service through privacy networks
- About, privacy, terms, contact, DPO, and security information pages
- Public abuse, DMCA, privacy, and security reporting, including private status tracking and researcher acknowledgments
- Privacy-respecting analytics that loads only after visitor consent

**Non-goals:**
- WebSocket real-time updates (future)
- Multi-tenant or SaaS features
- Feature gating or premium tiers — all functionality is free

### Roles & permissions

| Role | Description | Capabilities |
|------|-------------|-------------|
| **Anonymous** | Any visitor or API client | Public IP/GeoIP lookups, public site pages, and token issuance without an account. |
| **Owner** | Credential-only identity with no profile or login | Use owner-token features, including authenticated MCP access and linked-token management. |
| **Operator** | Person who deploys and manages the server | Configure and maintain the service; there is no admin web UI. |

The product has no user accounts, passwords, or login sessions. Public lookup endpoints remain available without authentication.

### Data model & sensitivity

**Entities and sensitivity:**
- Owner identity: an opaque identifier that groups a primary API token and its linked tokens; it does not represent a user account.
- API token: a secret credential used for owner or operator access. Token values are sensitive; list operations return metadata only, while authenticated reveal actions expose the selected token.
- Guest preferences: a visitor's theme, language, and landing-page example choices.
- Contact and security reports: submissions may contain reporter contact details and vulnerability information. Security reports are confidential and protected for coordinated disclosure.
- Lookup results: public IP and derived GeoIP information may be sensitive personal data when associated with a visitor.
- Public lookup results include the visitor's IP address and, when available, derived country, city, region, ASN, coordinates, timezone, EU membership, and postal code information. Parsed user-agent details may also be present.

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
| Official service | A compatible service available to CLI users | The CLI can be configured to use another compatible server |

### Threat model & abuse cases

**Primary assets being protected:**
- GeoIP database integrity
- Service availability

**Trusted inputs:**
- GeoIP data from the selected provider

**Untrusted inputs:**
- All inbound HTTP requests: IP headers, query parameters, request body, user-agent string
- Any IP address submitted for lookup via path or query parameter
- Forwarded client-IP metadata unless it comes from an operator-configured trusted proxy

**Attacker/abuser goals:**
- Trigger SSRF via IP lookup of internal/RFC1918 addresses
- Abuse the GeoIP lookup as a DoS amplifier (high-volume requests)
- Inject malformed IP addresses or path traversal via query strings
- Scrape GeoIP data at volume to exhaust download quotas

**Required defenses:**
- Specific IP lookups do not contact the submitted address or trigger outbound connections.

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
| `GET` | `/ip.txt` | None | Plain-text compatibility alias for `/ip`. |
| `GET` | `/country.txt` | None | Plain-text compatibility alias for `/country`. |
| `GET` | `/country-iso.txt` | None | Plain-text compatibility alias for `/country-iso`. |
| `GET` | `/city.txt` | None | Plain-text compatibility alias for `/city`. |
| `GET` | `/coordinates.txt` | None | Plain-text compatibility alias for `/coordinates`. |
| `GET` | `/asn.txt` | None | Plain-text compatibility alias for `/asn`. |
| `GET` | `/asn-org.txt` | None | Plain-text compatibility alias for `/asn-org`. |
| `GET` | `/branding/logo` | None | Serve the configured or embedded brand logo. |
| `GET` | `/locales/{lang}.json` | None | Serve the embedded translation catalog for the requested language. |
| `GET` | `/static/{path}` | None | Serve an allowlisted embedded static asset. |
| `GET` | `/theme.css` | None | Serve the theme stylesheet for the current request preferences. |
| `GET` | `/cli/binaries/{filename}` | Optional bearer token | Download a published CLI binary when binary download authorization is enabled. |
| `GET` | `/api/healthz.txt` | None | Plain-text response from the unversioned health alias. |
| `GET` | `/api/v1/server/healthz.txt` | None | Plain-text response from the versioned health endpoint. |
| `POST` | `/api/v1/server/backups/restore` | Operator bearer token | Multipart fields: `archive` (`.tar.gz` or `.tar.gz.enc`), optional `base_archive` for an incremental backup, optional `password` for encrypted backups, and `confirmation` exactly `RESTORE {uploaded filename}`. Verifies the archive before entering maintenance and returns `202` when the restore restart is scheduled. |
| `GET` | `/server/backups/restore` | None | Operator restore page; the upload action requires an operator token. |
| `GET` | `/api/v1/version` | None | Return the running server version for CLI compatibility checks. |
| `GET` | `/manifest.json` | None | Serve the installable web app manifest. |
| `GET` | `/sw.js` | None | Serve the service worker for offline static assets. |
| `GET` | `/robots.txt` | None | Serve the crawler policy and sitemap location. |
| `GET` | `/sitemap.xml` | None | Serve the dynamically generated public-page sitemap. |
| `GET` | `/feed.xml` | None | Serve the Atom feed; IPGaze returns a valid empty feed because it has no public item collection. |
| `GET` | `/rss.xml` | None | Serve the RSS feed; IPGaze returns a valid empty feed because it has no public item collection. |
| `GET` | `/favicon.ico` | None | Serve the embedded or configured browser icon. |
| `GET` | `/.well-known/llms.txt` | None | Serve the generated AI agent discovery document. |
| `GET` | `/llms.txt` | None | Alias for the generated AI agent discovery document. |
| `GET` | `/server/docs/swagger/theme.css` | None | Serve the Swagger UI theme stylesheet. |
| `GET` | `/server/docs/graphql/theme.css` | None | Serve the GraphiQL theme stylesheet. |
The compatibility endpoints preserve echoip request and response behavior.
GeoIP-dependent fields are available when lookup data is available. The
versioned lookup routes return the same product information through JSON,
plain text, or HTML as appropriate. The standard GraphQL and CLI capabilities
follow AI.md PARTS 14 and 32.

The restore page and API accept an uploaded backup only after archive
verification and a typed `RESTORE {filename}` confirmation. The server enters
maintenance, stops scheduled writers, executes the same restore command used
by the offline CLI flow, and exits through the update-restart path so its
service manager can start it with restored state.
