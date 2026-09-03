# API Reference

Complete API reference for **ipgaze** - IP address lookup service.

## Base URL

```
https://ifcfg.us
```

---

## Endpoints

### Get Your IP Address

#### `GET /`

Returns your IP address in different formats based on the `Accept` header or User-Agent.

**Request**:
```bash
curl -q -LSsf https://ifcfg.us/
```

**Response** (plain text):
```
203.0.113.42
```

**Request** (JSON):
```bash
curl -q -LSsf -H "Accept: application/json" https://ifcfg.us/
```

**Response** (JSON):
```json
{
  "ip": "203.0.113.42",
  "ip_decimal": 3405803306,
  "country": "United States",
  "country_iso": "US",
  "city": "Mountain View",
  "region_name": "California",
  "region_code": "CA",
  "latitude": 37.386,
  "longitude": -122.0838,
  "timezone": "America/Los_Angeles",
  "asn": "AS15169",
  "asn_org": "Google LLC",
  "hostname": "dns.google"
}
```

---

### Lookup Specific IP

#### `GET /{ip}`

Lookup information for a specific IP address (IPv4 or IPv6).

**IPv4 Example**:
```bash
curl -q -LSsf https://ifcfg.us/8.8.8.8
```

**IPv6 Example**:
```bash
curl -q -LSsf https://ifcfg.us/2001:4860:4860::8888
```

**Response**:
```json
{
  "ip": "8.8.8.8",
  "ip_decimal": 134744072,
  "country": "United States",
  "country_iso": "US",
  "asn": "AS15169",
  "asn_org": "Google LLC"
}
```

---

### Health Check

#### `GET /healthz`

Server health check endpoint with content negotiation.

**Request (JSON)**:
```bash
curl -q -LSsf -H "Accept: application/json" https://ifcfg.us/healthz
```

**Response (JSON)**:
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "mode": "standalone",
  "uptime": "3d 2h 15m",
  "timestamp": "2025-01-15T10:30:00Z",
  "node": {
    "hostname": "server1",
    "id": "abc123"
  },
  "cluster": {
    "enabled": false
  },
  "checks": {
    "database": "ok",
    "geoip": "ok"
  }
}
```

**Request (Text)**:
```bash
curl -q -LSsf https://ifcfg.us/healthz
```

**Response (Text)**:
```
healthy
```

#### `GET /api/v1/healthz`

API health endpoint (always returns JSON).

**Request**:
```bash
curl -q -LSsf https://ifcfg.us/api/v1/healthz
```

**Response**: Same JSON format as above.
```

---

### Get Specific Fields

#### `GET /ip`
Returns just your IP address (text).

```bash
curl -q -LSsf https://ifcfg.us/ip
# Output: 203.0.113.42
```

#### `GET /country`
Returns your country name (text).

```bash
curl -q -LSsf https://ifcfg.us/country
# Output: United States
```

#### `GET /country-iso`
Returns your country ISO code (text).

```bash
curl -q -LSsf https://ifcfg.us/country-iso
# Output: US
```

#### `GET /city`
Returns your city name (text).

```bash
curl -q -LSsf https://ifcfg.us/city
# Output: Mountain View
```

#### `GET /coordinates`
Returns your coordinates (text).

```bash
curl -q -LSsf https://ifcfg.us/coordinates
# Output: 37.386,-122.0838
```

#### `GET /asn`
Returns your Autonomous System Number (text).

```bash
curl -q -LSsf https://ifcfg.us/asn
# Output: AS15169
```

#### `GET /asn-org`
Returns your ASN organization (text).

```bash
curl -q -LSsf https://ifcfg.us/asn-org
# Output: Google LLC
```

---

## API v1 Endpoints

RESTful API with versioned endpoints.

### `GET /api/v1`

Get your IP information (JSON).

**Request**:
```bash
curl -q -LSsf https://ifcfg.us/api/v1
```

**Response**:
```json
{
  "ip": "203.0.113.42",
  "ip_decimal": 3405803306,
  "country": "United States",
  "country_iso": "US",
  ...
}
```

### `GET /api/v1/ip`

Get your IP address (text).

**Request**:
```bash
curl -q -LSsf https://ifcfg.us/api/v1/ip
```

**Response**:
```
203.0.113.42
```

### `GET /api/v1/ip/{ip}`

Lookup specific IP address (JSON).

**Request**:
```bash
curl -q -LSsf https://ifcfg.us/api/v1/ip/8.8.8.8
```

**Response**:
```json
{
  "ip": "8.8.8.8",
  "ip_decimal": 134744072,
  "country": "United States",
  ...
}
```

### `GET /api/v1/country`

Get your country (text).

### `GET /api/v1/city`

Get your city (text).

### `GET /api/v1/asn`

Get your ASN (text).

---

## Query Parameters

### `?ip={address}`

Lookup information for a specific IP address.

**Example**:
```bash
curl -q -LSsf https://ifcfg.us/json?ip=8.8.8.8
```

---

## Port Testing

### `GET /port/{port}`

Test if a specific port is reachable on your IP address.

**Request**:
```bash
curl -q -LSsf https://ifcfg.us/port/22
```

**Response**:
```json
{
  "ip": "203.0.113.42",
  "port": 22,
  "reachable": true
}
```

---

## Response Formats

### JSON

Use `Accept: application/json` header or access `/json` endpoint.

```bash
curl -q -LSsf -H "Accept: application/json" https://ifcfg.us/
```

### Plain Text

Default for CLI tools (curl, wget, etc.).

```bash
curl -q -LSsf https://ifcfg.us/
```

---

## IPv6 Support

### Force IPv4 or IPv6

Use your client's flags:

```bash
# Force IPv4
curl -q -LSsf -4 https://ifcfg.us/

# Force IPv6
curl -q -LSsf -6 https://ifcfg.us/
```

### IPv6 Lookups

```bash
# Lookup IPv6 address
curl -q -LSsf https://ifcfg.us/2001:4860:4860::8888
```

---

## Rate Limiting

**Automated Use**: Please limit requests to **1 request per minute**.

Requests exceeding this limit may be rate-limited (HTTP 429) or dropped.

---

## Error Responses

### 400 Bad Request

```json
{
  "status": 400,
  "error": "Invalid IP address: invalid"
}
```

### 404 Not Found

```json
{
  "status": 404,
  "error": "Not found"
}
```

### 500 Internal Server Error

```json
{
  "status": 500,
  "error": "Internal server error"
}
```

---

## Examples

### cURL

```bash
curl -q -LSsf https://ifcfg.us/
curl -q -LSsf https://ifcfg.us/json
curl -q -LSsf https://ifcfg.us/8.8.8.8
curl -q -LSsf https://ifcfg.us/api/v1/ip/8.8.8.8
```

### HTTPie

```bash
http https://ifcfg.us/
http https://ifcfg.us/json
```

### wget

```bash
wget -qO- https://ifcfg.us/
```

### PowerShell

```powershell
Invoke-RestMethod https://ifcfg.us/json
```

---

## GeoIP Data

GeoIP data is provided by [sapics/ip-location-db](https://github.com/sapics/ip-location-db) — free, no API key required. Databases download automatically at runtime via jsDelivr CDN.

- **Country**: ISO code, name, EU membership
- **City**: Name, region, postal code
- **Coordinates**: Latitude, longitude
- **Timezone**: IANA timezone identifier
- **ASN**: Autonomous System Number and organization

**Update Frequency**: Twice weekly (automatic)

---

## Server Administration

ipgaze is an anonymous public IP lookup service. There is **no admin web UI, no login,
no admin API, and no runtime config mutation**. All administration is performed by
editing `server.yml` on disk. See [Server Administration](admin.md) for details.

---

## OpenAPI / Swagger

Interactive API documentation using OpenAPI/Swagger.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `GET /openapi` | GET | Swagger UI (HTML) |
| `GET /openapi.json` | GET | OpenAPI spec (JSON) |

**Example**:
```bash
# View API spec
curl -q -LSsf https://ifcfg.us/openapi.json

# Open in browser for interactive docs
open https://ifcfg.us/openapi
```

---

## GraphQL

GraphQL endpoint for flexible queries.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `GET /graphql` | GET | GraphiQL UI |
| `POST /graphql` | POST | Execute GraphQL query |

**Example Query**:
```bash
curl -q -LSsf -X POST https://ifcfg.us/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ ip { address country city asn } }"}'
```

**Response**:
```json
{
  "data": {
    "ip": {
      "address": "203.0.113.42",
      "country": "United States",
      "city": "Mountain View",
      "asn": "AS15169"
    }
  }
}
```

---

## Special Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `GET /robots.txt` | GET | Robots file for crawlers |
| `GET /security.txt` | GET | Security contact information |
| `GET /.well-known/security.txt` | GET | Security.txt (standard path) |
| `GET /manifest.json` | GET | PWA web app manifest |
| `GET /sw.js` | GET | Service worker for offline support |

---

## Debug Endpoints

Only available when profiling is enabled (`--profile` flag).

| Endpoint | Method | Description |
|----------|--------|-------------|
| `GET /debug/cache` | GET | Cache statistics |
| `POST /debug/cache/resize` | POST | Resize cache |
| `GET /debug/pprof/*` | GET | Go profiling endpoints |

**Example**:
```bash
# Cache stats
curl -q -LSsf https://ifcfg.us/debug/cache

# Resize cache
curl -q -LSsf -X POST -d "1000" https://ifcfg.us/debug/cache/resize
```

---

## Text Format Variants

All field endpoints support `.txt` extension for explicit plain text output:

| Endpoint | Description |
|----------|-------------|
| `GET /ip.txt` | Your IP as text |
| `GET /country.txt` | Country name as text |
| `GET /country-iso.txt` | Country ISO as text |
| `GET /city.txt` | City name as text |
| `GET /coordinates.txt` | Coordinates as text |
| `GET /asn.txt` | ASN number as text |
| `GET /asn-org.txt` | ASN organization as text |

---

## Technical Details

- **Version**: Check with `ipgaze --version`
- **Health**: Check with `/healthz` endpoint
- **Performance**: Sub-millisecond response times (with cache)
- **Capacity**: Handles thousands of requests per second
