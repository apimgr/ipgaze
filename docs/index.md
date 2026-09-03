# ipgaze

IP address lookup service with GeoIP information.

## Overview

**ipgaze** is a fast, lightweight IP address lookup service providing:

- IPv4 and IPv6 support
- GeoIP location data (country, city, coordinates)
- ASN information
- Reverse DNS lookups
- Port connectivity testing
- RESTful API with JSON responses

## Quick Start

### Get Your IP

```bash
curl -q -LSsf https://ifcfg.us/
```

Output: `203.0.113.42`

### Get IP Information (JSON)

```bash
curl -q -LSsf https://ifcfg.us/json
```

```json
{
  "ip": "203.0.113.42",
  "country": "United States",
  "country_iso": "US",
  "city": "Mountain View",
  "latitude": 37.386,
  "longitude": -122.0838,
  "asn": "AS15169",
  "asn_org": "Google LLC"
}
```

### Lookup Specific IP

```bash
curl -q -LSsf https://ifcfg.us/8.8.8.8
```

## Features

- **Fast & Lightweight**: Single static binary, <15MB
- **IPv6 Support**: Full dual-stack IPv4/IPv6
- **GeoIP Data**: Country, city, ASN, coordinates, timezone
- **Auto-Updates**: Weekly GeoIP database updates
- **RESTful API**: Versioned `/api/v1` endpoints
- **Multiple Formats**: JSON, plain text, HTML
- **Port Testing**: Check port connectivity
- **Reverse DNS**: Optional hostname lookups

## Documentation

- [Installation](installation.md) - Docker, binary, systemd setup
- [Configuration](configuration.md) - All configuration options
- [API Reference](api.md) - Complete API documentation
- [CLI Reference](cli.md) - Command-line options
- [Server Administration](admin.md) - File-based configuration
- [Development](development.md) - Contributing guide

## Installation

### Docker (Recommended)

```bash
docker run -d -p 8080:80 ghcr.io/apimgr/ipgaze:latest
curl -q -LSsf http://localhost:8080/
```

### Binary

```bash
curl -q -LSsf -o ipgaze \
  https://github.com/apimgr/ipgaze/releases/latest/download/ipgaze-linux-amd64
chmod +x ipgaze
./ipgaze --listen :8080
```

See [Installation](installation.md) for detailed instructions.

## API Documentation

- [Swagger UI](/openapi) - Interactive REST API explorer
- [GraphQL Playground](/graphql) - Interactive GraphQL explorer

## Links

- [Repository](https://github.com/apimgr/ipgaze)
- [Releases](https://github.com/apimgr/ipgaze/releases)
- [Issues](https://github.com/apimgr/ipgaze/issues)

## License

MIT License - see [LICENSE](https://github.com/apimgr/ipgaze/blob/main/LICENSE.md)
