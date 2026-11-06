# IPGaze

IPGaze is a public IPv4 and IPv6 lookup service with GeoIP and autonomous
system number (ASN) details, plain text and JSON responses, and a companion
command line client.

## Quick Start

Run the production image with persistent configuration and data volumes:

```bash
docker run -d \
  --name ipgaze \
  -p 172.17.0.1:64580:80 \
  -v ipgaze-config:/config \
  -v ipgaze-data:/data \
  ghcr.io/apimgr/ipgaze:latest
```

The service listens on container port `80`. See [Installation](installation.md)
for reverse proxy, binary, and service setup.

## Features

- IPv4 and IPv6 address detection and lookup
- GeoIP country, region, city, timezone, and coordinate information
- ASN and organization lookup
- Plain text, JSON, and server-rendered HTML responses
- Versioned REST API, OpenAPI, and GraphQL
- Optional GeoIP, cache, metrics, Tor, and I2P services
- Server rendered pages and a companion `ipgaze-cli` client

Optional services and their defaults are documented in
[Configuration](configuration.md) and [Integrations](integrations.md).

## Documentation

- [Installation](installation.md) — Docker, binaries, and service management
- [Configuration](configuration.md) — `server.yml` and environment variables
- [API Reference](api.md) — routes, formats, and response behavior
- [CLI Reference](cli.md) — server and client commands
- [Server Administration](admin.md) — file based operator workflows
- [Security](security.md) — public endpoints and reporting
- [Integrations](integrations.md) — discovery and protocol interfaces
- [Development](development.md) — build, test, and contribution workflow

## Links

- [Official site](https://ifcfg.us)
- [Repository](https://github.com/apimgr/ipgaze)
- [Releases](https://github.com/apimgr/ipgaze/releases)
- [Swagger UI](https://ifcfg.us/server/docs/swagger)
- [GraphQL UI](https://ifcfg.us/server/docs/graphql)
- [ReadTheDocs](https://apimgr-ipgaze.readthedocs.io)

## License

IPGaze is licensed under the MIT License. See [LICENSE.md](../LICENSE.md).
