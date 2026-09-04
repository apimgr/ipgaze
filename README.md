# ipgaze

[![CI](https://github.com/apimgr/ipgaze/actions/workflows/ci.yml/badge.svg)](https://github.com/apimgr/ipgaze/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/apimgr/ipgaze)](https://github.com/apimgr/ipgaze/releases)
[![License](https://img.shields.io/github/license/apimgr/ipgaze)](LICENSE.md)
[![Docs](https://readthedocs.org/projects/apimgr-ipgaze/badge/?version=latest)](https://apimgr-ipgaze.readthedocs.io)

A simple, fast IP address lookup service with full IPv4/IPv6 support and GeoIP location data. Implements the echoip-compatible API for zero-change migration from existing integrations.

## About

**ipgaze** is a lightweight IP address lookup service that returns your public IP address along with GeoIP location data (country, city, coordinates, timezone, ASN). It ships as a single self-contained binary, plus a companion CLI client for scripting and terminal use.

## Official Site

https://ifcfg.us

## Features

- **Instant IP Detection** - Returns your public IP address
- **GeoIP Location Data** - Country, city, coordinates, timezone, ASN
- **Full IPv6 Support** - Dual-stack IPv4 and IPv6
- **RESTful API** - Versioned API at `/api/v1`
- **Multiple Output Formats** - JSON, plain text, or custom
- **Auto-Updating GeoIP** - Weekly automatic database updates
- **Mobile-Friendly** - Responsive web interface
- **Fast & Lightweight** - Single static binary <15MB
- **No API Keys Required** - GeoIP databases auto-download
- **VPN/Proxy & Tor Detection** - `is_vpn`, `is_proxy`, `is_tor` fields from daily-updated threat lists
- **GraphQL Endpoint** - Flexible queries alongside the REST API
- **OpenAPI/Swagger UI** - Interactive API documentation
- **Prometheus Metrics** - Internal `/metrics` endpoint for operators
- **PWA Support** - Web app manifest and service worker for offline use
- **Tor Hidden Service** - Auto-enabled when the `tor` binary is present
- **I2P Eepsite** - Opt-in via `server.i2p.enabled`
- **Built-in Scheduler** - GeoIP, blocklist, threat, and CVE updates; cert renewal; backups; log rotation

## Production

### Binary Installation

#### Linux (systemd)

```bash
# Download binary (AMD64)
curl -q -LSsf -o ipgaze https://github.com/apimgr/ipgaze/releases/latest/download/ipgaze-linux-amd64
chmod +x ipgaze
sudo mv ipgaze /usr/local/bin/

# Or use installation script
curl -q -LSsf https://raw.githubusercontent.com/apimgr/ipgaze/master/scripts/install.sh | sudo bash
```

The installation script will:
- Download the appropriate binary for your system
- Create systemd service
- Create dedicated user and directories
- Start the service automatically

**Service Management**:
```bash
sudo systemctl status ipgaze
sudo systemctl start ipgaze
sudo systemctl stop ipgaze
sudo systemctl restart ipgaze
sudo journalctl -u ipgaze -f
```

**Configuration**: Edit `/etc/systemd/system/ipgaze.service`

#### macOS

```bash
# Download binary (ARM64 for Apple Silicon, AMD64 for Intel)
curl -q -LSsf -o ipgaze https://github.com/apimgr/ipgaze/releases/latest/download/ipgaze-darwin-arm64
chmod +x ipgaze
sudo mv ipgaze /usr/local/bin/

# Run
ipgaze --port 8080
```

#### Windows

```powershell
# Download binary
Invoke-WebRequest -Uri "https://github.com/apimgr/ipgaze/releases/latest/download/ipgaze-windows-amd64.exe" -OutFile "ipgaze.exe"

# Run
.\ipgaze.exe --port 8080
```

### Docker Deployment

#### Docker Compose (Production)

**Download**:
```bash
curl -q -LSsf -o docker-compose.yml https://raw.githubusercontent.com/apimgr/ipgaze/master/docker/docker-compose.yml
```

**Start**:
```bash
docker-compose up -d
```

**Access**:
```bash
curl -q -LSsf http://172.17.0.1:64580/
```

**Configuration**: `docker-compose.yml`
```yaml
services:
  ipgaze:
    image: ghcr.io/apimgr/ipgaze:latest
    container_name: ipgaze-app
    restart: always
    environment:
      PORT: 80
      CACHE_URL: valkey://ipgaze-cache:6379
    volumes:
      - './volumes/config:/config:z'
      - './volumes/data:/data:z'
    ports:
      - '172.17.0.1:64580:80'
    depends_on:
      ipgaze-cache:
        condition: service_healthy
    networks:
      - ipgaze

  ipgaze-cache:
    image: valkey/valkey:alpine
    container_name: ipgaze-cache
    restart: always
    volumes:
      - './volumes/data/db/valkey:/data:z'
    networks:
      - ipgaze

networks:
  ipgaze:
    external: false
```

See `docker/docker-compose.yml` for the full reference file (logging,
healthchecks, and SMTP/DOMAIN overrides).

#### Docker Run

```bash
docker run -d \
  --name ipgaze \
  -p 8080:80 \
  -v ./data:/data \
  -e DATA_DIR=/data \
  --restart unless-stopped \
  ghcr.io/apimgr/ipgaze:latest
```

## Server CLI

`ipgaze --help` prints the full reference; `ipgaze <command> --help` prints
per-command detail for `--service`, `--maintenance`, `--shell`, and `--update`.

### Flags

| Flag | Description |
|------|-------------|
| `-h`, `--help` | Show help |
| `-v`, `--version` | Show version information |
| `--status` | Show server status and health (used by the container healthcheck) |
| `--mode {production\|development}` | Application mode (default: `production`) |
| `--config DIR` | Configuration directory |
| `--data DIR` | Data directory |
| `--cache DIR` | Cache directory |
| `--log DIR` | Log directory |
| `--backup DIR` | Backup directory |
| `--pid FILE` | PID file path |
| `--address ADDR` | Listen address (default: `[::]`) |
| `--port PORT` | Listen port (default: random `64xxx`, `80` in a container) |
| `--baseurl PATH` | URL path prefix (default: `/`) |
| `--daemon` | Run as a daemon (detach from the terminal) |
| `--debug` | Enable debug mode (unlocks `/debug/*` only — never bypasses auth) |
| `--color {auto\|yes\|no}` | Color output (default: `auto`; `NO_COLOR` honored) |
| `--lang CODE` | Language for output (default: auto-detect from `LANG`) |
| `--header HEADER` | Header to trust for the remote IP; repeatable. Replaces the default priority list when set |
| `--include-ssl` | Include SSL/TLS private keys in a backup (default: excluded) |
| `--include-data` | Include the full data directory in a backup (default: excluded) |

### Subcommands

| Command | Description |
|---------|-------------|
| `--service start\|stop\|restart\|reload\|status` | Control the installed OS service |
| `--service --install\|--uninstall\|--disable` | Install, remove, or disable the systemd/launchd/Windows service |
| `--maintenance backup [file]` | Create a `.tar.gz` backup archive (add `--include-ssl` / `--include-data` to widen it) |
| `--maintenance restore <file>` | Restore from a backup archive |
| `--maintenance update` | Alias for `--update yes` — install the newest binary |
| `--maintenance mode` | Show or set maintenance mode |
| `--maintenance setup` | Re-run first-run setup |
| `--maintenance pgp generate\|rotate\|publish\|export\|import\|delete` | Manage the server PGP keypair |
| `--maintenance secret rotate` | Rotate `server.security.encryption_key` (30-day grace period) |
| `--maintenance token list\|revoke` | List or revoke operator API tokens |
| `--maintenance data export\|delete` | Data-subject export/erasure for a given IP |
| `--maintenance compliance report` | Print the compliance status report |
| `--shell completions [SHELL]` | Print shell completions (bash, zsh, fish, powershell) |
| `--shell init [SHELL]` | Print the shell init snippet |
| `--update check` | Check GitHub Releases for a newer binary |
| `--update yes` | Download and install the newer binary |
| `--update branch {stable\|beta\|daily}` | Select the update channel |

## Client

**ipgaze-cli** is the companion terminal client — a scriptable CLI with an interactive TUI mode, built from the same source tree and versioned alongside the server (`make build` produces both binaries).

### Installation

```bash
# Download binary (Linux AMD64)
curl -q -LSsf -o ipgaze-cli https://github.com/apimgr/ipgaze/releases/latest/download/ipgaze-cli-linux-amd64
chmod +x ipgaze-cli
sudo mv ipgaze-cli /usr/local/bin/
```

### Usage

```bash
# Your public IP (plain text)
ipgaze-cli

# Lookup a specific IP
ipgaze-cli 8.8.8.8

# Full JSON output
ipgaze-cli --output json

# One field only
ipgaze-cli --field country

# Point at a specific server
ipgaze-cli --server https://ifcfg.us list

# Shell completions
ipgaze-cli --shell completions bash

# Check for / install CLI updates
ipgaze-cli --update check
ipgaze-cli --update yes
```

Running `ipgaze-cli` with no arguments and no piped output launches the interactive TUI.

### Configuration

The CLI reads/writes `cli.yml` (created automatically on first run, `0600` permissions):

| OS | Path |
|----|------|
| Linux/macOS | `~/.config/apimgr/ipgaze/cli.yml` (`$XDG_CONFIG_HOME` honored) |
| Windows | `%APPDATA%\apimgr\ipgaze\cli.yml` |

Server and token resolve in priority order: `--server`/`--token` flag > `IPGAZE_SERVER_PRIMARY`/`IPGAZE_TOKEN` env var > `cli.yml`. A flag only persists to `cli.yml` if the current config value is empty or invalid — otherwise it's used for that invocation only.

The CLI is an unauthenticated client to ipgaze's open API by default; a token is only needed to manage resources the token owns.

## Configuration

ipgaze uses `server.yml` for all operator configuration — auto-created with sane defaults on first run. It is the sole source of truth for server settings; the database only stores resource state, tokens, and the audit log.

### Location

| User Type | Path |
|-----------|------|
| Root | `/etc/apimgr/ipgaze/server.yml` |
| Regular user | `~/.config/apimgr/ipgaze/server.yml` (`$XDG_CONFIG_HOME` honored) |
| Docker container | `/config/ipgaze/server.yml` |

Override the config directory with `--config` or the `CONFIG_DIR` env var (first run only).

### Example

```yaml
server:
  port: "64123"
  fqdn: "ip.example.com"
  address: "[::]"
  mode: production

  database:
    driver: sqlite

  geoip:
    enabled: true
    deny_countries: []
    allow_countries: []

  rate_limit:
    enabled: true
    read:
      requests: 120
      window: 60
    write:
      requests: 10
      window: 60

  logging:
    level: warn

  cache:
    type: memory
    ttl: "1h"

  ssl:
    enabled: false
    letsencrypt:
      enabled: false

web:
  ui:
    theme: dark
  cors: "*"
```

### Precedence

For any value settable by flag, env var, and config file (highest wins):

1. CLI flag (e.g. `--port`, `--address`)
2. Project-prefixed environment variable (e.g. `IPGAZE_PORT`)
3. Generic environment variable (e.g. `PORT`)
4. `server.yml`
5. Built-in default

### Key Settings

| Section | Purpose |
|---------|---------|
| `server.port` / `server.address` | Listen port/address (default: random `64xxx`, `[::]`) |
| `server.mode` | `production` (default) or `development` |
| `server.database` | `sqlite` (default) or `libsql`/Turso |
| `server.geoip` | GeoIP database enable/disable, country allow/deny lists |
| `server.rate_limit` | Per-class (read/write/health) request limits |
| `server.cache` | `none`, `memory` (default), `valkey`, `redis`, or `memcache` |
| `server.logging` | Global + per-log level, rotation, retention |
| `server.ssl` | TLS and Let's Encrypt (DNS-01/HTTP-01) |
| `server.trusted_proxies` | Additional trusted proxy CIDRs (private ranges always trusted) |
| `web.cors` | Single origin, `*`, or comma-separated list |

Environment variables (`DOMAIN`, `MODE`, `DEBUG`, `DATABASE_DRIVER`, `SMTP_*`, and more), the full GeoIP/cache/rate-limit/logging schema, reverse-proxy examples, and the complete key reference live in [docs/configuration.md](docs/configuration.md).

## API

### Quick Examples

#### Get Your IP

```bash
# Plain text
curl -q -LSsf https://ifcfg.us/
# Output: 203.0.113.42

# JSON
curl -q -LSsf https://ifcfg.us/json
```

```json
{
  "ip": "203.0.113.42",
  "ip_decimal": 3405803306,
  "country": "United States",
  "country_iso": "US",
  "city": "Mountain View",
  "latitude": 37.386,
  "longitude": -122.0838,
  "timezone": "America/Los_Angeles",
  "asn": "AS15169",
  "asn_org": "Google LLC"
}
```

#### Lookup Specific IP

```bash
# IPv4
curl -q -LSsf https://ifcfg.us/8.8.8.8

# IPv6
curl -q -LSsf https://ifcfg.us/2001:4860:4860::8888
```

#### Get Specific Fields

```bash
curl -q -LSsf https://ifcfg.us/ip          # Your IP address
curl -q -LSsf https://ifcfg.us/country     # Your country
curl -q -LSsf https://ifcfg.us/city        # Your city
curl -q -LSsf https://ifcfg.us/asn         # Your ASN
```

### API v1 Endpoints

```bash
# Your IP info (JSON)
curl -q -LSsf https://ifcfg.us/api/v1

# Lookup specific IP
curl -q -LSsf https://ifcfg.us/api/v1/ip/8.8.8.8

# Get specific fields
curl -q -LSsf https://ifcfg.us/api/v1/country
curl -q -LSsf https://ifcfg.us/api/v1/city
curl -q -LSsf https://ifcfg.us/api/v1/asn
```

### IPv6 Support

```bash
# Force IPv4
curl -q -LSsf -4 https://ifcfg.us/

# Force IPv6
curl -q -LSsf -6 https://ifcfg.us/

# Lookup IPv6 address
curl -q -LSsf https://ifcfg.us/2001:4860:4860::8888
```

### Rate Limiting

Rate limiting is enabled by default and bucketed by request class — 120 reads
and 10 writes per 60-second window per client IP. Tune it under
`server.rate_limit` in `server.yml`.

On the public instance at https://ifcfg.us, please keep automated use to
**1 request per minute**.

## Development

### Requirements

- **Go**: latest stable
- **Make**: GNU Make
- **Docker**: For containerized testing (recommended)
- **Git**: For version control

### Build System & Testing

#### Makefile Targets

```bash
# Build for all platforms
make build
# Outputs to: binaries/

# Build for the local platform only
make local

# Run tests
make test

# Build Docker images
make docker

# Build and run locally for development
make dev

# Build release artifacts
make release
# Outputs to: releases/

# Cleanup
make clean          # Remove binaries/, releases/, and temp files
```

#### Platform Support

Builds for 8 platforms:
- Linux: amd64, arm64
- macOS: amd64, arm64
- Windows: amd64, arm64
- FreeBSD: amd64, arm64

#### Versioning

Version managed in `release.txt`:
```bash
cat release.txt
# Output: 0.0.9

# Version embedded in binary
./ipgaze -version
# Output: 0.0.9
```

### Development Mode

#### Local Development

```bash
# Clone repository
git clone https://github.com/apimgr/ipgaze.git
cd ipgaze

# Build for local testing (host OS/arch, output to a tempdir)
make local

# Build a Docker development image
make dev
```

#### Development Flags

```bash
# Minimal (no GeoIP)
./ipgaze --port 8080

# With GeoIP
./ipgaze --port 8080 --data data

# With custom directories
./ipgaze \
  --port 8080 \
  --data /tmp/ipgaze/data \
  --config /tmp/ipgaze/config
```

#### Debug Features

```bash
# Enable debug mode (unlocks /debug/*, /debug/pprof/*, /debug/vars)
./ipgaze --port 8080 --debug

# Access profiler
curl -q -LSsf http://localhost:8080/debug/pprof/
go tool pprof -http=:8081 http://localhost:8080/debug/pprof/heap
```

### CI/CD

#### GitHub Actions

- **Triggers**: Push to main/master, monthly schedule, manual
- **Workflows**:
  - `ci.yml` - Lint and test on push/PR
  - `licenses.yml` - License compatibility check on push/PR
  - `release.yml` - Binary builds for 8 platforms
  - `docker.yml` - Multi-arch Docker images (amd64, arm64)
- **Schedule**: 1st of month, 3:00 AM UTC

#### Jenkins Pipeline

- **Server**: jenkins.casjay.cc
- **Agents**: amd64, arm64
- **Stages**: Test → Build → Docker → Push → Release
- **Artifacts**: Binaries, Docker images, GitHub releases

### Testing

```bash
# Run Go tests
make test

# Run integration tests (auto-detects Incus, falls back to Docker)
./tests/run_tests.sh

# Run integration tests in Docker directly
./tests/docker.sh
```

## Disclaimer

This software is provided "as is" without warranty of any kind. Use at your own risk.

- **No Warranty**: The authors are not responsible for any damages, data loss, or issues arising from use of this software
- **Not Professional Advice**: This software does not constitute legal, financial, medical, or other professional advice
- **Third-Party Services**: If this software connects to external APIs or services, their terms of service apply separately
- **Security**: While we strive to follow security best practices, no software is guaranteed to be free of vulnerabilities
- **Production Use**: Evaluate thoroughly before deploying in production environments

By using this software, you acknowledge that you have read and understood this disclaimer.

## License

MIT License - See [LICENSE.md](LICENSE.md)

### Credits

- **echoip-compatible API**: implements the same route and response format as echoip for zero-change migrations
- **GeoIP Data**: [sapics/ip-location-db](https://github.com/sapics/ip-location-db) — free, no API key required
- **Maintained by**: [apimgr](https://github.com/apimgr)

### Attribution

GeoIP data:
- [sapics/ip-location-db](https://github.com/sapics/ip-location-db) — country, city, and ASN data (public domain / CC0)
- Country data: public domain (WHOIS aggregation)
