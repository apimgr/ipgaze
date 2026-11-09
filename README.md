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
- **Multiple Output Formats** - JSON, plain text, or server-rendered HTML
- **Built-In Languages** - Interface and CLI translations in English, Spanish, French, German, Italian, Chinese, Arabic, and Japanese
- **Auto-Updating GeoIP** - Weekly automatic database updates
- **Mobile-Friendly** - Responsive web interface
- **Fast & Lightweight** - Self-contained static binaries that manage their runtime data
- **No API Keys Required** - GeoIP databases auto-download
- **VPN/Proxy & Tor Detection** - `is_vpn`, `is_proxy`, `is_tor` fields from daily-updated threat lists
- **GraphQL Endpoint** - Flexible queries alongside the REST API
- **OpenAPI/Swagger UI** - Interactive API documentation
- **Model Context Protocol (MCP)** - Anonymous Streamable HTTP tools for public API operations
- **Prometheus Metrics** - Optional authenticated metrics endpoints for operators
- **PWA Support** - Web app manifest and service worker for offline use
- **Tor Hidden Service** - Auto-enabled when the `tor` binary is present; optional outbound Tor routing via `server.tor.use_network`
- **I2P Eepsite** - Opt-in via `server.i2p.enabled`
- **Privacy & Security Pages** - Consent-gated analytics, DPO contact, coordinated disclosure, and configurable form CAPTCHA
- **Abuse Protection** - IPv4/IPv6 allowlists and blocks with persisted, temporary request-flood blocking
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
curl -q -LSsf https://raw.githubusercontent.com/apimgr/ipgaze/main/scripts/install.sh | sudo bash
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

**Configuration**: Edit the generated `server.yml` in the configuration
directory. Do not use the service unit as the application configuration.

#### macOS

```bash
# Download binary (ARM64 for Apple Silicon, AMD64 for Intel)
curl -q -LSsf -o ipgaze https://github.com/apimgr/ipgaze/releases/latest/download/ipgaze-darwin-arm64
chmod +x ipgaze
sudo mv ipgaze /usr/local/bin/

# Run
ipgaze --port 64580
```

#### Windows

```powershell
# Download binary
Invoke-WebRequest -Uri "https://github.com/apimgr/ipgaze/releases/latest/download/ipgaze-windows-amd64.exe" -OutFile "ipgaze.exe"

# Run
.\ipgaze.exe --port 64580
```

### Docker Deployment

#### Docker Compose (Production)

**Download**:
```bash
curl -q -LSsf -o docker-compose.yml https://raw.githubusercontent.com/apimgr/ipgaze/main/docker/docker-compose.yml
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
  -p 172.17.0.1:64580:80 \
  -v ipgaze-config:/config \
  -v ipgaze-data:/data \
  --restart unless-stopped \
  ghcr.io/apimgr/ipgaze:latest
```

## Server CLI

`ipgaze --help` prints the full reference. Detailed help is available with
`ipgaze --service --help`, `ipgaze --maintenance --help`,
`ipgaze --shell --help`, and `ipgaze --update --help`.

### Flags

| Flag | Description |
|------|-------------|
| `-h`, `--help` | Show help |
| `-v`, `--version` | Show version information |
| `--status` | Show server status and health (used by the container healthcheck) |
| `--mode {production\|development\|debug}` | Application mode (default: `production`) |
| `--config DIR` | Configuration directory |
| `--data DIR` | Data directory |
| `--cache DIR` | Cache directory |
| `--log DIR` | Log directory |
| `--backup DIR` | Backup directory |
| `--pid FILE` | PID file path |
| `--address ADDR` | Listen address (default: `0.0.0.0`) |
| `--port PORT` | Listen port (default: random `64xxx`, `80` in a container) |
| `--baseurl PATH` | URL path prefix (default: `/`) |
| `--daemon` | Run as a daemon (detach from the terminal) |
| `--debug` | Enable debug mode (unlocks `/debug/*` only — never bypasses auth) |
| `--color {auto\|yes\|no}` | Color output (default: `auto`; `NO_COLOR` honored) |
| `--lang CODE` | Language for output (default: auto-detect from `LANG`; supported (8): `en`, `es`, `fr`, `de`, `it`, `zh`, `ar`, `ja`) |
| `--header HEADER` | Header to trust for the remote IP; repeatable. Replaces the default priority list when set |
| `--include-ssl` | Include SSL/TLS private keys in a backup (default: excluded) |
| `--include-data` | Include the full data directory in a backup (default: excluded) |

### Subcommands

| Command | Description |
|---------|-------------|
| `--service start\|stop\|restart\|reload\|status` | Control the installed OS service |
| `--service --install\|--uninstall\|--disable` | Install, remove, or disable the detected service (Linux systemd/OpenRC/runit/SysVinit/s6-overlay, macOS launchd, BSD rc.d, or Windows Service Control Manager) |
| `--maintenance backup [file]` | Create and verify a timestamped full `.tar.gz` archive (add `--include-ssl` / `--include-data` to widen it) |
| `--maintenance backup test` | Dry-run restore the backup set and verify the encrypted PGP key decrypts |
| `--maintenance restore <file>` | Restore from a backup archive |
| `--maintenance update` | Alias for `--update yes` — install the newest binary |
| `--maintenance mode` | Show or set maintenance mode |
| `--maintenance setup` | Re-run first-run setup |
| `--maintenance pgp generate\|rotate\|publish\|export\|import\|delete` | Manage the server PGP keypair |
| `--maintenance secret rotate` | Rotate `server.security.encryption_key` (30-day grace period) |
| `--maintenance security-report list` | List non-identifying security report triage metadata |
| `--maintenance security-report set <id> <status> [date] [comment...]` | Update a report's researcher-visible status and comment |
| `--maintenance token list\|revoke` | List or revoke operator API tokens |
| `--maintenance data export` | Print a JSON inventory of stored operational data and the configured privacy policy |
| `--maintenance data delete` | Interactively erase rate-limit and audit-log history |
| `--maintenance compliance report` | Show enabled standards and configured privacy/security controls; enabled standards require encrypted backups |
| `--shell --help` | Show shell integration usage and supported shells |
| `--shell completions [SHELL]` | Print shell completions (bash, zsh, fish, sh, dash, ksh, powershell, pwsh) |
| `--shell init [SHELL]` | Print the shell init snippet |
| `--update check` | Check GitHub Releases for a newer binary |
| `--update yes` | Download and install the newer binary |
| `--update branch {stable\|beta\|devel}` | Select the update channel; daily, rolling, dev, and development normalize to devel |

Scheduled backups create a full archive and a cumulative daily incremental
based on the previous full. The incremental is verified and retained with its
base; restoring it applies both archives. Hourly incrementals are optional and
disabled by default. See [backup configuration](docs/configuration.md#backups)
for retention and restore details.

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
ipgaze-cli --server https://ifcfg.us

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

The server resolves in priority order: `--server` flag > `server.primary` in `cli.yml` > the compiled-in official site. The token resolves through `--token`, `--token-file`, `IPGAZE_TOKEN`, and `cli.yml`. A flag only persists to `cli.yml` if the current config value is empty or invalid — otherwise it's used for that invocation only.

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
2. `server.yml` (once a value has been persisted there)
3. Environment variable — for `PORT`/`LISTEN` this only applies on first
   run (Init-Only); Runtime variables are re-checked every start
4. Built-in default

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

## Other

- [Installation guide](https://apimgr-ipgaze.readthedocs.io/en/latest/installation/)
- [Configuration reference](https://apimgr-ipgaze.readthedocs.io/en/latest/configuration/)
- [Translation guide](https://apimgr-ipgaze.readthedocs.io/en/latest/translating/)
- [Security policy](.github/SECURITY.md)
- Report product issues at the [GitHub issue tracker](https://github.com/apimgr/ipgaze/issues).

## Development

### Requirements

- **Go**: not required locally; the Makefile uses `casjaysdev/go:latest`
- **Make**: GNU Make
- **Docker**: Required for Go builds, tests, and binary execution
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

# Quick development build in a unique OS temp directory
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

# Build the server and client in the approved Go container
make local
```

### Development Mode

#### Local Development

```bash
# Clone repository
git clone https://github.com/apimgr/ipgaze.git
cd ipgaze

# Quick build for local testing (output to a project-scoped temp directory)
make dev

# Build local-platform binaries with version metadata
make local
```

#### Development Flags

```bash
# Run the service in its container with development mode enabled
docker run --rm -p 64580:80 -e MODE=development \
  ghcr.io/apimgr/ipgaze:latest

# With custom directories
docker run --rm -p 64580:80 \
  -v ipgaze-config:/config -v ipgaze-data:/data \
  ghcr.io/apimgr/ipgaze:latest
```

#### Debug Features

```bash
# Enable debug mode (unlocks /debug/*, /debug/pprof/*, /debug/vars)
docker run --rm -p 64580:80 -e MODE=debug -e DEBUG=true \
  ghcr.io/apimgr/ipgaze:latest

# Access profiler
curl -q -LSsf http://localhost:64580/debug/pprof/
docker run --rm --network host casjaysdev/go:latest \
  go tool pprof -http=:8081 http://127.0.0.1:64580/debug/pprof/heap
```

### CI/CD

#### GitHub Actions

- **Triggers**: Push and pull request to main/master, weekly schedule, manual
- **Workflows**:
  - `ci.yml` - Lint, tests, builds, coverage, vulnerability and full-history secret scans, image scan, and action SHA policy; main/master push and pull request, weekly, or manual
  - `licenses.yml` - Dependency license check; main/master push and pull request, or manual
  - `daily.yml` - Eight-platform daily builds and rolling release; daily, main/master push, or manual
  - `beta.yml` - Beta builds; push to `beta` or manual
  - `release.yml` - Eight-platform tagged release; version tag or manual
  - `docker.yml` - Multi-architecture Docker images (amd64, arm64); all branch pushes, version tags, daily, or manual

#### Other CI Providers

GitLab CI, Gitea Actions, Forgejo Actions, and Jenkins provide equivalent
build, test, security, and release workflows. GitLab and Jenkins agents need
Docker Engine access and Python 3 for secret-scan policy evaluation. GitLab
shell runners also need `curl`, Docker Buildx, and ARM64 binfmt support for
multi-architecture release images. Set a masked `GITLAB_TOKEN` CI variable to
a project access token with API scope and Maintainer access so scheduled devel
pipelines can replace the rolling `devel` release and tag. Go builds run in
`casjaysdev/go:latest` containers.

#### Jenkins Pipeline

- **Server**: jenkins.casjay.cc
- **Agents**: amd64, arm64
- **Stages**: Build → Lint → Security → Test → License Check → Docker → Push → Release
- **Artifacts**: Binaries, Docker images, GitHub releases

### Testing

```bash
# Run the Go test suite in Docker with coverage enforcement
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
