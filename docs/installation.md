# Installation

Complete guide for installing **ipgaze** on various platforms.

## Docker (Recommended)

The easiest way to run ipgaze is with Docker.

### Docker Compose

Download and start with docker-compose:

```bash
# Download compose file
curl -q -LSsf -o docker-compose.yml \
  https://raw.githubusercontent.com/apimgr/ipgaze/main/docker/docker-compose.yml

# Start service
docker-compose up -d

# Test (the published port is bound to the Docker bridge)
curl -q -LSsf http://172.17.0.1:64580/
```

ipgaze creates and owns everything under `/config` and `/data` itself on
first run — no manual directory creation or permission fixing needed.

### Docker Run

```bash
docker run -d \
  --name ipgaze \
  -p 172.17.0.1:64580:80 \
  -v ipgaze-config:/config \
  -v ipgaze-data:/data \
  --restart unless-stopped \
  ghcr.io/apimgr/ipgaze:latest
```

## Binary Installation

### Linux (AMD64)

```bash
# Download
curl -q -LSsf -o ipgaze \
  https://github.com/apimgr/ipgaze/releases/latest/download/ipgaze-linux-amd64

# Make executable
chmod +x ipgaze

# Move to PATH
sudo mv ipgaze /usr/local/bin/

# Verify
ipgaze --version
```

### Linux (ARM64)

```bash
curl -q -LSsf -o ipgaze \
  https://github.com/apimgr/ipgaze/releases/latest/download/ipgaze-linux-arm64
chmod +x ipgaze
sudo mv ipgaze /usr/local/bin/
```

### macOS (Darwin)

```bash
# Intel
curl -q -LSsf -o ipgaze \
  https://github.com/apimgr/ipgaze/releases/latest/download/ipgaze-darwin-amd64

# Apple Silicon
curl -q -LSsf -o ipgaze \
  https://github.com/apimgr/ipgaze/releases/latest/download/ipgaze-darwin-arm64

chmod +x ipgaze
sudo mv ipgaze /usr/local/bin/
```

### Windows

Download the appropriate binary from the [releases page](https://github.com/apimgr/ipgaze/releases):

- `ipgaze-windows-amd64.exe` (Intel/AMD)
- `ipgaze-windows-arm64.exe` (ARM)

### FreeBSD

```bash
# AMD64
curl -q -LSsf -o ipgaze \
  https://github.com/apimgr/ipgaze/releases/latest/download/ipgaze-freebsd-amd64

# ARM64
curl -q -LSsf -o ipgaze \
  https://github.com/apimgr/ipgaze/releases/latest/download/ipgaze-freebsd-arm64

chmod +x ipgaze
```

## System Service

The server installs the supported service unit and prepares its directories
through its service command. Run the command with the privileges required by
your operating system:

```bash
sudo ipgaze --service --install
sudo ipgaze --service status
```

Use `ipgaze --service --help` to see platform-specific service operations.
The application reads its settings from the generated `server.yml`; do not
edit the service unit to configure the application.

## Build from Source

### Prerequisites

- Docker (required for builds)
- Make

### Build

```bash
git clone https://github.com/apimgr/ipgaze.git
cd ipgaze
make build
```

Binaries are output to `binaries/` directory.

### Build All Platforms

```bash
make release
```

Builds for all 8 supported platforms:

- linux-amd64, linux-arm64
- darwin-amd64, darwin-arm64
- windows-amd64, windows-arm64
- freebsd-amd64, freebsd-arm64

## Verify Installation

```bash
# Check version
ipgaze --version

# Start server
ipgaze --address 0.0.0.0 --port 8080

# Test (in another terminal)
curl -q -LSsf http://localhost:8080/
```

## Next Steps

- [Configuration](configuration.md) - Configure ipgaze for your environment
- [CLI Reference](cli.md) - All command-line options
- [Server Administration](admin.md) - File-based configuration
