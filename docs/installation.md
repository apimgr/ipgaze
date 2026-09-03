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

# Test
curl -q -LSsf http://localhost:8080/
```

ipgaze creates and owns everything under `/config` and `/data` itself on
first run — no manual directory creation or permission fixing needed.

### Docker Run

```bash
docker run -d \
  --name ipgaze \
  -p 8080:80 \
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

## Systemd Service

For production Linux deployments, use systemd.

### Create User

```bash
sudo useradd -r -s /bin/false ipgaze
```

### Create Directories

```bash
sudo mkdir -p /var/lib/ipgaze /var/log/ipgaze /etc/ipgaze
sudo chown ipgaze:ipgaze /var/lib/ipgaze /var/log/ipgaze /etc/ipgaze
```

### Service File

Create `/etc/systemd/system/ipgaze.service`:

```ini
[Unit]
Description=ipgaze - IP address lookup service
Documentation=https://apimgr-ipgaze.readthedocs.io
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ipgaze
Group=ipgaze
ExecStart=/usr/local/bin/ipgaze --listen :8080 --data /var/lib/ipgaze
Restart=on-failure
RestartSec=5s

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/ipgaze /var/log/ipgaze

[Install]
WantedBy=multi-user.target
```

### Enable and Start

```bash
sudo systemctl daemon-reload
sudo systemctl enable ipgaze
sudo systemctl start ipgaze
sudo systemctl status ipgaze
```

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
ipgaze --listen :8080

# Test (in another terminal)
curl -q -LSsf http://localhost:8080/
```

## Next Steps

- [Configuration](configuration.md) - Configure ipgaze for your environment
- [CLI Reference](cli.md) - All command-line options
- [Server Administration](admin.md) - File-based configuration
