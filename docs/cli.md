# CLI Reference

Command-line interface reference for **ipgaze** server and client binaries.

## Server Binary

The main `ipgaze` binary runs the IP lookup server.

### Usage

```bash
ipgaze [flags]
ipgaze [command]
```

### Commands

| Command | Description |
|---------|-------------|
| `--shell completions` | Generate shell completions |
| `--shell init` | Initialize shell integration |

### Flags

Only `-h` (help) and `-v` (version) have short forms.

| Flag | Description | Default |
|------|-------------|---------|
| `-h`, `--help` | Show help (`--help` for any command shows its help) | - |
| `-v`, `--version` | Show version | - |
| `--status` | Show server status and health | - |
| `--mode {production\|development}` | Application mode | `production` |
| `--config DIR` | Config directory | - |
| `--data DIR` | Data directory | - |
| `--cache DIR` | Cache directory | - |
| `--log DIR` | Log directory | - |
| `--backup DIR` | Backup directory | - |
| `--include-ssl` | Include SSL/TLS keys in backup | excluded |
| `--include-data` | Include full data dir in backup | excluded |
| `--pid FILE` | PID file path | - |
| `--address ADDR` | Listen address | `0.0.0.0` |
| `--port PORT` | Listen port | random `64xxx` (`80` in container) |
| `--baseurl PATH` | URL path prefix | `/` |
| `--daemon` | Run as daemon (detach from terminal) | `false` |
| `--debug` | Enable debug mode | `false` |
| `--color {auto\|yes\|no}` | Color output | `auto` |
| `--lang CODE` | Language for output | `auto` |
| `--header HEADER` | Header to trust for remote IP (repeatable) | - |
| `--service CMD` | Service management (`--service --help` for details) | - |
| `--maintenance CMD` | Maintenance operations (`--maintenance --help` for details) | - |
| `--update [CMD]` | Check/perform updates (`--update --help` for details) | - |

Reverse DNS hostname lookup and port reachability testing (`/port/{port}`)
are always enabled — no flag needed.

### Examples

```bash
# Start with defaults
ipgaze

# Custom port
ipgaze --port 9090

# With custom data directory
ipgaze --port 8080 --data /var/lib/ipgaze

# Debug mode with colors
ipgaze --debug --color yes

# Run as daemon
ipgaze --port 8080 --daemon --pid /var/run/ipgaze.pid
```

### Version Output

```bash
$ ipgaze --version
ipgaze 1.0.0
Built: 2026-01-15T10:30:00Z
Go: go1.24.0
OS/Arch: linux/amd64
```

Format: `{binary} {version}`, then `Built:`, `Go:` and `OS/Arch:` lines.

### Shell Completions

Generate completions for your shell:

```bash
# Bash
ipgaze --shell completions bash > /etc/bash_completion.d/ipgaze

# Zsh
ipgaze --shell completions zsh > ~/.zsh/completions/_ipgaze

# Fish
ipgaze --shell completions fish > ~/.config/fish/completions/ipgaze.fish
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `NO_COLOR` | Disable colored output (per no-color.org) |
| `PORT` | Override listen port |
| `DATA_DIR` | Override data directory |

```bash
# Disable colors
NO_COLOR=1 ipgaze

# Custom port via environment
PORT=9090 ipgaze
```

## Client Binary

The `ipgaze-cli` binary is a command-line client for IP lookups.

### Usage

```bash
ipgaze-cli [flags] [ip]
ipgaze-cli [command]
```

### Commands

| Command | Description |
|---------|-------------|
| `--shell completions` | Shell integration: print completions |
| `--shell init` | Shell integration: print init command |
| `--update check` | Check for updates |
| `--update yes` | Download and install update |

### Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-h`, `--help` | Show this help message | - |
| `-v`, `--version` | Show version information | - |
| `--server URL` | Server URL to query | - |
| `--token TOKEN` | API token for authenticated operations | - |
| `--output FORMAT` | Output format: `json`, `plain`, `auto` | `auto` |
| `--field NAME` | Output specific field only | - |
| `--lang CODE` | Language for output | `auto` |
| `--color MODE` | Color output: `auto`, `yes`, `no` | `auto` |
| `--debug` | Enable debug output | `false` |
| `--shell CMD` | Shell integration: `completions`, `init` | - |
| `--update CMD` | Auto-update: `check`, `yes` | - |

Fields: `ip`, `country`, `country-iso`, `city`, `region`, `asn`,
`asn-org`, `latitude`, `longitude`, `timezone`, `postal-code`.

### Examples

```bash
# Get your IP
ipgaze-cli

# Lookup specific IP
ipgaze-cli 8.8.8.8

# Full JSON output
ipgaze-cli --output json

# Country only
ipgaze-cli --field country

# Use custom server
ipgaze-cli --server https://ip.example.com

# Check for updates
ipgaze-cli --update check
```

### Client Environment Variables

Each overrides `cli.yml` and is in turn overridden by the matching flag.

| Variable | Description |
|----------|-------------|
| `IPGAZE_DEBUG` | Enable client debug output; accepts any truthy value (`true`, `1`, `yes`, `on`). Overridden by `--debug` |
| `IPGAZE_SERVER_TIMEOUT` | HTTP request timeout, as a Go duration (`5s`, `1m`) or a bare number of seconds (`12`). Invalid values fall back to the built-in default |
| `IPGAZE_SERVER_PRIMARY` | Server base URL. Overridden by `--server`; falls back to `server.primary` in `cli.yml`, then the compiled-in official site |
| `IPGAZE_TOKEN` | API token. Resolved after `--token`/`--token-file` and before `auth.token`/`auth.token_file` in `cli.yml` |
| `IPGAZE_OUTPUT_FORMAT` | Output format. Overridden by `--output`; falls back to `output.format` in `cli.yml` |

### Configuration File

Client configuration is stored at `~/.config/apimgr/ipgaze/cli.yml`:

```yaml
# Default server
server: "https://ifcfg.us"

# Output settings
output: auto
color: auto
```

### First-Run Wizard

On first run, the client prompts for configuration:

```bash
$ ipgaze-cli
Welcome to ipgaze CLI!

Enter server URL [https://ifconfig.co]: https://ip.example.com
Save configuration? [Y/n]: y

Configuration saved to ~/.config/apimgr/ipgaze/cli.yml

Your IP: 203.0.113.42
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Invalid arguments |
| 3 | Configuration error |
| 4 | Network error |
| 5 | Server error |

## Signals

The server handles these signals:

| Signal | Action |
|--------|--------|
| `SIGTERM` | Graceful shutdown |
| `SIGINT` | Graceful shutdown (Ctrl+C) |
| `SIGHUP` | Reload configuration |
| `SIGUSR1` | Reload GeoIP databases |
