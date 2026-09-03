# Server Administration

Server administration for **ipgaze** is file-only — there is no admin web UI and no
runtime configuration API.

## Overview

All configuration is managed via `server.yml`. The server watches this file for changes
and reloads immediately — no restart required.

## Configuration

Edit `server.yml` with any text editor. Changes take effect as soon as the file is saved.

See the [Configuration](configuration.md) reference for all available settings.

## server.token

On first run, ipgaze auto-generates a `server.token` value and writes it to `server.yml`:

```yaml
server:
  token: tok_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

This token is the operator identity used for resource ownership operations via the CLI.
It allows the operator to manage resource tokens (view, revoke) regardless of which
per-resource token was originally issued.

To rotate the token: edit `server.yml` and replace the value, then save — the server
reloads the new token immediately.

## Token Management (CLI)

```bash
# List all active resource tokens
ipgaze token list

# Revoke a specific resource token by prefix
ipgaze token revoke <prefix>
```

## Service Management

```bash
# Install and start as a system service
ipgaze --service --install

# Stop the service (keeps all data)
ipgaze --service --disable

# Uninstall and delete all data
ipgaze --service --uninstall
```
