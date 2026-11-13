# Server Administration

Server administration for **ipgaze** is file-only — there is no admin web UI and no
runtime configuration API.

## Overview

All configuration is managed via `server.yml`. The server watches this file
and reloads settings that support live changes. Settings bound at startup, such
as the listen address or port, require a restart; the health endpoint reports
when a restart is required.

## Configuration

Edit `server.yml` with any text editor. Live-changeable settings take effect
after the file is saved; restart-required settings are applied after restarting
the service.

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

Operator tokens are managed by the maintenance command group:

```bash
ipgaze --maintenance token list
ipgaze --maintenance token revoke <prefix>
```

## Service Management

The service manager is detected automatically. With `sudo`, installation
creates a system service. Without elevation, Linux systemd and macOS launchd
create a service for the current user. Linux installations can also use
OpenRC, runit, SysVinit, or s6-overlay; BSD uses rc.d.

```bash
# Install and start a system service
sudo ipgaze --service --install

# Install and start a per-user systemd service or LaunchAgent
ipgaze --service --install

# Show current service status
ipgaze --service status

# Disable the service at startup (keeps configuration and data)
ipgaze --service --disable

# Uninstall the service
ipgaze --service --uninstall
```

For s6-overlay, run the service command with permission to update
`/etc/s6-overlay/s6-rc.d` and its live database. Installation enables the
service in the user bundle and starts it. Disable removes it from the bundle
while retaining its service definition and data; install again to re-enable
and start it.

Uninstall asks for confirmation, stops and removes the service definition,
then deletes configuration and data. The executable remains and its path is
printed so it can be removed manually.

Back up before changing or replacing `server.yml`. The service lifecycle and
maintenance commands are also listed by `ipgaze --help` and the relevant
`--service --help` or `--maintenance --help` output.
