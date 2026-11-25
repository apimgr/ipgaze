# Server Administration

Server administration for **ipgaze** is file-only — there is no admin web UI and no
runtime configuration API.

## Overview

Configuration is split between `server.yml`, ordered `yaml.d/*.yml` drop-ins,
and credential-only `secrets.yml`. The server watches these files and reloads
settings that support live changes. Settings bound at startup, such as the
listen address or port, require a restart; the health endpoint reports when a
restart is required.

## Configuration

Edit the appropriate file with any text editor. Put node-local settings in
`server.yml`, application settings in the matching `yaml.d/` drop-in, and
credentials in `secrets.yml`. Live-changeable settings take effect after the
file is saved; restart-required settings are applied after restarting the
service.

See the [Configuration](configuration.md) reference for all available settings.

## server.token

On first run, ipgaze auto-generates an `adm_` operator token and writes it to
`secrets.yml`:

```yaml
server:
  token: <shown-once-value>
```

This is the server-wide operator credential for protected operator operations.
The raw value is shown once at first startup; the maintenance token commands do
not display it. Owner tokens are separate credentials for resources visitors
create and for MCP access. Visitors can issue them from the public tokens page.

To replace the token, update its value in `secrets.yml` and restart the service.

## Email Maintenance

Configure SMTP under `server.notifications.email` before using email features.
The maintenance test command sends a real test message to the configured
reply-to address, or to an explicit address. Its dry-run validates and renders
all built-in templates and any file overrides without contacting SMTP:

```bash
ipgaze --maintenance email test --dry-run
ipgaze --maintenance email test --to operator@example.net
```

Template overrides live in `{config_dir}/template/email/{name}.txt`. Each file
starts with `Subject: ...`, followed by a line containing `---`, then a plain
text body. Supported `{variable}` placeholders are validated by the dry-run;
an invalid override is reported and the embedded default remains active.

## Token Management (CLI)

The maintenance token commands support listing and revoking issued API tokens
by prefix. They do not rotate `server.token`. Owner tokens are issued by
visitors; linked tokens can be created, revealed, rotated, renamed, expired,
and revoked from the tokens page. Token-management API mirrors require the
primary owner Bearer token.

```bash
ipgaze --maintenance token list
ipgaze --maintenance token revoke <prefix>
```

## Service Management

The service manager is detected automatically. With `sudo`, installation
creates a system service. Without elevation, Linux systemd and macOS launchd
create a service for the current user. Linux installations can also use
OpenRC, runit, SysVinit, or s6-overlay; BSD uses rc.d.
Incus/LXC system containers running systemd or OpenRC use system-service mode;
the server starts with the privileges needed for setup, then drops to its
dedicated service account.

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
