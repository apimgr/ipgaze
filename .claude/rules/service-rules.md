# Service Rules (PART 23, 24)

⚠️ **These rules are NON-NEGOTIABLE. Violations are bugs.** ⚠️

## CRITICAL - NEVER DO
- Never prompt for escalation if the user cannot actually escalate (not in sudoers/wheel/admin) — show an
  informative error instead; only prompt when escalation is actually possible, and skip the prompt entirely
  if already root/admin
- Never use a UID/GID that isn't equal — the same numeric value MUST back both UID and GID
- Never pick a UID/GID from the reserved/well-known list (65534 nobody, 999/998/997/996/995 systemd/docker,
  994-980 systemd-network/kvm/render/pipewire/colord/geoclue/avahi/rtkit/saned/usbmux/cups, 170-179, 101-110
  sshd/postfix/dovecot) even if it currently appears free on the host
- Never let `--service --install` do anything beyond installing, enabling, and starting the service — user
  creation, privilege escalation, directory setup, and permissions belong to normal binary startup, not to
  install
- Never uninstall without the confirmation prompt: "This will delete ALL data, configs, and the system
  user. Continue? [y/N]"
- Never delete the binary itself during `--service --uninstall` — print
  "Service uninstalled. Delete binary manually: rm {binary_path}" instead
- Never skip dedicated service-user creation unless IDEA.md explicitly approves permanent root/Administrator
  for this project
- Never run a Windows service as Local System, Administrator, or a logged-in user — Virtual Service Account
  (`NT SERVICE\{internal_name}`) is the default and required unless documented otherwise

## CRITICAL - ALWAYS DO
- Follow OS escalation order: Linux — already root, sudo, su, pkexec, doas; macOS — already root, sudo,
  osascript (GUI); BSD — already root, doas, sudo, su; Windows — already Administrator, UAC prompt, runas
- On Unix, start elevated only to bind privileged ports, then drop privileges to `{internal_name}` after
  binding; on macOS this is root→bind→drop→run; Windows uses VSA so no privilege drop is needed
- Find the UID/GID by scanning from the top of the safe range downward, skipping reserved IDs and any ID
  already used for UID or GID, stopping at the bottom of the range with an error if none are free: Linux/BSD
  safe range 200-899 (scan from 899 down to 200), macOS safe range 200-399 (scan from 399 down to 200)
- Create the system user as: username=group=`{internal_name}`, matching UID/GID, shell
  `/sbin/nologin`/`/usr/sbin/nologin`, home = config dir or data dir (home directory must exist before user
  creation — create directories, then user, then set ownership), gecos `{internal_name} service account`,
  no password/no login
- On `--service --install`: detect the platform's init system (systemd/OpenRC/SysVinit/runit on Linux,
  launchd on macOS, rc.d on FreeBSD, Windows Service on Windows), then if root/admin install+enable+start a
  system service, else fall back to a user-level service (systemd --user, launchctl user agent) and
  install+enable+start that instead
- On `--service --uninstall`: stop, disable, remove the service file, then delete config/data/cache/log/
  backup directories, the PID file, and the system user/group — in that order — after the confirmation
  prompt passes
- On `--service --disable`: stop and disable only — keep the service file, all data, and the user/group so
  `--service --install` can re-enable it later
- Support the full `--service` subcommand set: `start`, `stop`, `restart`, `reload`, `status`,
  `--install`, `--disable`, `--uninstall`, `--help` — status output must show Service/State/Auto-start/PID
- Detect the init system correctly per platform: systemd (`/etc/systemd/system/{internal_name}.service`),
  OpenRC (`/etc/init.d/{internal_name}`, openrc-run script), SysVinit (`/etc/init.d/{internal_name}`,
  chosen only when `/sbin/openrc-run` and `systemctl` are both absent but `update-rc.d`/`chkconfig` work),
  runit (`/etc/sv/{internal_name}/run` + `log/run`), rc.d (`/usr/local/etc/rc.d/{internal_name}`), launchd
  (`/Library/LaunchDaemons/{plist_name}.plist`), Windows Service (`golang.org/x/sys/windows/svc`)
- Every service unit/script must reference `{internal_name}` for identity/paths (stable across binary
  renames) and `{project_name}`/`{app_name}` only for the executable path and display text
- Apply systemd security hardening (`ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, explicit
  `ReadWritePaths=` for config/data/cache/log dirs) on every systemd unit

## Key Rules Summary
Application user creation requires privilege escalation; if escalation is impossible, run unprivileged with
user-level directories. `--service --install/--uninstall/--disable` only manage the service lifecycle — the
binary's own normal startup sequence (not the install/uninstall paths) owns user creation, privilege
escalation, and directory setup. UID/GID are always equal, chosen from a safe range by scanning downward and
skipping a fixed reserved-ID list, never reused from that list even if free. Every supported init system
(systemd, OpenRC, SysVinit, runit, rc.d, launchd, Windows Service) must be detected and supported, each
keyed off `{internal_name}` for paths/identity. Uninstall is destructive — it always deletes all data and
the system user after an explicit y/N confirmation — and never removes the binary itself.

For complete details, see AI.md PART 23, PART 24.
