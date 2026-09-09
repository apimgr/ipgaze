# Binary Rules (PART 7, 8, 32)

⚠️ **These rules are NON-NEGOTIABLE. Violations are bugs.** ⚠️

## CRITICAL - NEVER DO
- Never build with `go` directly on the host — all builds go through Docker (`casjaysdev/go:latest`) or the Makefile targets
- Never guess CLI flag names, binary output paths, or client behavior — read AI.md PART 7/8/32 before touching `src/client/` or binary entrypoints
- Never skip `--help`/`--version` verification after a CLI change
- (PART 7) Never embed security databases (GeoIP, blocklists, CVE/NVD, Trivy DB) in the binary — they live under `{data_dir}/security/` with `.last_updated` markers, downloaded at runtime, and every consumer degrades gracefully when they are absent
- (PART 7) Never require CGO or a dynamically linked dependency — one static binary, `CGO_ENABLED=0`, pure-Go deps only
- (PART 7) Never emit ANSI escapes, emojis, spinners, or box-drawing when `TERM=dumb` — that forces CLI mode
- (PART 8) Never hand-roll flag parsing in the server binary and never add cobra/viper to it — stdlib `flag` only (cobra/viper are the client binary's, PART 32)
- (PART 8) Never add, rename, or remove a server command/flag — the `--help`/`--version`/`--status`/`--shell`/`--mode`/`--config`/`--data`/`--cache`/`--log`/`--backup`/`--pid`/`--address`/`--port`/`--baseurl`/`--daemon`/`--debug`/`--color`/`--lang`/`--service`/`--maintenance`/`--update` set is fixed
- (PART 8) Never resolve `~`/`$HOME` after the privilege drop — the system-vs-user directory mode is locked once at process start from the EUID (`paths.startedElevated`)
- (PART 8) Never handle SIGHUP — it is explicitly ignored; config reloads come from the file watcher
- (PART 8) Never write or check a PID file inside a container — process supervision belongs to the orchestrator
- (PART 8) Never treat a signal-0 `EPERM` as a dead process — the PID belongs to another user and is still running, so the PID file is not stale
- (PART 8) Never substring-match the process name for stale-PID checks — exact basename only, or `ipgaze-cli` matches `ipgaze`
- (PART 32) Never implement `--tui`, `--cli`, `--gui`, or a `--mode tui/cli/gui` flag — display mode is auto-detected from the environment (`display.DetectDisplayEnv()`); `--mode` is reserved for `production`/`development` app mode only, never UI mode
- (PART 32) Never launch the TUI for `-h`/`--help`/`-v`/`--version` — these always print and exit immediately, in CLI/plain mode, never TUI
- (PART 32) Never persist a `--server`/`--token`/other config-flag value to `cli.yml` when the current stored value is already valid — only save when current is empty or invalid (`SaveIfEmptyOrInvalid`); a valid flag value is used for the session only
- (PART 32) Never store `cli.yml` with anything looser than `0600` (Unix) / non-user-only ACL (Windows) — it holds the API token
- (PART 32) Never build the CLI's optional GUI with Electron or a web view — native toolkit only (GTK4/Qt6 Linux, Cocoa macOS, Win32/WinUI Windows), and never let it lag the TUI in feature coverage
- (PART 32) Never attempt GUI mode over SSH/Mosh even if `DISPLAY` is set — remote sessions always use TUI

## CRITICAL - ALWAYS DO
- Use `make dev` / `make local` / `make build` for binary builds, never a raw `go build`
- Keep `src/client/` present for all projects (client scope is mandatory per PART 32)
- Verify CLI changes by building and exercising the binary (flags, exit codes, stdout/stderr) before reporting done
- (PART 7) Embed templates, static assets, locales, and bundled data with `embed`; keep the binary self-contained and runnable with zero config on first run
- (PART 7) Detect the display environment through `display.DetectDisplayEnv()` — Wayland before X11, macOS, then Windows — and honor SSH/mosh/screen/container detection
- (PART 7) Size output through `terminal.GetTerminalSize()` and the seven `SizeMode` tiers (Micro/Minimal/Compact/Standard/Wide/Ultrawide/Massive) plus `ShowASCIIArt`/`ShowBorders`/`ShowSidebar`/`ShowIcons`
- (PART 7) Resolve palettes through `theme.GetThemePalette(mode)` — `"auto"` consults `theme.IsSystemDarkTheme()` (COLORFGBG); never hardcode colors
- (PART 8) Resolve color with the full priority chain: `--color` flag > `output.color` in server.yml > `NO_COLOR` env > TTY/`TERM` autodetect. `output.emoji: true` deliberately keeps emojis on under `NO_COLOR`; NO_COLOR never disables bold or box-drawing
- (PART 8) Create every directory flag's target if missing, with root perms `0755`/`0644` or user perms `0700`/`0600`, validate writability, and log creation at INFO (`EnsureDir`, `EnsurePIDFile`)
- (PART 8) Prefer the system backup dir when writable; fall back to `{data_dir}/backup/` in system mode and the user dir in user mode (`GetBackupDir`)
- (PART 8) Handle SIGTERM/SIGINT/SIGQUIT/SIGRTMIN+3 (signal 37) as graceful shutdown, SIGUSR1 as log reopen, SIGUSR2 as status dump
- (PART 8) Re-check runtime env fallbacks every start (`CONFIG_DIR`, `DATA_DIR`, `CACHE_DIR`, `LOG_DIR`, `PID_FILE`, `PORT`, `LISTEN`, `MODE`, `DATABASE_DIR`, `BACKUP_DIR`) and keep Init-Only vars first-run only
- (PART 8) Take the display name from `filepath.Base(os.Args[0])` so a renamed binary self-identifies, while User-Agent and default paths keep the hardcoded `ipgaze`/`apimgr` identifiers
- (PART 32) Resolve the CLI server URL by priority: `--server` flag > `{PROJECT_NAME}_SERVER_PRIMARY` env > `cli.yml` `server.primary` > compiled default
- (PART 32) Honor `NO_COLOR` (any non-empty value) ahead of `--color`/auto-detect for every colorized/emoji code path; priority is CLI flag > `NO_COLOR` env > TTY/TERM auto-detect
- (PART 32) Run the CLI auto-update check on every invocation (it's short-lived) plus on `--update check`; verify SHA-256 before an atomic binary replace; refuse further requests below `cli_min_version` until updated
- (PART 32) Use the actual invoked binary name (`filepath.Base(os.Args[0])`) for `--help`/`--version` display text, but the hardcoded `{project_name}` for the internal project name and `{project_name}-cli/{version}` User-Agent

## PART 32: Client

**Binary:** default name `{project_name}-cli`; versioned with the main app; built by the same `make build`.

**Config file (`cli.yml`):**

| OS | Path |
|----|------|
| Unix | `~/.config/{internal_org}/{internal_name}/cli.yml` |
| Windows | `%APPDATA%\{internal_org}\{internal_name}\cli.yml` |

Perms: `0600` (Unix) / user-only ACL (Windows) — contains server URL + API token.

**Mode detection (no UI flags — see NEVER DO):**

| Condition | Result |
|-----------|--------|
| `-h`/`--help`/`-v`/`--version` | Print, exit — CLI mode, never TUI |
| Interactive terminal + no command | TUI |
| Interactive terminal + config-only flags (`--config`/`--server`/`--token`/`--debug`) | TUI |
| Interactive terminal + positional command/args | CLI (plain text) |
| Piped/redirected output, or non-interactive (cron/CI) | Plain output |
| `cli.yml` `display.mode: gui\|tui` | Forces that mode (errors if unavailable) |

**Exit codes:** `0` success, `1` general error, `2` config error, `4` auth error, `64` usage error (matches `EX_USAGE`).

**Auto-update (`--update check` / `--update yes`):** discover via `/api/autodiscover` (`cli_versions[os-arch]`, `cli_min_version`) → download `{base}/cli/binaries/{project_name}-cli-{os}-{arch}` to a tmp path → verify SHA-256 → atomic replace → re-exec with original argv. Permission-denied install path prints a clean message instead of failing hard.

**Setup wizard:** only binary with a full interactive first-run flow (no WebUI for CLI). SSH/Mosh always forces TUI; local display with no remote session gets GUI; terminal-without-display gets TUI; neither → error. Wizard prompts for server URL, tests the connection, optionally saves the token, then launches the full TUI/GUI.

**Theming:** CLI/TUI use the ANSI-mapped `TerminalPalette` (`src/common/theme/colors.go`), never the literal hex `ThemePalette` used by web/GUI.

**Responsive layout:** must look professional from Micro (<40 cols) through Massive (400+ cols) terminal widths, plus GUI DPI/window-size scaling.

## Key Rules Summary

### PART 7: Binary Requirements

**One static binary.** `CGO_ENABLED=0`, pure-Go dependencies, cross-compiled for Linux/BSD/macOS/Windows on amd64 and arm64. Templates, static assets, locales, and bundled data ship inside it via `embed`; running it with no config, no data dir, and no arguments must work.

**Not embedded:** security databases — GeoIP, blocklists, CVE/NVD, and the Trivy DB (OCI artifact `ghcr.io/aquasecurity/trivy-db:2`) — live under `{data_dir}/security/` with `.last_updated` markers and are fetched at runtime. Every consumer degrades gracefully when a database is missing or stale.

**Display detection** (`src/common/display`): `DisplayEnv` records terminal/SSH/mosh/screen/container state and platform display (Wayland > X11 > macOS > Windows); `DisplayMode` is one of Headless/CLI/TUI/GUI. `TERM=dumb` forces CLI with no ANSI, emojis, spinners, or box-drawing.

**Terminal sizing** (`src/common/terminal/size.go`): `SizeModeMicro` (<40 cols/<10 rows) through `SizeModeMassive` (400+/80+), with `ShowASCIIArt` (>= Standard), `ShowBorders` (>= Compact), `ShowSidebar` (>= Wide), `ShowIcons` (>= Minimal).

**Shared modules:** `src/common/{display,theme,terminal,banner,version}` — used by both the server and the client binary. The banner renders in four tiers (full/compact/minimal/micro) chosen from the terminal size.

### PART 8: Server Binary CLI

**Flag parsing:** stdlib `flag` only. The command set in AI.md PART 8 "Server Binary Commands" is complete and immutable, and the `--help` layout (Information / Shell Integration / Server Configuration / Service Management) is fixed.

**NO_COLOR:** priority is CLI flag > config file (`output.color`) > `NO_COLOR` env > autodetect. `NO_COLOR` (any non-empty value) disables colors *and* emojis but never bold/underline/italic or Unicode box drawing; `output.emoji: true` re-enables emojis under `NO_COLOR`.

**Directory flags** (`--config`/`--data`/`--cache`/`--log`/`--backup`/`--pid`): create the target when missing (parents included), perms `0755`/`0644` as root and `0700`/`0600` as a user, validate writability, log creation at INFO. System-vs-user mode is decided once from the EUID at process start and never re-derived — no `~`/`$HOME` lookup after the privilege drop.

**PID file:** stale detection is required. Signal 0 tests liveness and `EPERM` counts as running; the process identity check compares the exact binary basename, never a substring. Containers skip PID files entirely.

**Startup:** immediate-exit flags first (`--help`/`--version`/`--shell`), then `--service`, `--maintenance`, `--update`, then real startup — context detection, path resolution once, root-only setup, privilege drop, verification.

**Daemonization:** re-exec with `_DAEMON_CHILD=1` and `Setsid`, filtering the `--daemon` flag from the child argv; Windows warns and stays in the foreground.

**Signals** (`src/signal`): SIGTERM/SIGINT/SIGQUIT/SIGRTMIN+3 (37) shut down gracefully, SIGUSR1 reopens logs, SIGUSR2 dumps status, SIGHUP is explicitly ignored.

**Env fallbacks:** Init-Only vars seed `server.yml` on first run only; runtime vars (`MODE`, `NO_COLOR`, `TERM`, `DATABASE_*`, `SMTP_*`, …) are re-read every start. Config changes hot-reload except the `server.port`/`server.address`/`server.daemonize`/`ssl.`/`database.`/`tor.` prefixes, which require a restart.

For complete details, see AI.md PART 7, PART 8, PART 32.
