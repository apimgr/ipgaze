# Configuration Rules (PART 5, 6, 12)

⚠️ **These rules are NON-NEGOTIABLE. Violations are bugs.** ⚠️

## CRITICAL - NEVER DO

- NEVER name the config file `server.yaml` — it is always `server.yml`
- NEVER use `strconv.ParseBool()` for config/env booleans — use
  `config.ParseBool()` / `config.IsTruthy()` (handles yes/no, oui/non,
  si/no, da/net, and other locale truthy/falsy forms)
- NEVER store user accounts, credentials, or settings in the database —
  `server.yml` is the sole source of truth for configuration; the
  database only holds resource state, tokens, and audit logs
- NEVER put inline YAML comments — comments always go on the line above
  the setting
- NEVER let `--debug`/`DEBUG=true` bypass auth or security checks —
  debug mode only unlocks `/debug/*`, `/debug/pprof/*`, `/debug/vars`
- NEVER read Init-Only env vars (`CONFIG_DIR`, `DATA_DIR`, `LOG_DIR`,
  `DATABASE_DIR`, `BACKUP_DIR`, `PORT`, `LISTEN`, `APPLICATION_NAME`,
  `APPLICATION_TAGLINE`) after first-run — they are saved to
  `server.yml` and only apply once

## CRITICAL - ALWAYS DO

- ALWAYS re-check Runtime env vars every start (`NO_COLOR`, `TERM`,
  `DOMAIN`, `MODE`, `DATABASE_DRIVER`, `DATABASE_URL`, `SMTP_*`)
- ALWAYS resolve mode via priority: `--mode` flag > `MODE` env > default
  production; resolve debug via `--debug` flag > `DEBUG` env (truthy) >
  `MODE=debug`/`--mode debug` alias > default false — explicit
  `--debug`/`DEBUG` always overrides the `MODE=debug` alias
  (see `src/mode/mode.go`, already implements this correctly)
  ALWAYS support all four operational states: Production,
  Production+Debug, Development, Development+Debug
- ALWAYS default to a random unused port in the 64000-64999 range on
  first run, then persist it to `server.yml`
- ALWAYS follow the privileged-port (<1024) bind-then-drop-privilege
  pattern rather than running the whole process as root
- ALWAYS trigger maintenance mode / self-healing on critical errors
  (DB connection failure, disk write failure) instead of crashing

## Key Rules Summary

`server.yml` is authoritative for configuration; env vars only seed it
on first run (Init-Only) or override at runtime for a fixed allow-list
(Runtime). Mode/Debug resolution has a strict precedence order already
implemented in `src/mode/mode.go`. Boolean parsing must go through
`src/config/bool.go`'s `ParseBool`/`IsTruthy`, already implemented
correctly. **PART 12 (Server Configuration details beyond PART 5/6) has
not been read in this pass — do not assume this file's coverage of
PART 12 is complete; read AI.md PART 12 directly before further
config-related work.**

For complete details, see AI.md PART 5, PART 6, PART 12.
