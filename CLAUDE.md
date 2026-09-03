# CLAUDE.md — ipgaze

Project memory for Claude Code. This file is the entry point; the
implementation spec itself lives in `AI.md` (read-only) and the project
plan lives in `IDEA.md` (update as features change).

## Critical Rules (always in effect)

- **AI.md is READ-ONLY.** Never edit it. It is the implementation spec —
  the source of truth for HOW this project is built.
- **IDEA.md is the project plan** (WHAT this project does) — keep it
  current as features change.
- **Never install Go locally.** All builds/tests run in Docker
  (`casjaysdev/go:latest`) or Incus — see `AI.md` PART 1 and PART 28.
  Use `make dev` / `make local` / `make build` / `make test`.
- **Config file is always `server.yml`**, never `.yaml`.
- **Boolean parsing always uses `config.ParseBool()` / `config.IsTruthy()`**
  — never `strconv.ParseBool()`.
- **SQLite driver is `modernc.org/sqlite`** — never `mattn/go-sqlite3`
  (CGO forbidden; `CGO_ENABLED=0` required).
- **No GPL/AGPL/LGPL dependencies** — MIT/Apache/BSD/ISC only.
- **Full web app pattern**: every feature needs a web route AND a
  matching `/api/{api_version}/...` JSON route.

## Auto-Loaded Rule Cheatsheets

`.claude/rules/*.md` are generated from `AI.md` and mirror its PART
groupings. They are regenerated whenever `AI.md` changes — do not hand-edit
them; edit `AI.md`'s source PART instead (if this were not read-only) or
flag a discrepancy for the user.

## Project Identity

| Variable | Value |
|----------|-------|
| project_name | ipgaze |
| project_org | apimgr |
| internal_name | ipgaze |
| app_name | IPGaze |
| official_site | https://ifcfg.us |
| repository | https://github.com/apimgr/ipgaze |
| license | MIT |

See `AI.md` PART 3 for the full variable system and `IDEA.md` for
project-specific feature scope.
