# Project Structure, License & OS Paths Rules (PART 2, 3, 4)

⚠️ **These rules are NON-NEGOTIABLE. Violations are bugs.** ⚠️

## CRITICAL - NEVER DO

- NEVER edit files outside project root as a workaround for a failing
  build/test/tool — fix inside the project; the only exception is a path
  the user explicitly names for that specific task
- NEVER use a license other than MIT for this project (LICENSE.md, root)
- NEVER use GPL/AGPL/LGPL dependencies — copyleft is forbidden
- NEVER hardcode `{project_name}`/`{project_org}` — infer from git remote
  or directory path; `{internal_name}` is frozen at first-time setup and
  never changes even on rename
- NEVER commit `binaries/`, `releases/`, `docker/rootfs/`, or `volumes/`
  (all gitignored — build/runtime output only)
- NEVER use a CGO-requiring library — all deps must work with `CGO_ENABLED=0`
- NEVER use `github.com/mattn/go-sqlite3`, `lib/pq`, `go-libtor`,
  `dgrijalva/jwt-go`, or `gorilla/mux` (forbidden libraries)
- NEVER assume current working directory is project root — always resolve
  explicitly (`git rev-parse --show-toplevel` or equivalent)
- NEVER pin/hardcode a specific Go patch version — always latest stable

## CRITICAL - ALWAYS DO

- ALWAYS keep LICENSE.md's embedded Third-Party Licenses table current
  with go.mod direct dependencies
- ALWAYS put a linked, platform-correct CI badge + license badge in
  README.md
- ALWAYS support Linux, BSD, macOS, and Windows, on both AMD64 and ARM64
- ALWAYS use `modernc.org/sqlite` (driver name `sqlite`, aliases
  `sqlite2`/`sqlite3`) for local SQLite; `tursodatabase/libsql-client-go`
  (driver `libsql`, alias `turso`) for remote
- ALWAYS keep `.claude/rules/`, `.claude/memory/`, `docs/`, `docker/`,
  `scripts/`, `tests/` in their mandated locations relative to project root
- ALWAYS keep `.claude/memory/MEMORY.md` as the index for project-specific
  durable knowledge (decisions, gotchas, codebase-only conventions) —
  committed to the repo, never gitignored; distinct from `.claude/rules/`
  (spec-derived cheatsheets)
- ALWAYS use OS-specific paths per PART 4 tables — config/data/cache/log
  differ by OS and privilege level; Docker uses `/config` + `/data` only
  inside containers, never on native OS

## Key Rules Summary

Project root layout is fixed: `src/`, `docker/`, `docs/`, `scripts/`,
`tests/`, `binaries/` (gitignored), `releases/` (gitignored), `volumes/`
(gitignored), plus root files (README.md, LICENSE.md, AI.md, IDEA.md,
Jenkinsfile, release.txt, site.txt). OS-specific runtime paths always
follow `{internal_org}/{internal_name}` under the platform-correct base
(`/etc`, `/var/lib`, `~/.config`, `~/Library/Application Support`,
`%ProgramData%`, etc.) — see AI.md PART 4 tables for the exact path per
OS and privilege level. Config file is always `server.yml`.

For complete details, see AI.md PART 2, PART 3, PART 4.
