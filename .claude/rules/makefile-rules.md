# Makefile Rules (PART 25)

⚠️ **These rules are NON-NEGOTIABLE. Violations are bugs.** ⚠️

## CRITICAL - NEVER DO
- Never build Go on the host — Makefile targets must invoke Docker (`casjaysdev/go:latest`)
- Never let the Makefile diverge from what CI/CD actually runs (Makefile is for local dev only, not CI/CD)

## CRITICAL - ALWAYS DO
- Keep `make dev`, `make local`, `make build`, `make test` targets working and pointed at correct output paths (`binaries/`, tempdir for dev builds)
- Verify Makefile changes by actually running the target, not just reading it
- Tempdir paths (`make dev`, `make test`) use `$(INTERNAL_NAME)` (or the
  Makefile's no-underscore `$(INTERNALNAME)` convention), never
  `$(PROJECT_NAME)` — `${TMPDIR}/${PROJECT_ORG}/${INTERNAL_NAME}-XXXXXX/`
- `COMMIT_ID` uses `git rev-parse --short=7 HEAD` (never bare `--short`)

## Key Rules Summary
- **NOT YET FULLY POPULATED**: PART 25 (Makefile) has not been read in this pass — only PART 0/1 general rules above are included. Read AI.md PART 25 directly before doing Makefile-specific work.

For complete details, see AI.md PART 25.
