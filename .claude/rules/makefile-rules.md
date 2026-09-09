# Makefile Rules (PART 25)

⚠️ **These rules are NON-NEGOTIABLE. Violations are bugs.** ⚠️

## CRITICAL - NEVER DO
- Never build Go on the host — every target invokes Docker (`casjaysdev/go:latest`) via the shared
  `GO_DOCKER`/`GO_DOCKER_RUN` prefix, never a raw `go build`/`go test`
- Never add a 7th target — PART 25 mandates exactly `dev`, `local`, `build`, `test`, `release`, `docker`
  (plus `clean`, used by `build`/`local` as a pre-step and present in the spec's own reference `.PHONY`
  list). **"Six core targets. DO NOT ADD MORE."** — the current Makefile's `.PHONY: build local release
  docker test dev clean` already matches the spec's reference implementation exactly; do not add `all` or
  any other convenience target even though a separate FINAL CHECKPOINT checklist elsewhere in AI.md
  mentions `make all` — that is a self-contradiction within the read-only spec, not a real requirement, and
  must be flagged rather than silently resolved by adding a target PART 25 explicitly forbids
- Never hardcode `PROJECT_NAME`/`PROJECT_ORG` — always infer from `git remote get-url origin`, falling back
  to the directory path, never a literal string
- Never add a `v` prefix to a non-numeric version tag (`dev`, `beta`, `daily`, a raw timestamp) — `v` is
  added only when the tag matches `^[0-9]+\.[0-9]+\.[0-9]+`, and never doubled if already present
- Never use a bare `git rev-parse --short HEAD` for `COMMIT_ID` — always `--short=7`
- Never key `REGISTRY`/image tags off `PROJECT_NAME` — use `INTERNAL_NAME` so a later rename doesn't orphan
  the registry path
- Never guess `site.txt`/`OFFICIAL_SITE` — leave empty for self-hosted projects if neither the file nor the
  env var is present; never infer it from project name or domain

## CRITICAL - ALWAYS DO
- Keep the six targets working and pointed at their mandated outputs:

  | Target | Purpose | Output | When to use |
  |--------|---------|--------|-------------|
  | `dev` | Quick development build | `${TMPDIR}/${PROJECT_ORG}/${INTERNAL_NAME}-XXXXXX/` | Active coding |
  | `local` | Production test build | `binaries/` (versioned) | Test prod builds locally |
  | `build` | Full release, all 8 platforms | `binaries/` | Before release |
  | `test` | Run unit tests | Coverage report | After code changes |
  | `release` | Release with source archive | `releases/` | Creating releases |
  | `docker` | Build and push container | `$REGISTRY` | Container deployment |

- Resolve `VERSION` in strict priority order: `release.txt` (if present, wins over everything) > `VERSION`
  env var > fallback `devel`; create `release.txt` with `0.1.0` before the first real release
- Resolve `OFFICIAL_SITE`/`site.txt` in order: `site.txt` file > `OFFICIAL_SITE` env var > CI/CD repo
  secret > empty; `site.txt` wins over `IDEA.md`, README, and env vars when present
- Build the full 8-platform matrix by default: linux/darwin/windows/freebsd × amd64/arm64, comma-separated
  in `PLATFORMS`
- Name binaries `{project_name}[-cli]-{os}-{arch}[.exe]` for distribution, plain `{project_name}`/
  `{project_name}-cli` for local builds; strip any `-musl` suffix from the final release name even when
  built with musl
- Embed build info via `LDFLAGS` (`-s -w -X main.Version=... -X main.CommitID=... -X main.BuildEpoch=...
  -X main.OfficialSite=...`); derive `BuildDate` from `BuildEpoch` at process start, never embed it directly
- Use `COMMIT_ID := $(shell git rev-parse --short=7 HEAD 2>/dev/null || echo "N/A")`
- Scope `GO_BUILD` cache per project (`$(HOME)/.cache/go-build/$(PROJECT_NAME)`) while sharing `GO_CACHE`
  (`$(HOME)/go/pkg/mod`) across projects — Go file-locks module downloads so sharing is safe
- Always pass `-e CGO_ENABLED=0 -e GOFLAGS=-buildvcs=false` to the Docker build container
- Build the CLI binaries only when `src/client/` exists, using the same platform loop as the server

## Key Rules Summary
The Makefile has exactly six core targets (`dev`, `local`, `build`, `test`, `release`, `docker`) plus
`clean` as a shared pre-step — this list is fixed by explicit spec instruction ("DO NOT ADD MORE") and
matches the spec's own reference `.PHONY` line, which is exactly what this repo's Makefile currently has.
**Open spec contradiction:** AI.md's FINAL CHECKPOINT section separately lists `make all` as required
alongside build/test/docker/release/clean; PART 25's body and reference implementation both omit it. Do not
add an `all` target to resolve this — it conflicts with PART 25's explicit target-count rule — flag it as
an unresolved spec inconsistency instead. Versioning is fully deterministic (`release.txt` > `VERSION` env
> `devel`), version tags only get a `v` prefix when numeric, and all identifiers that key a rename-durable
path (registry, tempdir) use `INTERNAL_NAME`, never `PROJECT_NAME`.

For complete details, see AI.md PART 25.
