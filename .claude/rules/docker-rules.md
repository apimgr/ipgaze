# Docker Rules (PART 26)

⚠️ **These rules are NON-NEGOTIABLE. Violations are bugs.** ⚠️

## CRITICAL - NEVER DO
- **PART 26:** NEVER place Dockerfile or docker-compose.yml in project root
- **PART 26:** | **NEVER modify ENTRYPOINT** | Always use entrypoint.sh for customization |
- **PART 26:** | **NEVER modify CMD** | Pass commands to entrypoint.sh instead |
- **PART 26:** **NEVER modify ENTRYPOINT or CMD** - all customization goes in `entrypoint.sh`
- **PART 26:** `MODE=debug`: Explicit opt-in only — NEVER implied or auto-enabled. Minimal sanitization (internals, dumps, stack traces may be exposed). Credentials (keys, tokens, passwords, secrets) are ALWAYS redacted in every mode, no exceptions
- **PART 26:** | `build:` | **NEVER include** |
- **PART 26:** | `version:` | **NEVER include** |
- **PART 26:** | `container_name:` | **Always set**, one fixed name per service, the same in production, dev, and test: `{project_name}-app`, `{project_name}-db`, `{project_name}-cache` (only the services that file includes). Dev and test never run on a production host, so a clash fails `docker compose up` instead of replacing production; their compose `name:` and network keep the `-dev` / `-test` suffix so it fails rather than adopting production's project |
- **PART 26:** | Environment variables | **Hardcode with sane defaults** (NEVER use .env files); always YAML map style (`KEY: value`), never list style (`- KEY=value`) |
- **PART 26:** *⚠️ FOR HUMAN USE ONLY — AI assistants must NEVER run this file.**
- **PART 26:** *FOR HUMAN USE ONLY — AI assistants must NEVER run this file.**
- **PART 26:** *There are TWO different filesystem concepts here - do not confuse them:**
- **PART 26:** | **Runtime** | `./volumes/` next to the compose file | Volume mounts (config, data) | NEVER |
- **PART 26:** *Runtime `./volumes/`** (never committed from repo-local runs):
- **PART 26:** NEVER commit runtime `volumes/` from local runs
- **PART 26:** *AI must NEVER run `docker-compose.yml` or `docker-compose.dev.yml` — those are human-only.** AI's preferred interface for testing is the project's `tests/` directory scripts (`tests/docker.sh`, `tests/run_tests.sh`), which wrap the temp-dir copy/run/cleanup sequence below. Direct invocation of `docker-compose.test.yml` is only a fallback when no `tests/` script exists yet.
- **PART 26:** *NEVER:**
- **PART 26:** | **NEVER** | Create `.env`, `.env.example`, `.env.sample` files |
- **PART 26:** | **NEVER** | Use `${VAR}` without a fallback (stack breaks if var is unset) |
- **PART 26:** | **NEVER** | Use list-style env vars (`- KEY=value`) — always YAML map style (`KEY: value`) |
- **PART 26:** Debug enabled for test visibility. Includes an ephemeral Valkey cache service (`tmpfs`, no persistent volume). **MUST be copied to temp directory before direct use - NEVER run from project directory.**
- **PART 26:** 3. **NEVER push `:dev` or `:test` tags to production registry**

## CRITICAL - ALWAYS DO
- **PART 26:** ALWAYS use `docker/` for Dockerfiles/compose files and `docker/rootfs/` for build-time overlay files
- **PART 26:** ALWAYS use `entrypoint.sh` for container startup
- **PART 26:** ALWAYS use multi-stage build (no pre-built binaries needed)
- **PART 26:** | Required packages | git, curl, bash, tini, tor |
- **PART 26:** Database name is ALWAYS `server.db` (globally consistent)
- **PART 26:** All images MUST carry these labels. Dockerfiles stay clean — no `LABEL` blocks; CI applies every label at build time via `--label` flags (or the workflow `labels:` input):
- **PART 26:** See dockerfile_conventions.md → OCI Annotations for the complete list of required annotation keys.
- **PART 26:** | **Privilege drop, not Dockerfile users** | NO `USER` directive and no user/group creation in the Dockerfile — the container starts as root and the binary creates its own user/group, creates its directories, sets permissions, then drops privileges after initialization (see "Privileged Port Binding (<1024)" for the run-mode and drop rules). Running permanently as root is the exception and MUST be documented in `IDEA.md`. |
- **PART 26:** | **entrypoint.sh tail** | Must end with `exec "$@"` (or `exec <binary> ... "$@"`) so the application replaces the shell as PID 1 and receives signals directly — without `exec`, tini/Docker signals are delivered to bash, not the app, and graceful shutdown breaks |
- **PART 26:** Self-contained - no pre-built binaries required
- **PART 26:** *Note:** Tor is auto-enabled if the `tor` binary is installed. No `ENABLE_TOR` flag needed. Docker image always includes Tor.
- **PART 26:** | `pull_policy:` | `always` |
- **PART 26:** | `restart:` | `always` |
- **PART 26:** | `restart:` | `always` | Always restart on failure |
- **PART 26:** | `pull_policy:` | `always` | Always pull latest image |
- **PART 26:** *Every docker-compose.yml MUST include the x-logging anchor:**
- **PART 26:** *Every service MUST use the anchor:**
- **PART 26:** *When a direct invocation is unavoidable, always use the temp directory workflow:**
- **PART 26:** Internal port is always `80` (`PORT: 80` in every compose file)
- **PART 26:** *Stack must work with zero `.env` files. Use inline `${VAR:-default}` fallbacks.**
- **PART 26:** | **ALWAYS** | Use `${VAR:-default}` so the stack works without any `.env` |
- **PART 26:** | **ALWAYS** | Operators may override via `.env` or shell env — the fallback just handles zero-config |
- **PART 26:** Works out of the box — no setup required
- **PART 26:** *AI/Automated Testing Workflow (REQUIRED — prefer `tests/` scripts; this is the fallback):**
- **PART 26:** | Internal port | **80** (always) |
- **PART 26:** | Always enabled | Docker image includes `tor`, so always enabled in containers |
- **PART 26:** 1. **Release builds** MUST push to `{PLATFORM_CONTAINER_REGISTRY}/{project_org}/{internal_name}`
- **PART 26:** 2. **Development builds** MUST use local-only tags (no registry prefix)

## Key Rules Summary

### PART 26 — DOCKER
- Docker Directory Structure
- Dockerfile Requirements
- Docker Compose Requirements
- Container Configuration
- Tor in Container
- Container Detection
- Image Tags

For complete details, see AI.md PART 26.
