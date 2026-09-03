# Docker Rules (PART 26)

⚠️ **These rules are NON-NEGOTIABLE. Violations are bugs.** ⚠️

## CRITICAL - NEVER DO
- Never hardcode secrets into Dockerfile or compose files
- Never let `docker/docker-compose.test.yml` use a non-ephemeral cache/data service

## CRITICAL - ALWAYS DO
- Build both `linux/amd64` and `linux/arm64` by default; keep builds reproducible in containers
- Verify Docker changes by building the image and smoke-testing at least one endpoint/command

## Key Rules Summary
- **NOT YET FULLY POPULATED**: PART 26 (Docker) has not been read in this pass — only PART 0/1 general rules above are included. Read AI.md PART 26 directly before doing Docker-specific work.

For complete details, see AI.md PART 26.
