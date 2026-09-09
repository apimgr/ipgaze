# Docker Rules (PART 26)

⚠️ **These rules are NON-NEGOTIABLE. Violations are bugs.** ⚠️

## CRITICAL - NEVER DO
- Never place a Dockerfile or docker-compose file in project root — everything lives under `docker/`,
  with build-time overlay files under `docker/rootfs/` (which mirrors the container filesystem)
- Never add a `LABEL` block to the Dockerfile — all OCI metadata (image title, description, licenses,
  created/version/revision, url/source/documentation, vendor/authors, `com.github.containers.toolbox`) is
  applied at build time by CI via `--label`/`--annotation` flags or `docker/metadata-action`, never baked in
- Never add a `USER` directive or create a user/group in the Dockerfile — the container starts as root and
  the binary creates its own user/group, directories, and permissions, then drops privileges itself; running
  permanently as root is the exception and MUST be documented in `IDEA.md`
- Never create data/config directories in the Dockerfile — the binary handles all setup from env vars, and
  volume mounts auto-create their own mount points
- Never modify `ENTRYPOINT` or `CMD` for customization — all customization goes through `entrypoint.sh`
- Never omit `exec "$@"` (or `exec <binary> ... "$@"`) at the tail of `entrypoint.sh` — without `exec`, the
  app is not PID 1 and tini/Docker signals never reach it, breaking graceful shutdown
- Never bake `MODE` into the image via `ENV` — the binary defaults to production; compose files set `MODE`
  explicitly (`production`/`development`)
- Never include a `build:` or `version:` key in a docker-compose file
- Never let `docker/docker-compose.test.yml` use a non-ephemeral cache/data service
- Never hardcode secrets into any Dockerfile or compose file

## CRITICAL - ALWAYS DO
- Use a multi-stage build: `casjaysdev/go:latest` builder stage (git+bash, `CGO_ENABLED=0` static build with
  the standard `-ldflags "-s -w -X main.Version=... -X main.CommitID=... -X main.BuildEpoch=... -X
  main.OfficialSite=..."`) → `alpine:latest` runtime stage
- Install `git curl bash tini tor` in the runtime stage — Tor is installed but the binary controls all Tor
  setup and startup (see PART 31), never configured in the Dockerfile
- Copy the compiled binary from the builder stage and the `docker/rootfs/` build-time overlay
  (`entrypoint.sh`) into the image; `chmod 755 /usr/local/bin/*`
- `EXPOSE 80` always as the internal container port
- `STOPSIGNAL SIGRTMIN+3` for proper shutdown
- `ENTRYPOINT [ "tini", "-p", "SIGTERM", "--", "/usr/local/bin/entrypoint.sh" ]`
- `HEALTHCHECK --start-period=10m --interval=5m --timeout=15s --retries=3 CMD /usr/local/bin/{project_name}
  --status || exit 1`
- Mount exactly two host volumes in every compose file: `./volumes/config:/config:z` and
  `./volumes/data:/data:z` — never mount individual subdirectories
- Keep container paths organized as documented: `/config/{project_name}/` (server.yml, ssl/, tor/),
  `/data/{project_name}/` (uploads, cache, tor/), `/data/db/sqlite/server.db` (always this exact filename),
  `/data/db/{service}/` for external services (e.g. valkey), `/data/log/{project_name}/`,
  `/data/backups/{project_name}/`
- Apply every required OCI label via CI (`maintainer`, `org.opencontainers.image.{vendor,authors,title,
  base.name,description,licenses,created,version,schema-version,revision,url,source,documentation,
  vcs-type}`, `com.github.containers.toolbox=false`) — apply the same metadata as manifest **annotations**
  too (via `docker/metadata-action` + `build-push-action` with `annotations:` set and `labels: ""`), since
  registries read multi-arch metadata from the manifest index, not per-platform `--label` layers
- Build both `linux/amd64` and `linux/arm64` by default; keep builds reproducible in containers
- Verify Docker changes by actually building the image and smoke-testing at least one endpoint/command

## Key Rules Summary
Dockerfiles are multi-stage (`casjaysdev/go:latest` → `alpine:latest`), carry no `LABEL`/`USER`/directory-
creation instructions — the binary self-manages users, directories, and privilege drop entirely from env
vars — and route all customization through `entrypoint.sh` behind `tini`. All OCI metadata is CI-applied as
both build-time labels and manifest annotations, never hardcoded in the Dockerfile. Compose files mount only
`/config` and `/data` as whole trees, never `build:`/`version:` keys, and keep the container path layout
(`/config/{project_name}`, `/data/{project_name}`, `/data/db/sqlite/server.db`, `/data/log`,
`/data/backups`) exactly as documented so the binary's auto-created host `./volumes/` tree matches.

For complete details, see AI.md PART 26.
