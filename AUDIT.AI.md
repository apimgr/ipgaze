# Project Audit

Started: 2026-08-29
Revalidated: 2026-11-05
Spec version: AI.md SHA-256 `0891ecedc0882c16ef6286f5d060ee0cda8ba85296ee275d488d0f09d26ed759` (49,178 lines)
Authority: AI.md (read-only) and IDEA.md

## Issues Found

- [ ] AI.md PART 31.1 defines eight `/server/tor/*` endpoints, methods,
  loopback access, and classification, but not complete request, success
  payload, and error payload contracts for all endpoints. The structures in
  `src/server/tor_control.go` and `src/main.go` include behavior not fully
  specified by AI.md. The spec owner must define those contracts before the
  implementation can be judged exactly.
- [ ] `server.tor.max_circuits` is parsed and passed to the Tor manager, but
  the manager does not use it. AI.md PART 31.1 does not define how this setting
  maps to Tor behavior. Do not invent runtime semantics.
- [ ] AI.md PART 16 requires app-specific guest preferences and export/import
  round-tripping, but its required preference cookie table omits the
  implemented `ipgaze_pref_widget` cookie and its values/default. The code and
  IDEA document the preference; AI.md remains the implementation authority
  and read-only, so its owner must add the cookie contract.
- [ ] AI.md PART 25 says to have exactly its six listed Makefile targets;
  FINAL CHECKPOINT separately requires `make all`. The Makefile follows PART
  25. The spec owner must reconcile the conflict.
- [ ] AI.md PART 8's reference implementation detects containers before
  selecting a service manager and explicitly treats Incus/LXC as containers,
  while PART 28's preferred Incus workflow requires installing and checking a
  systemd service. `src/service/service.go` follows the PART 8 behavior and
  `tests/incus.sh` falls back to direct binary startup. The spec owner must
  decide whether Incus service installation is required.
- [ ] AI.md PART 14 requires an MCP toggle in Web settings, while PART 12
  requires file-only configuration without runtime mutation, PART 16 rules
  out an admin panel, and PART 14's frontend rules say there are no admin
  pages. `server.mcp.enabled` remains file-configured and hot-reloadable. The
  spec owner must reconcile these requirements before a settings UI or route
  can be implemented.
- [ ] AI.md PART 14's universal API success envelope requires `{ok,data}`;
  IDEA.md and echoip compatibility require bare responses at `/`, `/{ip}`,
  and `/{ip}/{field}`. The routes are implemented as compatibility endpoints.
  AI.md does not document an exception for these routes, so the spec owner
  must define whether they are exempt from the universal JSON response rule.
- [ ] AI.md PART 0's current `--mode debug` rule says debug mode defaults the
  debug flag on; its Six Operational States table defines `debug` with debug
  false; the Mode Shortcuts table defines `--mode debug` as development plus
  debug on. `src/mode/mode.go` follows the explicit debug-mode description and
  Six Operational States. The spec owner must reconcile the contradictory
  table entries.
- [ ] AI.md PART 28 mandates all temporary data under
  `{project_org}/{internal_name}-XXXXXX`, but its PART 22 updater example
  creates a temp file directly under the OS temp root using
  `os.CreateTemp("", "{project_name}-update-*")`. Project temp handling now
  follows PART 28; the spec owner should update the inconsistent example.

## Sync Required

- [ ] AI.md must resolve the incomplete contracts and conflicting requirements
  listed above before exact code/documentation alignment can be verified.

## Completed

- `[PASS]` Runtime backup verification and restore now create unique,
  owner-only temp directories under the project/org namespace and report
  cleanup failures.
- `[PASS]` CLI self-update now uses a unique project-scoped temporary
  directory and removes it before restarting the replaced process.
- `[PASS]` `make test` exports a project-scoped `TMPDIR` to Go test processes,
  so `t.TempDir`, `os.TempDir`, and empty-dir temporary-file creation inherit
  the required namespace. GitHub Actions, Gitea Actions, and Jenkins test
  jobs likewise set a project-scoped temp root.
- `[PASS]` Custom E2E, SSL, and Tor test temp directory prefixes now use the
  required `{internal_name}-` prefix.
- `[PASS]` Rechecked the Makefile Go toolchain command substitution; `go env`
  runs inside the Docker toolchain, not on the host.
- `[PASS]` Rechecked config reload classes, runtime route registration and
  discovery filtering, MCP audit source, and optional route handling against
  AI.md PARTS 12 and 14.
- `[PASS]` No `TODO.*` files exist in the repository.

## Verification

- `[PASS]` `bash "$HOME/.codex/hooks/test-lint-run.sh" test -- make test` —
  passed; coverage 60.3% (required minimum 60%).
- `[PASS]` `bash "$HOME/.codex/hooks/test-lint-run.sh" lint -- go vet ./...` —
  passed.
- `[PASS]` `bash "$HOME/.codex/hooks/test-lint-run.sh" lint -- shellcheck tests/e2e.sh` —
  passed.
- `[PASS]` `make dev` — built server and CLI binaries successfully.
- `[PASS]` Docker `gofmt -w` completed for changed Go files.
- `[PASS]` `timeout 120 act --list -W .github/workflows/ci.yml` — listed
  configured workflow jobs successfully.
- `[FAIL]` Local Act execution of the CI `test` job failed only
  `TestValidateNotPrivateIP_DNSFailure`: the test expects
  `this-host-does-not-exist.invalid` to fail DNS resolution, but the Act
  runner's resolver returned an address. The project test suite passed with
  `make test`; hosted CI must confirm this resolver-dependent test.
- `[NOT RUN]` `staticcheck ./...` — the test/lint wrapper rejected the
  command before execution.
