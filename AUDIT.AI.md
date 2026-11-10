# Project Audit

Started: 2026-11-09
Status: in progress; AI.md is the sole implementation authority and remains read-only.

## Pass 5: Spec and Rules Compliance

- [ ] Part 32 CLI GUI: AI.md requires native `gogpu/ui` + `gogpu/gogpu` GUI mode on Linux/macOS/Windows for local display sessions (PART 32 lines 45286-45305 and 45522-45620), but `src/client/main.go` and `src/client/setup/wizard.go` collapse GUI mode to TUI and no GUI implementation/dependencies exist.
- [ ] Part 21 restore verification: `verifyBackup` previously accepted a missing/blank manifest checksum because SHA-256 comparison only ran when `checksum` was non-empty; PART 21 requires every backup checksum check to pass before restore.
- [ ] Part 22 scheduled notifications: `update_check` logged the same update on every run and only persisted the seen version when email was enabled; PART 22 requires update-available notification/logging once per version.
- [ ] Part 22 defer eligibility: `updater.IsEligible` treated absent or invalid `published_at` as eligible despite the PART 22 rule requiring the release age to meet `defer_days`.
- [ ] Part 22 eligible release selection: the scheduler checked only the newest release and skipped the whole task if it was too young, instead of continuing to the newest older eligible release; added a scheduled selector that scans releases newest-first and stops at the running version.
- [ ] Part 22 service-aware update: scheduled and `--update yes` installs always called `RestartSelf`, even when running under a service manager; PART 22 requires coordinating restart with the manager. Added runtime service detection and dispatch to `RestartService` for managed processes.
- [ ] Part 24 Windows services: the installer created an SCM service but the binary had no `windows/svc` entrypoint/control handler, so it could not report running state or receive SCM Stop/Shutdown as required by PART 24's Windows service integration example.
- [ ] Part 26 test Compose names: the test stack used `ipgaze-test`/`ipgaze-cache-test` container and service names instead of the fixed cross-variant names `ipgaze-app`/`ipgaze-cache` required at AI.md PART 26 lines 34377 and 34466.
- [ ] Part 28 project-specific E2E: the required three-tier domain coverage had SSR and no-JS IP lookup checks but no browser-tier specific-IP lookup assertion; added a named browser test for `8.8.8.8` rendering.
- [ ] Part 27 devel workflow naming: provider workflows were named `daily.yml` while AI.md requires `devel.yml`; files and display labels are synchronized. A follow-up comparison also changed rolling release tags and Jenkins `BUILD_TYPE` from `daily` to `devel`, matching the Part 27 devel workflow contract.
- [ ] Part 25 Makefile contract: implementation used noncanonical `PROJECTNAME`/`PROJECTORG`/`INTERNALNAME`, prevented `PLATFORMS` overrides, used `unknown` instead of `N/A` for missing commit IDs, and formed the registry from `internal_name`; aligned variable names, overridability, fallback, and registry source with the AI.md example.
- [ ] Part 23 Windows VSA paths: system config path lacked the required `config` subdirectory, Windows SCM context could select user-scope paths, and installer did not grant the VSA access to required ProgramData/runtime directories; aligned system paths and added service-context detection plus per-service ACL preparation before start.
- [ ] AI tool rules: all 13 `.claude/rules/*.md` files are older than AI.md; Part 0 lines 2644 and 3172 require regeneration when AI.md is newer. Regenerate each file from its mapped PARTs and the required format.
- [ ] I2P Model A: `src/i2p/i2p.go` writes a server-tunnel `tunnels.conf` and starts i2pd without the dedicated `i2pd.conf`, private random SAM port, empty tunnel config, and `--conf`/`--pidfile` contract in AI.md PART 31.2 lines 43874-43918 and 43995-44020.
- [ ] I2P SAM protocol: implementation negotiates SAM 3.0 (MIN=3.0), while PART 31.2 lines 43965 and 44513 require SAM 3.1; all SAM socket commands need bounded deadlines.
- [ ] I2P sockets: `SESSION CREATE` and `STREAM FORWARD` share one connection and the forward omits `SILENT=true`; PART 31.2 lines 43964-43977 and required checklist line 44039 mandate distinct HELLO-negotiated sockets and silent forwarding.
- [ ] I2P backend readiness: session setup issued `STREAM FORWARD` before the dedicated listener's HTTP accept loop started; PART 31.2 line 43982 requires the listener to be accepting first. The listener now starts its handler loop before SAM setup; primary validation remains pending.
- [ ] I2P bootstrap: `SESSION STATUS` uses an unbounded read and the configured timeout is not range-checked to 30-600 seconds; PART 31.2 lines 43990-44008 requires bounded waits and timeout recovery.
- [ ] I2P Model B monitoring: added the separate 30-second SAM probe, session-loss recovery, and bounded backoff. Follow-up review found speculative deadline reads could consume bytes from idle SAM sockets; replaced them with passive watchers and focused tests. Primary validation remains pending.
- [ ] I2P Model A lifecycle: process shutdown only signals Interrupt and does not wait/kill after 10 seconds; startup has no stale PID reap, PID-file backstop, or Linux parent-death signal as required by PART 31.2 lines 44016-44037 and 44037.
- [ ] I2P runtime state: preserved the `no_provider`/`starting`/`building`/`running`/`error` transitions through status reporting; session recovery now exposes `error` before restart. Primary validation remains pending.
- [ ] Metrics database category: PART 20 lines 29655-29663 and 29710-29739 require query totals/duration, DB pool open/in-use gauges, and error totals. `src/server/metrics/metrics.go` declares them, but no production caller updates them; database queries use `src/db`/`database/sql` directly.
- [ ] Metrics system category: PART 20 lines 29798-29807 and configuration require system CPU/memory/disk metrics when `include_system: true` (default true). `RegisterSystemMetrics` exists in `src/server/metrics/metrics.go` but has no call site, and no system collector updates those gauges; `src/main.go` only registers and starts the optional Go runtime collector.
- [ ] Metrics authentication category: PART 20 lines 29665-29670 requires auth attempt counters and an active-session gauge. `src/server/metrics/metrics.go` declares both, but no production code updates them. The active-session metric's semantics conflict with PART 11's no-session model; clarification is recorded in `../TODO.API.md`.
- [ ] Metrics Tor category: PART 20 lines 29817-29823 requires Tor enabled/running/circuit/request metrics when using PART 31 Tor. The metrics were declared but had no production update sites in `src/tor/tor.go`.

## Pass Progress

- PART 0: requirement walk begun; AI rule freshness and generation requirements checked.
- PART 1: requirement headings reviewed; implementation checks pending.
- PART 3: structure/build-output requirements reviewed; tracked `binaries/` still under investigation.
- PART 31.2: provider contract compared with implementation; findings above confirmed.
- All other PARTs and audit passes remain in progress.
