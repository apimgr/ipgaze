# TODO.AI.md

Reconciliation items from the AI.md bootstrap/compliance passes.

## Resolved

1. **README.md structure** — Reordered into PART 1's mandated section order;
   added a "Client" section documenting `ipgaze-cli` (install, usage,
   config precedence) per PART 32. `Read: AI.md PART 1, PART 32`

2. **README.md "Configuration" section** — Rewritten to match the real
   nested `server:`/`web:` `server.yml` schema, with location table,
   precedence order, and a key-settings table cross-linking
   `docs/configuration.md`. `Read: AI.md PART 5, PART 12`

3. **CI wiring for `scripts/verify-licenses.sh`** — Added
   `.github/workflows/licenses.yml` per the reference workflow in PART 2,
   calling the repo's own `scripts/verify-licenses.sh` instead of inlining
   `go-licenses` steps (script already existed and matches the spec's
   script reference). Validated with `act --list -W
   .github/workflows/licenses.yml`. `Read: AI.md PART 2, PART 27`

4. **`--mode` flag semantics** — Confirmed via PART 6 ("Mode and Debug
   Detection Priority": `--mode` flag > `MODE` env > default) and PART 8's
   CLI flag table that `--mode` is an ephemeral per-run flag, not a
   persist-and-exit action. Persisting a mode change is a separate
   `--maintenance mode <value>` action. `src/main.go`'s `--mode` handling
   now sets `cfg.Server.Mode` in-memory for the current run instead of
   writing `server.yml` and exiting. `Read: AI.md PART 6, PART 8`

5. **`src/mode` dead code + `init()` ordering bug** — Confirmed by repo-wide
   grep that nothing called `mode.GetAppMode/IsAppModeDev/IsAppModeProd/
   IsDebug/SetDebugEnabled/FromEnv` etc. — `config.AppConfig.IsDebug()` is
   the actual source of truth read by `src/server`. Removed the unused
   package-level state and the racy `init()` (it ran before `--debug` was
   parsed in `main()`, so it could never reflect the CLI flag). Kept
   `ParseMode`/`ParseModeWithDebugAlias`, which `main.go` does use.
   Verified: `go build ./...`, `go vet ./...`, and `go test ./src/mode/...
   ./src/config/...` all pass (run in `casjaysdev/go:latest`).
   `Read: AI.md PART 6`

6. **Stray `.audit1_build.log`** — Confirmed via repo-wide grep it is
   referenced nowhere (not in Makefile, scripts, CI, or docs). Removed with
   `git rm`.

7. **PART 6 debug-config subsystem implemented.** Added `server.debug.*`
   (`pprof`, `log_queries`, `log_cache`, `log_bodies`, `max_body_log_size`,
   `block_profile_rate`, `mutex_profile_fraction`, `runtime_endpoints`) as a
   new `DebugConfig` struct on `ServerConfig` in `src/config/config.go`
   (defaults match AI.md's example: pprof/log_queries/log_cache/
   runtime_endpoints true, log_bodies false, max_body_log_size "10KB",
   block/mutex profile rate 1), plus `DebugConfig.MaxBodyLogSizeBytes()`
   and a new exported `config.ParseByteSize` (TB/GB/MB/KB/B suffixes).
   `src/main.go` now calls `runtime.SetBlockProfileRate`/
   `SetMutexProfileFraction` (explicitly 0 when not debugging) and
   `db.SetQueryLogging(cfg.IsDebug() && cfg.Server.Debug.LogQueries)` at
   startup, and both production DB-open call sites use `db.OpenSQLite`.
   `src/server/debug.go`'s `registerDebugRoutes` now gates `/debug/pprof/*`
   behind `Debug.Pprof` and the rest of `/debug/*` behind
   `Debug.RuntimeEndpoints` (both still nested inside the existing
   `IsDebug()` gate). Added `src/db/logging_driver.go` (transparent
   `database/sql/driver` wrapper registered as `sqlite+logged`/
   `libsql+logged`, toggled via `db.SetQueryLogging`) and
   `src/cache/logging.go` (`cache.NewLogging` decorator), wired into
   `main.go`'s cache setup when `Debug.LogCache` is on. Added
   `src/server/debug.go`'s `debugBodyLoggingMiddleware` (request/response
   body capture up to `MaxBodyLogSizeBytes()`, gated by `Debug.LogBodies`),
   registered in `src/server/http.go`'s middleware chain. Updated
   `src/server/http_test.go`, `src/server/server_config_test.go`, and
   `src/server/coverage_boost_test.go` to set `Debug.RuntimeEndpoints: true`
   on the zero-value `config.AppConfig{}` test fixtures that exercise
   `/debug/*` routes through the full HTTP router.
   Verified: `go build ./...`, `go vet ./...`, `gofmt -l .` (clean after
   formatting `config.go`), `go test ./...` (all packages pass, including
   `src/db`, `src/cache`, `src/server`), and the `go-lint` agent (no
   violations) — all run in `casjaysdev/go:latest`. A live smoke test
   (built binary run in Docker, `--debug` + `server.debug.*` enabled)
   could not directly confirm HTTP 200s on `/debug/*` because of the
   unrelated blocklist bug logged as item 8 below; `registerDebugRoutes`'s
   gating was instead confirmed by code review and by the existing
   `src/server` test suite, which exercises `/debug/*` through the real
   chi router with a nil blocklist lookup. `Read: AI.md PART 6`

8. **Blocklist middleware blocked all requests from 127.0.0.1, including
   nonexistent paths, even with zero network access and no blocklists
   downloaded.** Found incidentally while smoke-testing the PART 6
   debug-config work (item 7): running the built `ipgaze-server` binary
   with `--debug` under Docker with `--network none` (so no blocklist
   ipset ever downloads) still returned HTTP 403 "Access denied" from
   `BlocklistMiddleware` (`src/server/middleware_blocklist.go`) for every
   request from `127.0.0.1`. Root cause: unlike `GeoIPMiddleware`,
   `BlocklistMiddleware` had no private/loopback IP exemption, and public
   blocklists such as firehol_level1 intentionally include bogon ranges
   (127.0.0.0/8, 10.0.0.0/8, 192.168.0.0/16, ...) for perimeter filtering,
   so any successfully-loaded list would match loopback/RFC1918 traffic.
   Fixed by reusing `GeoIPMiddleware`'s `isPrivateIP` helper: `Contains()`
   is now only consulted for non-private IPs. Added
   `TestBlocklistMiddlewarePrivateIPExempt`. Verified via `go build/vet/
   test` in `casjaysdev/go:latest`. Committed `5723313e21bf`, pushed, all
   4 CI workflows green. `Read: AI.md PART 12, PART 19`

9. **Release outputs missing SBOM and build provenance/attestation.**
   AI.md's Release Integrity requirements (lines 672, 879, 2027, 4148)
   mandate that tagged releases publish checksums, release notes, an SBOM
   (CycloneDX or SPDX JSON), and build provenance/attestation where the
   host platform supports it. `release.yml` published none of these
   before this session; a "Generate checksums" step (`sha256sum -- * >
   checksums.txt`) was added to close the checksums gap (commit
   `3bb1319a3e9e`), which also unblocks `scripts/install.sh`'s new
   checksum verification and the pre-existing (previously non-functional)
   `src/client/updater` checksum-verification code path. SBOM generation
   and GitHub Actions build provenance/attestation
   (`actions/attest-build-provenance`) are still unimplemented — needs a
   decision on SBOM tooling (e.g. `anchore/sbom-action` or `cyclonedx-gomod`)
   before implementing, since AI.md forbids faking signatures/attestations
   and requires asking if keys/permissions are unavailable. `Read: AI.md
   PART 27` (lines 672, 879, 2027, 4148)

10. **`src/server/request.go` failed `gofmt -l`.** Found incidentally while
    Docker-verifying the Task #7 cache/blocklist/cve/update fixes —
    pre-existing formatting drift already in the last committed revision
    (old-style `// * ` bullet doc-comment syntax on `ipFromRequest`),
    unrelated to this session's other edits. Fixed directly (rather than
    deferred) per the explicit instruction that everything discovered is
    in scope for production readiness: converted to gofmt-canonical
    `//   - ` list syntax, no logic change. Verified clean via `gofmt -l`
    and `go test ./src/server/...`.

11. **Let's Encrypt auto-renewal never reissued app-managed certs**
    (was open item 2). `RenewIfExpiring` called `GetTLSConfig`, which
    reloaded the near-expiry cert via `findCertByPriority` instead of
    re-obtaining it. Fixed to force `obtainLetsEncryptCert` only for
    app-managed `{config_dir}/ssl/letsencrypt/{fqdn}/` certs when LE is
    enabled, leaving certbot- and user-managed certs untouched per PART 15's
    ownership table. Added `TestRenewIfExpiring_Expiring_AppManagedLE_
    ForcesReissue`. Commit `06ac2ec11540`. `Read: AI.md PART 15`

12. **Tor binary detection never searched PATH** (PART 31). `IsAvailable`
    only stat'd the configured binary or three hardcoded Linux paths; a
    PATH-only tor made `Start()` bail even though the bine launch path
    resolves via PATH. Added `resolveBinary()` (config → PATH → per-OS
    locations, adding macOS/homebrew and Windows) used by both
    `IsAvailable` and `startDedicated`. Commit `14172487b4aa`.
    `Read: AI.md PART 31`

13. **Root-package test wrote `server.db` into the source tree**
    (was open item 3, mis-attributed to `db_pragma_test.go`).
    `TestOpenMaintenanceDB_CreatesSqliteFile` set only `dirs.DB`, but
    `openMaintenanceDB` resolves from `dirs.Data`, so `NewDB("")` created
    `src/db/server.db`. Set `dirs.Data` to the tempdir; added `server.db*`
    to `.gitignore` as defense-in-depth. Commit `a9648f1e886e`.

14. **GeoIP disabled in production — jsDelivr distribution of
    sapics/ip-location-db is dead** (was open item 4, re-verified this
    pass). Production (`ifcfg.us`) had `features.geoip: false` because
    `DownloadDatabases()` was all-or-nothing and jsDelivr's npm CDN 403s on
    the city MMDB file (structural 50 MB per-file cap; the whole npm/
    jsDelivr distribution of `sapics/ip-location-db` was also deprecated
    2026-06-18 — confirmed via direct `curl`, not assumption). Switched
    `src/geoip/geoip.go` to download from GitHub Releases
    (`https://github.com/sapics/ip-location-db/releases/download/latest/`)
    instead: `origin-asn.mmdb` (PDDL), `user-country.mmdb` (PDDL),
    `dbip-city-ipv4.mmdb` + `dbip-city-ipv6.mmdb` (CC BY 4.0 — these two
    filenames match AI.md's literal spec text exactly). Also: (a) added the
    IPv4/IPv6 city split PART 19 requires as two separate rows —
    `src/iputil/geo/geo.go`'s `Open()`/`geoip` struct/`City()`/`IsEmpty()`
    now take `cityV4DB`+`cityV6DB` and pick by `ip.To4() != nil`; (b)
    removed the dead `whoisFile`/`whoisDB` entirely — PART 19's own text
    says "no whois.mmdb file exists," it was never passed to `geo.Open()`
    even before this change, and `geoip.databases.whois` remains a config
    flag with no file behind it, per spec; (c) made `DownloadDatabases()`
    and `loadDatabases()` resilient per-file (one bad/missing database no
    longer disables the other three), per PART 19's fail-open mandate.
    **Spec drift resolved upstream:** AI.md was subsequently updated
    (commit `b1e5672416cc`) to move the City IPv4/IPv6 databases to the
    GitHub Releases URLs used here while keeping ASN/Country on the
    jsDelivr npm CDN; the code now matches the spec and no manual AI.md
    edit is outstanding. Verified:
    `go build ./...`, `go test ./src/iputil/geo/... ./src/geoip/...
    ./src/server/... ./src/config/...`, and full `make test` (60.2%
    coverage) all pass in `casjaysdev/go:latest`. `Read: AI.md PART 19`;
    `src/geoip/geoip.go`, `src/geoip/geoip_test.go`,
    `src/iputil/geo/geo.go`, `src/iputil/geo/geo_test.go`,
    `src/server/http_test.go`, `src/config/config.go`.

15. **AI.md PART 16's two color-palette sections are NOT contradictory;
    both specify Dracula-dark/GitHub-Light-light.** A prior pass
    incorrectly concluded the "CSS Variable Reference" section overrode
    "Themes (NON-NEGOTIABLE)" with Dracula/navy values, and converted the
    palette to an invented "Tokyo Night" scheme instead — that was a
    misread. Direct re-read of both AI.md sections confirmed they agree
    on Dracula-based dark (`#282a36` background, `#bd93f9` primary, etc.)
    and GitHub-Light-based light (`#ffffff` background, `#0969da`
    primary, etc.), matching the pre-existing `config.go`
    `ThemeColor: "#bd93f9"` default. Reverted `src/common/theme/colors.go`,
    `src/common/theme/css.go`, `src/swagger/theme.go`,
    `src/graphql/theme.go`, and their tests (`swagger_test.go`,
    `graphql_test.go`) from Tokyo Night back to Dracula/GitHub-Light
    literal hex; corrected stale "Tokyo Night" doc comments. Also found
    and fixed a previously-undiscovered violation in
    `src/server/handler/special.go` (PWA manifest `ManifestHandler` +
    `OfflineHandler`'s inline `<style>`), which hardcoded `#1a1a2e`/
    `#0066cc`/etc. instead of using the theme package at all — now
    sources its colors from `theme.ThemePaletteDark`. `Read: AI.md
    PART 16 lines 24327-24491`; `src/common/theme/colors.go`,
    `src/common/theme/css.go`, `src/swagger/theme.go`,
    `src/graphql/theme.go`, `src/server/handler/special.go`.

16. **"No reverse header detection" was `s.IPHeaders` defaulting to
    empty.** User clarified the report meant X-Forwarded-For / proxy
    headers not being detected (real client IP not used, proxy's own IP
    shown instead). Root cause found: `src/server/http.go`'s `RequestIP`
    (feeds `/`, `/json`, GraphQL `myIP`, etc. — the whole app's "what is
    my IP" answer) resolves via `ipFromRequest(s.IPHeaders, ...)`, and
    `s.IPHeaders` (`src/main.go`) was populated ONLY from the `--header`
    CLI flag with no default — so unless an operator manually passed
    `--header X-Forwarded-For` etc. on every start, those headers were
    never read regardless of `trusted_proxies`, and the app always showed
    the immediate peer's IP. This contradicted AI.md PART 12 "Client IP
    Detection" (line 12797), which specifies `CF-Connecting-IP` /
    `True-Client-IP` / `X-Real-IP` / `X-Forwarded-For` / `X-Client-IP` as
    an always-active priority list gated only by `trusted_proxies`, not
    by an opt-in flag — `src/netutil/proxy.go`'s `GetClientIP` (used for
    logging/rate-limiting/allowlist) already implemented this list
    correctly and was the reference for the fix. Fixed by adding
    `defaultTrustedIPHeaders` (the same 5-header priority list) in
    `src/main.go`, applied to `srv.IPHeaders` whenever `--header` is not
    explicitly set. Verified live: `curl -H "X-Forwarded-For: 8.8.8.8"
    .../` now returns `"ip": "8.8.8.8"` (previously returned the loopback
    peer IP regardless of the header). `Read: AI.md PART 12 lines
    12797-12808`; `src/main.go`, `src/server/http.go`,
    `src/server/request.go`.

17. **`src/client/` CLI and TUI now consume the `theme` package's
    ANSI-mapped `TerminalPalette` instead of hardcoded hex/raw ANSI.** Per
    AI.md PART 16 "CLI/TUI Color Mapping" and PART 32 "CLI/TUI/GUI
    Theming", CLI/TUI must map semantic roles to ANSI 16-color indices
    (never the literal hex `ThemePalette`, which is web/Swagger/GraphiQL-
    only). Added `TerminalPalette` struct + `TerminalPaletteDark`/
    `TerminalPaletteLight` + `TerminalPaletteFor()` to
    `src/common/theme/colors.go` with the spec's exact index values.
    Rewrote `src/client/tui/theme.go` (`ActivePalette` selected via
    `detectMode()`, `COLORFGBG`-based per PART 16 "System Theme
    Detection") and `src/client/tui/styles.go`
    (`StylesFromTerminalPalette`), fixed `layout.go`/`model.go`'s
    remaining `DefaultTheme.Border`/`.Accent` references. Rewrote
    `src/client/cli/output.go` to hold a `theme.TerminalPalette`, gate
    color via the existing `display.ColorEnabled(colorFlag)` (PART 8
    priority order, reused rather than duplicated), and emit
    `\033[38;5;%sm...\033[0m` escapes per PART 32's exact template.
    Removed `main.go`'s dead `_ = display.ColorEnabled(colorFlag)` line
    now that `output.go` calls it internally. Updated
    `src/client/cli/output_test.go` for the renamed `colors`/`palette`
    fields. Verified: `go build ./...` and `go test ./src/client/...`
    (all packages, including `cli` and `tui`) pass in
    `casjaysdev/go:latest`; repo-wide sweep confirms zero remaining
    `DefaultTheme`/hardcoded-hex references under `src/client/`.
    `Read: AI.md PART 16 lines 24413-24491, PART 32 lines 41746-41830`;
    `src/common/theme/colors.go`, `src/client/tui/theme.go`,
    `src/client/tui/styles.go`, `src/client/tui/layout.go`,
    `src/client/tui/model.go`, `src/client/cli/output.go`,
    `src/client/cli/output_test.go`, `src/client/main.go`.

18. **`privacy.tmpl` now renders the Cookie Policy / Data Usage / CCPA
    sections AI.md PART 16 specifies (was open items 1 and 5).** Added all
    12 required sections (Summary, Cookie Policy, Data Collection, Data
    Usage, Data Security, Data Storage, Data Retention, Third Parties,
    Your Rights, conditional CCPA Opt-Out, Manage Preferences, Contact) to
    `src/server/template/page/privacy.tmpl`, calling
    `.Privacy.GetAnalyticsDescription`/`.Privacy.GetDataUsageContent` and
    the new `markdownToHTML`/`humanize` template funcs
    (`src/server/templates.go`, via `goldmark`, added as a direct
    dependency). Added `TrackingConfig.TypeName()`
    (`src/config/config.go`) for the Analytics Cookies section's provider
    name. Wired `PagesHandler.Privacy`/`.Tracking`/`.CCPAOptedOut` into
    `PageData` and added `CCPAHandler` (POST `/server/ccpa`, PRG pattern
    matching `ConsentHandler`/`ThemeHandler`) plus the route in
    `src/server/http.go`. Rewrote `APIV1ServerPrivacyHandler`/
    `PrivacyResponse` to source the JSON response from live config instead
    of hardcoded placeholders, and added `json` tags (previously missing)
    to `SharingCondition`/`ThirdPartyService` so the API's `data.sharing`/
    `third_party.services` fields serialize as the spec's lowercase
    `condition`/`when`/`data`/`name`/`purpose`/`data_sent`/`policy_url`
    keys instead of Go's default capitalized field names. Added the one
    missing i18n key (`privacy.uses_analytics`) to all 7 locales. Verified
    by building via `make dev` and curling a live instance: HTML and JSON
    both correctly toggle the CCPA section/`ccpa.applicable` and the
    Data-Usage content on `data.sold` true/false, third-party services
    table and sharing conditions render from config, and the CCPA opt-out
    forms are correctly gated behind `.CSRFToken` (matching
    `contact.tmpl`'s established guard pattern) so they don't render
    without a CSRF cookie. Added test coverage for the new code
    (`TestCCPAHandler_*` in `pages_test.go`,
    `TestTrackingConfig_TypeName_*` in `config_test.go`,
    `TestTemplateFuncMap_MarkdownToHTML`/`_Humanize` in new
    `templates_test.go`) to keep `make test`'s 60% coverage gate passing.
    `Read: AI.md PART 16 "/server/privacy" (lines 26179-26495)`;
    `src/server/template/page/privacy.tmpl`, `src/server/templates.go`,
    `src/config/config.go`, `src/server/handler/pages.go`,
    `src/server/http.go`.

19. **`openMaintenanceDB`/server startup ignored `dirs.DB` and reconstructed
    the sqlite path from `dirs.Data`, silently discarding a custom
    `DATABASE_DIR`.** Confirmed against `AI.md` PART 4/PART 12
    (`GetDatabaseDir`, lines 12131-12144): `DATABASE_DIR` is meant to
    independently relocate the sqlite database directory (Native default
    `{data_dir}/db/`, Docker default `/data/db/sqlite`), separate from the
    data directory — the maintenance backup/restore path
    (`maintenanceBackup`/`maintenanceRestore`) already treated `dirs.DB` as
    the authoritative, self-contained sqlite directory (copying it as a
    unit), confirming `db.NewDB` was the outlier. Changed `db.NewDB`'s
    second parameter from `dataDir` to `dbDir` — it now uses the passed
    directory directly instead of joining `dataDir + "db"` — and updated
    both call sites (`main()`'s server-startup DB open and
    `openMaintenanceDB`) to pass `dirs.DB` instead of `*dataDir`/
    `dirs.Data`. Updated `TestNewDB_SQLite`'s expected path accordingly.
    Verified live via `make dev`: with `DATABASE_DIR` set to a directory
    outside the data dir, `server.db`/`-wal`/`-shm` were created directly
    inside it and no `{data}/db` directory was created at all; `make test`
    passes (60.1% coverage, gate is 60%). `Read: AI.md PART 4, PART 12
    (lines 12096-12144)`; `src/db/db.go` (`NewDB`), `src/main.go`
    (`openMaintenanceDB`, server-startup DB open), `src/db/db_test.go`.

20. **Privilege drop did not clear supplementary groups (hardening).**
    `src/privilege_unix.go`'s `dropPrivileges` called `Setgid` then
    `Setuid` but never `setgroups(2)`, so any supplementary groups
    inherited from the root process (e.g. a `docker`/admin group) stayed
    attached to the service-account process after the drop. AI.md PART 23
    (Server Startup Sequence step 8h, "DROP PRIVILEGES") and the
    PART 5-referenced drop-sequence table do not explicitly mandate
    `setgroups` clearing — grepped the whole spec for "setgroups", zero
    matches — so this is a defense-in-depth hardening fix, not a
    spec-compliance bug. Added `syscall.Setgroups([]int{})` immediately
    before `Setgid`/`Setuid` (must run while still root — only root can
    call `setgroups(2)`). Verified live in an Incus `debian:latest`
    container: added a supplementary group (`extragrp`, gid 1000) to
    root via `groupadd`/`usermod -aG`, launched the binary through
    `su -c '...' root` (a bare `incus exec ... &` does not trigger
    `initgroups(3)` and gave a false-negative first test), and confirmed
    via `/proc/<pid>/status` that the dropped `ipgaze` process showed
    `Uid: 899 899 899 899`, `Gid: 899 899 899 899`, and an empty
    `Groups:` line despite root having had the supplementary group
    beforehand. `make test` passes (60.1% coverage). `Read: AI.md PART 23`;
    `src/privilege_unix.go` (`dropPrivileges`).

21. **CLI `cli.yml` config schema used flat `Server`/`Token` fields where
    AI.md PART 32 documents nested `server.primary`/`auth.token` keys.**
    Confirmed against the PART 32 example (`server:` block with a
    `primary:` subkey, `auth:` block with a `token:` subkey, lines
    44481-44503) and the priority-order text (lines 44586, 44594-44595,
    45096-45103) that both consistently reference the nested form —
    `src/client/setup/config.go`'s `CLIConfig.Server`/`.Token` were flat
    top-level strings, a real schema deviation, not the spec being wrong.
    `display.mode` was already correctly wired (`cfg.Display.Mode`,
    `src/client/main.go` line 189) — no change needed there. Changed
    `CLIConfig.Server` to a new `ServerConfig{Primary string}` and
    `CLIConfig.Token` to a new `AuthConfig{Token string}`, updated the 2
    read call sites in `src/client/main.go` (`cfg.Server.Primary`,
    `cfg.Auth.Token`) and all field literals/assertions in
    `config_test.go`. Found a second, related but separately-scoped issue
    while doing this (logged as new open item 6): the save-side
    `SaveIfEmptyOrInvalid`/`SaveCLIConfigToFile` helpers already exist but
    are never called from `main.go`, so `--server`/`--token` are never
    actually persisted despite the spec requiring it. `make test` passes
    (60.1% coverage; `src/client/setup` package itself at 86.4%). `Read:
    AI.md PART 32 lines 44481-44503, 44586-44595, 45096-45103`;
    `src/client/setup/config.go`, `src/client/setup/config_test.go`,
    `src/client/main.go`.

22. **Open item 8: `src/server/theme.go` did not exist — theme detection
    logic was duplicated verbatim in `src/server/http.go`
    (`DefaultHandler`) and `src/server/handler/pages.go`
    (`NewPageData`).** AI.md PART 16's "Theme Implementation Location"
    table (lines 24603-24610) specifies "Theme core logic" belongs in
    `src/server/theme.go` ("Theme detection, switching, persistence").
    Created `src/server/theme.go` (package `server`) with `DetectTheme`,
    `ValidateTheme`, and `ThemeCookie` as the single implementation.
    `DefaultHandler` (same package) now calls `DetectTheme(r)` directly.
    `handler.PagesHandler` (package `handler`, a different package)
    **cannot** import `src/server` to call it directly — `src/server`
    already imports `src/server/handler` one-directionally (confirmed via
    repo-wide grep: no reverse import exists) to build `PagesHandler`, so
    `handler` importing `server` back would be a compile-breaking Go
    import cycle. Resolved via dependency injection, matching the
    existing `PagesHandler.Render` func-field pattern already used in
    this struct: added `PagesHandler.DetectTheme func(*http.Request)
    string`, set to `server.DetectTheme` where `s.PagesHandler` is built
    (`http.go`, `~s.setupServer` area), and `NewPageData` now calls
    `h.DetectTheme(r)` when set (falls back to the old inline read only
    when unset, e.g. tests that construct `PagesHandler` directly without
    going through `server.Server`). This is the single implementation the
    spec's table intends ("Theme detection, switching, persistence" in
    one place, never duplicated) even though the literal file both
    call-sites resolve through is `src/server/theme.go` rather than a
    file `handler` can import directly — documenting the deviation here
    since AI.md is read-only and the literal path is not achievable
    without breaking Go's package graph. ThemeHandler (switching) and its
    cookie-set (persistence) already lived in one place
    (`handler.PagesHandler.ThemeHandler`, matching the `ConsentHandler`/
    `CCPAHandler` PRG-pattern siblings in the same file) so were not
    moved — only the duplicated detection snippet needed
    consolidating. `go build ./...` and `go test
    ./src/server/...` both pass; `go-lint` agent reports all three
    changed files clean. `Read: AI.md PART 16 lines 24603-24610`;
    `src/server/theme.go` (new), `src/server/http.go`,
    `src/server/handler/pages.go`.

23. **Open item: CLI never persisted `--server`/`--token` flags to
    `cli.yml` (dead code).** AI.md PART 32 requires `--server`/`--token`
    flag values be saved to `cli.yml` (`server.primary`/`auth.token`)
    "only if empty/invalid" (lines 44594-44595, 45097). The existing
    `SaveIfEmptyOrInvalid`/`SaveCLIConfigToFile` helpers were never
    called from `main.go`. Wired them up: captured the raw `--server`
    flag value (`flagServerURL`) before the priority-fallback chain
    overwrites `serverURL` with env/config/default values, added
    `persistCLIFlags(cfg, flagServerURL, tokenFlag)` (called right after
    token resolution) which saves only when the flag is valid AND the
    existing stored value is empty/invalid, per "never clear valid".
    Added `setup.ValidateServerURL` (http/https scheme + non-empty host)
    and `setup.ValidateToken` (non-empty) since no reusable validators
    existed — `urlutil.ValidateRemoteURL` was considered but is an
    SSRF-guarded remote-fetch validator (blocks private/localhost IPs),
    wrong fit for a user's own server URL which may legitimately be
    localhost in dev. Env vars (`IPGAZE_SERVER_PRIMARY`,
    `IPGAZE_TOKEN`) and the compiled `{official_site}` default never
    persist — only an explicit flag does, matching PART 32's token rule
    ("environment variable ... does NOT save to config") applied
    consistently to `--server` too. Added 6 new tests
    (`main_test.go`: nil config, no flags, empty-current-saves,
    valid-current-not-overwritten, invalid-current-replaced,
    invalid-flag-not-saved) and 2 validator test tables
    (`config_test.go`). `go build ./...`, `go test ./src/client/...`,
    and `gofmt -l` all pass; `go-lint` agent reports all four changed
    files clean. `Read: AI.md PART 32 lines 44581-44598, 45095-45103`;
    `src/client/main.go` (`persistCLIFlags`, new; `main`, edited),
    `src/client/setup/config.go` (`ValidateServerURL`, `ValidateToken`,
    new), `src/client/main_test.go` (new), `src/client/setup/config_test.go`.

24. **`IPGAZE_SERVER_PRIMARY` env var is not documented in AI.md PART
    32's "Server Address Resolution" priority table** (lines 44583-44588:
    flag → `server.primary` → `{official_site}` → error — no env-var
    step), yet `src/client/main.go` reads it between the flag and the
    config-file check. By contrast the token env var
    (`{PROJECT_NAME}_TOKEN`) IS documented (line 45102). Found while
    implementing item 23 (`persistCLIFlags`); not resolved this pass —
    removing working env-var support to match the letter of an
    undocumented-by-omission table is a design decision (does the spec
    intend no server env var at all, or was it just left out of this one
    table), not a mechanical fix, so it needs a decision rather than a
    silent change. `Read: AI.md PART 32 lines 44581-44598`;
    `src/client/main.go` (`serverURL` priority chain, ~line 150).

25. **Open item: `OfflineHandler` hardcoded `lang="en"` and English-only
    PWA offline-page strings.** AI.md PART 16 frontend rules and PART 30
    (I18N & A11Y) require every user-facing string be translatable via
    `{{t .Lang "key"}}`/`i18n.T` and `<html lang dir>` set from the
    request, never a literal `lang="en"`. `OfflineHandler` built its HTML
    with `fmt.Fprintf` and literal English text ("You are offline",
    "Try again", etc.) and a hardcoded `lang="en"`. Fixed by detecting
    the request's locale/direction the same way `PagesHandler.NewPageData`
    does (`i18n.DetectLocale(r)` / `i18n.LocaleDirection(lang)`), building
    a lang-scoped context with `i18n.WithLang`, and replacing the literal
    strings with three new `pwa.*` translation keys (`offline_title`,
    `offline_description`, `offline_try_again`) rendered via `i18n.T`.
    Added the three keys, translated, to all 7 locale files
    (`en.json`, `ar.json`, `de.json`, `es.json`, `fr.json`, `ja.json`,
    `zh.json`). Added 3 new tests to `special_test.go`
    (`TestOfflineHandler_DefaultEnglish`,
    `TestOfflineHandler_TranslatesViaLangCookie`,
    `TestOfflineHandler_RTLDirection`) covering default English, cookie-
    driven French translation, and Arabic RTL direction. `go build ./...`,
    `go test ./src/server/handler/... ./src/common/i18n/...`, and
    `gofmt -l` all pass. `Read: AI.md PART 16 "Frontend Rules", PART 30
    (I18N)`; `src/server/handler/special.go` (`OfflineHandler`),
    `src/server/handler/special_test.go` (3 new tests), 7 locale JSON
    files under `src/common/i18n/locales/`.

26. **Open item: Tor `Start()` failure reason was not surfaced past a
    single Warning log.** AI.md PART 13's health-response field table
    (line 17832) documents `features.tor.status` as accepting
    `"healthy, error:{short message}"` — meaning the "needs a design
    decision" note on this item (previously logged as Open item 2) was
    wrong: the API shape is already spec'd, this only needed an
    implementation. Added a `lastErr error` field to `TorManager`, set
    in `Start()` on failure (cleared on success), and cleared in
    `Stop()` — moved the clear to before `Stop()`'s early-return guard
    so a `Stop()` call with nothing running still clears a stale error.
    `statusLocked()` now returns `"error:" + shortErrMsg(m.lastErr)`
    when not running, available, and `lastErr != nil` (instead of
    falling through to `"stopped"`). Added `shortErrMsg(err error)
    string`, which strips newlines and caps the message at 120 runes
    (ellipsis-suffixed) so a verbose wrapped Go error doesn't bloat the
    health payload. Added 5 new tests to `tor_test.go`
    (`TestStatus_ErrorAfterFailedStart`,
    `TestStop_ClearsLastErrAfterFailedStart`,
    `TestShortErrMsg_ShortMessagePassesThrough`,
    `TestShortErrMsg_TruncatesLongMessage`,
    `TestShortErrMsg_StripsNewlines`) plus a minimal `testError` helper
    type. `go build ./...`, `go test ./src/tor/...`, and `gofmt -l`
    all pass. `Read: AI.md PART 13 lines 17812-17843 (Health Response
    Fields)`; `src/tor/tor.go` (`TorManager` struct, `Start`, `Stop`,
    `statusLocked`, new `shortErrMsg`), `src/tor/tor_test.go` (5 new
    tests + `testError`).

27. **Open item: `src/main.go` had 39 `os.Exit(1)` call sites that
    should have used the sysexits constants already defined in the
    file.** The file defines `exUsage`, `exOsErr`, `exIoErr`,
    `exCantCreat`, `exConfig`, `exNoPerm` (lines 75-90) but 39 sites
    (lines 260, 433, 445, 459, 1718, 1771, 1788, 1817, 1823, 1850, 1854,
    2234, 2285, 2640, 2671, 3574, 3590, 3600, 3616, 3627, 3688, 3694,
    3714, 3721, 3729, 3755, 3765, 3768, 3774, 3781, 3794, 3799, 3805,
    3819, 3881, 3888, 3896, 3910, 3918) used plain `os.Exit(1)` instead.
    Delegated the classification/substitution to a `general-purpose`
    agent with the full line list and constant definitions; each site
    was matched to its actual failure category (fork/daemonize/OS
    dependency unavailable → `exOsErr`; network/file I/O failure →
    `exIoErr`; invalid flag/subcommand/argument → `exUsage`; missing
    output dir → `exCantCreat`; missing PGP config → `exConfig`;
    privilege-escalation/sudo denial → `exNoPerm`). Four sites had no
    exact sysexits category and needed a judgment call: line 2285
    (rate-limited operation → `exNoPerm`, no EX_TEMPFAIL equivalent
    defined in this file), line 3805 (no key files found at supplied
    path → `exIoErr`, treated as missing input data), line 3910 (I2P
    address regeneration key-file op failure → `exIoErr`, consistent
    with the Tor import-keys I/O sites), and the Tor/I2P "binary or
    provider not found" sites (1854, 3688, 3694, 3714, 3729, 3881, 3896)
    → `exOsErr` as the best fit for an unavailable OS-level dependency
    (no dedicated "service unavailable" constant exists). Exactly 39
    insertions/39 deletions in the diff (1:1 substitution, no other
    logic changed); `grep -n "os.Exit(1)" src/main.go` now returns zero
    matches. Verified with two separate `go-lint` agent passes (both
    clean) plus `gofmt -l ./src/`, `go build ./...`, and `go vet ./...`
    in Docker (all exit 0, no findings). `Read: src/main.go` lines
    75-90 (constant definitions) plus all 39 call sites before fixing;
    `src/main.go` (all 39 substitutions).

28. **Open item: `src/client/main.go:122` was flagged as building
    `cliout.NewOutput(colorFlag)` without checking `NO_COLOR` first.**
    Investigation found this to be a false positive — no code change
    needed. `cliout.NewOutput` (`src/client/cli/output.go`) already
    delegates color resolution to `display.ColorEnabled(colorFlag)`
    (`src/common/display/display.go:272-288`), whose precedence is
    exactly the order AI.md PART 8 requires: explicit `--color`
    flag (`yes`/`no`/`always`/`never`) first, then `NO_COLOR` (any
    non-empty value disables color), then `TERM=dumb`, then TTY
    auto-detect. `colorFlag` defaulting to `"auto"` was never the bug
    — `"auto"` correctly falls through to the `NO_COLOR` check inside
    `ColorEnabled`, it doesn't bypass it. Existing tests already cover
    this (`TestNewOutput_AutoWithNoColor`, `TestNewOutput_NeverColor`,
    `output_test.go` lines 34-48). `Read: src/client/main.go` line 122,
    `src/client/cli/output.go` (`NewOutput`),
    `src/common/display/display.go` lines 272-288 (`ColorEnabled`).

29. **`contact.sending`/`index.widget_port_label` locale-parity gap fixed**
    (app-breaking bug, fixed immediately rather than left in Open per
    AI.md PART 30's build-time key-validation requirement).
    `src/common/i18n/i18n.go`'s `init()` panics if any non-`en` locale
    is missing a key `en.json` has, so the two keys added to `en.json`
    by Resolved item 30 below broke `go test ./...` (every package
    that imports `i18n` failed at `init()`). Added `sending` (after
    `send`) and `widget_port_label` (before `widget_check_ip_label`) to
    `es.json`, `ar.json`, `zh.json`, `fr.json`, `de.json`, `ja.json`
    with real translations matching each locale's existing tone (not
    machine-literal copies of the English). Verified: `go test
    ./src/common/i18n/...` passes in Docker; all 7 locale files pass
    `jq empty`.

30. **Open item 1: "General UI/UX not that good" — "Smart Content Detection"**
    (AI.md PART 16, lines 20790-20929), **"UI Components"** (lines
    21718-21897), and **"Accessibility"** (line 22289) cross-checked
    against actual templates/CSS/JS this pass. "Smart Content Detection":
    `src/server/request.go` `detectClientType()` (lines 91-131) confirmed
    byte-for-byte compliant with the spec's Accept-header → User-Agent →
    empty-UA → default precedence — no fix needed. "UI Components" +
    "Accessibility": dispatched to the `designer` subagent, which found
    heading hierarchy, alt text, skip-link, and `lang`/`dir` attributes
    already compliant, and toggle-switch/danger-button/empty-state
    guidance not applicable to any current page, then applied six fixes:
    (1) `src/server/template/partial/nav.tmpl` — removed inline
    `onchange="this.form.submit()"` (JS-necessity violation, the
    `<select>` degrades fine as a plain `<form method="post">` submit);
    added `aria-expanded`/`aria-controls` to `#nav-toggle` and
    `id="nav-panel"` to the panel it controls; (2)
    `src/server/template/partial/consent_banner.tmpl` — added a native
    `<dialog id="cookie-preferences-modal">` that was referenced by
    `data-action="cookie-preferences"` in `privacy.tmpl:54,146` but never
    defined (a dead button before this fix); (3)
    `src/server/template/index.tmpl` — added `aria-label` (new key
    `index.widget_port_label`) to `#portInput`; (4)
    `src/server/template/page/contact.tmpl` — wired the submit button to
    the new generic `data-loading-text` loading-state handler (new key
    `contact.sending`); (5) `src/server/static/js/app.js` — added
    backdrop-click-to-close for `<dialog>`s, a generic single-submit/
    loading-text/re-enable-on-bfcache handler, `initNavToggleAria()`, and
    rewrote the toast system (max-5 visible queue, `dismissToast`,
    fixed a hover-pause/mouseleave-resume bug, Escape-to-dismiss,
    moved to top-right newest-on-top per the PART 16 "Toast Behavior
    Rules"); `handleCookieConsent` now also closes the new modal and
    shows a confirmation toast; (6) `src/server/static/css/main.css` —
    replaced the legacy JS-toggled `.modal`/`.modal-backdrop` with
    native `dialog.modal`/`::backdrop`; changed `.nav-checkbox` from
    `display: none` (a WCAG 2.1 AA keyboard-navigation failure — it
    removed the mobile nav toggle from the tab order entirely) to an
    sr-only clip with a `:focus-visible` outline; added
    `.modal-footer`/`.cookie-preference-list` rules, `.toast-progress`/
    `@keyframes countdown`, and a `:user-invalid`/`.field-error`
    form-validation CSS foundation. Verified: `go build ./...` in
    `casjaysdev/go:latest` exits 0 (template/CSS/JS-only change, no `.go`
    files touched); every new/consumed i18n key
    (`cookie_consent.manage_preferences`, `.essential_description`,
    `.preference_description`, `.analytics_description`, `.accept`,
    `.decline`, `common.close`) confirmed already present in `en.json`;
    the two genuinely new keys (`contact.sending`,
    `index.widget_port_label`) added to `en.json` only — not yet
    translated into other locales, and four follow-ups the designer
    agent explicitly deferred — tracked as Open items 1-4 below.

31. **AI.md commit `e18697ec7b1b`'s three NON-NEGOTIABLE requirements**
    **audited against actual code (was Open item 4):**
    (a) JS-necessity-gate (PART 16 ~line 18006) — spot-checked
    `src/server/static/js/app.js` and `landing.js`; the global
    `document.addEventListener('submit', ...)` handlers
    (`initSiteBannerDismiss`, submit-button-disable) are documented,
    genuine progressive enhancement ("JS enhancement; no-JS uses form
    POST" — `app.js:337`) with a native `<form method>` fallback, not a
    forms/validation reimplementation. No violation found; no fix
    needed. (b) Service worker guaranteed-`Response` audit (PART 16 PWA
    ~line 22390) — found a real bug: `src/server/handler/special.go`
    `ServiceWorkerHandler`'s dynamically-served `/sw.js` ended both the
    HTML-navigation and static-asset `fetch` branches on
    `cached || caches.match('/offline.html')`, which resolves to
    `undefined` (net::ERR_FAILED) when both the request cache and the
    offline-page cache miss — exactly the anti-pattern the spec warns
    against. Fixed by adding a synthesized guaranteed fallback
    (`new Response('', {status: 503, ...})` for navigations, `504` for
    static assets) after the offline-cache lookup on both branches. (c)
    Backend guaranteed-response audit (~line 23792, PART 9) — found no
    `recover()` anywhere in `src/server` (confirmed via
    `grep -rln "recover()" src/server/`); a handler panic was only
    caught by Go's stdlib `http.Server`, which logs it and drops the
    connection with no response body — a dead connection, not an error
    page. Added `RecoverMiddleware` (`src/server/middleware.go`), wired
    as the outermost middleware in `Handler()`
    (`src/server/http.go`, before `URLNormalizeMiddleware`) so it wraps
    every other middleware and handler. It recovers the panic, logs it
    with full request context (request id, method, path, IP), and — only
    if no response bytes have been written yet — falls back to a
    minimal hardcoded response honoring content negotiation via
    `detectClientType` (JSON `{"ok":false,"error":"SERVER_ERROR",...}`
    or a bare inline-HTML 500 page), per the spec's explicit "minimal,
    hardcoded" wording (not a template render, which could itself fail).
    Verified: `go build ./...` and `go vet ./src/server/...` clean in
    Docker; `make test` passes (`src/server` 81.5% coverage,
    `src/server/handler` 70.6%, both unchanged pass/fail status, overall
    project coverage 60.2%).

    **New Open item logged below (item 4)**: the PART 9 rule "ALL error
    pages MUST use the site theme system — no plain/unstyled error
    pages" is still violated for the *normal* (non-panic) error path —
    scoped out of this fix as a separate design decision, not guessed.

32. **Normal (non-panic) HTML error responses now render the themed**
    `error.tmpl` partial instead of bare plain text (was Open item 4).
    Took design option (a) from item 4's writeup: added
    `Code`/`Title`/`Message`/`RequestID` fields to `handler.PageData`
    (`src/server/handler/pages.go`); added
    `src/server/template/page/error_page.tmpl` (named to avoid a
    template-name collision with `template/partial/error.tmpl`'s
    `error.tmpl` basename) whose `content` block does `{{template
    "error" .}}`; added `buildBaseTemplate`/`NewTemplateExecutor` to
    `src/server/templates.go` — a shared layout+partials base plus a
    status-agnostic executor that renders into an `io.Writer` without
    touching HTTP headers, reusing the same `ParseFS` call list as
    `NewPageRenderer`. `src/server/error.go`'s `appHandler.ServeHTTP`
    now renders into a `bytes.Buffer` first via two package-level vars
    (`errorPageExecute`, `errorPageData`) injected at server startup
    (`src/server/http.go`, right after `PagesHandler` is configured —
    mirrors the existing `DetectTheme` injection pattern, since
    `appHandler` is a package-level function type with no access to a
    `*handler.PagesHandler` instance) — only committing the write
    (headers + `WriteHeader(e.Code)` + buffer flush) once the render
    succeeds; a render failure is logged and falls through untouched to
    the pre-existing guaranteed plain-text response, so the error path
    itself can never break the response. Gated on
    `detectClientType(r) == "html"` and `!e.IsJSON()`, so JSON clients
    (`Accept: application/json` or explicit `.AsJSON()` callers) are
    unaffected and still get the canonical `{"ok":false,"error":...,
    "message":...}` shape. `RecoverMiddleware`'s panic-recovery fallback
    (item 31c) was explicitly left untouched — still minimal/hardcoded
    per spec. Verified: `go build ./...` clean in
    `casjaysdev/go:latest`; `go test ./src/server/...` passes (run with
    `MODE=production` to work around an unrelated pre-existing i18n
    `init()` panic from Open item 1's in-flight locale-key gap, which
    blocks the full `make test` run for every package importing i18n —
    not caused by or fixed by this change); built the binary
    (`go build ./src`) and ran it standalone, then `curl`'d a 404 both
    ways: `Accept: text/html` returned `200`-styled `404 Not Found` HTML
    with the full themed layout (nav/footer/CSS variables,
    `<div class="error-container">`, `🔍` icon, `<h1 class="error-title">
    404 Not Found</h1>`, `<p class="error-message">Not found</p>`, and a
    `Request ID:` row) at `Content-Type: text/html; charset=utf-8`;
    `Accept: application/json` returned the unchanged canonical JSON
    body (`{"ok": false, "error": "NOT_FOUND", "message": "Not found"}`)
    at `Content-Type: application/json`.

33. **Open item 1: hardcoded English toast strings in**
    `src/server/static/js/app.js` (`'Cookies accepted'`/`'Cookies
    declined'` in `handleCookieConsent`, plus `'Copy failed'`, the
    `'Theme: '` prefix in `toggleTheme`, and the `'Error: '` prefix in
    `apiGet`/`apiPost`) now go through a `data-i18n-*` attribute bridge:
    `#toast-container` in `src/server/template/layout/base.tmpl` carries
    `data-i18n-cookie-accepted`/`-declined`, `data-i18n-copy-failed`,
    `data-i18n-theme-dark`/`-light`/`-auto`, `data-i18n-theme-toggle-prefix`,
    and `data-i18n-error-prefix`, each rendered via `{{t .Lang "key"}}`.
    A new `i18nStr(key, fallback)` helper in `app.js` reads
    `#toast-container`'s `dataset`, falling back to the prior literal
    English only if the attribute is missing. Added keys
    `cookie_consent.accepted_toast`/`declined_toast`, `common.copy_failed`,
    `common.error_prefix`, and `theme.toast_prefix` to
    `src/common/i18n/locales/en.json`, and the identical English values
    (placeholders pending real translation) to the other six locale files
    (`ar`, `de`, `es`, `fr`, `ja`, `zh`) — required because
    `src/common/i18n/i18n.go`'s `init()` panics outside `MODE=production`
    on any locale missing a key present in `en.json` (this was the
    pre-existing i18n panic Resolved item 32 had to work around with
    `MODE=production`; it is now fixed at the source). These six
    placeholder values still need a human translator to replace them with
    real `ar`/`de`/`es`/`fr`/`ja`/`zh` translations — no foreign-language
    text was invented. Verified: `jq .` on all seven locale JSON files
    passes; `grep -n "'Cookies accepted'\|'Cookies declined'\|'Copy
    failed'\|'Theme: '"` against `app.js` shows only `i18nStr(...,
    'fallback')` call sites, no standalone hardcoded toast strings; `go
    test ./src/common/... ./src/server/...` passes in
    `casjaysdev/go:latest` with no `MODE` override needed (the i18n
    `init()` panic no longer triggers).

34. **Open item 2: Form Validation was CSS-foundation-only** — `main.css`
    had `:user-invalid`/`.field-error` rules (Resolved item 30) but no
    form wired up matching markup. `src/server/template/page/contact.tmpl`
    (the only form in `src/server/template/` with real user-input fields;
    `privacy.tmpl`'s and `consent_banner.tmpl`'s forms are hidden-field/
    button-only, nothing to validate) now has `aria-describedby="email-error"`
    on the email `<input>` and `aria-describedby="message-error"` on the
    `<textarea>`, each paired with a `<span class="field-error" role="alert">`
    using existing i18n keys `errors.invalid_email`/`errors.required`. The
    CSS foundation only hid/showed `.field-error` via a `hidden` attribute
    concept that doesn't compose with `:user-invalid` — fixed
    `src/server/static/css/main.css`'s `.field-error` rule to `display:
    none` by default, revealed via new
    `.form-group input:user-invalid + .field-error` (and `select`/`textarea`
    variants) sibling-combinator rules, so the browser's native constraint
    validation drives visibility with zero JS, exactly per AI.md PART 16
    "Form Validation"'s "HTML5 first" rule. Verified: `grep -c '{{'`/`'}}'`
    on `contact.tmpl` and `base.tmpl` show matching open/close counts
    (22/22, 30/30) — template syntax unaffected; `go build ./...` and
    `gofmt -l src/common/theme/` clean in `casjaysdev/go:latest`.

35. **Open item 3: color contrast was only spot-checked visually**
    (Resolved item 29), not measured against WCAG AA. Computed WCAG 2.1
    relative luminance/contrast for every text-on-background and
    UI-element-on-background pair in `src/common/theme/colors.go`'s
    `ThemePaletteDark`/`ThemePaletteLight` (the single source for the
    injected `--color-*` CSS variables, per `src/common/theme/css.go`).
    Dark theme: text `#f8f8f2` 13.36:1, success `#50fa7b` 10.38:1, warning
    `#ffb86c` 8.36:1, info `#8be9fd` 10.29:1, accent `#ff79c6` 5.97:1,
    primary `#bd93f9` 5.90:1, error `#ff5555` 4.53:1 — all pass 4.5:1.
    `border-hover` `#6272a4` 3.03:1 passes the 3:1 UI-component minimum.
    `muted` `#6272a4` on `--color-bg` was **3.03:1**, below the 4.5:1
    normal-text minimum, and it is used as real body/label/caption text
    in ~20 places in `main.css` (form labels, timestamps, footer text),
    none large enough to qualify for the 3:1 large-text exception — a
    genuine WCAG AA failure. Fixed by changing `ThemePaletteDark.Muted`
    from `#6272a4` to `#8894ba` (same hue, lightened) — recomputed
    contrast 4.74:1 on `--color-bg`, 4.54:1 on `--color-bg-card`
    (`--color-bg-card` is the tightest surface it appears on). Light
    theme's `muted` (`#59636e`, 6.11:1) and all other light-theme pairs
    already passed and were left unchanged. `--color-border` (dark
    1.56:1, light 1.43:1) is below the 3:1 UI-component minimum but was
    deliberately left unchanged: it is a decorative card/divider outline,
    not the sole means of identifying an interactive component's
    boundary (inputs/cards are also visually distinguished by background
    fill and spacing), which WCAG 2.1 SC 1.4.11 treats as exempt — changing
    it to reach 3:1 (`#6f7492`) would visibly clash with the adjacent
    `border-hover`/`muted` hues and was judged too large a look change for
    a decorative element that isn't a hard failure; flagged here rather
    than silently skipped. Updated `colors.go`'s and `css.go`'s doc
    comments (previously claimed the palette matched AI.md's literal
    values "verbatim") to note the one intentional Muted deviation and
    why. Verified: contrast ratios above computed via the standard WCAG
    relative-luminance formula (`(L1+0.05)/(L2+0.05)`); `go test
    ./src/common/theme/...` passes in `casjaysdev/go:latest` (no test
    asserts an exact Muted hex, only hex-format validity); `gofmt -l
    src/common/theme/` and `go build ./...` clean.

36. **PART 9 "Asset Version-Busting" / "Version-Change Purge" audit** —
    verified all five requirements against the codebase. Already
    compliant: the `asset()` template helper exists
    (`src/server/templates.go:55`) and every template already routes
    through it — `grep -rn '"/static/`/`src="/static` across
    `src/server/template/` found zero hand-written bare URLs; the static
    handler (`src/server/http.go:798-806`) already sent `immutable` only
    on a matching `?v=`, else `no-cache`+`ETag`; HTML responses
    (`IndexHandler` in `http.go`, `NewPageRenderer` in `templates.go`,
    the themed error page in `error.go`) already sent `no-store`+
    build-stamp `ETag`. Missing and fixed: (1) `/sw.js` and
    `/manifest.json` (`src/server/handler/special.go`) set no
    `Cache-Control`/`ETag` at all — added `no-cache` + build-stamp `ETag`
    via a new `SpecialHandler.AssetStamp` field (wired from
    `Server.AssetStamp()` in `http.go`) and an `assetStampOrCommit()`
    fallback for contexts that construct `SpecialHandler` directly. (2)
    "Version-Change Purge (Clear-Site-Data)" was entirely unimplemented —
    no `ipgaze_build` cookie, no `Clear-Site-Data` header anywhere. Added
    `applyVersionPurge(w, r, stamp)` in `http.go` (sets/reads the
    `ipgaze_build` cookie, `Path=/`, `Max-Age=31536000`, `Secure`,
    `SameSite=Lax`; emits `Clear-Site-Data: "cache", "storage"` — never
    `"cookies"` — only on a stamp mismatch) and wired it into all three
    HTML response paths (`IndexHandler`, `NewPageRenderer`, the themed
    error page). This required widening the `PageRenderer` function type
    from `func(w, page, data) error` to `func(w, r, page, data) error` so
    the renderer can read the request cookie; updated the 6 call sites
    (`src/server/handler/pages.go` x5, `src/server/handler/health.go` x1)
    and the matching test helpers (`coverage_boost_test.go`,
    `pages_test.go`). Verified: `make test` passes (60.1% coverage,
    Docker `casjaysdev/go:latest`); `go vet ./...` clean; built the binary
    (`go build -ldflags "-X main.Version=1.2.3 -X main.CommitID=abc1234"`)
    and curled a running instance — static asset with matching `?v=` got
    `Cache-Control: public, max-age=31536000, immutable`; without/with a
    stale `?v=` got `no-cache`+`ETag`; `/sw.js` and `/manifest.json` both
    got `no-cache`+`ETag: "1.2.3-abc1234"`; `/` and `/server/about` with
    `Accept: text/html` got `Cache-Control: no-store`, `ETag`, and
    `Set-Cookie: ipgaze_build=1.2.3-abc1234`; a stale
    `Cookie: ipgaze_build=0.0.1-stale` on those two HTML routes produced
    `Clear-Site-Data: "cache", "storage"` in the response, while the same
    stale cookie on `/static/...`, `/sw.js`, and `/api/v1/ip` never
    produced `Clear-Site-Data`. `Read: AI.md PART 9`

37. **PART 11/16 audit: constant-time compare, four secrets, CORS/CSRF**
    — verified constant-time comparison and the four required secrets are
    already correct: every token/signature comparison in the codebase
    already uses `crypto/subtle.ConstantTimeCompare` or `hmac.Equal` (grep
    across `src/` found no `==`/`strings.Compare` comparisons of
    secret-derived values), and `installation_secret`,
    `cookie_signing_key`, `csrf_token_secret`, and
    `server.security.encryption_key` all already exist as four distinct
    generated values. Missing and fixed, in `src/server/middleware_csrf.go`:
    (1) removed the Origin/Referer-based same-origin CSRF bypass
    (`isSameOrigin`) — AI.md PART 16 requires the double-submit token on
    every mutating browser request regardless of Origin, since
    Origin/Referer can be absent or spoofed by non-browser clients; (2)
    replaced the `logSecurityEvent` no-op placeholder with a real call to
    `applog.Manager.WriteAuditEvent("", "security.csrf_failure",
    "security", "warn", "failure", clientIP, details)`, threading
    `*log.Manager` through `CSRFMiddleware`'s signature from its one call
    site in `src/server/http.go`. Also fixed in `src/server/http.go`: CORS
    `AllowedHeaders` was `[]string{"*"}`, which AI.md PART 16 forbids
    combined with credentials and which does not actually cover
    `Authorization` per the Fetch spec — replaced with an explicit
    allow-list (`Content-Type`, `Accept`, `X-Requested-With`,
    `Authorization`, API-key/token/session/CSRF header variants). Updated
    `src/server/middleware_csrf_test.go` for the new `CSRFMiddleware`
    signature and the removed same-origin-bypass test case. Verified:
    `make test` passes (60.1% coverage, Docker `casjaysdev/go:latest`);
    `go vet ./...` clean. `Read: AI.md PART 11, PART 16`

41. **Dangling help anchors: `#tor-access` and `#i2p-access`** — added a Tor
    Access and a conditional (`.I2PEnabled`) I2P Access section to
    `src/server/template/page/help.tmpl`, each carrying the matching `id`,
    reusing the existing `.onion-address`/`.i2p-address`/`copy-value` CSS and
    copy-button pattern from `healthz.tmpl`. Added `api_help.tor_access_intro`,
    `api_help.tor_access_disabled`, `api_help.i2p_access_intro`,
    `api_help.i2p_access_disabled` to all 7 locale files. Verified: curl of
    `/server/help` shows `id="tor-access"` in the rendered HTML.
    `Read: AI.md PART 31.1, PART 31.2`

42. **`data.cve.source` / `data.cve.filter_by_cpe` missing from
    `src/config/config.go`** — AI.md's `data.cve` schema was itself updated to
    default `filter_by_cpe: false` with a documented rationale (no verified
    Go-module-to-CPE mapping exists, so filtering could silently drop a real
    CVE). Added `DataConfig`/`CVEDataConfig` to `src/config/config.go`
    (`data.cve.source`, `data.cve.filter_by_cpe`), wired defaults into
    `DefaultConfig()` and `mergeDefaults`, added the `data:` block to
    `generateConfigYAML()`, and threaded `cfg.Data.CVE.Source` into
    `cve.NewCVEManager(...)` in `src/main.go` (previously always passed `""`).
    `filter_by_cpe` is stored but intentionally not enforced, matching the
    spec's decision. Verified: generated `server.yml` contains the `data:`
    block; `make test` passes (60.9% coverage).
    `Read: AI.md PART 20 (CVE feed), src/config/config.go, src/cve/cve.go`

43. **`src/common/urlutil/fetch_test.go` not gofmt-clean** — ran `gofmt -w` on
    the file (Docker `casjaysdev/go:latest`). Verified: `gofmt -l src/` empty.

44. **The landing page (`src/server/template/index.tmpl`) had no header** —
    added `{{ template "nav" . }}` right after `<body>`, added
    `template/partial/nav.tmpl` to the `ParseFS` call in
    `DefaultHandler` (`src/server/http.go`), and added a `CSRFToken` field
    (populated via `GetCSRFToken(r, "csrf_token")`) to the handler's page-data
    struct, since `nav.tmpl`'s theme-toggle form requires it. Verified: built
    the binary, ran it, and curled `/` with `Accept: text/html` — response now
    contains `site-nav`/`nav-logo`/`theme-toggle-form`.
    `Read: AI.md PART 16 "Header Layout"`

## Open — needs investigation

38. ~~**Tor CLI control-channel unimplemented (PART 32)**~~ — RESOLVED.
    All seven loopback-only internal endpoints now exist in
    `src/server/tor_control.go` (`/server/tor/status`, `/validate`,
    `/restart`, `/regenerate`, `/vanity/start`, `/vanity/stop`,
    `/vanity/apply`, `/import-keys`), each 404ing for a non-loopback peer
    and excluded from OpenAPI/well-known/FeaturesInfo, covered by
    `src/server/tor_control_test.go`. The matching
    `ipgaze tor {status|validate|restart|regenerate|vanity|import-keys}`
    subcommand is in `handleTorCommand` (`src/main.go`), falling back to
    on-disk inspection when the server is not running. Response body
    shapes beyond the fields AI.md names remain an open question logged in
    AUDIT.AI.md. The vanity search itself is now fully specified and
    implemented per AI.md PART 31.1 "Vanity Onion Address Search".

39. ~~**ldflags pass `main.BuildEpoch` but `main.go` declares `BuildDate`,
    not `BuildEpoch`**~~ — RESOLVED. `src/main.go` now declares
    `BuildEpoch` alongside `BuildDate`, parses it in `buildEpoch()`, and
    derives `BuildDate` (RFC 3339 UTC, "N/A" when unset) in `init()`,
    mirroring `src/client/main.go`. All six ldflags injection sites bind
    correctly, and `/api/v1/version` now populates its `date` field from
    the embedded `BuildDate` instead of returning it empty.

40. ~~**`src/scheduler/scheduler.go` uses external `github.com/go-co-op/
    gocron/v2`**~~ — RESOLVED, no change needed. AI.md names
    `github.com/go-co-op/gocron/v2` explicitly in its mandated dependency
    table (line 6453, "In-process job scheduler") and in the go.mod
    template (line 6652), so the library is spec-sanctioned. AI.md 28190
    ("Use Go's time/ticker - No external cron libraries required") states
    only that an external library is not *mandatory*, not that one is
    forbidden — it does not contradict 6453. License verified MIT from the
    `v2.21.2` tag, so the no-copyleft rule is satisfied. go-lint's
    forbidden-library flag is a generic global heuristic that AI.md
    overrides. The stale "per AI.md PART 18" justification comment this
    item referenced no longer exists in the file.

41. **`manifest.json.version` set to the app version, not a manifest schema
    version** (`src/main.go`) — AI.md does not say which one it should be.
    Left as-is per the user's ruling to leave this as an open TODO rather
    than resolve now.

42. **`.trivyignore` at the repo root is not in AI.md's allowed root-files
    list** — left in place per the user's ruling to leave this as an open
    TODO rather than resolve now.
