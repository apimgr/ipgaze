# Project Audit

Started: 2026-08-29
Revalidated: 2026-11-05
Spec version: AI.md, 49178 lines (last updated 2026-10-15)

This file tracks implementation/spec alignment findings. The unchecked items
below were rechecked against the current spec and implementation on the date
above. Checked historical items are retained from earlier audit passes and
were not revalidated in this update. AI.md is read-only for this project.

## Open Spec Gaps and Contradictions — revalidated 2026-11-05

- [x] AI.md 18305 vs AI.md 19670-19681 envelope contradiction — RESOLVED.
      The user edited AI.md directly to make both sections consistent
      (`{ok, data}` envelope). Verified both sections now agree; no handler
      change was needed.
- [x] Vanity onion address search was unspecified — RESOLVED. The user added
      AI.md PART 31.1 "Vanity Onion Address Search", which fixes the prefix
      rules (1-6 base32 chars, longer prefixes deferred to `mkp224o` plus
      `tor import-keys`), the worker default (logical CPUs - 1, min 1), the
      one-search-at-a-time rule, the `state`/`prefix`/`workers`/`attempts`/
      `rate`/`elapsed_seconds`/`candidates` progress shape, candidate storage
      under `{data_dir}/tor/vanity/{address}/`, and the apply handoff
      (prefix resolution, confirmation, key swap, hostname verification,
      candidate cleanup). Implemented in `src/tor/vanity.go`,
      `src/server/tor_control.go` (adding `/server/tor/vanity/stop`), and
      `src/main.go` (`ipgaze tor vanity stop`).
- [ ] AI.md PART 31.1 lists eight internal `/server/tor/*` endpoints and
      defines their methods, loopback access, and classification. It specifies
      the shared API envelope elsewhere and some vanity-search fields, but
      does not define the complete request, success-payload, and error-payload
      contract for all eight endpoints. The server and CLI currently have
      typed request/response structures in `src/server/tor_control.go` and
      `src/main.go`; those code-defined details are not fully anchored by
      AI.md. This is a spec gap, not a missing CLI parser.
- [ ] `server.tor.max_circuits` is documented as the maximum number of open
      circuits and is parsed from `server.yml`, but the Tor manager currently
      accepts the value without using it. AI.md PART 31.1 does not specify how
      this setting maps to Tor behavior. Clarify the intended semantics in the
      authoritative spec before changing runtime behavior.
- [x] AI.md PART 16 requires app-specific guest preferences and export/import
      round-tripping. Added `ipgaze_pref_widget` with the existing landing-page
      curl-example choices (`ip`, `country`, `country-iso`, `city`, `asn`,
      `json`, `port`) to `/server/preferences`, the API mirror, and the
      canonical export/import flow. The landing page reads the cookie per
      request and changes only its UI widget, preserving echoip API responses.
      `IDEA.md` records the product behavior. **Documentation remains open:**
      AI.md requires this preference in its own cookie table, but project
      instructions make AI.md read-only. The cookie name/value/default rule
      should be added to AI.md by its owner before that documentation item can
      be marked fully resolved.
- [ ] AI.md PART 25 says not to add targets beyond its listed Makefile set;
      the FINAL CHECKPOINT separately lists `make all`. The Makefile follows
      PART 25 and has no `all` target. The contradiction remains in AI.md and
      requires its owner to reconcile the checklist with PART 25.
- [x] The Makefile command-substitution concern is resolved: both the AI.md
      reference and repository Makefile use `GOOS=$$(go env GOOS)` and
      `GOARCH=$$(go env GOARCH)` inside `sh -c` passed to the Docker toolchain.
      Make passes substitution to the container shell; it does not invoke Go
      on the host.
- [x] AI.md 18478/18503 vs IDEA.md echoip response conflict — RESOLVED by user:
      adhere to AI.md while preserving echoip compatibility. Bare responses
      remain for `/`, `/{ip}`, and `/{ip}/{field}` when requested by HTTP tools.

- [x] AI.md 8708-8709/9223-9252 ("Six Operational States") vs AI.md 8788
      (`--mode debug` = development + debug) debug-mode contradiction —
      RESOLVED. The user ruled to follow 8708-9252: `debug` is its own
      distinct `AppMode`, not a development alias. Fixed in
      `src/mode/mode.go` (`AppModeDebug`, `ParseModeWithDebugAlias` now
      returns it), propagated to `src/main.go`'s self-signed-cert dev
      fallback and `src/common/banner/banner.go`'s `modeEmoji()`.

- [ ] AI.md PART 8's reference implementation and PART 28's Incus test
      workflow contradict each other on service install inside a container.
      PART 8's reference `detectServiceManager()`
      checks `isContainer()` FIRST and returns `"container"`, and its
      `isContainer()` matches LXC/Incus explicitly (`/dev/lxc`, `$container`,
      `lxc` in `/proc/1/cgroup`) — so in an Incus system container the binary
      correctly refuses `--service --install` with "unsupported service
      manager". PART 28's mandated test workflow, however, launches
      `images:debian/trixie` and then runs `{project_name} --service --install`
      followed by `systemctl status {project_name}` as the preferred way to
      validate systemd support. Both cannot hold. `src/service/service.go`
      was left matching PART 8's reference implementation verbatim (container
      check first); `tests/incus.sh` was made to fall back to starting the
      binary directly when install is refused. AI.md needs to clarify whether
      Incus service installation is required or container detection takes
      precedence.

- [x] AI.md PART 12 defines three config reload classes. `ConfigManager`
      classifies hot, graceful, and restart-required changes. Logging changes
      reopen active writers, `server.baseurl` rebuilds the active router after
      in-flight requests complete, and timeout changes hand newly accepted
      connections to replacement HTTP servers on the existing bound listeners
      while prior servers drain active requests.
- [x] AI.md PART 14's MCP implementation uses Go SDK v1.8.0, which supports
      the current `2026-07-28` revision and its header/body checks. MCP
      operations are filtered against the registered runtime routes, ordered
      deterministically, and audited with `source: mcp`. `APIV1RouteDefinitions`
      now drives runtime API registration from the same route catalogue used
      by OpenAPI; the active operation-ID registry filters MCP and llms.txt.
      Optional GeoIP, port, GraphQL, and Swagger routes stay absent when their
      runtime handlers are disabled. Echoip root routes remain listed and
      unchanged. Parity tests cover definitions, active routes, and discovery.
      Owner-token tools are not applicable: IDEA.md defines no user-owned
      resource creation, and AI.md PART 14 only requires project-defined
      resources and prompts when IDEA.md defines them.
- [ ] AI.md contains an internal contradiction for the MCP setting. PART 14
      requires an MCP toggle in Web settings, while PART 12 says configuration
      is file-only with no runtime mutation, PART 16 says no admin web panel,
      and PART 14's later frontend rules say there are no admin pages. The
      user has ruled that AI.md takes precedence over IDEA.md and code, but
      that does not choose between these conflicting AI.md requirements.
      `server.mcp.enabled` remains file-configured, defaults to true, and is
      hot-reloadable. Do not add a public settings route or invent an auth/UI
      flow until AI.md resolves the contradiction.
