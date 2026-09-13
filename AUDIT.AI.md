# Project Audit

Started: 2026-08-29
Spec version: AI.md, 49114 lines (re-walked 2026-09-11 after the
2026-09-10 spec update)

Full line-by-line AI.md compliance audit (PARTs 0-33). Every finding from
Passes 1-6 has been fixed and deleted from this file. Only items blocked on a
user ruling remain. This file is deleted entirely once they are resolved.

## Open Questions — blocked, need a ruling

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
- [ ] Response body shapes for all seven `/server/tor/*` endpoints are
      unspecified — only endpoint, method, auth, and classification are given.
      Blocks the CLI-side parsing contract.
- [ ] Tor `max_circuits` is parsed from server.yml but no Tor directive matches
      "maximum circuits to keep open" — `MaxClientCircuitsPending` has
      different semantics, and emitting a wrong directive aborts Tor startup.
      Left unemitted rather than guessed.
- [ ] AI.md PART 16 requires a control on `/server/preferences` "for every
      app-specific `{project_name}_pref_*` setting" and says to "document each
      one in this project's own AI.md preferences table" — but AI.md is
      read-only and IDEA.md names no `ipgaze_pref_*` key. The editable page now
      ships theme, language, cookie-consent categories, and CCPA opt-out; no
      `ipgaze_pref_*` cookie was invented, and no empty registry was built
      (that would be dead code). Which app-specific guest preferences, if any,
      should ipgaze expose (default view mode, results-per-page, sort order,
      unit system, …)? Also blocks whether export/import needs to grow
      `{project_name}_pref_*` round-tripping, which today has nothing to carry.
- [ ] AI.md PART 25 vs the FINAL CHECKPOINT checklist contradict each other on
      the Makefile target set: PART 25's body and reference `.PHONY` line
      mandate exactly `dev local build test release docker` plus `clean` and
      say "Six core targets. DO NOT ADD MORE", while the FINAL CHECKPOINT
      separately lists `make all`. No `all` target was added — resolving the
      contradiction that way would violate PART 25's explicit rule. Which side
      wins?
- [ ] AI.md 18478/18503 vs IDEA.md line 34 conflict on the HTTP-tool (curl,
      wget, HTTPie) response body for the echoip data routes `/`, `/{ip}`,
      and `/{ip}/{field}`. AI.md mandates the frontend page rendered through
      `HTML2TextConverter()` ("Beautiful formatted ... full page with headers,
      navigation, formatting"); IDEA.md line 34 mandates an
      "echoip-compatible API surface (same routes, response formats,
      user-agent detection behavior)", whose defining behavior is
      `curl ifconfig.co` returning the bare address and nothing else.
      The existing bare-address `CLIHandler` output was preserved on those
      three routes, since converting them to formatted page text would break
      the product's core purpose. The conflict does not extend to
      `/server/*`, where AI.md applies cleanly — those pages now go through
      `HTML2TextConverter` via `renderNegotiated`. Which side wins for the
      data routes?
- [x] AI.md 8708-8709/9223-9252 ("Six Operational States") vs AI.md 8788
      (`--mode debug` = development + debug) debug-mode contradiction —
      RESOLVED. The user ruled to follow 8708-9252: `debug` is its own
      distinct `AppMode`, not a development alias. Fixed in
      `src/mode/mode.go` (`AppModeDebug`, `ParseModeWithDebugAlias` now
      returns it), propagated to `src/main.go`'s self-signed-cert dev
      fallback and `src/common/banner/banner.go`'s `modeEmoji()`.

`manifest.json.version` and `.trivyignore` moved to TODO.AI.md's Open
section per the user's ruling to leave both as open TODOs rather than
resolve now.
