# Project Audit

Started: 2026-08-29
Spec version: AI.md, 48520 lines

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
