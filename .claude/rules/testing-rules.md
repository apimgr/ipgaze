# Testing Rules (PART 28, 29, 30)

⚠️ **These rules are NON-NEGOTIABLE. Violations are bugs.** ⚠️

## CRITICAL - NEVER DO
- Never run `go test`, `go build`, or any build tooling directly on the host — Docker (`casjaysdev/go:latest`) for building, Incus (`debian:latest`/`alpine:latest`) or Docker for test execution only
- Never run broad/host-affecting commands (`docker system prune`, unscoped `kill`, unscoped `pkill`) — all process/container management stays scoped to this project's own containers/processes
- Never use a Docker Compose file other than `docker/docker-compose.test.yml` for AI-driven testing
- Never commit runtime-generated config (`server.yml`, tokens, etc.) into the repo — config files are runtime-only, never checked in
- Never commit with a failing test or missing the ≥60% coverage gate; never skip tests to save time
- Never put non-ReadTheDocs files in `docs/` — it is ONLY for MkDocs documentation (source code goes in `src/`, scripts in `scripts/`)
- Never let `docs/` describe a feature that doesn't exist, or omit a feature that does — it must reflect the shipped product as it actually behaves now
- Never hardcode a user-facing string outside the i18n system — every human-readable string (web, API, Swagger/GraphQL, email, CLI/agent output, health page, cookie consent, legal pages) goes through translation keys
- Never let a locale JSON file diverge from `en.json`'s key set — missing keys are a build-time failure, not a runtime fallback to design around
- Never use `fmt.Sprintf` for translation interpolation — use literal `{variable}` replacement
- Never skip WCAG 2.1 AA requirements (contrast, keyboard nav, ARIA, focus management, 44x44px touch targets) to simplify markup

## CRITICAL - ALWAYS DO
- Run `make test` (Docker, `casjaysdev/go:latest`) as the Phase 1 Toolchain Gate before every commit — unit tests via `*_test.go`, ≥60% coverage required
- Use `./tests/run_tests.sh`, `./tests/docker.sh`, `./tests/incus.sh` for Phase 2 Binary Validation (100% endpoint coverage; manual/developer-initiated, not a commit gate)
- Use temp directories shaped `/tmp/{project_org}/{internal_name}-XXXXXX/` for all test/build scratch output — never write test artifacts into the project tree
- Test every route under both applicable content-negotiation types: frontend routes with `text/html` and `text/plain`; API routes with `application/json` and `text/plain`; verify `.txt` endpoints explicitly
- Keep browser E2E tests (`tests/e2e.sh`, `tests/e2e/`, `e2e` build tag, chromedp-based) covering all 3 mandatory tiers: SSR/No-JS, Full-JS, and the universal project-feature checklist — these run outside the commit gate
- Host documentation on ReadTheDocs via MkDocs Material (`mkdocs.yml`, `.readthedocs.yaml`) with dark/light/auto theme switching per PART 16
- Keep all of `docs/index.md`, `installation.md`, `configuration.md`, `api.md`, `security.md`, `integrations.md`, `development.md`, `requirements.txt` present and current; add `cli.md` if the project ships a CLI
- Document any public discovery/standards endpoints (`/.well-known/**`, Swagger/GraphQL docs, autodiscover, OAuth/OIDC metadata, native app association files, security-reporting endpoints) in the relevant docs page
- Support all 7 required languages (en, es, zh, fr, ar, de, ja) with locale files at `src/common/i18n/locales/{lang}.json`, embedded via `go:embed`
- Resolve language via `?lang= query param → lang cookie → Accept-Language header → default en`; resolve `--lang` CLI flag via `flag > config > LANG/LC_ALL env > default en`
- Use dot-separated lowercase translation keys; nest plurals under `zero/one/two/few/many/other` per language's actual plural rules (e.g. Arabic uses all six categories, English/German/Spanish use only `one`/`other`)
- Enforce key-set parity between `en.json` and every other locale at build/init time (this project implements it as `validateKeys()` + an `init()` panic in `src/common/i18n/i18n.go`, not a standalone CLI tool)
- Provide skip links, correct ARIA roles/labels, visible focus states, and `lang="{{.Lang}}" dir="{{.Dir}}"` (never hardcoded `lang="en"`) on every rendered page

## Key Rules Summary
- **Two-phase testing strategy**: Phase 1 = Toolchain Gate (`make test`, Docker, ≥60% coverage, blocks commits) — Phase 2 = Binary Validation (`tests/*.sh`, full endpoint/content-negotiation coverage, developer-initiated, not a commit gate)
- **Container-only builds/tests**: `casjaysdev/go:latest` for building; Docker (`docker/docker-compose.test.yml` only) or Incus (`alpine:latest`/`debian:latest`) for test execution — never on the host
- **E2E is separate from the commit gate**: chromedp-based `tests/e2e/` behind the `e2e` build tag, 3 mandatory tiers (SSR/No-JS, Full-JS, feature checklist), must be deterministic/hermetic
- **`docs/` is operator/user/integrator documentation only**, must track the real shipped surface (browser, CLI, API, config, any public protocol/discovery endpoints) — generated OpenAPI/GraphQL output does not substitute for the required prose pages
- **ReadTheDocs stack**: MkDocs Material theme, `mkdocs.yml` + `.readthedocs.yaml` at repo root, `docs/requirements.txt` for Python deps, optional `docs/stylesheets/{dark,light}.css` (Dracula-like palette) for theme customization
- **RTD URL formats**: org-project (`{project_org}-{project_name}.readthedocs.io`), project-only (`{project_name}.readthedocs.io`), or a custom domain — pick whichever matches the actual RTD project dashboard
- **i18n scope is total**: every human-readable string anywhere in the system (web, API, Swagger/GraphQL, email, CLI, agent output, health page, legal/consent pages) must be translated, not just the main UI
- **Locale files** live at `src/common/i18n/locales/{lang}.json`, one file per one of the 7 required languages, embedded via `go:embed`, and MUST carry the exact same key set as `en.json` (extra plural categories a language needs beyond English's `one`/`other`, e.g. Arabic's `two`/`few`/`many`/`zero`, are expected and not a violation)
- **Language resolution precedence**: `?lang=` query param > `lang` cookie > `Accept-Language` header > default `en`; CLI `--lang` flag > config > `LANG`/`LC_ALL` env > default `en`
- **A11y baseline**: WCAG 2.1 AA — keyboard navigation, screen-reader support, 4.5:1 contrast minimum, skip links, correct ARIA patterns, visible focus management, 44x44px minimum touch targets

For complete details, see AI.md PART 28, PART 29, PART 30.
