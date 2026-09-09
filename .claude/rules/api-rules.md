# API Rules (PART 13, 14, 15)

⚠️ **These rules are NON-NEGOTIABLE. Violations are bugs.** ⚠️

## CRITICAL - NEVER DO
- Never bypass the web-route ⇄ API-route parity pattern — every web page needs a corresponding `/api/{api_version}/...` JSON endpoint and vice versa
- Never hardcode bare `/path` URLs in embedded/server-rendered code — use the FQDN/request-aware URL builder
- Never change the `HealthResponse` field order or omit a field — canonical order is `Project{Name,Tagline,Description}`, `Status`, `PendingRestart`/`RestartReason`, `Version`/`GoVersion`/`Build{Commit,Date}`, `Uptime`/`Mode`/`Timestamp`, `Features{Tor{Enabled,Running,Status,Hostname},I2P{...,Provider},GeoIP}`, `Checks{Database,Cache,Disk,Scheduler,Tor(omitempty),I2P(omitempty)}`, `Stats{RequestsTotal,Requests24h,ActiveConns}`
- Never return a non-200 status for `healthy`/`degraded`/`restart_required` — only `unhealthy`/`maintenance`/`shutting_down` return 503
- Never resurrect a legacy/deprecated endpoint (`/openapi`, `/openapi.json`, root `/graphql`, etc.) as a redirect or shim — deleted endpoints stay deleted, no compatibility layer
- Never let our own CLI (`{project_name}-cli/` User-Agent) receive HTML or pre-formatted text — it is INTERACTIVE and must always get JSON so it can render its own TUI
- Never let a text browser (lynx/w3m/links/elinks/browsh/carbonyl/netsurf) receive `HTML2TextConverter()` plain-text output — that conversion path is for HTTP tools (curl/wget/httpie/empty UA) only; text browsers get normal server-rendered HTML
- Never let ACME renewal touch a certificate ipgaze does not manage (user-supplied/externally-issued certs are never auto-renewed)
- Never use `SELECT *`, string-concatenated SQL, or reveal internals (stack traces, DB structure, internal hosts/ports, dependency versions) in any API error response

## CRITICAL - ALWAYS DO
- Keep Swagger/OpenAPI annotations and GraphQL schema in sync with actual handlers/resolvers
- Return the canonical error body shape (`ok`, `error`, `message`) with correct HTTP status and `Retry-After` header where applicable; success responses use `{ok:true,data}` (plus pagination metadata when the endpoint paginates) — `/healthz` is the one endpoint allowed a bare body instead of the envelope
- Use the documented query-param names for filtering/sorting/pagination: `page`, `limit`, `sort`, `order` (e.g. `?page=2&limit=10&sort=date`, `?sort=rating&order=desc`)
- Resolve `/api/{api_version}/**` response format by strict priority: (1) `.txt` path suffix → always plain text, wins over everything; (2) `Accept: text/plain` → text; (3) `isNonInteractiveClient(r)` (HTTP tools only — our CLI and text browsers are excluded) → text; (4) default → JSON
- Dispatch frontend (`handleFrontendRequest`) responses in this order: our CLI → JSON; text browser → normal server-rendered HTML; HTTP tool → render HTML then convert via `HTML2TextConverter(html, 80)` to `text/plain`; everyone else → normal server-rendered HTML
- Map `/healthz` to the same handler as `/server/healthz` only when explicitly opted in via config — it is not on by default
- Support all three ACME challenge types with the documented defaults: HTTP-01 (default, port 80), TLS-ALPN-01 (port 443), DNS-01 (required for wildcard certs)
- Run certificate renewal on the daily 03:00 scheduler job and renew only within 7 days of expiry, and only for certificates ipgaze itself issued/manages (4-tier lookup priority: explicit config path → ACME-managed → self-signed fallback → none)
- Log structured errors with request IDs server-side while returning only the minimal client-safe message

## Key Rules Summary
- **Health (PART 13):** `HealthResponse` has a fixed field order and field set (see NEVER DO above); status→HTTP code mapping is `healthy`/`degraded`/`restart_required`→200, `unhealthy`/`maintenance`/`shutting_down`→503. `/healthz` may alias `/server/healthz` only when config-enabled.
- **API structure (PART 14):** every endpoint follows the canonical `{ok,data}` / `{ok,error,message}` envelope (health's bare body is the sole exception); pagination/filter/sort use `page`/`limit`/`sort`/`order`; legacy endpoints are deleted outright, never redirected or shimmed. Content negotiation on `/api/**` is suffix → `Accept` header → non-interactive-client detection → JSON default. Frontend content negotiation additionally distinguishes our CLI (always JSON), text browsers (normal HTML — the project's JS Necessity Gate already keeps that HTML usable without JS, so no separate no-JS template/function exists or is needed), and HTTP tools (HTML converted to formatted plain text via `HTML2TextConverter`).
- **SSL/TLS (PART 15):** certificate lookup follows a 4-tier priority; ACME supports HTTP-01 (default), TLS-ALPN-01, and DNS-01 (wildcard); renewal runs daily at 03:00, only within 7 days of expiry, and only for app-managed certificates — never externally supplied ones.
- Rate-limit tier specifics live outside PART 13-15 (see PART 11/backend rules) — do not assume tier numbers from this file.

For complete details, see AI.md PART 13, PART 14, PART 15.
