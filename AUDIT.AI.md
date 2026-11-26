# Project Audit

Started: 2026-11-26
Status: In progress; this is a current-state checkpoint, not a completed line-by-line AI.md audit.

## Findings

- [ ] **PART 14 route inventory parser does not follow its own format contract.** AI.md lines 20504–20505 require explicit `Endpoint`/`Path` and `Method`/`Methods` columns, a backticked path, and an explicit method; they say other table forms are not inventories. `src/server/route_drift_test.go` additionally infers GET for frontend/static/well-known tables and hard-codes routes found in prose. This makes the test useful against drift, but not deterministic under the documented parser rule. AI.md also requires optional routes to be gated by `x-mounted-when`; `optionalTemplateRoute` currently exempts every absent `/.well-known/*` route (except three paths) without checking its feature condition. The template inconsistency has been recorded in `~/Projects/github/apimgr/TODO.API.md`; resolve it in the API template before treating this test as a strict implementation of AI.md.
- [ ] **Documentation review is incomplete.** `IDEA.md` now has an expanded route inventory, but README and all user-facing docs still need a final review against current behavior and the full AI.md requirements.
- [ ] **The exhaustive AI.md requirement walk and final gates are not complete.** Verify every PART and its required server pages, docs, security, runtime behavior, and CI/build/test/lint checks before removing this audit file.

## Completed in the current working tree

- Runtime API, root, page, and asset routes are mounted from handler-bearing route values in `src/server/http.go`; route definitions are assembled in `src/server/api_routes.go` and shared with OpenAPI and discovery.
- `src/server/route_drift_test.go` now compares the AI.md/IDEA.md inventories with registered routes, mounted-router matches, and generated OpenAPI, including internal/unlisted-route exclusion.
- Rendered page and error/health fallback checks exist in `src/server/accessibility_test.go` and `src/server/templates_test.go`; hub registry coverage and ordering checks exist in `src/server/handler/pages_test.go`.
- OpenAPI, GraphQL, and MCP have route-registry coverage tests in `src/swagger`, `src/graphql`, and `src/server`.
- Removed route declarations for API consent/CCPA/announcement writes and GraphQL POST on the docs UI path; AI.md specifies those privacy actions as web-only and GraphQL POST at the API endpoint.
- Added primary-token revocation coverage for confirmation failure, linked-token rejection, owner/token cascade deletion, and response counts.
