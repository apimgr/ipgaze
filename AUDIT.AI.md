# Project Audit

Started: 2026-11-06
Spec: AI.md (read-only)
Scope: Full implementation, server pages, API contracts, user documentation,
and project documentation synchronization.

## Issues Found

- [x] Docs homepage omitted required security, integration, and development
  documentation links and pointed at obsolete Swagger/GraphQL paths. Fixed in
  `docs/index.md`.
- [x] API documentation described obsolete health and protocol routes and
  omitted the standard JSON envelope. Fixed in `docs/api.md`.
- [x] CLI documentation omitted `debug`, token-file support, and current
  configuration behavior. Updated in `docs/cli.md`.
- [x] Installation instructions used obsolete `--listen`, port mappings, and
  a hand-written systemd unit. Updated in `docs/installation.md`.
- [x] Development documentation described nonexistent hot reload, coverage
  targets, file layout, and host Go commands. Updated in `docs/development.md`.
- [x] README had stale Docker ports, install branch, application address,
  Makefile behavior, and documentation sections. Updated in `README.md`.
- [x] Integration and security docs advertised obsolete API, GraphQL, metrics,
  and health routes. Updated in `docs/integrations.md` and `docs/security.md`.
- [x] Reverse-proxy and client setup examples had stale ports and defaults.
  Updated in `docs/configuration.md` and `docs/cli.md`.
- [x] Server page JSON responses for about, help, privacy, contact, terms, and
  security bypassed the canonical API envelope. Updated the handlers and CLI
  content negotiation to use the shared envelope writer.
- [ ] Required `/server/help/mcp` HTML and API documentation routes are not
  registered or implemented (AI.md PART 16, lines 27759–27784).
- [ ] Required security policy, acknowledgments, and security-report status
  routes and workflows are not registered or implemented (AI.md PART 16,
  lines 14956–14962).
- [ ] Full PART-by-PART audit of implementation, infrastructure, generated
  rule files, and all docs remains in progress.

## AI.md Issues

AI.md contradictions found during this audit are recorded in
`/root/Projects/github/apimgr/TODO.API.md`, as requested. AI.md remains
unchanged.
