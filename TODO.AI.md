# ipgaze AI.md Alignment

Implementation work only. AI.md defects and contradictions are tracked in the parent API template inbox, not here.

## Tasks

- [ ] Reconcile every server feature, API route, middleware, and rendered page with AI.md PARTS 5–24, 30–32 and IDEA.md; implement missing behavior and correct noncompliant behavior.
- [ ] Implement the AI.md owner/token storage and complete token-management routes, including on-demand primary issuance, primary reveal/rotation, linked-token create/list/reveal/rotate/update/revoke, and the guest `/server/preferences/tokens` page with New token and Restore forms. Require owner or operator Bearer authentication on every MCP request; exclude token-management routes from MCP tools.
- [ ] Add or correct the AI.md-required registries for rendered server pages and preferences pages; ensure every registered page resolves, is discoverable from its hub, and meets page/accessibility/navigation requirements.
- [ ] Reconcile project structure, CLI/client, service, Docker, Makefile, and provider workflows with AI.md PARTS 2–8 and 23–28; fix all concrete gaps.
- [ ] Bring README.md, docs/, MkDocs/ReadTheDocs, embedded Swagger/OpenAPI, GraphQL, and all server page content/templates into current agreement with implemented behavior and AI.md PARTS 14, 16, 29–30.
- [ ] Complete the project-wide AI.md final checkpoint, update IDEA.md where product behavior has changed, and run the required primary-session verification gates.
