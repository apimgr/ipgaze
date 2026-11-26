# Project Audit

Started: 2026-11-26
Spec version: AI.md at HEAD 8276804bc60a

## Issues Found

- [ ] API runtime mounting does not yet use registry values for every route; server pages, static assets, and root lookup aliases still have direct router registrations.
- [ ] The required AI.md + IDEA.md + generated OpenAPI + router route-drift test is missing.
- [x] OpenAPI schema generation now uses route `Request` and `Response` metadata, including typed struct, map, IP, and time schemas.
- [ ] OpenAPI, GraphQL, llms.txt, and runtime route snapshots need parity checks across disabled and internal routes.
- [ ] Current docs and generated route descriptions need a final sync against the implemented pages and APIs.

## Sync Required

- [ ] README.md and IDEA.md are current after implementation review.
- [ ] CI/CD and Makefile verification targets enforce the required project checks.

## Completed

- API and diagnostic routes now use handler-bearing registry values for runtime mounting, OpenAPI, GraphQL, MCP, llms.txt, and text serialization.
- OpenAPI request and response operations now consume exported route model metadata; reflection derives schemas from struct and map models.
- Rendered page and error-page conformance checks already exist; an explicit hub-registry coverage and ordering test was added.
