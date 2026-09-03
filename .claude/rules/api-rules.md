# API Rules (PART 13, 14, 15)

⚠️ **These rules are NON-NEGOTIABLE. Violations are bugs.** ⚠️

## CRITICAL - NEVER DO
- Never bypass the web-route ⇄ API-route parity pattern — every web page needs a corresponding `/api/{api_version}/...` JSON endpoint and vice versa
- Never hardcode bare `/path` URLs in embedded/server-rendered code — use the FQDN/request-aware URL builder

## CRITICAL - ALWAYS DO
- Keep Swagger/OpenAPI annotations and GraphQL schema in sync with actual handlers/resolvers
- Return the canonical error body shape (`ok`, `error`, `message`) with correct HTTP status and `Retry-After` header where applicable

## Key Rules Summary
- **NOT YET FULLY POPULATED**: PARTs 13 (Health & Versioning), 14 (API Structure), and 15 (SSL/TLS & Let's Encrypt) have not been read in this pass — only PART 0/1 general rules above are included. Read AI.md PART 13, 14, 15 directly before doing API/TLS-specific work.

For complete details, see AI.md PART 13, PART 14, PART 15.
