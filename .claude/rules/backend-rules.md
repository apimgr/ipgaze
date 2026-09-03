# Backend Rules (PART 9, 10, 11, 31)

⚠️ **These rules are NON-NEGOTIABLE. Violations are bugs.** ⚠️

## CRITICAL - NEVER DO
- Never use `SELECT *` in application code — always name columns explicitly
- Never build SQL via string concatenation — parameterized queries only
- Never reveal internals in error responses (stack traces, DB structure, internal hostnames/ports, dependency versions)
- Never weaken rate limiting, caching correctness, or logging fidelity to simplify implementation
- Never let the error-page/error-handling path itself be the thing that breaks a request — a panic/recover
  middleware and a template-render failure MUST both fall back to a minimal hardcoded error response
  (correct status code, short body, content-negotiation-aware) instead of a blank body, dropped connection,
  or leaked stack trace — the backend mirror of the service worker's guaranteed-`Response` rule

## CRITICAL - ALWAYS DO
- Validate and sanitize all input for its destination context (HTML-encode for HTML, parameterize for SQL)
- Follow the canonical error-response format and audience-specific detail levels (user/operator/console/log/audit)
- Log structured errors with request IDs and full context server-side, while returning minimal messages to clients
- Every request MUST terminate in a rendered response, no exceptions

## Key Rules Summary
- **NOT YET FULLY POPULATED**: PARTs 9 (Error Handling & Caching), 10 (Database), 11 (Security & Logging),
  and 31 (Tor Hidden Service) have not been read in this pass — only PART 0/1 general rules, plus the
  guaranteed-response error-page rule added 2026-08-20 (AI.md commit `e18697ec7b1b`), are included. Read
  AI.md PART 9, 10, 11, 31 directly before doing backend/database/security-logging work.

For complete details, see AI.md PART 9, PART 10, PART 11, PART 31.
