# API Rules (PART 13, PART 14, PART 15)

⚠️ **These rules are NON-NEGOTIABLE. Violations are bugs.** ⚠️

## CRITICAL - NEVER DO
- **PART 13:** *Healthz is PUBLIC. NEVER expose sensitive data.**
- **PART 13:** | ALLOWED (public) | FORBIDDEN (sensitive) |
- **PART 13:** *NEVER expose in /server/healthz response:**
- **PART 13:** | Category | NEVER Include | Why |
- **PART 13:** Never reuse version numbers
- **PART 13:** Devel: release tag is always the rolling `devel` tag (deleted and recreated nightly); VERSION is the short commit id of the built commit (`git rev-parse --short=7 HEAD`, e.g., `a1b2c3d`) — devel identity is the commit, never `release.txt` and never a timestamp
- **PART 14:** **Auth token extraction:** every auth-protected native API endpoint MUST read the token from `Authorization: Bearer {token}` only (PART 8 → "Auth Token Presentation"); any other header and any `?token=` query parameter is ignored, never logged and never treated as a credential. Compatibility-layer routes accept only the credential form their emulated protocol defines.
- **PART 14:** | **Legacy** | Old, changed, or removed endpoints from YOUR project | **NEVER KEEP - DELETE THEM** |
- **PART 14:** *When route rules change, migrate the implementation - do NOT layer new routes on top of old code.**
- **PART 14:** Do NOT keep old and new route trees alive in parallel "for now"
- **PART 14:** Do NOT duplicate handlers just to satisfy both old and new paths
- **PART 14:** Unversioned API aliases (`/api/swagger`, `/api/graphql`, `/api/healthz`) MUST mount the SAME handler as their versioned canonical route - never redirect, never fork behavior
- **PART 14:** | **No trailing slash** | Routes MUST NOT end with `/` (see PART 16 URL Normalization) | `/api/{api_version}/items/` | `/api/{api_version}/items` |
- **PART 14:** **JS is prohibited for anything HTML5 + CSS already does.** Reach for a script only when a specific interaction is genuinely impossible without one.
- **PART 14:** *NEVER reach for JS when an HTML/CSS-native mechanism exists:**
- **PART 14:** | Form submit | native `<form method>` POST/GET + server redirect | never — forms submit without JS |
- **PART 14:** | Show/hide, accordion | `<details>`/`<summary>`, `:target`, checkbox+`:checked` | never for basic disclosure |
- **PART 14:** | Tabs, carousels | radio inputs + `:checked` + CSS | never for the core switch |
- **PART 14:** | Styling, theming, layout, animation | CSS custom properties, media queries, transitions/keyframes | never |
- **PART 14:** | Formatting (dates, numbers) | server-rendered | never |
- **PART 14:** | Business logic | **Server** | Never in client - security and consistency |
- **PART 14:** *NEVER do these client-side:**
- **PART 14:** *Note:** Examples throughout this document use `/api/{api_version}/` as the default value. In code, always use `APIBasePath()` or `{api_version}` - never hardcode `v1`.
- **PART 14:** | **Indentation** | 2 spaces — never tabs, never 4 spaces |
- **PART 14:** | **No bare arrays at root** | Never emit a top-level JSON array — always wrap: `{ "data": [...] }`. Bare arrays cannot grow new sibling fields (pagination, metadata) without a breaking change, and some older clients reject them as JSON. |
- **PART 14:** **NEVER mix**: Use consistent indentation throughout file
- **PART 14:** *Frontend routes do NOT need `.txt` extension - smart detection handles it.**
- **PART 14:** *For frontend routes (`/**`), response format is determined in this order (the MCP aliases are API-class and never use it — see "MCP Endpoint"):**
- **PART 14:** Text browsers (lynx, w3m, links, elinks) do NOT support JavaScript
- **PART 14:** | **Never manual** | NEVER manually edit OpenAPI JSON or GraphQL schema |
- **PART 14:** | **Standardized locations** | ALWAYS `src/swagger/` and `src/graphql/` (NEVER in root `.`) |
- **PART 14:** | Component | Location | Never Use |
- **PART 14:** *All paths MUST be relative to `src/` directory. Files in project root (`.`) are FORBIDDEN.**
- **PART 14:** *NEVER:**
- **PART 14:** DO NOT replicate their entire API surface unless the user explicitly asked for route/API parity
- **PART 14:** | **Research first** | NEVER guess - look up actual API documentation |
- **PART 14:** | **No CSRF** | CSRF would break compatibility clients, so compatibility-layer routes never get the CSRF middleware, token, or `CSRF_FAILED` rejection — unless the emulated protocol itself defines a CSRF token and expects clients to send it, in which case enforce exactly what that protocol specifies on that layer's routes only (PART 16 → "CSRF Protection" → "Scope") |
- **PART 14:** | **Avoid complexity** | Do NOT add hundreds of redundant routes |
- **PART 14:** | `/metrics[/{service}]` | GET | Bearer token (per service) | Root alias when `server.metrics.root.enabled: true` (default true); same handler, NEVER a redirect |
- **PART 14:** | `/mcp` | POST | Bearer (optional) | MCP endpoint — root alias for current `{api_version}`; same handler, never a redirect |
- **PART 14:** *Old paths removed:** `/openapi`, `/openapi.json`, `/graphql` (GET and POST at root) are no longer served. The new paths above are the only valid routes — do not implement redirects from the old paths.
- **PART 14:** *Examples that do NOT get an alias:** `/api/{api_version}/items`, `/api/{api_version}/server/contact` (these stay versioned only).
- **PART 14:** | **Compatibility** | Many CLI tools, language SDKs, and minimal HTTP clients do not follow redirects by default. A direct response works for everyone. |
- **PART 14:** *Where to apply:** every unversioned `/api/<thing>` alias for a versioned endpoint. Mount the same handler at both the versioned path and the alias — do NOT implement the alias as a redirect to the versioned path.
- **PART 14:** | Redirects | Forbidden |
- **PART 14:** *Canonical error shape — same shape everywhere (PART 9, PART 11, PART 14, PART 16). The HTTP status code carries the status; do not duplicate it in the body.**
- **PART 14:** | `message` | Yes | Human-readable explanation, safe to display to end users. NEVER includes stack traces, internal IPs, DB structure, or "username vs password" disclosure (see PART 11 → "Public Endpoint Safety Principle"). |
- **PART 14:** *Forbidden in error responses (legacy formats — DO NOT use):**
- **PART 15:** *Do NOT set DOMAIN to overlay network addresses:**
- **PART 15:** *"Last update" MUST use build date, NEVER hardcoded.** Use `{build_datetime}` template variable which is derived from the embedded `BuildEpoch` at process start. This ensures the footer always shows when the binary was built, not a static date in the source code.
- **PART 15:** | **Log files** | ❌ Never | ❌ Never | ❌ Never | Raw text |
- **PART 15:** | **Log output (stdout)** | ❌ Never | ❌ Never | ❌ Never | Raw text |
- **PART 15:** | **Background tasks / scheduler** | ❌ Never | ❌ Never | ❌ Never | Log files only — never console |
- **PART 15:** | **Health checks / probes** | ❌ Never | ❌ Never | ❌ Never | Log files only — never console |
- **PART 15:** *Never this in logs:**
- **PART 15:** | Never printed to console | Where it goes instead |
- **PART 15:** Certificate must not be expired
- **PART 15:** | `{config_dir}/ssl/local/{fqdn}/` | Never | Manual only |
- **PART 15:** | `/etc/letsencrypt/live/**` | Never | System (certbot) manages |

## CRITICAL - ALWAYS DO
- **PART 13:** *This specification defines the COMPLETE global structure. Projects extend with app-specific data. ALL fields MUST be public-safe.**
- **PART 13:** 2. All data MUST be public-safe (see Security section below)
- **PART 13:** *Backend and frontend MUST use this exact order. Consistency across all projects.**
- **PART 13:** *Database/cache checks MUST be vague:**
- **PART 13:** *Optional root alias:** if `server.healthz.root.enabled: true`, `/healthz` MUST serve these exact same responses by mounting the same handler as `/server/healthz`. No redirect, no forked logic, no separate formatter path.
- **PART 13:** | Copy buttons | Required for Tor address and other long identifiers |
- **PART 13:** | `restart_required` | `.status-warning` | 🔄 | Restart Required |
- **PART 13:** *Note:** Only non-negotiable features shown with actual status (true/false, enabled/disabled). If project uses project-specific optional features, those become non-negotiable for that project and show their actual enabled/disabled status.
- **PART 13:** *ALL stable releases MUST follow semantic versioning:**
- **PART 13:** Plain text, no color. The first line is always `{project_name} {project_version} ({short_commit})` so scripts can parse it; the build metadata lines follow it.
- **PART 14:** *IF A ROUTE EXISTS, IT MUST FOLLOW THESE RULES. NO EXCEPTIONS.**
- **PART 14:** | **Versioning** | All canonical API routes MUST be versioned; only paths in "Unversioned API Exceptions" are exempt | `/api/items` | `/api/{api_version}/items` |
- **PART 14:** **Canonical API routes are versioned.** The exhaustive exceptions are the unversioned aliases in "Unversioned API Exceptions" plus `/api/autodiscover`, which is unversioned by design.
- **PART 14:** Docs and examples name canonical versioned routes; aliases appear only where the alias itself is documented. Every alias has a parity test for status, headers, and body.
- **PART 14:** | **Plural nouns** | All resource names MUST be plural | `/api/{api_version}/item` | `/api/{api_version}/items` |
- **PART 14:** | **Lowercase** | All routes MUST be lowercase | `/api/{api_version}/Items` | `/api/{api_version}/items` |
- **PART 14:** | API Type | Frontend Required | Example |
- **PART 14:** *Frontend is NOT just a display layer. It MUST be fully functional:**
- **PART 14:** *Frontend MUST work without JavaScript for core functionality (progressive enhancement).**
- **PART 14:** **Every `<script>` MUST name the capability that is impossible in HTML5 + CSS.** If you cannot name one, delete the script.
- **PART 14:** | Field validation | HTML5 `required`, `pattern`, `type=`, `min`/`max`, `minlength`; server re-render authoritative | mirroring `validationMessage` into an inline span (enhancement only) |
- **PART 14:** *Legitimate JS** names a concrete capability with no HTML/CSS equivalent: live search-as-you-type (`fetch`), client-side charts on canvas, drag-and-drop reordering, WebSocket streams, clipboard copy. Even then, the feature it decorates MUST work without it.
- **PART 14:** | Copy to clipboard | Browser API required |
- **PART 14:** | Required JavaScript for core features | Breaks text browsers, accessibility |
- **PART 14:** | Scope | Web Route | API Route | ID Required | Description |
- **PART 14:** *Public API routes with a UI have corresponding frontend routes. They MUST match.**
- **PART 14:** *Exceptions (when matching is NOT required):**
- **PART 14:** *ALL responses and ALL code MUST be properly formatted.**
- **PART 14:** | **Tab indentation** | Go code, Makefiles | Use tabs where required by language |
- **PART 14:** *Testing:** Test scripts MUST verify:
- **PART 14:** | **1** | `.txt` extension | `/api/{api_version}/joke.txt` | Plain text (ALWAYS) |
- **PART 14:** When an HTTP tool (curl, wget, httpie) is detected, the server MUST:
- **PART 14:** Server MUST detect text browsers and serve no-JS HTML alternative
- **PART 14:** All functionality must work without JavaScript:
- **PART 14:** | Type | Required |
- **PART 14:** *Swagger and GraphQL MUST always be in sync with each other AND with the project's API.**
- **PART 14:** | **Sync with project** | Both MUST reflect current project API at all times |
- **PART 14:** *Both Swagger UI and GraphiQL MUST match the PROJECT-WIDE theme system.**
- **PART 14:** See the **"Themes (NON-NEGOTIABLE - PROJECT-WIDE)"** section for the complete theme system that applies to the entire project, including Swagger and GraphQL.
- **PART 14:** BOTH light AND dark themes MUST be easy to read with no color conflicts
- **PART 14:** NO page reload required
- **PART 14:** Both themes MUST pass WCAG AA contrast requirements
- **PART 14:** Focus indicators MUST be visible in both themes
- **PART 14:** Keyboard navigation MUST work identically in both themes
- **PART 14:** Note required request parameters and authentication (if any)
- **PART 14:** | **Match response format** | Field names, structure, content-type must match target exactly |
- **PART 14:** ✓ Required authentication if applicable
- **PART 14:** *IF THE APPLICATION ITSELF IMPLEMENTS AN RFC-DEFINED PROTOCOL, YOU MUST FOLLOW ALL RELEVANT RFCs COMPLETELY.**
- **PART 14:** This is NOT optional. This is NOT about "adding compatibility." If you're building a protocol implementation, you MUST be RFC-compliant or the application is fundamentally broken.
- **PART 14:** | Application Type | Required RFCs | Compliance Level |
- **PART 14:** 2. **Implement ALL required behavior** per specifications
- **PART 14:** | **Protocol compliance** | Implement ALL required endpoints | Matrix, ActivityPub, XMPP |
- **PART 14:** "RFC 4918 defines 9 required methods. Should I implement the full RFC?"
- **PART 14:** *All API responses MUST follow these formats for consistency:**
- **PART 14:** | Field | Required | Description |
- **PART 14:** | `ok` | Yes | Always `true` for success |
- **PART 14:** *All 4xx/5xx responses MUST use this envelope** (RFC 7807-inspired — `ok` + `error` code + human `message` + structured `details`). No endpoint may invent its own error shape — except compatibility-layer routes, which return the emulated service's native error shape; this is the single source of truth for every other error response in the service.
- **PART 14:** | `ok` | Yes | Always `false` for errors. Mirrors the `ok: true` of success responses. |
- **PART 14:** [ ] Frontend is required for ALL projects
- **PART 14:** [ ] All 3 API types required: REST, Swagger, GraphQL (Swagger & GraphQL in sync)
- **PART 14:** [ ] Standard endpoints must exist (`/server/healthz`, `/api/{api_version}/server/swagger`, `/api/{api_version}/server/graphql`, `/api/swagger` alias, `/api/graphql` alias, `/server/docs/swagger`, `/server/docs/graphql`)
- **PART 15:** *ALL projects MUST have built-in Let's Encrypt support.**
- **PART 15:** | Provider | Required Fields |
- **PART 15:** *Note:** For production SSL/Let's Encrypt, always set `DOMAIN` explicitly:
- **PART 15:** *IMPORTANT: Logs are ALWAYS raw text. No icons, ASCII art, or special characters in log output.**
- **PART 15:** *Banner MUST adapt to terminal size. Phone SSH users are common.**
- **PART 15:** *Port Configuration (Project-Wide, NON-NEGOTIABLE):**
- **PART 15:** *ALWAYS strip :80 and :443.**
- **PART 15:** | Tor (.onion) | Always HTTP | None (TLS terminates in the Tor layer) |
- **PART 15:** | I2P (.i2p) | Always HTTP | None (TLS terminates in the I2P layer) |
- **PART 15:** Overlay networks are ALWAYS `http://` regardless of clearnet configuration (see PART 12)
- **PART 15:** *Footer timestamp format:** `%B %d, %Y at %H:%M:%S %Z` → `December 04, 2025 at 13:05:13 EST` — anything user-facing MUST use this format; use `%Y-%m-%dT%H:%M:%S%:z` (RFC 3339) only where machine-readability matters (API responses, logs, health endpoints)
- **PART 15:** *Example (First Run - Setup Required):**
- **PART 15:** *Log format is ALWAYS plain text:**
- **PART 15:** Certificate CN or SAN must match configured FQDN (`server.host`)
- **PART 15:** Both cert and key files must be readable

## Key Rules Summary

### PART 13 — HEALTH & VERSIONING
- Health Checks
- Versioning

### PART 14 — API STRUCTURE
- Authentication & CORS (Cross-References)
- Legacy vs Compatibility Endpoints
- API Versioning
- Route Compliance
- Route Naming Convention
- URL Parameters
- Response Formatting
- Content Negotiation
- API Types
- External API Compatibility
- Root-Level Endpoints
- Response Standards

### PART 15 — SSL/TLS & LET'S ENCRYPT
- Built-in Let's Encrypt Support

For complete details, see AI.md PART 13, PART 14, PART 15.

<!-- AI.md source: 03cc45ec58df -->
