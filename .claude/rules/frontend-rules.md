# Frontend Rules (PART 16)

⚠️ **These rules are NON-NEGOTIABLE. Violations are bugs.** ⚠️

## CRITICAL - NEVER DO
- Never hardcode English UI strings — use `{{t .Lang "key"}}` translation keys for every label/button/message
- Never hardcode `lang="en"` in `<html>` — use `lang="{{.Lang}}" dir="{{.Dir}}"`
- Never use bare relative `/path` fetches in JS — use `window.location.origin`-based or configured base URLs
- Never add JavaScript for anything HTML5+CSS already does (forms, validation, show/hide, dialogs, tabs) —
  JS is a LAST RESORT; every `<script>` must name a capability impossible without it; default answer to
  "add JS?" is NO. Forms use native `<form method>`; disclosure uses `<details>/<summary>` or
  checkbox+`:checked`; dialogs use `<dialog>`; tabs use radio inputs + `:checked` + CSS
- Never let a service worker `respondWith()` branch resolve to `undefined` or reject uncaught — every
  branch (navigations, static assets, everything else) MUST end in a guaranteed synthesized `Response`
  (offline page for navigations, 504 for subresources) or the browser shows `net::ERR_FAILED` instead of
  a page
- Never persist `theme`/`lang` preferences server-side — no preferences table; the server only ever reads
  the cookie per request
- Never include `cookie_consent` or `ccpa_opt_out` in preference export/import — consent is a per-browser
  legal acknowledgment, not a portable preference; never include `{project_name}_build` either — it is a
  device-local cache-purge stamp
- Never add a standalone `/prefs/*` path — export/import are sub-routes of `/server/preferences`
  (API-mirrored at `/api/{api_version}/server/preferences`)
- Never trust imported preference values as-is — validate each against its normal enum/BCP-47 allowlist;
  reject or drop anything unknown or malformed

## CRITICAL - ALWAYS DO
- Support dark/light/auto theme via CSS custom properties, never hardcoded colors
- Keep web UIs mobile-responsive from day one
- Navigations in the service worker are network-first (fetch first, cache fallback, then synthesized
  offline `Response`) — only intercept same-origin GET, let API/cross-origin/non-GET fall through untouched
- Preference export (`GET /server/preferences/export`, API-mirrored) returns both a full URL
  (`https://{host}/server/preferences/import?theme=dark&lang=fr`) and a short code
  (`base64url(theme=dark&lang=fr)`) built from the current `theme`/`lang` cookies only
- Preference import (`GET /server/preferences/import?theme=…&lang=…`, API-mirrored) decodes, validates,
  sets the matching cookies, then `303 See Other`s to `/` (or referrer) in one request — code must never
  linger in the visible URL/history
- API-only projects (no admin panel/WebUI — see Account Types: only `Server`/`Operator`) still get
  `/server/preferences` and its export/import sub-routes; there is no `/server/admin` or
  `{admin_path}`/`{admin_username}` segment to collide with

## Key Rules Summary
- **NOT YET FULLY POPULATED**: PART 16 (Web Frontend) has not been read in full in this pass — only
  PART 0/1 general rules, the JS-necessity-gate and service-worker-safety rules added 2026-08-20 (AI.md
  commit `e18697ec7b1b`), and the cross-device preference export/import rules added 2026-08-21 (AI.md
  commit `dd393bbe454c`) are included. Read AI.md PART 16 directly before doing frontend-specific work.

For complete details, see AI.md PART 16.
