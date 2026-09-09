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
- Never use `alert()`/`confirm()`/`prompt()` or plain-text option lists — use a custom modal/native
  `<dialog>`/custom input modal/`<select>`/checkboxes/radio buttons instead
- Never use inline event handlers (`onclick=`, `onchange=`, etc.) — CSP blocks them; bind listeners in
  `static/js/app.js` only
- Never let a service worker `respondWith()` branch resolve to `undefined` or reject uncaught — every
  branch (navigations, static assets, everything else) MUST end in a guaranteed synthesized `Response`
  (offline page for navigations, 504 for subresources) or the browser shows `net::ERR_FAILED` instead of
  a page
- Never persist `theme`/`lang` preferences server-side — no preferences table; the server only ever reads
  the cookie per request
- Never apply the `theme-{dark|light|auto}` class to `<body>` — it belongs on `<html>` so there is zero
  FOUC and zero JS needed to paint the correct theme on first byte
- Never hardcode the next value in a theme-toggle control — compute it server-side via `nextTheme(current)`
  (cycle: dark → light → auto → dark)
- Never include `cookie_consent` or `ccpa_opt_out` in preference export/import — consent is a per-browser
  legal acknowledgment, not a portable preference; never include `{project_name}_build` either — it is a
  device-local cache-purge stamp
- Never add a standalone `/prefs/*` path — export/import are sub-routes of `/server/preferences`
  (API-mirrored at `/api/{api_version}/server/preferences`)
- Never trust imported preference values as-is — validate each against its normal enum/BCP-47 allowlist;
  reject or drop anything unknown or malformed
- Never write generic placeholder content on standard pages (`/server/about`, `/server/privacy`,
  `/server/contact`, `/server/help`, `/server/terms`) — content must be sourced from IDEA.md (real
  endpoints, real curl examples), never "Your application name here" or example.com URLs
- Never embed GeoIP databases, IP/domain blocklists, CVE databases, or SSL certificates via `//go:embed`
  — those are downloaded/updated at runtime; only templates, CSS, JS, images, icons, fonts, and static
  application data (JSON) are embedded in the binary
- Never let a long unbreakable string (IP address, API token, hash, UUID) overflow its container — and
  never pair it with an adjacent copy button unless it also gets single-line horizontal scroll
- Never pin/fix the header, nav, or footer to the viewport — they scroll with the page; the only fixed
  elements are the cookie-consent banner (bottom) and toasts (top-right)
- Never put the Help, API, or Preferences links in the main nav-links row — they live in the
  header-actions cluster or footer instead
- Never ship more than one JS file (`static/js/app.js`) or more than one CSS load order
  (`common.css` → `components.css` → `public.css`)

## CRITICAL - ALWAYS DO
- Support dark/light/auto theme via CSS custom properties defined once in `:root`, never hardcoded colors
- Keep web UIs mobile-responsive from day one — breakpoints at 768px (tablet) and 1024px (desktop);
  interactive/touch targets ≥44×44px, including icon-only controls
- Negotiate content by Accept header/User-Agent on the same route: HTML for browsers, `text/plain` for
  CLI tools (curl), JSON for `Accept: application/json` — one endpoint, three representations
- Navigations in the service worker are network-first (fetch first, cache fallback, then synthesized
  offline `Response`); static assets are cache-first with a synthesized 504 fallback — only intercept
  same-origin GET, let API/cross-origin/non-GET fall through untouched
- Precache the PWA shell (`manifest.json`, `offline.html`, core CSS/JS) via the service worker's
  `PRECACHE_ASSETS` list
- Preference export (`GET /server/preferences/export`, API-mirrored) returns both a full URL
  (`https://{host}/server/preferences/import?theme=dark&lang=fr`) and a short code
  (`base64url(theme=dark&lang=fr)`) built from the current `theme`/`lang` cookies only
- Preference import (`GET /server/preferences/import?theme=…&lang=…`, API-mirrored) decodes, validates,
  sets the matching cookies, then `303 See Other`s to `/` (or referrer) in one request — code must never
  linger in the visible URL/history
- API-only projects (no admin panel/WebUI — see Account Types: only `Server`/`Operator`) still get
  `/server/preferences` and its export/import sub-routes; there is no `/server/admin` or
  `{admin_path}`/`{admin_username}` segment to collide with
- Build the mobile nav menu CSS-only (checkbox + `:checked`), sliding from the right edge with a
  closing overlay — no JS
- Keep nav to a single row, 4 zones in order: `{logo/text} {links} {profile/preferences} {theme_toggle}`
- Use the print utility classes (`.no-print`, `.print-only`, `.print-include`) for print stylesheets

## Key Rules Summary
- **Directory layout**: `template/layout/base.tmpl` is the ONE web layout (no separate admin/dashboard
  layout — there are no user accounts); `template/page/*.tmpl` per route; `template/partial/*.tmpl` for
  shared fragments (header, nav, footer, error, consent/announcement banners); `static/css/{common,
  components,public}.css` load in that order; `static/js/app.js` is the single JS file
- **Standard pages & content sourcing**: `/server/about`, `/server/privacy`, `/server/contact`,
  `/server/help`, `/server/terms` render real project content pulled from IDEA.md — real endpoints, real
  example commands, no filler text
- **Embedded vs external assets**: templates/CSS/JS/images/icons/fonts/app-data JSON are `//go:embed`;
  GeoIP DBs, IP/domain blocklists, CVE DBs, and SSL certs are downloaded at runtime and never embedded
- **Long-string CSS**: `.long-string`/`.ip-address`/`.api-token`/`.hash`/`.uuid`/`.monospace-data` use
  `word-break: break-all` with no adjacent copy button; `.onion-address`/`.i2p-address`/`.copy-value` use
  single-line horizontal scroll with an adjacent copy button — never mix the two patterns
- **Theme system**: `theme` cookie read server-side only, `theme-{dark|light|auto}` class on `<html>`,
  zero JS/zero FOUC; toggle target computed via `nextTheme()`, never hardcoded
- **Accessibility/touch targets**: interactive controls ≥44×44px; `lang`/`dir` always template-driven,
  never hardcoded; no inline handlers (CSP)

For complete details, see AI.md PART 16.
