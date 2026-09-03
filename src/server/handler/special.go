// Package handler contains HTTP handlers organized by domain
// Per AI.md: handler/ for HTTP request handlers, route handlers, request/response logic
package handler

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/apimgr/ipgaze/src/common/i18n"
	"github.com/apimgr/ipgaze/src/common/theme"
	"github.com/apimgr/ipgaze/src/config"
	"github.com/apimgr/ipgaze/src/netutil"
)

// SpecialHandler handles special file routes (robots.txt, security.txt, etc.)
type SpecialHandler struct {
	OfficialSite string
	// OnionAddress is the .onion hostname from tor.onion_address (AI.md PART 12).
	// When non-empty, SecurityTxtHandler serves the Tor variant for matching requests.
	OnionAddress string
	// TorContactEmail is the contact email from tor.contact_email (AI.md PART 12).
	// Shown only on Tor responses; never falls back to the clearnet contact email.
	TorContactEmail string
	// SecurityContact is web.security.contact (AI.md PART 11): the mailto: CC
	// address used in security.txt's Contact: line.
	SecurityContact string
	// PublishPGPKey mirrors web.security.publish_pgp_key (AI.md PART 11). When
	// true and a keypair exists on disk, SecurityTxtHandler emits the
	// Encryption: line and PGPKeyHandler serves the public key.
	PublishPGPKey bool
	// PGPPublicKeyPath is {config_dir}/security/pgp.pub.asc (AI.md PART 11
	// "GPG Keypair Management"). Empty or missing file means no keypair yet.
	PGPPublicKeyPath string
	// CommitID is the running build's short commit hash. Embedded into the
	// service worker's CACHE_VERSION (AI.md PART 16 "Cache Versioning &
	// Updates") so sw.js changes byte-for-byte on every deploy — without
	// this, the file is otherwise static across builds and the browser
	// never detects an update, so install/activate never rerun and old
	// caches are never purged.
	CommitID string
	// AssetStamp is the running build's {project_version}-{short_commit}
	// cache-busting stamp (Server.AssetStamp). ManifestHandler and
	// ServiceWorkerHandler use it as the ETag for their "no-cache" response
	// headers (AI.md PART 9 "HTTP Cache Headers": "/sw.js and manifest.json"
	// — never immutable, so the browser always revalidates and reliably sees
	// the next deploy).
	AssetStamp string
	// AIBots mirrors web.robots.ai_bots (AI.md PART 16 "AI Crawler Rules") and
	// decides which recognized AI crawlers get their own Disallow stanza in
	// robots.txt. The zero value denies nothing, matching the spec default.
	AIBots config.AIBotsConfig
	// Trust resolves whether the request's peer is a trusted proxy, so the
	// robots.txt "Sitemap:" line is built from the same request-aware URL
	// builder every other absolute URL uses.
	Trust *netutil.TrustResolver
	// SitemapEnabled mirrors server.seo.sitemap.enabled (AI.md PART 24). The
	// "Sitemap:" directive is omitted when the document is not served, so
	// robots.txt never points a crawler at a 404.
	SitemapEnabled bool
}

// NewSpecialHandler creates a new SpecialHandler
func NewSpecialHandler(officialSite string) *SpecialHandler {
	site := officialSite
	if site == "" {
		site = "https://ifcfg.us"
	}
	return &SpecialHandler{
		OfficialSite: site,
	}
}

// assetStampOrCommit returns AssetStamp when wired, falling back to CommitID
// (or "v1") so /sw.js and /manifest.json still carry a stable ETag in
// contexts that construct SpecialHandler directly (e.g. tests) without
// wiring the full build stamp.
func (h *SpecialHandler) assetStampOrCommit() string {
	if h.AssetStamp != "" {
		return h.AssetStamp
	}
	if h.CommitID != "" {
		return h.CommitID
	}
	return "v1"
}

// isTorRequest reports whether the request's Host matches the configured onion address.
func (h *SpecialHandler) isTorRequest(r *http.Request) bool {
	if h.OnionAddress == "" {
		return false
	}
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	return strings.EqualFold(host, h.OnionAddress)
}

// RobotsTxtHandler serves robots.txt.
// Recognized AI crawlers inherit the wildcard block above and get no stanza of
// their own while allowed; each denied crawler renders its own
// "User-agent: {bot}" / "Disallow: /" pair, since a bot's own block overrides
// the wildcard Allow for that bot only (AI.md PART 16 "AI Crawler Rules").
func (h *SpecialHandler) RobotsTxtHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintln(w, "User-agent: *")
	fmt.Fprintln(w, "Allow: /")
	fmt.Fprintln(w, "Allow: /api")
	fmt.Fprintln(w, "Disallow: /debug")
	// AI.md PART 16 "robots.txt" requires the generated file to point crawlers
	// at the sitemap. The URL is request-aware so a proxied or Tor request
	// gets the host it actually arrived on.
	if h.SitemapEnabled {
		fmt.Fprintln(w, "Sitemap: "+netutil.BuildURL(r, h.Trust, "/sitemap.xml"))
	}

	denied := h.AIBots.DeniedAIBots()
	if len(denied) == 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "# AI crawlers - default: no additional restrictions (inherit User-agent: * above)")
		fmt.Fprintln(w, "# Per-bot stanzas are only rendered when that bot is explicitly denied below")
		return
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "# AI crawlers - the bots below are denied; every other recognized bot inherits User-agent: * above")
	for _, bot := range denied {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "User-agent: "+bot)
		fmt.Fprintln(w, "Disallow: /")
	}
}

// hasPGPKey reports whether a project PGP keypair exists on disk and
// web.security.publish_pgp_key is enabled (AI.md PART 11 "GPG Keypair Management").
func (h *SpecialHandler) hasPGPKey() bool {
	if !h.PublishPGPKey || h.PGPPublicKeyPath == "" {
		return false
	}
	_, err := os.Stat(h.PGPPublicKeyPath)
	return err == nil
}

// SecurityTxtHandler serves security.txt.
// When the request is a Tor request (Host matches tor.onion_address), a Tor-safe
// variant is served per AI.md PART 12: all URLs use the onion address, no clearnet
// FQDN appears, Preferred-Languages is omitted, and tor.contact_email is used if set.
// The Encryption: line (AI.md PART 11) is emitted only when a project PGP keypair
// exists and web.security.publish_pgp_key is enabled.
func (h *SpecialHandler) SecurityTxtHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	if h.isTorRequest(r) {
		// Tor variant: all URLs use the onion address, no clearnet FQDN (AI.md PART 12).
		base := "http://" + h.OnionAddress
		fmt.Fprintln(w, "Contact: "+base+"/server/contact")
		if h.TorContactEmail != "" {
			fmt.Fprintln(w, "Contact: mailto:"+h.TorContactEmail)
		}
		fmt.Fprintln(w, "Expires: 2026-12-31T23:59:59.000Z")
		fmt.Fprintln(w, "Policy: "+base+"/server/security")
		if h.hasPGPKey() {
			fmt.Fprintln(w, "Encryption: "+base+"/.well-known/pgp-key.asc")
		}
		fmt.Fprintln(w, "Canonical: "+base+"/.well-known/security.txt")
		return
	}
	contact := h.SecurityContact
	if contact == "" {
		contact = "security@apimgr.us"
	}
	fmt.Fprintln(w, "Contact: mailto:"+contact)
	fmt.Fprintln(w, "Expires: 2026-12-31T23:59:59.000Z")
	if h.hasPGPKey() {
		fmt.Fprintf(w, "Encryption: %s/.well-known/pgp-key.asc\n", h.OfficialSite)
	}
	fmt.Fprintln(w, "Preferred-Languages: en")
	fmt.Fprintf(w, "Canonical: %s/.well-known/security.txt\n", h.OfficialSite)
}

// PGPKeyHandler serves the project's PGP public key (AI.md PART 11
// "GPG Keypair Management"), ASCII-armored, at /.well-known/pgp-key.asc.
// 404 if no keypair has been generated yet or publish_pgp_key is disabled.
func (h *SpecialHandler) PGPKeyHandler(w http.ResponseWriter, r *http.Request) {
	if !h.hasPGPKey() {
		http.NotFound(w, r)
		return
	}
	data, err := os.ReadFile(h.PGPPublicKeyPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/pgp-keys")
	_, _ = w.Write(data)
}

// ManifestHandler serves the PWA web app manifest per AI.md PART 16.
// Icons are served from /static/icons/ in multiple sizes including maskable variants.
func (h *SpecialHandler) ManifestHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/manifest+json")
	// Never immutable (AI.md PART 9 "HTTP Cache Headers"): the browser must
	// see a changed manifest.json promptly on its next revalidation.
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("ETag", `"`+h.assetStampOrCommit()+`"`)
	manifest := fmt.Sprintf(`{
  "name": "IPGaze",
  "short_name": "IPGaze",
  "description": "IP address lookup and geolocation service",
  "start_url": "/?source=pwa",
  "scope": "/",
  "display": "standalone",
  "orientation": "any",
  "background_color": "%s",
  "theme_color": "%s",
  "categories": ["utilities"],
  "icons": [
    {
      "src": "/static/icons/icon-72.png",
      "sizes": "72x72",
      "type": "image/png"
    },
    {
      "src": "/static/icons/icon-96.png",
      "sizes": "96x96",
      "type": "image/png"
    },
    {
      "src": "/static/icons/icon-128.png",
      "sizes": "128x128",
      "type": "image/png"
    },
    {
      "src": "/static/icons/icon-144.png",
      "sizes": "144x144",
      "type": "image/png"
    },
    {
      "src": "/static/icons/icon-152.png",
      "sizes": "152x152",
      "type": "image/png"
    },
    {
      "src": "/static/icons/icon-192.png",
      "sizes": "192x192",
      "type": "image/png"
    },
    {
      "src": "/static/icons/icon-384.png",
      "sizes": "384x384",
      "type": "image/png"
    },
    {
      "src": "/static/icons/icon-512.png",
      "sizes": "512x512",
      "type": "image/png"
    },
    {
      "src": "/static/icons/icon-maskable-192.png",
      "sizes": "192x192",
      "type": "image/png",
      "purpose": "maskable"
    },
    {
      "src": "/static/icons/icon-maskable-512.png",
      "sizes": "512x512",
      "type": "image/png",
      "purpose": "maskable"
    }
  ]
}`, theme.ThemePaletteDark.Background, theme.ThemePaletteDark.Primary)
	fmt.Fprintln(w, manifest)
}

// ServiceWorkerHandler serves the PWA service worker per AI.md PART 16.
// Handles install (pre-cache), activate (clean old caches), and fetch (cache-first).
func (h *SpecialHandler) ServiceWorkerHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript")
	// Never immutable (AI.md PART 9 "HTTP Cache Headers"): a long-cached
	// sw.js would delay every other update mechanism.
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("ETag", `"`+h.assetStampOrCommit()+`"`)
	// CACHE_VERSION is tied to the running build's commit so this file's
	// bytes change on every deploy — the browser's periodic sw.js byte
	// comparison then reliably detects updates and reruns install/activate.
	cacheVersion := h.CommitID
	if cacheVersion == "" {
		cacheVersion = "v1"
	}
	sw := `// IPGaze Service Worker — per AI.md PART 16
const CACHE_VERSION = '` + cacheVersion + `';
const CACHE_NAME = 'ipgaze-cache-' + CACHE_VERSION;

const PRECACHE_ASSETS = [
  '/',
  '/static/css/common.css',
  '/static/css/components.css',
  '/static/css/public.css',
  '/static/js/app.js',
  '/static/icons/icon-192.png',
  '/static/icons/icon-512.png',
  '/manifest.json',
  '/offline.html'
];

// INSTALL — pre-cache static assets and activate immediately
self.addEventListener('install', function(event) {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(function(cache) { return cache.addAll(PRECACHE_ASSETS); })
      .then(function() { return self.skipWaiting(); })
  );
});

// ACTIVATE — clean up stale caches from prior versions
self.addEventListener('activate', function(event) {
  event.waitUntil(
    caches.keys()
      .then(function(keys) {
        return Promise.all(
          keys
            .filter(function(key) { return key.startsWith('ipgaze-cache-') && key !== CACHE_NAME; })
            .map(function(key) { return caches.delete(key); })
        );
      })
      .then(function() { return self.clients.claim(); })
  );
});

// MESSAGE — the page's "Update Now" control posts SKIP_WAITING so a waiting
// worker activates without requiring every tab to close first. The page
// reloads itself on the resulting controllerchange event.
self.addEventListener('message', function(event) {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});

// FETCH — network-first for HTML (always get the latest page when online),
// cache-first for static assets (versioned by CACHE_NAME, safe to reuse)
self.addEventListener('fetch', function(event) {
  var url = new URL(event.request.url);
  // Only same-origin GET is handled here; cross-origin requests and non-GET
  // methods fall through to the browser untouched — respondWith() is never
  // called for them.
  if (event.request.method !== 'GET' || url.origin !== self.location.origin) {
    return;
  }
  // API calls are never cached
  if (url.pathname.startsWith('/api/')) {
    return;
  }
  var isHTML = event.request.mode === 'navigate' ||
    (event.request.headers.get('accept') || '').indexOf('text/html') !== -1;
  if (isHTML) {
    event.respondWith(
      fetch(event.request)
        .then(function(response) {
          var copy = response.clone();
          caches.open(CACHE_NAME).then(function(cache) { cache.put(event.request, copy); });
          return response;
        })
        .catch(function() {
          // Every branch MUST resolve to a real Response — a chain ending on
          // "cached || caches.match(...)" can itself miss and resolve
          // undefined, which the browser renders as net::ERR_FAILED instead
          // of a page (AI.md PART 16 service-worker guaranteed-Response rule).
          return caches.match(event.request).then(function(cached) {
            return cached || caches.match('/offline.html').then(function(offline) {
              return offline || new Response('', { status: 503, statusText: 'Service Unavailable' });
            });
          });
        })
    );
    return;
  }
  event.respondWith(
    caches.match(event.request).then(function(cached) {
      return cached || fetch(event.request).catch(function() {
        return caches.match('/offline.html').then(function(offline) {
          return offline || new Response('', { status: 504, statusText: 'Gateway Timeout' });
        });
      });
    })
  );
});
`
	fmt.Fprintln(w, sw)
}

// OfflineHandler serves the PWA offline fallback page per AI.md PART 16.
// The service worker caches this page and serves it when the user is offline.
func (h *SpecialHandler) OfflineHandler(w http.ResponseWriter, r *http.Request) {
	lang := i18n.DetectLocale(r)
	dir := string(i18n.LocaleDirection(lang))
	ctx := i18n.WithLang(r.Context(), lang)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="%s" dir="%s">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>IPGaze — %s</title>
  <style>
    :root { --bg: %s; --fg: %s; --muted: %s; --accent: %s; --accent-text: %s; }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: var(--bg); color: var(--fg); font-family: system-ui, sans-serif;
           display: flex; align-items: center; justify-content: center; min-height: 100vh; text-align: center; padding: 1rem; }
    .card { max-width: 400px; padding: 2rem; }
    h1 { font-size: 1.5rem; margin-bottom: 0.5rem; color: var(--accent); }
    p { color: var(--muted); line-height: 1.6; margin-bottom: 1rem; }
    .btn { background: var(--accent); color: var(--accent-text); border: none; padding: 0.75rem 1.5rem;
           border-radius: 4px; cursor: pointer; font-size: 1rem; display: inline-block; text-decoration: none; }
    .btn:hover { opacity: 0.85; }
  </style>
</head>
<body>
  <div class="card">
    <h1>%s</h1>
    <p>%s</p>
    <a class="btn" href="/">%s</a>
  </div>
</body>
</html>`,
		lang, dir,
		i18n.T(ctx, "pwa.offline_title"),
		theme.ThemePaletteDark.Background,
		theme.ThemePaletteDark.Foreground,
		theme.ThemePaletteDark.Muted,
		theme.ThemePaletteDark.Primary,
		theme.ReadableTextOn(theme.ThemePaletteDark.Primary),
		i18n.T(ctx, "pwa.offline_title"),
		i18n.T(ctx, "pwa.offline_description"),
		i18n.T(ctx, "pwa.offline_try_again"),
	)
}

// LLMsTxtHandler serves llms.txt for AI agent discovery per AI.md PART 11.
// Served at both /.well-known/llms.txt and /llms.txt.
func (h *SpecialHandler) LLMsTxtHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	content := `# IPGaze
> Lightweight, fast IP address lookup service with GeoIP information.
> echoip-compatible API — same routes, same response formats.

## API
Base URL: /api/v1
Authentication: None required for public endpoints
Rate limit: 120 requests/minute per IP

## Endpoints
- GET /health - Health check
- GET /version - Server version info
- GET / - Your IP address (plain text for CLI, JSON for API clients)
- GET /{ip} - Lookup specific IP address
- GET /ip - Your IP address
- GET /country - Your country
- GET /city - Your city
- GET /asn - Your ASN
- GET /json - Full response as JSON
- GET /api/v1/ip - Your IP (JSON)
- GET /api/v1/ip/{ip} - Lookup specific IP (JSON)
- GET /graphql - GraphQL endpoint

## Capabilities
- IPv4 and IPv6 support
- GeoIP lookup (country, city, region, ASN, coordinates, timezone)
- Reverse DNS hostname lookup
- Port reachability testing
- echoip-compatible API surface
- GraphQL endpoint for flexible queries
- OpenAPI/Swagger documentation at /swagger
- Prometheus metrics at /metrics (when enabled)

## Content Negotiation
- CLI tools (curl, wget, HTTPie) receive plain text
- Browsers receive HTML
- Accept: application/json returns JSON

## Source
Repository: https://github.com/apimgr/ipgaze
License: MIT
`
	fmt.Fprint(w, content)
}
