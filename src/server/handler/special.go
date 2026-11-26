// Package handler contains HTTP handlers organized by domain
// Per AI.md: handler/ for HTTP request handlers, route handlers, request/response logic
package handler

import (
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/apimgr/ipgaze/src/common/theme"
	"github.com/apimgr/ipgaze/src/config"
	"github.com/apimgr/ipgaze/src/netutil"
	"github.com/apimgr/ipgaze/src/swagger"
)

// SpecialHandler handles special file routes (robots.txt, security.txt, etc.)
type SpecialHandler struct {
	OfficialSite string
	// OnionAddress is the .onion hostname from tor.onion_address (AI.md PART 12).
	// When non-empty, SecurityTxtHandler serves the Tor variant for matching requests.
	OnionAddress string
	// TorContactEmail is the contact email from server.tor.contact_email (AI.md PART 12).
	// Shown only on Tor responses; never falls back to the clearnet contact email.
	TorContactEmail string
	// SecurityContact is web.security.contact (AI.md PART 11): the mailto: CC
	// address used in security.txt's Contact: line.
	SecurityContact string
	// SecurityReportURL is the repository's private vulnerability reporting URL.
	SecurityReportURL   string
	ContactFormDisabled bool
	// SecurityID returns the current rotating security.txt token.
	SecurityID func() (string, error)
	// PublishPGPKey mirrors web.security.publish_pgp_key (AI.md PART 11). When
	// true and a keypair exists on disk, SecurityTxtHandler emits the
	// Encryption: line and PGPKeyHandler serves the public key.
	PublishPGPKey bool
	// PGPPublicKeyPath is {config_dir}/security/pgp.pub.asc (AI.md PART 11
	// "GPG Keypair Management"). Empty or missing file means no keypair yet.
	PGPPublicKeyPath string
	// PGPFingerprint returns the active keypair fingerprint for security.txt comments.
	PGPFingerprint func() string
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
	// APIV1OperationIDs contains the versioned API operations registered by
	// the active runtime router. llms.txt uses it to omit disabled endpoints.
	APIV1OperationIDs map[string]struct{}
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
	if h.Trust != nil && netutil.IsTorRequest(r, h.Trust) {
		return true
	}
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
	_, _ = fmt.Fprintln(w, "User-agent: *")
	_, _ = fmt.Fprintln(w, "Allow: /")
	_, _ = fmt.Fprintln(w, "Allow: /api")
	_, _ = fmt.Fprintln(w, "Disallow: /debug")
	// AI.md PART 16 "robots.txt" requires the generated file to point crawlers
	// at the sitemap. The URL is request-aware so a proxied or Tor request
	// gets the host it actually arrived on.
	if h.SitemapEnabled {
		_, _ = fmt.Fprintln(w, "Sitemap: "+netutil.BuildURL(r, h.Trust, "/sitemap.xml"))
	}

	denied := h.AIBots.DeniedAIBots()
	if len(denied) == 0 {
		_, _ = fmt.Fprintln(w)
		_, _ = fmt.Fprintln(w, "# AI crawlers - default: no additional restrictions (inherit User-agent: * above)")
		_, _ = fmt.Fprintln(w, "# Per-bot stanzas are only rendered when that bot is explicitly denied below")
		return
	}
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "# AI crawlers - the bots below are denied; every other recognized bot inherits User-agent: * above")
	for _, bot := range denied {
		_, _ = fmt.Fprintln(w)
		_, _ = fmt.Fprintln(w, "User-agent: "+bot)
		_, _ = fmt.Fprintln(w, "Disallow: /")
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

// PGPKeyAvailable reports whether the configured public key can be served.
func (h *SpecialHandler) PGPKeyAvailable() bool {
	return h.hasPGPKey()
}

// SecurityTxtHandler serves security.txt.
// When the request is a Tor request (Host matches tor.onion_address), a Tor-safe
// variant is served per AI.md PART 12: all URLs use the onion address, no clearnet
// FQDN appears, Preferred-Languages is omitted, and server.tor.contact_email is used if set.
// The Encryption: line (AI.md PART 11) is emitted only when a project PGP keypair
// exists and web.security.publish_pgp_key is enabled.
func (h *SpecialHandler) SecurityTxtHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Cache-Control", "public, max-age=300")
	expires := time.Now().UTC().AddDate(1, 0, 0).Format("2006-01-02T15:04:05.000Z")
	if h.isTorRequest(r) {
		// Tor variant: all URLs use the onion address, no clearnet FQDN (AI.md PART 12).
		base := "http://" + h.OnionAddress
		if !h.ContactFormDisabled {
			if securityID, err := h.currentSecurityID(); err == nil && securityID != "" {
				_, _ = fmt.Fprintln(w, "Contact: "+base+"/server/contact?security_id="+securityID)
			}
		}
		if h.TorContactEmail != "" {
			_, _ = fmt.Fprintln(w, "Contact: mailto:"+h.TorContactEmail)
		}
		_, _ = fmt.Fprintln(w, "Expires: "+expires)
		_, _ = fmt.Fprintln(w, "Policy: "+base+"/server/security")
		if h.hasPGPKey() {
			_, _ = fmt.Fprintln(w, "Encryption: "+base+"/.well-known/pgp-key.asc")
			h.writePGPFingerprintComment(w)
		}
		_, _ = fmt.Fprintln(w, "Canonical: "+base+"/.well-known/security.txt")
		return
	}
	contact := h.SecurityContact
	if contact == "" {
		contact = "security@apimgr.us"
	}
	if h.SecurityReportURL != "" {
		_, _ = fmt.Fprintln(w, "Contact: "+h.SecurityReportURL)
	}
	if !h.ContactFormDisabled {
		if securityID, err := h.currentSecurityID(); err == nil && securityID != "" {
			_, _ = fmt.Fprintf(w, "Contact: %s/server/contact?security_id=%s\n", h.OfficialSite, securityID)
		}
	}
	_, _ = fmt.Fprintln(w, "Contact: mailto:"+contact)
	_, _ = fmt.Fprintln(w, "Expires: "+expires)
	if h.hasPGPKey() {
		_, _ = fmt.Fprintf(w, "Encryption: %s/.well-known/pgp-key.asc\n", h.OfficialSite)
		h.writePGPFingerprintComment(w)
	}
	_, _ = fmt.Fprintln(w, "Preferred-Languages: en")
	_, _ = fmt.Fprintf(w, "Canonical: %s/.well-known/security.txt\n", h.OfficialSite)
}

func (h *SpecialHandler) writePGPFingerprintComment(w http.ResponseWriter) {
	if h.PGPFingerprint == nil {
		return
	}
	if fingerprint := h.PGPFingerprint(); isValidPGPFingerprint(fingerprint) {
		_, _ = fmt.Fprintln(w, "# PGP Fingerprint: "+fingerprint)
	}
}

func isValidPGPFingerprint(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') && (char < 'A' || char > 'F') {
			return false
		}
	}
	return true
}

func (h *SpecialHandler) currentSecurityID() (string, error) {
	if h.SecurityID == nil {
		return "", nil
	}
	return h.SecurityID()
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
	_, _ = fmt.Fprintln(w, manifest)
}

// ServiceWorkerHandler serves the PWA service worker per AI.md PART 16.
// Handles install (pre-cache), activate (clean old caches), and fetch fallback behavior.
func (h *SpecialHandler) ServiceWorkerHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript")
	// Never immutable (AI.md PART 9 "HTTP Cache Headers"): a long-cached
	// sw.js would delay every other update mechanism.
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("ETag", `"`+h.assetStampOrCommit()+`"`)
	// CACHE_VERSION is tied to the running build's commit so this file's
	// bytes change on every deploy — the browser's periodic sw.js byte
	// comparison then reliably detects updates and reruns install/activate.
	cacheVersion := h.assetStampOrCommit()
	sw := `// IPGaze Service Worker — per AI.md PART 16
const CACHE_VERSION = '` + cacheVersion + `';
const CACHE_NAME = 'ipgaze-cache-' + CACHE_VERSION;

const PRECACHE_ASSETS = [
  '/theme.css?v=` + cacheVersion + `',
  '/static/css/common.css?v=` + cacheVersion + `',
  '/static/css/components.css?v=` + cacheVersion + `',
  '/static/css/public.css?v=` + cacheVersion + `',
  '/static/css/graphql.css?v=` + cacheVersion + `',
  '/static/js/app.js?v=` + cacheVersion + `',
  '/static/icons/icon-192.png?v=` + cacheVersion + `',
  '/static/icons/icon-512.png?v=` + cacheVersion + `'
];

// INSTALL — pre-cache assets. A first installation activates automatically;
// an update waits for the user to accept it or for existing tabs to close.
self.addEventListener('install', function(event) {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(function(cache) { return cache.addAll(PRECACHE_ASSETS); })
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

// Navigation fetches are bounded so server restarts cannot leave a tab loading forever.
const NAV_TIMEOUT_MS = 8000;
function withTimeout(promise, ms) {
  return new Promise(function(resolve, reject) {
    var timer = setTimeout(function() { reject(new Error('navigation timeout')); }, ms);
    promise.then(function(value) {
      clearTimeout(timer);
      resolve(value);
    }, function(error) {
      clearTimeout(timer);
      reject(error);
    });
  });
}

// FETCH — navigations are network-first; versioned static assets are cache-first.
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
  if (event.request.mode === 'navigate') {
    event.respondWith(
      withTimeout(fetch(event.request), NAV_TIMEOUT_MS)
        .then(function(response) {
          if (response.ok && !response.redirected && response.headers.get('X-Offline-Cache') === 'public') {
            var copy = response.clone();
            event.waitUntil(caches.open(CACHE_NAME).then(function(cache) {
              return cache.put(event.request, copy);
            }).catch(function() {}));
          } else {
            event.waitUntil(caches.open(CACHE_NAME).then(function(cache) {
              return cache.delete(event.request);
            }).catch(function() {}));
          }
          if (response.redirected) {
            throw new Error('redirected navigation');
          }
          return response;
        })
        .catch(function() {
          // Every branch MUST resolve to a real Response — a chain ending on
          // "cached || caches.match(...)" can itself miss and resolve
          // undefined, which the browser renders as net::ERR_FAILED instead
          // of a page (AI.md PART 16 service-worker guaranteed-Response rule).
          return caches.match(event.request).then(function(cached) {
            return cached || offlineFallbackResponse();
          });
        })
        .catch(function() {
          return offlineFallbackResponse();
        })
    );
    return;
  }
  event.respondWith(
    caches.match(event.request).then(function(cached) {
      if (cached) { return cached; }
      return fetch(event.request).then(function(response) {
        if (response.ok && !response.redirected) {
          var copy = response.clone();
          event.waitUntil(caches.open(CACHE_NAME).then(function(cache) {
            return cache.put(event.request, copy);
          }).catch(function() {}));
        }
        return response;
      });
    }).catch(function() {
      return new Response('', { status: 504, statusText: 'Gateway Timeout' });
    })
  );
});

const STRINGS_CACHE = 'ipgaze-offline-strings';
const DEFAULT_STRINGS = {
  lang: 'en', dir: 'ltr', title: 'Offline', heading: 'You are offline',
  message: 'This page could not be loaded and no cached copy is available. Check your connection and try again.',
  tryAgain: 'Try again'
};
function escapeHtml(text) {
  return String(text).replace(/[&<>\"]/g, function(c) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '\"': '&quot;' }[c];
  });
}
function offlineFallbackResponse() {
  return (async function() {
    var strings = DEFAULT_STRINGS;
    try {
      var cache = await caches.open(STRINGS_CACHE);
      var stored = await cache.match('/offline-strings.json');
      if (stored) {
        strings = Object.assign({}, DEFAULT_STRINGS, await stored.json());
      }
    } catch (error) {
      strings = DEFAULT_STRINGS;
    }
    return new Response(
      '<!doctype html><html lang="' + escapeHtml(strings.lang) + '" dir="' + escapeHtml(strings.dir) + '"><head><meta charset="utf-8">'
        + '<meta name="viewport" content="width=device-width,initial-scale=1"><title>' + escapeHtml(strings.title) + '</title>'
        + '<link rel="stylesheet" href="/theme.css?v=` + cacheVersion + `"><link rel="stylesheet" href="/static/css/common.css?v=` + cacheVersion + `"><link rel="stylesheet" href="/static/css/offline.css?v=` + cacheVersion + `">'
        + '</head><body><main class="container container-sm"><div class="offline-card"><h1>' + escapeHtml(strings.heading) + '</h1><p>' + escapeHtml(strings.message) + '</p><a class="btn btn-primary" href="/">' + escapeHtml(strings.tryAgain) + '</a></div></main></body></html>',
      { status: 503, statusText: 'Service Unavailable', headers: { 'Content-Type': 'text/html; charset=utf-8' } }
    );
  })();
}
`
	_, _ = fmt.Fprintln(w, sw)
}

// LLMsTxtHandler serves llms.txt for AI agent discovery per AI.md PART 11.
// Served at both /.well-known/llms.txt and /llms.txt.
func (h *SpecialHandler) LLMsTxtHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	apiBaseURL := netutil.BuildURL(r, h.Trust, "/api/v1")
	spec := swagger.GenerateSpec(swagger.SwaggerHandlerConfig{}, apiBaseURL, "en")
	content := `# IPGaze
> Lightweight, fast IP address lookup service with GeoIP information.
> echoip-compatible API — same routes, same response formats.

## API
Versioned API base URL: ` + apiBaseURL + `
Echoip-compatible routes use the site root.
Authentication: None required for public endpoints
`
	cfg := config.Get()
	if cfg != nil {
		apiContact := cfg.Server.Contact.General.Email
		securityContact := cfg.Server.Contact.Security.Email
		content += "Read rate limit: " + llmsReadRateLimit(cfg) + "\n"
		content += "MCP: " + strings.TrimSuffix(netutil.BuildURL(r, h.Trust, ""), "/") + "/mcp (Streamable HTTP; Bearer token required)\n\n"
		content += "## Contact\nAPI issues: " + llmsContact(apiContact) + "\nSecurity: " + llmsContact(securityContact) + "\n"
		if cfg.Web.LLMs.IncludeEndpoints {
			content += "\n## Endpoints\n"
			for _, endpoint := range llmsAPIEndpoints(spec.Paths, h.APIV1OperationIDs) {
				content += "- " + endpoint + "\n"
			}
		}
		if cfg.Web.LLMs.IncludeSchemas && len(spec.Components.Schemas) > 0 {
			content += "\n## Schemas\n"
			names := make([]string, 0, len(spec.Components.Schemas))
			for name := range spec.Components.Schemas {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				schema := spec.Components.Schemas[name]
				encoded, err := json.MarshalIndent(schema, "", "  ")
				if err == nil {
					content += "\n### " + name + "\n```json\n" + string(encoded) + "\n```\n"
				}
			}
		}
		for _, section := range validLLMCustomSections(cfg.Web.LLMs.CustomSections) {
			content += "\n## " + html.EscapeString(section.Title) + "\n\n" + safeLLMMarkdown(section.Content) + "\n"
		}
	}
	content += `
## Capabilities
- IPv4 and IPv6 support
- GeoIP lookup (country, city, region, ASN, coordinates, timezone)
- Reverse DNS hostname lookup
- Port reachability testing
- echoip-compatible API surface
- GraphQL endpoint for flexible queries
- OpenAPI/Swagger documentation at /swagger
- Streamable HTTP MCP endpoint at /mcp (Bearer token required)
- Prometheus metrics at /metrics (when enabled)

## Content Negotiation
- CLI tools (curl, wget, HTTPie) receive plain text
- Browsers receive HTML
- Accept: application/json returns JSON

`
	content += "\n## Source\nRepository: https://github.com/apimgr/ipgaze\nLicense: MIT\n"
	_, _ = fmt.Fprint(w, content)
}

var llmMarkdownLink = regexp.MustCompile(`\]\(([^)]*)\)`)

func llmsContact(email string) string {
	if strings.TrimSpace(email) == "" {
		return "not configured"
	}
	return "mailto:" + email
}

func validLLMCustomSections(sections []config.LLMCustomSection) []config.LLMCustomSection {
	capacity := len(sections)
	if capacity > 10 {
		capacity = 10
	}
	valid := make([]config.LLMCustomSection, 0, capacity)
	for index, section := range sections {
		title := strings.TrimSpace(section.Title)
		content := strings.TrimSpace(section.Content)
		if index >= 10 || title == "" || len([]rune(title)) > 80 || strings.ContainsAny(title, "\r\n") || len([]rune(content)) > 4096 || content == "" {
			log.Printf("web.llms.custom_sections[%d] skipped: section exceeds content rules", index)
			continue
		}
		valid = append(valid, config.LLMCustomSection{Title: title, Content: content})
	}
	return valid
}

func safeLLMMarkdown(content string) string {
	content = html.EscapeString(content)
	return llmMarkdownLink.ReplaceAllStringFunc(content, func(match string) string {
		parts := llmMarkdownLink.FindStringSubmatch(match)
		if len(parts) != 2 {
			return "](#)"
		}
		parsed, err := url.Parse(strings.TrimSpace(parts[1]))
		if err != nil || parsed.IsAbs() && parsed.Scheme != "https" || strings.HasPrefix(parts[1], "//") {
			return "](#)"
		}
		return "](" + parts[1] + ")"
	})
}

func llmsReadRateLimit(cfg *config.AppConfig) string {
	requests, window := 120, 60
	if cfg != nil {
		if cfg.Server.RateLimit.Read.Requests > 0 {
			requests = cfg.Server.RateLimit.Read.Requests
		}
		if cfg.Server.RateLimit.Read.Window > 0 {
			window = cfg.Server.RateLimit.Read.Window
		}
	}
	if window%60 == 0 {
		minutes := window / 60
		unit := "minutes"
		if minutes == 1 {
			unit = "minute"
		}
		return fmt.Sprintf("%d requests per %d %s per IP", requests, minutes, unit)
	}
	unit := "seconds"
	if window == 1 {
		unit = "second"
	}
	return fmt.Sprintf("%d requests per %d %s per IP", requests, window, unit)
}

func llmsAPIEndpoints(paths map[string]swagger.PathItem, activeAPIV1 map[string]struct{}) []string {
	var endpoints []string
	apiTags := map[string]bool{
		"IP Lookup":     true,
		"GeoIP":         true,
		"Port Check":    true,
		"System":        true,
		"API v1":        true,
		"Documentation": true,
	}
	pathNames := make([]string, 0, len(paths))
	for path := range paths {
		pathNames = append(pathNames, path)
	}
	sort.Strings(pathNames)
	for _, path := range pathNames {
		item := paths[path]
		operations := []struct {
			method    string
			operation *swagger.Operation
		}{
			{"DELETE", item.Delete}, {"GET", item.Get}, {"PATCH", item.Patch},
			{"POST", item.Post}, {"PUT", item.Put},
		}
		for _, operation := range operations {
			if operation.operation == nil || !llmsPublicAPIOperation(operation.operation, apiTags) {
				continue
			}
			if activeAPIV1 != nil && strings.HasPrefix(path, "/api/v1") {
				if _, active := activeAPIV1[operation.operation.OperationID]; !active {
					continue
				}
			}
			line := operation.method + " " + path
			if operation.operation.Summary != "" {
				line += " — " + operation.operation.Summary
			}
			endpoints = append(endpoints, line)
		}
	}
	return endpoints
}

func llmsPublicAPIOperation(operation *swagger.Operation, apiTags map[string]bool) bool {
	if operation == nil {
		return false
	}
	for _, tag := range operation.Tags {
		if apiTags[tag] {
			return true
		}
	}
	return false
}
