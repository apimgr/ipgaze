// Package handler contains HTTP handlers organized by domain
// Per AI.md: handler/ for HTTP request handlers, route handlers, request/response logic
package handler

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	i18n "github.com/apimgr/ipgaze/src/common/i18n"
	"github.com/apimgr/ipgaze/src/config"
	"github.com/apimgr/ipgaze/src/email"
	"github.com/apimgr/ipgaze/src/netutil"
	"github.com/apimgr/ipgaze/src/notify"
)

// =============================================================================
// PUBLIC /server/* ROUTES (per AI.md PART 16 - Standard Pages)
// Content sourced from IDEA.md per spec - NO generic placeholders
// =============================================================================

// PagesHandler handles all /server/* public page routes.
type PagesHandler struct {
	Version   string
	BuildDate string
	Trust     *netutil.TrustResolver
	// Render is the shared page renderer — clones layout+partials and executes the named template.
	Render func(w http.ResponseWriter, r *http.Request, page string, data interface{}) error
	// WebUI exposes announcement configuration for template rendering.
	WebUI *config.WebUIConfig
	// Privacy exposes consent configuration for the cookie consent banner.
	Privacy *config.PrivacyConfig
	// TorStatus reports Tor availability/running state for the footer onion
	// row (AI.md "Footer Customization"); nil means Tor not configured.
	TorStatus TorStatusProvider
	// I2PStatus reports I2P availability/running state for the footer eepsite
	// row (AI.md PART 31.2); nil means I2P not enabled (opt-in).
	I2PStatus I2PStatusProvider
	// Config is the live application config, used to resolve contact roles
	// (email + webhooks) per AI.md PART 12 on every dispatch. Re-read fresh
	// each request rather than cached, so a live config edit takes effect
	// immediately.
	Config *config.AppConfig
	// EmailMgr sends contact-form email once SMTP is configured; nil means
	// email delivery is disabled (webhook dispatch still applies).
	EmailMgr *email.EmailManager
	// DetectTheme resolves the active theme for a request. Injected by the
	// server package at construction time (src/server/theme.go) so this
	// package and src/server/http.go share one theme-detection
	// implementation without an import cycle (server already imports
	// handler; handler cannot import server back). Falls back to a local
	// default when unset (e.g. in tests that construct PagesHandler
	// directly without going through server.Server).
	DetectTheme func(*http.Request) string
	// ValidateTheme normalizes/validates a candidate theme value, returning
	// it unchanged when it is one of the recognized themes ("light", "dark",
	// "auto") or a safe default otherwise. Injected by the server package at
	// construction time (src/server/theme.go), same import-cycle rationale
	// as DetectTheme. Used by the preferences import endpoint to validate
	// the untrusted "theme" query parameter before writing the cookie.
	ValidateTheme func(string) string
	// CSRFToken resolves the CSRF token to embed in server-rendered forms.
	// Injected by the server package at construction time
	// (server.GetCSRFToken, src/server/middleware_csrf.go) so this package
	// can read the context value CSRFMiddleware sets for a request whose
	// csrf_token cookie was only just minted on THIS response (the request
	// itself never carried it) — same import-cycle rationale as DetectTheme.
	// Falls back to the request cookie when unset (e.g. tests constructing
	// PagesHandler directly).
	CSRFToken func(*http.Request) string
}

// contactThrottle rate-limits /server/contact submissions per client IP so a
// single sender can't flood the configured recipients (AI.md PART 12:
// general/abuse roles are "spam-filtered before dispatch"). This is a simple
// per-IP cooldown, not content-based spam filtering.
var contactThrottle = struct {
	mu   sync.Mutex
	last map[string]time.Time
}{last: make(map[string]time.Time)}

// contactThrottleWindow is the minimum time between accepted submissions
// from the same client IP.
const contactThrottleWindow = 60 * time.Second

// allowContactSubmission reports whether a submission from ip should be
// accepted, recording the attempt either way.
func allowContactSubmission(ip string) bool {
	contactThrottle.mu.Lock()
	defer contactThrottle.mu.Unlock()
	if t, ok := contactThrottle.last[ip]; ok && time.Since(t) < contactThrottleWindow {
		return false
	}
	contactThrottle.last[ip] = time.Now()
	return true
}

// NewPagesHandler creates a new PagesHandler with the provided renderer and trust resolver.
func NewPagesHandler(version, buildDate string, trust *netutil.TrustResolver, render func(http.ResponseWriter, *http.Request, string, interface{}) error) *PagesHandler {
	return &PagesHandler{
		Version:   version,
		BuildDate: buildDate,
		Trust:     trust,
		Render:    render,
	}
}

// PageData is the template context for simple public pages.
type PageData struct {
	Lang         string
	Dir          string
	Theme        string
	CanonicalURL string
	// Robots is the per-route <meta name="robots"> directive computed by
	// ResolveRobotsDirective (AI.md PART 16 "Robots Directive"). Never
	// hardcoded in a template: every route that is not explicitly public
	// fails closed to "noindex,nofollow".
	Robots    string
	CSRFToken string
	// Announcements holds active operator announcements for the site banner per AI.md PART 16.
	Announcements []config.AnnouncementMessage
	// ShowConsentBanner is true when the user has not yet acknowledged the cookie consent.
	ShowConsentBanner bool
	// ConsentMessage is the consent banner message text.
	ConsentMessage string
	// ConsentPolicyURL is the link shown in the consent banner.
	ConsentPolicyURL string
	// ConsentPolicyText is the link text shown in the consent banner.
	ConsentPolicyText string
	// ConsentDeclineText is the decline button label.
	ConsentDeclineText string
	// ConsentAcceptText is the accept button label.
	ConsentAcceptText string
	// CurrentYear is the current year for the footer copyright/build stamp row.
	CurrentYear int
	// ProjectName is the display application name from branding config
	// (AI.md PART 16 project.name); used in nav/footer/titles instead of a
	// hardcoded literal. Falls back to the app default when unset.
	ProjectName string
	// Host is the request host, used to build the curl/API example commands
	// shown on help.tmpl (mirrors the Host field DefaultHandler already sets
	// from r.Host for index.tmpl). Was previously missing from this struct
	// entirely, so help.tmpl's {{.Host}} lookups failed template execution
	// mid-render (partial output already streamed to the client, followed by
	// a raw "Internal Server Error" append from the handler's error path).
	Host string
	// Version is the running application version (footer branding row).
	Version string
	// BuildDate is the compile-time build timestamp (footer "Last update" row).
	BuildDate string
	// RepoURL is the upstream repository link (footer branding row).
	RepoURL string
	// TorEnabled is true when a Tor binary/manager is configured.
	TorEnabled bool
	// TorRunning is true when the Tor hidden service is currently running.
	TorRunning bool
	// OnionAddress is the .onion hostname, populated only when Tor is enabled and running.
	OnionAddress string
	// I2PEnabled is true when I2P is enabled and a provider is available (AI.md PART 31.2).
	I2PEnabled bool
	// I2PRunning is true when the I2P eepsite is currently running.
	I2PRunning bool
	// I2PAddress is the .b32.i2p hostname, populated only when I2P is enabled and running.
	I2PAddress string
	// ContactEmail is the resolved "general" contact role address (AI.md
	// PART 12); empty means no contact email is configured or reachable
	// (admin has none set either).
	ContactEmail string
	// SecurityEmail is the resolved "security" contact role address,
	// surfaced as the secondary/CC channel next to GitHub private
	// vulnerability reporting (AI.md PART 12).
	SecurityEmail string
	// FooterCustomHTML is the operator's sanitized footer branding HTML,
	// rendered above the Application Footer (AI.md PART 16 "Footer
	// Customization"). Empty when custom_html is unset ("") or disabled (" ").
	FooterCustomHTML template.HTML
	// FooterShowDefaultBranding is true only when custom_html is unset, so the
	// built-in "Made with" branding row renders. A custom value or the disable
	// sentinel (" ") both suppress the default branding row.
	FooterShowDefaultBranding bool
	// Privacy is a pass-through of the live privacy config, so privacy.tmpl
	// can read .Privacy.Data/.Privacy.Cookies/.Privacy.Content/etc. and call
	// its Get*/Is* methods directly (AI.md PART 16 "/server/privacy").
	Privacy *config.PrivacyConfig
	// Tracking is a pass-through of the live analytics config, so
	// privacy.tmpl's "Analytics Cookies" section can name the configured
	// provider (AI.md PART 16 "/server/privacy").
	Tracking config.TrackingConfig
	// CCPAOptedOut is true when the visitor has previously opted out of data
	// sales via the ccpa_opt_out cookie (AI.md PART 16 "/server/privacy").
	CCPAOptedOut bool
	// Code is the HTTP status code being rendered, populated only on the
	// themed error page (AI.md PART 16 "Error Pages (MUST Match Theme)");
	// zero on every other page.
	Code int
	// Title is the short status label shown next to Code on the error page
	// (e.g. "Not Found"), populated only on the themed error page.
	Title string
	// Message is the human-readable error message shown on the error page,
	// populated only on the themed error page.
	Message string
	// RequestID is the per-request correlation id shown on the error page
	// when available, populated only on the themed error page.
	RequestID string
	// Description is the resolved meta description: the operator's branding
	// description, falling back to the tagline, then the translated app
	// description (AI.md PART 24 "Where Branding Is Used").
	Description string
	// Keywords is the comma-joined server.seo.keywords list; empty when the
	// operator configured none, in which case the tag is not rendered.
	Keywords string
	// Author is server.seo.author, rendered as <meta name="author">.
	Author string
	// OGImage is the OpenGraph/Twitter card image URL (server.seo.og_image).
	OGImage string
	// TwitterHandle is the @handle credited on Twitter cards.
	TwitterHandle string
	// VerificationTags maps a <meta name="..."> attribute to its already
	// validated verification code. Built by ValidVerificationCodes, so an
	// invalid or over-length code never reaches the template (AI.md PART 24
	// "NEVER render").
	VerificationTags map[string]string
	// CustomVerificationTags holds the operator's extra verification tags,
	// already validated by ValidCustomTags.
	CustomVerificationTags []config.SEOCustomVerificationTag
}

// publicIndexableRoutes is the explicit allowlist of routes that may carry
// "index,follow" per AI.md PART 16 "Robots Directive": the homepage plus the
// informational/documentation pages. Everything else — API paths, health,
// debug, preferences, and any future admin/auth page — falls through to the
// fail-closed default. Adding a route here is a deliberate SEO decision.
var publicIndexableRoutes = map[string]bool{
	"/":               true,
	"/server/about":   true,
	"/server/help":    true,
	"/server/privacy": true,
	"/server/terms":   true,
	"/server/contact": true,
}

// ResolveRobotsDirective returns the <meta name="robots"> value for a request
// path per AI.md PART 16 "Robots Directive". Public pages get "index,follow";
// every other route — including anything under /api, /debug, /server/healthz,
// and /server/preferences — fails closed to "noindex,nofollow".
func ResolveRobotsDirective(path string) string {
	// Trailing slashes are normalized away so "/server/about/" resolves the
	// same as "/server/about"; the bare root path is preserved.
	normalized := path
	if len(normalized) > 1 {
		normalized = strings.TrimRight(normalized, "/")
		if normalized == "" {
			normalized = "/"
		}
	}
	if publicIndexableRoutes[normalized] {
		return "index,follow"
	}
	return "noindex,nofollow"
}

// getCSRFToken reads the csrf_token from the request cookie.
// The CSRF middleware always sets the cookie on GET/HEAD/OPTIONS responses,
// so it is available for templates that render forms.
func getCSRFToken(r *http.Request) string {
	c, err := r.Cookie("csrf_token")
	if err != nil {
		return ""
	}
	return c.Value
}

// dismissedAnnouncements parses the dismissed_announcements cookie into a slice of IDs.
func dismissedAnnouncements(r *http.Request) []string {
	c, err := r.Cookie("dismissed_announcements")
	if err != nil || c.Value == "" {
		return nil
	}
	var ids []string
	for _, id := range strings.Split(c.Value, ",") {
		if id = strings.TrimSpace(id); id != "" {
			ids = append(ids, id)
		}
	}
	return ids
}

// hasConsentCookie returns true when the user has already responded to the cookie consent banner.
func hasConsentCookie(r *http.Request) bool {
	c, err := r.Cookie("cookie_consent")
	return err == nil && c.Value != ""
}

// hasCCPAOptOutCookie returns true when the visitor has opted out of data
// sales via the ccpa_opt_out cookie (AI.md PART 16 "/server/privacy" CCPA
// opt-out section).
func hasCCPAOptOutCookie(r *http.Request) bool {
	c, err := r.Cookie("ccpa_opt_out")
	return err == nil && c.Value == "true"
}

// NewPageData builds a PageData for the current request.
// Canonical URL is built via netutil.BuildURL which gates proxy headers on peer trust.
// Active announcements and consent banner visibility are computed from config + cookies.
// CSRFToken is read from the request context (set by CSRFMiddleware) or from the cookie.
func (h *PagesHandler) NewPageData(r *http.Request) PageData {
	lang := i18n.DetectLocale(r)
	dir := string(i18n.LocaleDirection(lang))
	canonicalURL := netutil.BuildURL(r, h.Trust, r.URL.Path)
	theme := "dark"
	if h.DetectTheme != nil {
		theme = h.DetectTheme(r)
	} else if tc, err := r.Cookie("theme"); err == nil {
		switch tc.Value {
		case "light", "auto":
			theme = tc.Value
		}
	}
	csrfToken := getCSRFToken(r)
	if h.CSRFToken != nil {
		csrfToken = h.CSRFToken(r)
	}
	data := PageData{
		Lang:         lang,
		Dir:          dir,
		Theme:        theme,
		CanonicalURL: canonicalURL,
		Robots:       ResolveRobotsDirective(r.URL.Path),
		CSRFToken:    csrfToken,
		CurrentYear:  time.Now().Year(),
		Version:      h.Version,
		BuildDate:    h.BuildDate,
		ProjectName:  "IPGaze",
		RepoURL:      "https://github.com/apimgr/ipgaze",
		Host:         r.Host,
	}
	if h.Config != nil && h.Config.Server.Branding.Title != "" {
		data.ProjectName = h.Config.Server.Branding.Title
	}
	if h.WebUI != nil {
		data.Announcements = h.WebUI.Announcements.Active(dismissedAnnouncements(r))
	}
	if h.Privacy != nil {
		data.ShowConsentBanner = !hasConsentCookie(r)
		data.ConsentMessage = h.Privacy.GetConsentMessage()
		data.ConsentPolicyURL = h.Privacy.Consent.Policy.URL
		data.ConsentPolicyText = h.Privacy.Consent.Policy.Text
		data.ConsentDeclineText = h.Privacy.Consent.Buttons.Decline
		data.ConsentAcceptText = h.Privacy.Consent.Buttons.Accept
		data.Privacy = h.Privacy
	}
	data.CCPAOptedOut = hasCCPAOptOutCookie(r)
	if h.Config != nil {
		data.Tracking = h.Config.Server.Tracking
		// SEO metadata (AI.md PART 24 "SEO Meta Tags (Generated)"). The
		// description falls back branding.description -> branding.tagline so a
		// half-configured install still emits a meaningful og:description
		// rather than an empty attribute.
		data.Description = strings.TrimSpace(h.Config.Server.Branding.Description)
		if data.Description == "" {
			data.Description = strings.TrimSpace(h.Config.Server.Branding.Tagline)
		}
		seo := h.Config.Server.SEO
		data.Keywords = strings.Join(seo.Keywords, ", ")
		data.Author = seo.Author
		data.OGImage = seo.OGImage
		data.TwitterHandle = seo.TwitterHandle
		// Both accessors drop anything failing its documented format, so the
		// template never has to validate and can render what it is handed.
		data.VerificationTags = seo.Verification.ValidVerificationCodes()
		data.CustomVerificationTags = seo.Verification.ValidCustomTags()
	}
	if h.TorStatus != nil {
		data.TorEnabled = h.TorStatus.IsAvailable()
		data.TorRunning = h.TorStatus.IsRunning()
		if data.TorEnabled && data.TorRunning {
			// Read the hostname live from TorStatus (same source healthz uses),
			// not h.Trust.OnionAddress — that field is a one-time snapshot taken
			// in main.go via SetTrust() before the hidden service descriptor is
			// generated, so it stays empty for the process lifetime.
			data.OnionAddress = h.TorStatus.GetHostname()
		}
	}
	if h.I2PStatus != nil {
		data.I2PEnabled = h.I2PStatus.IsAvailable()
		data.I2PRunning = h.I2PStatus.IsRunning()
		if data.I2PEnabled && data.I2PRunning {
			data.I2PAddress = h.I2PStatus.GetHostname()
		}
	}
	if h.Config != nil {
		data.ContactEmail = config.ResolveContactRole(h.Config, "general").Email
		data.SecurityEmail = config.ResolveContactRole(h.Config, "security").Email
	}
	data.FooterCustomHTML, data.FooterShowDefaultBranding = ResolveFooterBranding(h.Config, data)
	return data
}

// substituteFooterVariables replaces the AI.md PART 16 "Available Footer
// Variables" placeholders in operator-supplied custom_html with live values,
// before sanitization. project_org is derived from RepoURL's path (the repo
// owner segment) rather than hardcoded, per the project's "never hardcode
// project_org" rule.
func substituteFooterVariables(html string, data PageData) string {
	projectOrg := ""
	if u, err := url.Parse(data.RepoURL); err == nil {
		if parts := strings.Split(strings.Trim(u.Path, "/"), "/"); len(parts) > 0 {
			projectOrg = parts[0]
		}
	}
	replacer := strings.NewReplacer(
		"{current_year}", fmt.Sprintf("%d", data.CurrentYear),
		"{project_name}", data.ProjectName,
		"{project_org}", projectOrg,
		"{project_version}", data.Version,
		"{build_datetime}", data.BuildDate,
		"{onion_address}", data.OnionAddress,
		"{i2p_address}", data.I2PAddress,
	)
	return replacer.Replace(html)
}

// ResolveFooterBranding maps the live web.footer.custom_html config value to
// the sanitized footer HTML and the default-branding flag per AI.md PART 16
// "Footer Customization". Reading config live keeps hot-reloaded footer edits
// in effect immediately. Semantics:
//   - "" (unset): no custom HTML, show default built-in branding row
//   - " " (disable): no custom HTML, hide default branding (Application Footer only)
//   - custom value: substitute footer variables, render sanitized HTML, hide default branding
//
// Exported so callers outside package handler (e.g. the homepage handler in
// package server, which builds its own page data struct) can compute the
// same footer fields that footer.tmpl requires on every page it is included
// on, rather than duplicating this logic.
func ResolveFooterBranding(cfg *config.AppConfig, data PageData) (template.HTML, bool) {
	if cfg == nil {
		return "", true
	}
	switch cfg.Web.Footer.CustomHTML {
	case "":
		return "", true
	case " ":
		return "", false
	default:
		substituted := substituteFooterVariables(cfg.Web.Footer.CustomHTML, data)
		sanitized, err := config.ValidateFooterHTML(substituted)
		if err != nil {
			// Entirely-disallowed input: fall back to default branding rather
			// than rendering an empty custom block with branding suppressed.
			return "", true
		}
		return template.HTML(sanitized), false
	}
}

// ServerRedirectHandler redirects /server to /server/about (301)
func (h *PagesHandler) ServerRedirectHandler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/server/about", http.StatusMovedPermanently)
}

// AboutResponse for JSON API
type AboutResponse struct {
	Name        string   `json:"name"`
	Tagline     string   `json:"tagline"`
	Description string   `json:"description"`
	Version     string   `json:"version"`
	BuildDate   string   `json:"build_date,omitempty"`
	Features    []string `json:"features"`
	Links       struct {
		Website    string `json:"website"`
		Repository string `json:"repository"`
		Docs       string `json:"docs"`
	} `json:"links"`
}

// buildAboutResponse creates about info from IDEA.md content
func (h *PagesHandler) buildAboutResponse() AboutResponse {
	version := h.Version
	if version == "" {
		version = "dev"
	}
	return AboutResponse{
		Name:        "IPGaze",
		Tagline:     "Fast, lightweight IP address lookup service",
		Description: "IPGaze is a lightweight, fast IP address lookup service that returns the visitor's public IP address along with comprehensive GeoIP information. It supports both IPv4 and IPv6 and provides multiple output formats (JSON, plain text, HTML).",
		Version:     version,
		Features: []string{
			"Full IPv4 and IPv6 support",
			"GeoIP information (country, city, region, coordinates, timezone)",
			"ASN lookup (autonomous system number and organization)",
			"Multiple output formats (JSON, plain text, HTML)",
			"CLI detection (curl, wget, HTTPie auto-detected)",
			"Specific IP address lookup via /{ip} endpoint",
			"PWA support (installable on mobile devices)",
			"OpenAPI/Swagger documentation",
			"GraphQL API support",
			"Prometheus metrics endpoint",
		},
		Links: struct {
			Website    string `json:"website"`
			Repository string `json:"repository"`
			Docs       string `json:"docs"`
		}{
			Website:    "https://ifcfg.us",
			Repository: "https://github.com/apimgr/ipgaze",
			Docs:       "https://ipgaze.readthedocs.io",
		},
	}
}

// ServerAboutHandler serves /server/about (HTML)
func (h *PagesHandler) ServerAboutHandler(w http.ResponseWriter, r *http.Request) {
	if err := h.Render(w, r, "about.tmpl", h.NewPageData(r)); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// APIV1ServerAboutHandler serves /api/v1/server/about (JSON)
func (h *PagesHandler) APIV1ServerAboutHandler(w http.ResponseWriter, r *http.Request) {
	about := h.buildAboutResponse()
	w.Header().Set("Content-Type", jsonMediaType)
	b, _ := json.MarshalIndent(about, "", "  ")
	// Write errors are unrecoverable once headers are sent; log is not actionable here.
	w.Write(b)            //nolint:errcheck
	w.Write([]byte("\n")) //nolint:errcheck
}

// ServerHelpHandler serves /server/help (HTML)
func (h *PagesHandler) ServerHelpHandler(w http.ResponseWriter, r *http.Request) {
	if err := h.Render(w, r, "help.tmpl", h.NewPageData(r)); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// HelpResponse for JSON API
type HelpResponse struct {
	Sections []HelpSection `json:"sections"`
}

// HelpSection represents a help section
type HelpSection struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Content string `json:"content"`
}

// APIV1ServerHelpHandler serves /api/v1/server/help (JSON)
func (h *PagesHandler) APIV1ServerHelpHandler(w http.ResponseWriter, r *http.Request) {
	help := HelpResponse{
		Sections: []HelpSection{
			{ID: "getting-started", Title: "Getting Started", Content: "Get your public IP with: curl https://ifcfg.us"},
			{ID: "endpoints", Title: "Endpoints", Content: "Main: /, /json, /ip, /{ip}. GeoIP: /country, /city, /asn, /coordinates. API: /api/v1/*"},
			{ID: "formats", Title: "Output Formats", Content: "Auto-detects CLI tools (curl, wget, HTTPie). Use Accept header to force format."},
			{ID: "faq", Title: "FAQ", Content: "No API key required. Supports IPv4 and IPv6. GeoIP data updated regularly."},
		},
	}
	w.Header().Set("Content-Type", jsonMediaType)
	b, _ := json.MarshalIndent(help, "", "  ")
	// Write errors are unrecoverable once headers are sent; log is not actionable here.
	w.Write(b)            //nolint:errcheck
	w.Write([]byte("\n")) //nolint:errcheck
}

// ServerPrivacyHandler serves /server/privacy (HTML)
func (h *PagesHandler) ServerPrivacyHandler(w http.ResponseWriter, r *http.Request) {
	if err := h.Render(w, r, "privacy.tmpl", h.NewPageData(r)); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// PrivacyResponse mirrors the AI.md PART 16 "/server/privacy" API example —
// a JSON view of the live server.privacy + server.tracking config, sourced
// from h.Privacy/h.Config rather than hardcoded placeholder text.
type PrivacyResponse struct {
	Summary struct {
		DataStoredOnServer bool `json:"data_stored_on_server"`
		DataSold           bool `json:"data_sold"`
		UserControl        bool `json:"user_control"`
	} `json:"summary"`
	Cookies struct {
		Essential   privacyCookieCategory `json:"essential"`
		Preferences privacyCookieCategory `json:"preferences"`
		Analytics   privacyCookieCategory `json:"analytics"`
	} `json:"cookies"`
	Data struct {
		Sold           bool                      `json:"sold"`
		StoredOnServer bool                      `json:"stored_on_server"`
		Sharing        []config.SharingCondition `json:"sharing"`
	} `json:"data"`
	Tracking struct {
		Enabled  bool   `json:"enabled"`
		Type     string `json:"type"`
		TypeName string `json:"type_name"`
	} `json:"tracking"`
	Retention struct {
		Period            string `json:"period"`
		ExportAvailable   bool   `json:"export_available"`
		DeletionAvailable bool   `json:"deletion_available"`
	} `json:"retention"`
	ThirdParty struct {
		Services []config.ThirdPartyService `json:"services"`
	} `json:"third_party"`
	CCPA struct {
		Applicable   bool   `json:"applicable"`
		OptOutURL    string `json:"opt_out_url"`
		UserOptedOut bool   `json:"user_opted_out"`
	} `json:"ccpa"`
	Content struct {
		ConsentMessage string `json:"consent_message"`
		DataUsage      string `json:"data_usage"`
	} `json:"content"`
}

// privacyCookieCategory is the JSON shape of a single cookie category entry.
type privacyCookieCategory struct {
	Enabled     bool   `json:"enabled"`
	Description string `json:"description"`
}

// APIV1ServerPrivacyHandler serves /api/{api_version}/server/privacy (JSON).
func (h *PagesHandler) APIV1ServerPrivacyHandler(w http.ResponseWriter, r *http.Request) {
	var privacy PrivacyResponse
	privacy.Summary.UserControl = true
	if h.Privacy != nil {
		p := h.Privacy
		privacy.Summary.DataStoredOnServer = p.Data.StoredOnServer
		privacy.Summary.DataSold = p.Data.Sold

		privacy.Cookies.Essential = privacyCookieCategory{Enabled: p.Cookies.Essential.Enabled, Description: p.Cookies.Essential.Description}
		privacy.Cookies.Preferences = privacyCookieCategory{Enabled: p.Cookies.Preferences.Enabled, Description: p.Cookies.Preferences.Description}
		privacy.Cookies.Analytics = privacyCookieCategory{Enabled: p.Cookies.Analytics.Enabled, Description: p.GetAnalyticsDescription()}

		privacy.Data.Sold = p.Data.Sold
		privacy.Data.StoredOnServer = p.Data.StoredOnServer
		privacy.Data.Sharing = p.Data.Sharing
		if privacy.Data.Sharing == nil {
			privacy.Data.Sharing = []config.SharingCondition{}
		}

		privacy.Retention.Period = p.Retention.Period
		privacy.Retention.ExportAvailable = p.Retention.ExportAvailable
		privacy.Retention.DeletionAvailable = p.Retention.DeletionAvailable

		privacy.ThirdParty.Services = p.ThirdParty.Services
		if privacy.ThirdParty.Services == nil {
			privacy.ThirdParty.Services = []config.ThirdPartyService{}
		}

		privacy.CCPA.Applicable = p.IsCCPAApplicable()
		privacy.CCPA.OptOutURL = "/server/privacy#ccpa-opt-out"
		privacy.CCPA.UserOptedOut = hasCCPAOptOutCookie(r)

		privacy.Content.ConsentMessage = p.GetConsentMessage()
		privacy.Content.DataUsage = p.GetDataUsageContent()
	} else {
		privacy.Data.Sharing = []config.SharingCondition{}
		privacy.ThirdParty.Services = []config.ThirdPartyService{}
		privacy.CCPA.OptOutURL = "/server/privacy#ccpa-opt-out"
	}
	if h.Config != nil {
		t := h.Config.Server.Tracking
		privacy.Tracking.Enabled = t.Type != "" && t.Type != "none"
		privacy.Tracking.Type = t.Type
		privacy.Tracking.TypeName = t.TypeName()
	}

	w.Header().Set("Content-Type", jsonMediaType)
	b, _ := json.MarshalIndent(privacy, "", "  ")
	// Write errors are unrecoverable once headers are sent; log is not actionable here.
	w.Write(b)            //nolint:errcheck
	w.Write([]byte("\n")) //nolint:errcheck
}

// ServerContactHandler serves /server/contact (GET) and accepts POST submissions.
// Submissions are dispatched to the "general" contact role's configured
// email + webhooks per AI.md PART 12.
func (h *PagesHandler) ServerContactHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err == nil {
			req := ContactRequest{
				Name:    strings.TrimSpace(r.FormValue("name")),
				Email:   strings.TrimSpace(r.FormValue("email")),
				Subject: strings.TrimSpace(r.FormValue("subject")),
				Message: strings.TrimSpace(r.FormValue("message")),
			}
			if req.Email != "" && req.Message != "" && allowContactSubmission(clientIP(r)) {
				h.dispatchContactSubmission(req)
			}
		}
		http.Redirect(w, r, "/server/contact", http.StatusSeeOther)
		return
	}
	if err := h.Render(w, r, "contact.tmpl", h.NewPageData(r)); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// ContactRequest for POST submissions
type ContactRequest struct {
	Name    string `json:"name"`
	Email   string `json:"email"`
	Subject string `json:"subject"`
	Message string `json:"message"`
}

// ContactResponse for JSON API
type ContactResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// APIV1ServerContactHandler handles POST /api/v1/server/contact
func (h *PagesHandler) APIV1ServerContactHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", jsonMediaType)
		w.WriteHeader(http.StatusMethodNotAllowed)
		resp := ContactResponse{Success: false, Message: i18n.T(r.Context(), "errors.method_not_allowed")}
		b, _ := json.MarshalIndent(resp, "", "  ")
		// Write errors are unrecoverable once headers are sent; log is not actionable here.
		w.Write(b)            //nolint:errcheck
		w.Write([]byte("\n")) //nolint:errcheck
		return
	}

	var req ContactRequest
	// A malformed/empty body just yields a zero-value req, caught by the
	// validation check below — no separate decode-error branch needed.
	_ = json.NewDecoder(r.Body).Decode(&req)
	req.Name = strings.TrimSpace(req.Name)
	req.Email = strings.TrimSpace(req.Email)
	req.Subject = strings.TrimSpace(req.Subject)
	req.Message = strings.TrimSpace(req.Message)

	var response ContactResponse
	status := http.StatusOK
	switch {
	case req.Email == "" || req.Message == "":
		response = ContactResponse{Success: false, Message: i18n.T(r.Context(), "errors.bad_request")}
		status = http.StatusBadRequest
	case !allowContactSubmission(clientIP(r)):
		response = ContactResponse{Success: false, Message: i18n.T(r.Context(), "errors.rate_limited")}
		status = http.StatusTooManyRequests
	default:
		h.dispatchContactSubmission(req)
		response = ContactResponse{Success: true, Message: i18n.T(r.Context(), "contact.success")}
	}

	w.Header().Set("Content-Type", jsonMediaType)
	w.WriteHeader(status)
	b, _ := json.MarshalIndent(response, "", "  ")
	// Write errors are unrecoverable once headers are sent; log is not actionable here.
	w.Write(b)            //nolint:errcheck
	w.Write([]byte("\n")) //nolint:errcheck
}

// clientIP extracts the request's remote IP (without port) for the contact
// throttle key. This is a plain RemoteAddr read, not the trust-aware
// resolver used for GeoIP/rate-limit decisions elsewhere — sufficient for a
// best-effort per-sender cooldown.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// dispatchContactSubmission resolves the "general" contact role (AI.md PART
// 12) and sends req to its configured webhooks and, if SMTP is enabled, its
// email address. Webhook sends happen asynchronously in notify.Dispatch;
// email is sent synchronously but its result is not surfaced to the
// submitter, since the form submission itself has already succeeded from
// their perspective.
func (h *PagesHandler) dispatchContactSubmission(req ContactRequest) {
	if h.Config == nil {
		return
	}
	resolved := config.ResolveContactRole(h.Config, "general")
	appURL := "https://" + h.Config.Server.FQDN
	userAgent := fmt.Sprintf("%s/%s (+%s)", h.Config.Server.Branding.Title, h.Version, appURL)

	subject := req.Subject
	if subject == "" {
		subject = "Contact form submission"
	}
	body := fmt.Sprintf("From: %s <%s>\n\n%s", req.Name, req.Email, req.Message)

	notify.Dispatch(notify.DispatchTargets{
		Telegram:   notify.WebhookTarget{URL: resolved.Telegram, Secret: resolved.TelegramSecret},
		Discord:    notify.WebhookTarget{URL: resolved.Discord, Secret: resolved.DiscordSecret},
		Slack:      notify.WebhookTarget{URL: resolved.Slack, Secret: resolved.SlackSecret},
		Mattermost: notify.WebhookTarget{URL: resolved.Mattermost, Secret: resolved.MattermostSecret},
		Pushover:   notify.WebhookTarget{URL: resolved.Pushover, Secret: resolved.PushoverSecret},
		Gotify:     notify.WebhookTarget{URL: resolved.Gotify, Secret: resolved.GotifySecret},
		Generic:    notify.WebhookTarget{URL: resolved.Generic, Secret: resolved.GenericSecret},
	}, notify.Event{
		Name:           "contact.general_submitted",
		Subject:        subject,
		Body:           body,
		Level:          notify.LevelInfo,
		UserAgent:      userAgent,
		Role:           "general",
		ProjectName:    h.Config.Server.Branding.Title,
		ProjectVersion: h.Version,
		AppURL:         appURL,
	})

	if resolved.Email != "" && h.EmailMgr != nil && h.EmailMgr.IsEnabled() {
		_ = h.EmailMgr.SendDirect(&email.Message{
			To:      []string{resolved.Email},
			Subject: subject,
			Body:    body,
		})
	}
}

// ServerTermsHandler serves /server/terms (HTML)
func (h *PagesHandler) ServerTermsHandler(w http.ResponseWriter, r *http.Request) {
	if err := h.Render(w, r, "terms.tmpl", h.NewPageData(r)); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// TermsResponse for JSON API
type TermsResponse struct {
	Sections []struct {
		Title   string `json:"title"`
		Content string `json:"content"`
	} `json:"sections"`
	LastUpdated string `json:"last_updated"`
}

// APIV1ServerTermsHandler serves /api/v1/server/terms (JSON)
func (h *PagesHandler) APIV1ServerTermsHandler(w http.ResponseWriter, r *http.Request) {
	terms := TermsResponse{
		LastUpdated: "2024",
		Sections: []struct {
			Title   string `json:"title"`
			Content string `json:"content"`
		}{
			{Title: "Acceptance of Terms", Content: "By using IPGaze, you agree to these terms."},
			{Title: "Service Description", Content: "IP address lookup including GeoIP and ASN information. Provided as-is."},
			{Title: "Acceptable Use", Content: "No illegal use, no service disruption, no excessive automated requests."},
			{Title: "Rate Limiting", Content: "Rate limiting may be applied to ensure fair access."},
			{Title: "Data Accuracy", Content: "GeoIP data is informational only, accuracy not guaranteed."},
			{Title: "Limitation of Liability", Content: "Not liable for damages from use or inability to use service."},
			{Title: "Changes to Terms", Content: "Terms may be updated; continued use constitutes acceptance."},
			{Title: "Open Source", Content: "Released under MIT license."},
		},
	}

	w.Header().Set("Content-Type", jsonMediaType)
	b, _ := json.MarshalIndent(terms, "", "  ")
	// Write errors are unrecoverable once headers are sent; log is not actionable here.
	w.Write(b)            //nolint:errcheck
	w.Write([]byte("\n")) //nolint:errcheck
}

// safeRedirectTarget validates a client-supplied redirect target (e.g. from the Referer
// header) and returns it only if it is a same-origin relative path, preventing open
// redirect attacks. Falls back to "/" for anything absolute, protocol-relative, or
// pointing at a different host.
func safeRedirectTarget(r *http.Request, target string) string {
	if target == "" {
		return "/"
	}
	// Reject protocol-relative URLs ("//evil.com") and anything not starting with "/".
	if !strings.HasPrefix(target, "/") || strings.HasPrefix(target, "//") {
		return "/"
	}
	u, err := url.Parse(target)
	if err != nil {
		return "/"
	}
	// A bare relative path has no Host component; only allow an explicit Host if it
	// matches the current request's Host exactly.
	if u.Host != "" && u.Host != r.Host {
		return "/"
	}
	out := u.Path
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	return out
}

// ConsentHandler handles POST /server/consent — records the user's cookie consent choice.
// This is the no-JS fallback path (AI.md PART 16 "Cookie Consent Banner"): JS clients write
// the cookie_consent cookie directly via document.cookie (writeConsentCookie in app.js) and
// never hit this endpoint. The value is a JSON object of granular categories + timestamp,
// matching the client-side shape exactly, stored in a first-party "cookie_consent" cookie
// (1-year expiry, SameSite=Lax). HttpOnly is false so the same client-side JS can also read it.
func (h *PagesHandler) ConsentHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	choice := r.FormValue("choice")
	if choice != "accept" && choice != "decline" {
		choice = "decline"
	}
	accepted := choice == "accept"
	consent := struct {
		Essential   bool  `json:"essential"`
		Preferences bool  `json:"preferences"`
		Analytics   bool  `json:"analytics"`
		Timestamp   int64 `json:"timestamp"`
	}{
		Essential:   true,
		Preferences: accepted,
		Analytics:   accepted,
		Timestamp:   time.Now().UnixMilli(),
	}
	value, err := json.Marshal(consent)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	// URL-encode the JSON so it satisfies RFC 6265 cookie-value grammar (no raw
	// '"'/'{'/'}'), matching the encodeURIComponent() the client-side
	// writeConsentCookie() JS uses for the same cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     "cookie_consent",
		Value:    url.QueryEscape(string(value)),
		Path:     "/",
		MaxAge:   365 * 24 * 60 * 60,
		HttpOnly: false,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})
	// PRG redirect for no-JS browser form submissions (Accept: text/html).
	// JS fetch does not set text/html in Accept, so it receives 204 and handles the UI update.
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		ref := safeRedirectTarget(r, r.Referer())
		http.Redirect(w, r, ref, http.StatusSeeOther)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// CCPAHandler handles POST /server/ccpa — records the visitor's CCPA
// "Do Not Sell My Personal Information" choice (AI.md PART 16
// "/server/privacy" CCPA opt-out section). The value is stored in a
// first-party "ccpa_opt_out" cookie (1-year expiry, SameSite=Lax).
// JS path: responds 204 No Content so app.js can update the UI without a
// page reload. No-JS path: detects text/html Accept header and redirects
// (PRG pattern) back to referrer, mirroring ConsentHandler/ServerPreferencesUpdateHandler.
func (h *PagesHandler) CCPAHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	choice := r.FormValue("choice")
	optedOut := "false"
	if choice == "opt-out" {
		optedOut = "true"
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "ccpa_opt_out",
		Value:    optedOut,
		Path:     "/",
		MaxAge:   365 * 24 * 60 * 60,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		ref := safeRedirectTarget(r, r.Referer())
		http.Redirect(w, r, ref, http.StatusSeeOther)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// NextTheme returns the next mode in the cycle: dark -> light -> auto -> dark
// (AI.md PART 16 "Theme Toggle" -> "Theme Cycle Logic"). It is called when
// rendering the toggle so the form's target is always derived from the theme
// actually in effect for this request, never a fixed value — a hardcoded
// target only works for the first click and then resubmits the same mode.
func NextTheme(current string) string {
	switch current {
	case "dark":
		return "light"
	case "light":
		return "auto"
	default:
		return "dark"
	}
}

// ServerPreferencesUpdateHandler handles POST /server/preferences — the theme
// toggle's form target (AI.md PART 16 "Theme Toggle" -> "HTML Structure").
// The toggle is a real form submit, so switching works identically with and
// without JavaScript; the JS enhancement intercepts the submit only to avoid
// a full page reload.
func (h *PagesHandler) ServerPreferencesUpdateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	theme := r.FormValue("theme")
	switch theme {
	case "light", "dark", "auto":
		// valid
	default:
		theme = "dark"
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "theme",
		Value:    theme,
		Path:     "/",
		MaxAge:   365 * 24 * 60 * 60,
		HttpOnly: false,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})
	ref := safeRedirectTarget(r, r.Referer())
	http.Redirect(w, r, ref, http.StatusSeeOther)
}

// =============================================================================
// Client-side preference export/import (AI.md PART 16 "Client-Side
// Preferences" -> "Cross-device preference sync"). Stateless: only the
// theme/lang cookies feed the export, and import decodes -> validates ->
// sets cookies -> redirects in the one request. No DB row, no preferences
// table. cookie_consent, ccpa_opt_out, and {project_name}_build are NEVER
// exportable/importable through this feature.
// =============================================================================

// currentTheme resolves the visitor's active theme the same way NewPageData
// does, defaulting to "dark" when DetectTheme was never injected (e.g. tests
// constructing PagesHandler directly).
func (h *PagesHandler) currentTheme(r *http.Request) string {
	if h.DetectTheme != nil {
		return h.DetectTheme(r)
	}
	return "dark"
}

// PreferencesPageData extends PageData with the export link/code for
// preferences.tmpl. The visitor's current theme/lang are already available
// via the embedded PageData.Theme/.Lang (same values NewPageData resolves
// them to), so this only adds what PageData doesn't already carry.
type PreferencesPageData struct {
	PageData
	PreferencesExportURL  string
	PreferencesExportCode string
}

// ServerPreferencesHandler serves GET /server/preferences — a minimal
// server-rendered page showing the visitor's current theme/lang and a link
// to the export action (No-JS-first: the export link/copy button works
// without JavaScript; JS only adds copy-to-clipboard convenience).
func (h *PagesHandler) ServerPreferencesHandler(w http.ResponseWriter, r *http.Request) {
	base := h.NewPageData(r)
	export := h.buildPreferencesExport(r)
	data := PreferencesPageData{
		PageData:              base,
		PreferencesExportURL:  export.URL,
		PreferencesExportCode: export.Code,
	}
	if err := h.Render(w, r, "preferences.tmpl", data); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// PreferencesResponse is the JSON shape for GET
// /api/{api_version}/server/preferences.
type PreferencesResponse struct {
	Theme      string `json:"theme"`
	Lang       string `json:"lang"`
	ExportURL  string `json:"export_url"`
	ExportCode string `json:"export_code"`
}

// APIV1ServerPreferencesHandler serves /api/{api_version}/server/preferences (JSON).
func (h *PagesHandler) APIV1ServerPreferencesHandler(w http.ResponseWriter, r *http.Request) {
	export := h.buildPreferencesExport(r)
	SendAPIResponseOK(w, PreferencesResponse{
		Theme:      export.Theme,
		Lang:       export.Lang,
		ExportURL:  export.URL,
		ExportCode: export.Code,
	}, nil)
}

// preferencesExport holds the two representations of the visitor's
// exportable preferences (theme + lang only), shared by the web export page
// and its JSON API mirror.
type preferencesExport struct {
	Theme string
	Lang  string
	URL   string
	Code  string
}

// buildPreferencesExport reads the visitor's current theme/lang cookies and
// renders both the full import URL and its base64url-encoded short code
// (AI.md PART 16 "Cross-device preference sync").
func (h *PagesHandler) buildPreferencesExport(r *http.Request) preferencesExport {
	theme := h.currentTheme(r)
	lang := i18n.DetectLocale(r)
	query := url.Values{"theme": {theme}, "lang": {lang}}.Encode()
	fullURL := netutil.BuildURL(r, h.Trust, "/server/preferences/import?"+query)
	code := base64.RawURLEncoding.EncodeToString([]byte(query))
	return preferencesExport{Theme: theme, Lang: lang, URL: fullURL, Code: code}
}

// ServerPreferencesExportHandler serves GET /server/preferences/export — the
// same preferences.tmpl page as ServerPreferencesHandler (it already shows
// the export URL/code), so a direct link to the export sub-route lands on
// working, No-JS-first content rather than a JSON-only response (AI.md PART
// 16 "Cross-device preference sync" -> "Export").
func (h *PagesHandler) ServerPreferencesExportHandler(w http.ResponseWriter, r *http.Request) {
	h.ServerPreferencesHandler(w, r)
}

// APIV1ServerPreferencesExportHandler serves
// /api/{api_version}/server/preferences/export (JSON).
func (h *PagesHandler) APIV1ServerPreferencesExportHandler(w http.ResponseWriter, r *http.Request) {
	export := h.buildPreferencesExport(r)
	SendAPIResponseOK(w, PreferencesResponse{
		Theme:      export.Theme,
		Lang:       export.Lang,
		ExportURL:  export.URL,
		ExportCode: export.Code,
	}, nil)
}

// decodePreferencesCode decodes a base64url short code produced by
// buildPreferencesExport back into its theme/lang query values. Returns an
// empty url.Values on any decode failure — malformed codes are simply
// treated as carrying no preferences to import, never a hard error.
func decodePreferencesCode(code string) url.Values {
	raw, err := base64.RawURLEncoding.DecodeString(code)
	if err != nil {
		return url.Values{}
	}
	values, err := url.ParseQuery(string(raw))
	if err != nil {
		return url.Values{}
	}
	return values
}

// resolvePreferencesImport reads theme/lang from the request's explicit
// query params, falling back to a "code" param (a pasted short code, or the
// same short code with the full import URL prefix still attached — the
// import form strips that prefix client-side, but the server also tolerates
// it since url.ParseQuery on the trailing query string still works). Each
// value is validated against its normal allowlist; unknown/malformed values
// are dropped rather than defaulted, so an import never silently forces a
// theme/lang the visitor didn't ask for.
func (h *PagesHandler) resolvePreferencesImport(r *http.Request) (theme, lang string) {
	q := r.URL.Query()
	if code := strings.TrimSpace(q.Get("code")); code != "" {
		if idx := strings.LastIndex(code, "?"); idx != -1 {
			code = code[idx+1:]
		}
		decoded := decodePreferencesCode(code)
		if q.Get("theme") == "" && decoded.Get("theme") != "" {
			q.Set("theme", decoded.Get("theme"))
		}
		if q.Get("lang") == "" && decoded.Get("lang") != "" {
			q.Set("lang", decoded.Get("lang"))
		}
	}
	if candidate := q.Get("theme"); candidate != "" && h.ValidateTheme != nil {
		// ValidateTheme normalizes to a safe default ("dark") for anything
		// outside its enum, so a round-trip match confirms the candidate was
		// already one of the three recognized values — the only signal
		// ValidateTheme exposes for "valid vs. dropped".
		if normalized := h.ValidateTheme(candidate); normalized == candidate {
			theme = normalized
		}
	}
	if candidate := q.Get("lang"); candidate != "" && i18n.IsSupported(candidate) {
		lang = candidate
	}
	return theme, lang
}

// ServerPreferencesImportHandler handles GET /server/preferences/import —
// decodes/validates the theme/lang query params (or a "code" short code),
// sets the matching first-party cookies for whichever values validated, and
// 303-redirects to referrer or "/" so the values never linger in the
// visible URL/history (AI.md PART 16 "Cross-device preference sync" ->
// "Import"). Invalid/unknown values are silently dropped, never a hard
// error — an untrusted query param is not grounds for a 400 on a plain link
// click.
func (h *PagesHandler) ServerPreferencesImportHandler(w http.ResponseWriter, r *http.Request) {
	theme, lang := h.resolvePreferencesImport(r)
	secure := r.TLS != nil
	if theme != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     "theme",
			Value:    theme,
			Path:     "/",
			MaxAge:   365 * 24 * 60 * 60,
			HttpOnly: false,
			SameSite: http.SameSiteLaxMode,
			Secure:   secure,
		})
	}
	if lang != "" {
		i18n.SetLangCookie(w, r, lang)
	}
	ref := safeRedirectTarget(r, r.Referer())
	http.Redirect(w, r, ref, http.StatusSeeOther)
}

// PreferencesImportResponse is the JSON shape for GET
// /api/{api_version}/server/preferences/import — confirms which values were
// actually applied (empty string means the corresponding param was missing,
// unknown, or malformed and was dropped).
type PreferencesImportResponse struct {
	Theme string `json:"theme"`
	Lang  string `json:"lang"`
}

// APIV1ServerPreferencesImportHandler serves
// /api/{api_version}/server/preferences/import (JSON). Unlike the web path
// it does not redirect — it sets whichever cookies validated and returns a
// JSON confirmation of what was applied.
func (h *PagesHandler) APIV1ServerPreferencesImportHandler(w http.ResponseWriter, r *http.Request) {
	theme, lang := h.resolvePreferencesImport(r)
	secure := r.TLS != nil
	if theme != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     "theme",
			Value:    theme,
			Path:     "/",
			MaxAge:   365 * 24 * 60 * 60,
			HttpOnly: false,
			SameSite: http.SameSiteLaxMode,
			Secure:   secure,
		})
	}
	if lang != "" {
		i18n.SetLangCookie(w, r, lang)
	}
	SendAPIResponseOK(w, PreferencesImportResponse{Theme: theme, Lang: lang}, nil)
}

// DismissAnnouncementHandler handles POST /announcements/dismiss.
// Appends the given announcement ID to the "dismissed_announcements" cookie.
// JS path: responds 204 No Content so JS can remove the banner without a page reload.
// No-JS path: detects text/html Accept header and redirects (PRG pattern) back to referrer.
func (h *PagesHandler) DismissAnnouncementHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimSpace(r.FormValue("id"))
	if id == "" {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	existing := dismissedAnnouncements(r)
	alreadyDismissed := false
	for _, ex := range existing {
		if ex == id {
			alreadyDismissed = true
			break
		}
	}
	if !alreadyDismissed {
		existing = append(existing, id)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "dismissed_announcements",
		Value:    strings.Join(existing, ","),
		Path:     "/",
		MaxAge:   365 * 24 * 60 * 60,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})
	// PRG redirect for no-JS browser form submissions (Accept: text/html).
	// JS fetch does not set text/html in Accept, so it receives 204 and handles the UI update.
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		ref := safeRedirectTarget(r, r.Referer())
		http.Redirect(w, r, ref, http.StatusSeeOther)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
