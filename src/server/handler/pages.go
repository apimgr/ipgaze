// Package handler contains HTTP handlers organized by domain
// Per AI.md: handler/ for HTTP request handlers, route handlers, request/response logic
package handler

import (
	"context"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	i18n "github.com/apimgr/ipgaze/src/common/i18n"
	"github.com/apimgr/ipgaze/src/common/urlutil"
	"github.com/apimgr/ipgaze/src/config"
	"github.com/apimgr/ipgaze/src/email"
	"github.com/apimgr/ipgaze/src/netutil"
	"github.com/apimgr/ipgaze/src/notify"
	"github.com/apimgr/ipgaze/src/pgp"
	"github.com/apimgr/ipgaze/src/security"
	"github.com/apimgr/ipgaze/src/tor"
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
	CSRFToken        func(*http.Request) string
	MCPEnabled       bool
	MCPTools         func(*http.Request) []MCPToolDescription
	PGPKeyAvailable  func() bool
	PGPFingerprint   func() string
	DB               *sql.DB
	PGPPublicKeyPath string
	SecurityLogger   func(message, ip string)
	CommitID         string
}

// MCPToolDescription is the public name and description of a registered MCP tool.
type MCPToolDescription struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// MCPHelpResponse is the information required to connect an MCP client.
type MCPHelpResponse struct {
	Enabled bool     `json:"enabled"`
	URL     string   `json:"url"`
	Aliases []string `json:"aliases"`
	Auth    struct {
		Scheme string `json:"scheme"`
	} `json:"auth"`
	Tools   []MCPToolDescription `json:"tools"`
	Project string               `json:"project"`
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

// contactThrottleMaxEntries bounds the per-IP timestamp map. The endpoint is
// unauthenticated, so without a ceiling a spoofed-source flood would grow the
// map without limit; past this size expired entries are swept before insert.
const contactThrottleMaxEntries = 4096

// allowContactSubmission reports whether a submission from ip should be
// accepted, recording the attempt either way.
func allowContactSubmission(ip string) bool {
	contactThrottle.mu.Lock()
	defer contactThrottle.mu.Unlock()
	if t, ok := contactThrottle.last[ip]; ok && time.Since(t) < contactThrottleWindow {
		return false
	}
	if len(contactThrottle.last) >= contactThrottleMaxEntries {
		for k, t := range contactThrottle.last {
			if time.Since(t) >= contactThrottleWindow {
				delete(contactThrottle.last, k)
			}
		}
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
	Lang          string
	Dir           string
	RequestPath   string
	Theme         string
	DefaultWidget string
	CanonicalURL  string
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
	// About contains project-specific application identity, version and links.
	About AboutResponse
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
	// BaseURL is the request-aware origin used by copyable help examples.
	BaseURL                  string
	MCPEnabled               bool
	PGPKeyAvailable          bool
	SecurityReportMode       bool
	SecurityID               string
	SecurityReportSubmitted  bool
	SecurityReportTrackingID string
	CaptchaQuestion          string
	CaptchaToken             string
	CaptchaProvider          string
	CaptchaSiteKey           string
	ContactError             string
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
	// AbuseEmail is server.contact.abuse.email, falling back only to
	// server.contact.general.email — never to admin (AI.md PART 16
	// "/server/contact" Abuse Reports section explicitly forbids ever
	// rendering server.contact.admin.email on this page, so this field is
	// resolved directly here rather than via ResolveContactRole("abuse"),
	// whose fallback chain also includes admin). Empty when neither is set.
	AbuseEmail string
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
	// AnalyticsEnabled is true only when analytics is configured, consent allows
	// it, the request is not CCPA-opted-out, and CSP permits its script source.
	AnalyticsEnabled bool
	// AnalyticsNoScript is true when the consented Simple Analytics fallback
	// pixel is permitted by the effective img-src policy.
	AnalyticsNoScript bool
	// AnalyticsScriptURL is passed to the same-origin loader as data only; the
	// loader requests it after the server has checked consent and CSP policy.
	AnalyticsScriptURL string
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
	"/":                       true,
	"/server/about":           true,
	"/server/help":            true,
	"/server/privacy":         true,
	"/server/terms":           true,
	"/server/contact":         true,
	"/server/dpo":             true,
	"/server/security":        true,
	"/server/security/policy": true,
	"/server/security/thanks": true,
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

// formatUserTimestamp formats build timestamps with the user-facing format in AI.md PART 16.
func formatUserTimestamp(value string) string {
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.In(time.Local).Format("January 02, 2006 at 15:04:05 MST")
		}
	}
	return value
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
		Lang:          lang,
		Dir:           dir,
		RequestPath:   r.URL.Path,
		Theme:         theme,
		DefaultWidget: lookupWidgetPreference(r),
		CanonicalURL:  canonicalURL,
		Robots:        ResolveRobotsDirective(r.URL.Path),
		CSRFToken:     csrfToken,
		CurrentYear:   time.Now().Year(),
		Version:       h.Version,
		BuildDate:     formatUserTimestamp(h.BuildDate),
		ProjectName:   "IPGaze",
		RepoURL:       "https://github.com/apimgr/ipgaze",
		Host:          r.Host,
		BaseURL:       strings.TrimSuffix(netutil.BuildURL(r, h.Trust, ""), "/"),
		MCPEnabled:    h.MCPEnabled,
	}
	if h.PGPKeyAvailable != nil {
		data.PGPKeyAvailable = h.PGPKeyAvailable()
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
		data.AnalyticsEnabled, data.AnalyticsScriptURL = h.analyticsTracking(r)
		data.AnalyticsNoScript = data.AnalyticsEnabled && h.analyticsNoScriptAllowed(r)
		data.CaptchaProvider = h.contactCaptchaProvider(r)
		if data.CaptchaProvider != "simple" {
			data.CaptchaSiteKey = h.Config.Pages.Contact.CaptchaSiteKey
		}
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
		abuse := h.Config.Server.Contact.Abuse.Email
		if abuse == "" {
			abuse = h.Config.Server.Contact.General.Email
		}
		data.AbuseEmail = abuse
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
	name := "IPGaze"
	tagline := "Fast, lightweight IP address lookup service"
	description := "IPGaze is a lightweight, fast IP address lookup service that returns the visitor's public IP address along with comprehensive GeoIP information. It supports both IPv4 and IPv6 and provides multiple output formats (JSON, plain text, HTML)."
	if h.Config != nil {
		branding := h.Config.Server.Branding
		if branding.Title != "" {
			name = branding.Title
		}
		if branding.Tagline != "" {
			tagline = branding.Tagline
		}
		if branding.Description != "" {
			description = branding.Description
		}
	}
	return AboutResponse{
		Name:        name,
		Tagline:     tagline,
		Description: description,
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

// ServerAboutHandler serves /server/about under the PART 14 frontend dispatch.
func (h *PagesHandler) ServerAboutHandler(w http.ResponseWriter, r *http.Request) {
	about := h.buildAboutResponse()
	page := h.NewPageData(r)
	page.Version = about.Version
	page.About = about
	h.renderNegotiated(w, r, "about.tmpl", page, about)
}

// APIV1ServerAboutHandler serves /api/v1/server/about (JSON)
func (h *PagesHandler) APIV1ServerAboutHandler(w http.ResponseWriter, r *http.Request) {
	about := h.buildAboutResponse()
	SendAPIResponseOK(w, about, nil)
}

// ServerHelpHandler serves /server/help under the PART 14 frontend dispatch.
func (h *PagesHandler) ServerHelpHandler(w http.ResponseWriter, r *http.Request) {
	h.renderNegotiated(w, r, "help.tmpl", h.NewPageData(r), buildHelpResponse())
}

// ServerMCPHelpHandler serves the MCP connection guide only while MCP is enabled.
func (h *PagesHandler) ServerMCPHelpHandler(w http.ResponseWriter, r *http.Request) {
	if !h.MCPEnabled {
		h.renderErrorPage(w, r, http.StatusNotFound, i18n.T(r.Context(), "errors.not_found"))
		return
	}
	response := h.buildMCPHelpResponse(r)
	data := struct {
		PageData
		MCPHelpResponse
	}{PageData: h.NewPageData(r), MCPHelpResponse: response}
	h.renderNegotiated(w, r, "help_mcp.tmpl", data, response)
}

// APIV1ServerMCPHelpHandler serves the MCP connection guide as a JSON envelope.
func (h *PagesHandler) APIV1ServerMCPHelpHandler(w http.ResponseWriter, r *http.Request) {
	if !h.MCPEnabled {
		SendAPIResponseError(w, http.StatusNotFound, "NOT_FOUND", i18n.T(r.Context(), "errors.not_found"), nil)
		return
	}
	SendAPIResponseOK(w, h.buildMCPHelpResponse(r), nil)
}

func (h *PagesHandler) buildMCPHelpResponse(r *http.Request) MCPHelpResponse {
	baseURL := netutil.BuildURL(r, h.Trust, "")
	tools := []MCPToolDescription{}
	if h.MCPTools != nil {
		tools = h.MCPTools(r)
	}
	response := MCPHelpResponse{
		Enabled: true,
		URL:     baseURL + "/api/v1/server/mcp",
		Aliases: []string{baseURL + "/api/mcp", baseURL + "/mcp"},
		Tools:   tools,
		Project: "IPGaze provides public IP detection and IPv4/IPv6 lookups. GeoIP details depend on the databases enabled on this server.\n\nExample prompts:\n- What is my public IP address?\n- Look up 8.8.8.8 and summarize its GeoIP data.\n- Which ASN announces 1.1.1.1?",
	}
	response.Auth.Scheme = "Bearer"
	return response
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

// buildHelpResponse returns the help sections shared by the /server/help page
// dispatch and its /api/{api_version}/server/help JSON twin.
func buildHelpResponse() HelpResponse {
	return HelpResponse{
		Sections: []HelpSection{
			{ID: "getting-started", Title: "Getting Started", Content: "Get your public IP with: curl https://ifcfg.us"},
			{ID: "features", Title: "Features", Content: "Look up the requesting IP at /ip or /json, choose IPv4 or IPv6 with curl -4 or curl -6, and look up a specific address with /8.8.8.8/json. GeoIP fields are included when the server has its optional GeoIP databases."},
			{ID: "endpoints", Title: "Endpoints", Content: "Main: /, /json, /ip, /{ip}. GeoIP: /country, /city, /asn, /coordinates. API: /api/v1/*"},
			{ID: "formats", Title: "Output Formats", Content: "Auto-detects CLI tools (curl, wget, HTTPie). Use Accept header to force format."},
			{ID: "faq", Title: "FAQ", Content: "Do I need an API key? No. Public IP and GeoIP lookups are anonymous. How do I look up an address? Request /{ip}, for example /8.8.8.8/json. Why are GeoIP fields missing? The server may not have GeoIP databases configured or available; IP lookup still works."},
			{ID: "troubleshooting", Title: "Troubleshooting", Content: "429 Too Many Requests: slow down and retry after the duration in the Retry-After response header. 404 Not Found: check that the route is supported, such as /ip, /json, /country, or /{ip}."},
		},
	}
}

// APIV1ServerHelpHandler serves /api/v1/server/help (JSON)
func (h *PagesHandler) APIV1ServerHelpHandler(w http.ResponseWriter, r *http.Request) {
	help := buildHelpResponse()
	SendAPIResponseOK(w, help, nil)
}

// ServerPrivacyHandler serves /server/privacy under the PART 14 frontend dispatch.
func (h *PagesHandler) ServerPrivacyHandler(w http.ResponseWriter, r *http.Request) {
	h.renderNegotiated(w, r, "privacy.tmpl", h.NewPageData(r), h.buildPrivacyResponse(r))
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

// buildPrivacyResponse assembles the live privacy/tracking view shared by the
// /server/privacy page dispatch and its /api/{api_version}/server/privacy twin.
func (h *PagesHandler) buildPrivacyResponse(r *http.Request) PrivacyResponse {
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
	return privacy
}

// APIV1ServerPrivacyHandler serves /api/{api_version}/server/privacy (JSON).
func (h *PagesHandler) APIV1ServerPrivacyHandler(w http.ResponseWriter, r *http.Request) {
	privacy := h.buildPrivacyResponse(r)

	SendAPIResponseOK(w, privacy, nil)
}

// ServerDPOHandler serves the public Data Protection Officer contact details.
func (h *PagesHandler) ServerDPOHandler(w http.ResponseWriter, r *http.Request) {
	response := h.buildDPOResponse()
	data := struct {
		PageData
		DPOResponse
	}{PageData: h.NewPageData(r), DPOResponse: response}
	h.renderNegotiated(w, r, "dpo.tmpl", data, response)
}

// APIV1ServerDPOHandler serves the public DPO contact details as JSON.
func (h *PagesHandler) APIV1ServerDPOHandler(w http.ResponseWriter, r *http.Request) {
	SendAPIResponseOK(w, h.buildDPOResponse(), nil)
}

type DPOResponse struct {
	Name       string `json:"name"`
	Email      string `json:"email"`
	PrivacyURL string `json:"privacy_url"`
}

func (h *PagesHandler) buildDPOResponse() DPOResponse {
	response := DPOResponse{PrivacyURL: "/server/privacy"}
	if h.Config == nil {
		return response
	}
	contact := h.Config.Server.Contact.DPO
	response.Name = strings.TrimSpace(contact.Name)
	response.Email = strings.TrimSpace(contact.Email)
	if response.Email == "" {
		response.Email = strings.TrimSpace(h.Config.Server.Contact.General.Email)
	}
	return response
}

// ServerContactHandler serves /server/contact (GET) and accepts POST submissions.
// Submissions are dispatched to the "general" contact role's configured
// email + webhooks per AI.md PART 12.
func (h *PagesHandler) ServerContactHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err == nil {
			req := contactRequestFromForm(r, h.contactCaptchaProvider(r))
			validSecurityID, _ := h.validSecurityID(req.SecurityID)
			if validSecurityID {
				if !allowContactSubmission(clientIP(r)) {
					h.renderContactError(w, r, http.StatusTooManyRequests)
					return
				}
				if id, err := h.submitSecurityReport(r, req); err == nil {
					w.Header().Set("Cache-Control", "no-store")
					data := h.NewPageData(r)
					data.SecurityReportSubmitted = true
					data.SecurityReportTrackingID = id
					h.renderNegotiated(w, r, "contact.tmpl", data, ContactResponse{Success: true, Message: translateRequest(r, "contact.report_received_body"), TrackingID: id})
					return
				} else if errors.Is(err, errCaptchaProviderUnavailable) {
					h.renderContactError(w, r, http.StatusServiceUnavailable)
				} else {
					h.renderContactError(w, r, http.StatusBadRequest)
				}
				return
			}
			if !validStandardContactRequest(req) {
				http.Redirect(w, r, "/server/contact", http.StatusSeeOther)
				return
			}
			validCaptcha, captchaErr := h.verifyContactCaptcha(r, req.CaptchaToken, req.Captcha, time.Now())
			if captchaErr != nil {
				h.renderContactError(w, r, http.StatusServiceUnavailable)
				return
			}
			if !validCaptcha {
				h.renderContactError(w, r, http.StatusBadRequest)
				return
			}
			if !allowContactSubmission(clientIP(r)) {
				h.renderContactError(w, r, http.StatusTooManyRequests)
				return
			}
			h.dispatchContactSubmission(r, req)
		}
		http.Redirect(w, r, "/server/contact", http.StatusSeeOther)
		return
	}
	data := h.NewPageData(r)
	if candidate := r.URL.Query().Get("security_id"); candidate != "" {
		if valid, err := h.validSecurityID(candidate); err == nil && valid {
			data.SecurityReportMode = true
			data.SecurityID = candidate
		} else if h.SecurityLogger != nil {
			h.logInvalidSecurityID(r, candidate)
		}
	}
	data.CaptchaProvider, data.CaptchaQuestion, data.CaptchaToken = h.newContactCaptcha(r, time.Now())
	if data.CaptchaProvider != "simple" && h.Config != nil {
		data.CaptchaSiteKey = h.Config.Pages.Contact.CaptchaSiteKey
	}
	form := buildContactFormResponse()
	form.CaptchaQuestion, form.CaptchaToken = data.CaptchaQuestion, data.CaptchaToken
	form.CaptchaProvider, form.CaptchaSiteKey = data.CaptchaProvider, data.CaptchaSiteKey
	form.SecurityReportMode = data.SecurityReportMode
	if data.SecurityReportMode {
		form.Fields = []string{"name", "handle", "email", "captcha", "captcha_token", "researcher_gpg", "affected_component", "affected_endpoint", "severity", "summary", "steps_to_reproduce", "impact", "suggested_fix", "cve_requested", "disclosure_days", "credit_preference", "coordinated_disclosure_agreement"}
	}
	h.renderNegotiated(w, r, "contact.tmpl", data, form)
}

func contactRequestFromForm(r *http.Request, provider string) ContactRequest {
	captcha := strings.TrimSpace(r.FormValue("captcha"))
	switch provider {
	case "recaptcha":
		captcha = strings.TrimSpace(r.FormValue("g-recaptcha-response"))
	case "hcaptcha":
		captcha = strings.TrimSpace(r.FormValue("h-captcha-response"))
	}
	return ContactRequest{
		Name: strings.TrimSpace(r.FormValue("name")), Handle: strings.TrimSpace(r.FormValue("handle")), Email: strings.TrimSpace(r.FormValue("email")),
		Subject: strings.TrimSpace(r.FormValue("subject")), Message: strings.TrimSpace(r.FormValue("message")),
		SecurityID: strings.TrimSpace(r.FormValue("security_id")), ResearcherGPG: strings.TrimSpace(r.FormValue("researcher_gpg")),
		AffectedComponent: strings.TrimSpace(r.FormValue("affected_component")), AffectedEndpoint: strings.TrimSpace(r.FormValue("affected_endpoint")),
		Severity: strings.TrimSpace(r.FormValue("severity")), Summary: strings.TrimSpace(r.FormValue("summary")),
		StepsToReproduce: strings.TrimSpace(r.FormValue("steps_to_reproduce")), Impact: strings.TrimSpace(r.FormValue("impact")),
		SuggestedFix: strings.TrimSpace(r.FormValue("suggested_fix")), CVERequested: isCheckboxChecked(r.FormValue("cve_requested")),
		DisclosureDays: r.FormValue("disclosure_days"), CreditPreference: strings.TrimSpace(r.FormValue("credit_preference")),
		CoordinatedAgreement: isCheckboxChecked(r.FormValue("coordinated_disclosure_agreement")),
		Captcha:              captcha, CaptchaToken: strings.TrimSpace(r.FormValue("captcha_token")),
	}
}

// ContactFormResponse describes the contact form to a non-browser client, so
// our CLI can render the same submission form the HTML page offers. The field
// list mirrors the form fields ServerContactHandler's POST branch reads.
type ContactFormResponse struct {
	Method             string   `json:"method"`
	Action             string   `json:"action"`
	Fields             []string `json:"fields"`
	CaptchaQuestion    string   `json:"captcha_question,omitempty"`
	CaptchaToken       string   `json:"captcha_token,omitempty"`
	CaptchaProvider    string   `json:"captcha_provider"`
	CaptchaSiteKey     string   `json:"captcha_site_key,omitempty"`
	SecurityReportMode bool     `json:"security_report_mode,omitempty"`
}

// buildContactFormResponse returns the contact form description served to
// non-browser clients on GET /server/contact.
func buildContactFormResponse() ContactFormResponse {
	return ContactFormResponse{
		Method: http.MethodPost,
		Action: "/api/v1/server/contact",
		Fields: []string{"name", "email", "subject", "message", "captcha", "captcha_token"},
	}
}

// ContactRequest for POST submissions
type ContactRequest struct {
	Name                 string `json:"name"`
	Handle               string `json:"handle,omitempty"`
	Email                string `json:"email"`
	Subject              string `json:"subject"`
	Message              string `json:"message"`
	SecurityID           string `json:"security_id,omitempty"`
	ResearcherGPG        string `json:"researcher_gpg,omitempty"`
	AffectedComponent    string `json:"affected_component,omitempty"`
	AffectedEndpoint     string `json:"affected_endpoint,omitempty"`
	Severity             string `json:"severity,omitempty"`
	Summary              string `json:"summary,omitempty"`
	StepsToReproduce     string `json:"steps_to_reproduce,omitempty"`
	Impact               string `json:"impact,omitempty"`
	SuggestedFix         string `json:"suggested_fix,omitempty"`
	CVERequested         bool   `json:"cve_requested,omitempty"`
	DisclosureDays       string `json:"disclosure_days,omitempty"`
	CreditPreference     string `json:"credit_preference,omitempty"`
	CoordinatedAgreement bool   `json:"coordinated_disclosure_agreement,omitempty"`
	Captcha              string `json:"captcha,omitempty"`
	CaptchaToken         string `json:"captcha_token,omitempty"`
}

// ContactResponse for JSON API
type ContactResponse struct {
	Success    bool   `json:"success"`
	Message    string `json:"message"`
	TrackingID string `json:"tracking_id,omitempty"`
}

// APIV1ServerContactHandler handles POST /api/v1/server/contact
func (h *PagesHandler) APIV1ServerContactHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		SendAPIResponseError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", i18n.T(r.Context(), "errors.method_not_allowed"), nil)
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
	req.SecurityID = strings.TrimSpace(req.SecurityID)
	req.Captcha = strings.TrimSpace(req.Captcha)
	req.CaptchaToken = strings.TrimSpace(req.CaptchaToken)

	validSecurityID, securityIDErr := h.validSecurityID(req.SecurityID)
	if req.SecurityID != "" && securityIDErr == nil && !validSecurityID && h.SecurityLogger != nil {
		h.logInvalidSecurityID(r, req.SecurityID)
	}
	if securityIDErr == nil && validSecurityID {
		if !allowContactSubmission(clientIP(r)) {
			SendAPIResponseError(w, http.StatusTooManyRequests, "RATE_LIMITED", i18n.T(r.Context(), "errors.rate_limited"), nil)
			return
		}
		trackingID, err := h.submitSecurityReport(r, req)
		if err != nil {
			if errors.Is(err, errCaptchaProviderUnavailable) {
				SendAPIResponseError(w, http.StatusServiceUnavailable, "CAPTCHA_UNAVAILABLE", i18n.T(r.Context(), "errors.maintenance_mode"), nil)
			} else {
				SendAPIResponseError(w, http.StatusBadRequest, "BAD_REQUEST", i18n.T(r.Context(), "errors.bad_request"), nil)
			}
			return
		}
		SendAPIResponseOK(w, ContactResponse{Success: true, Message: translateRequest(r, "contact.report_received_body"), TrackingID: trackingID}, nil)
		return
	}

	switch {
	case !validStandardContactRequest(req):
		SendAPIResponseError(w, http.StatusBadRequest, "BAD_REQUEST", i18n.T(r.Context(), "errors.bad_request"), nil)
		return
	case !allowContactSubmission(clientIP(r)):
		SendAPIResponseError(w, http.StatusTooManyRequests, "RATE_LIMITED", i18n.T(r.Context(), "errors.rate_limited"), nil)
		return
	default:
		validCaptcha, captchaErr := h.verifyContactCaptcha(r, req.CaptchaToken, req.Captcha, time.Now())
		if captchaErr != nil {
			SendAPIResponseError(w, http.StatusServiceUnavailable, "CAPTCHA_UNAVAILABLE", i18n.T(r.Context(), "errors.maintenance_mode"), nil)
			return
		}
		if !validCaptcha {
			SendAPIResponseError(w, http.StatusBadRequest, "BAD_REQUEST", i18n.T(r.Context(), "errors.bad_request"), nil)
			return
		}
		h.dispatchContactSubmission(r, req)
	}
	SendAPIResponseOK(w, ContactResponse{Success: true, Message: i18n.T(r.Context(), "contact.success")}, nil)
}

func validStandardContactRequest(req ContactRequest) bool {
	if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.Email) == "" ||
		strings.TrimSpace(req.Subject) == "" || strings.TrimSpace(req.Message) == "" {
		return false
	}
	_, err := mail.ParseAddress(req.Email)
	return err == nil
}

func (h *PagesHandler) validSecurityID(candidate string) (bool, error) {
	if candidate == "" || h.DB == nil {
		return false, nil
	}
	return security.IsValidSecurityID(h.DB, candidate, time.Now())
}

func (h *PagesHandler) logInvalidSecurityID(r *http.Request, supplied string) {
	if h.SecurityLogger == nil {
		return
	}
	digest := sha256.Sum256([]byte(supplied))
	userAgent := strings.TrimSpace(r.UserAgent())
	if len(userAgent) > 256 {
		userAgent = userAgent[:256]
	}
	h.SecurityLogger(fmt.Sprintf("security.security_id_invalid user_agent=%q security_id_sha256_prefix=%s", userAgent, hex.EncodeToString(digest[:4])), clientIP(r))
}

func newSimpleCaptcha(db *sql.DB, now time.Time) (string, string, error) {
	if db == nil {
		return "", "", fmt.Errorf("captcha secret database unavailable")
	}
	first, err := cryptorand.Int(cryptorand.Reader, big.NewInt(9))
	if err != nil {
		return "", "", err
	}
	second, err := cryptorand.Int(cryptorand.Reader, big.NewInt(9))
	if err != nil {
		return "", "", err
	}
	tokenBytes := make([]byte, 32)
	if _, err := cryptorand.Read(tokenBytes); err != nil {
		return "", "", err
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	secret, err := security.GetOrCreateSecret(db, security.SecretCSRFTokenSecret)
	if err != nil {
		return "", "", err
	}
	answer := fmt.Sprint(first.Int64() + second.Int64())
	answerHash := simpleCaptchaAnswerHash(secret, answer)
	tokenHash := sha256.Sum256([]byte(token))
	if _, err := db.Exec(`DELETE FROM contact_captcha_challenges WHERE expires_at <= ? OR used_at IS NOT NULL`, now.Unix()); err != nil {
		return "", "", err
	}
	if _, err := db.Exec(`INSERT INTO contact_captcha_challenges (token_hash, answer_hash, created_at, expires_at)
VALUES (?, ?, ?, ?)`, hex.EncodeToString(tokenHash[:]), hex.EncodeToString(answerHash), now.Unix(), now.Add(10*time.Minute).Unix()); err != nil {
		return "", "", err
	}
	return fmt.Sprintf("What is %d + %d?", first.Int64(), second.Int64()), token, nil
}

func verifySimpleCaptcha(db *sql.DB, token, answer string, now time.Time) bool {
	if db == nil || token == "" || strings.TrimSpace(answer) == "" {
		return false
	}
	if _, err := base64.RawURLEncoding.DecodeString(token); err != nil {
		return false
	}
	secret, err := security.GetOrCreateSecret(db, security.SecretCSRFTokenSecret)
	if err != nil {
		return false
	}
	tokenHash := sha256.Sum256([]byte(token))
	var storedHash string
	err = db.QueryRow(`UPDATE contact_captcha_challenges SET used_at = ?
WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?
RETURNING answer_hash`, now.Unix(), hex.EncodeToString(tokenHash[:]), now.Unix()).Scan(&storedHash)
	if err != nil {
		return false
	}
	answerHash := simpleCaptchaAnswerHash(secret, strings.TrimSpace(answer))
	return hmac.Equal([]byte(storedHash), []byte(hex.EncodeToString(answerHash)))
}

func simpleCaptchaAnswerHash(secret []byte, answer string) []byte {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(answer))
	return mac.Sum(nil)
}

func (h *PagesHandler) configuredContactCaptchaProvider() string {
	if h.Config == nil {
		return "simple"
	}
	provider := strings.ToLower(strings.TrimSpace(h.Config.Pages.Contact.Captcha))
	switch provider {
	case "recaptcha", "hcaptcha":
		return provider
	default:
		return "simple"
	}
}

func (h *PagesHandler) contactCaptchaProvider(r *http.Request) string {
	if netutil.IsTorRequest(r, h.Trust) || netutil.IsI2PRequest(r, h.Trust) {
		return "simple"
	}
	return h.configuredContactCaptchaProvider()
}

var errCaptchaProviderUnavailable = errors.New("captcha provider unavailable")

func (h *PagesHandler) newContactCaptcha(r *http.Request, now time.Time) (string, string, string) {
	provider := h.contactCaptchaProvider(r)
	if provider != "simple" {
		return provider, "", ""
	}
	question, token, _ := newSimpleCaptcha(h.DB, now)
	return provider, question, token
}

func (h *PagesHandler) verifyContactCaptcha(r *http.Request, token, answer string, now time.Time) (bool, error) {
	provider := h.contactCaptchaProvider(r)
	if provider == "simple" {
		return verifySimpleCaptcha(h.DB, token, answer, now), nil
	}
	if h.Config == nil || strings.TrimSpace(answer) == "" {
		return false, nil
	}
	endpoint := ""
	values := url.Values{}
	values.Set("secret", h.Config.Pages.Contact.CaptchaSecretKey)
	values.Set("response", strings.TrimSpace(answer))
	switch provider {
	case "recaptcha":
		endpoint = "https://www.google.com/recaptcha/api/siteverify"
		values.Set("remoteip", clientIP(r))
	case "hcaptcha":
		endpoint = "https://api.hcaptcha.com/siteverify"
	default:
		return false, nil
	}
	request, err := http.NewRequestWithContext(r.Context(), http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return false, errCaptchaProviderUnavailable
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := tor.NewHTTPClient(5 * time.Second)
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(request)
	if err != nil {
		return false, errCaptchaProviderUnavailable
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return false, errCaptchaProviderUnavailable
	}
	var result struct {
		Success bool `json:"success"`
	}
	if json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&result) != nil {
		return false, errCaptchaProviderUnavailable
	}
	return result.Success, nil
}

func (h *PagesHandler) submitSecurityReport(r *http.Request, req ContactRequest) (string, error) {
	if h.DB == nil || h.Config == nil || req.Name == "" || req.Email == "" || req.AffectedComponent == "" ||
		req.Summary == "" || req.StepsToReproduce == "" || req.Impact == "" || !req.CoordinatedAgreement ||
		!validCreditPreference(req.CreditPreference) || req.CreditPreference == "handle" && req.Handle == "" || !validSecuritySeverity(req.Severity) {
		return "", fmt.Errorf("security report validation failed")
	}
	validCaptcha, captchaErr := h.verifyContactCaptcha(r, req.CaptchaToken, req.Captcha, time.Now())
	if captchaErr != nil {
		return "", errCaptchaProviderUnavailable
	}
	if !validCaptcha {
		return "", fmt.Errorf("security report validation failed")
	}
	if _, err := mail.ParseAddress(req.Email); err != nil {
		return "", fmt.Errorf("invalid reporter email")
	}
	days := 90
	if req.DisclosureDays != "" {
		parsed, err := strconv.Atoi(req.DisclosureDays)
		if err != nil || parsed < 1 || parsed > 365 {
			return "", fmt.Errorf("invalid disclosure timeline")
		}
		days = parsed
	}
	valid, err := h.validSecurityID(req.SecurityID)
	if err != nil || !valid {
		return "", fmt.Errorf("security report token invalid")
	}
	var researcherKey []byte
	if req.ResearcherGPG != "" {
		if strings.HasPrefix(req.ResearcherGPG, "https://") {
			keyData, _, fetchErr := urlutil.FetchRemoteImage(r.Context(), req.ResearcherGPG, urlutil.FetchRemoteImageConfig{
				MaxSize: 1 << 20, Timeout: 15 * time.Second,
				AllowedTypes:   []string{"application/pgp-keys", "application/octet-stream", "text/plain"},
				AllowedSchemes: []string{"https"},
			})
			if fetchErr != nil {
				return "", fmt.Errorf("fetch researcher public key: %w", fetchErr)
			}
			researcherKey = keyData
		} else {
			researcherKey = []byte(req.ResearcherGPG)
		}
		if _, validateErr := pgp.EncryptFor(string(researcherKey), []byte("IPGaze security report acknowledgment key validation.")); validateErr != nil {
			return "", fmt.Errorf("invalid researcher public key: %w", validateErr)
		}
	}
	content := map[string]any{
		"name": req.Name, "email": req.Email, "researcher_gpg": string(researcherKey),
		"security_id":        req.SecurityID,
		"affected_component": req.AffectedComponent, "affected_endpoint": req.AffectedEndpoint,
		"severity": req.Severity, "summary": req.Summary, "steps_to_reproduce": req.StepsToReproduce,
		"impact": req.Impact, "suggested_fix": req.SuggestedFix, "cve_requested": req.CVERequested,
		"disclosure_days": days, "credit_preference": req.CreditPreference,
		"app_version": h.Version, "commit_hash": h.CommitID,
		"timestamp": time.Now().UTC().Format(time.RFC3339), "request_user_agent": r.UserAgent(),
	}
	plain, err := json.Marshal(content)
	if err != nil {
		return "", fmt.Errorf("encode report: %w", err)
	}
	trackingID, err := security.NewSecurityTrackingID()
	if err != nil {
		return "", err
	}
	accessToken, accessTokenHash, err := security.NewSecurityAccessToken()
	if err != nil {
		return "", err
	}
	resolved := config.ResolveContactRole(h.Config, "security")
	appURL := strings.TrimSuffix(netutil.BuildURL(r, h.Trust, ""), "/")
	statusURL := appURL + "/server/security/report/" + url.PathEscape(trackingID) + "?token=" + url.QueryEscape(accessToken)
	ack := translateRequest(r, "security.report_email_body", "tracking_id", trackingID, "status_url", statusURL)
	if len(researcherKey) > 0 {
		ack, err = encryptResearcherAcknowledgment(string(researcherKey), ack)
		if err != nil {
			ack = ""
		}
	}
	var ciphertext []byte
	encryption := "aes-256-gcm"
	var publicKey []byte
	if h.PGPPublicKeyPath != "" {
		if data, readErr := os.ReadFile(h.PGPPublicKeyPath); readErr == nil && len(data) > 0 {
			publicKey = data
		}
	}
	if len(publicKey) > 0 {
		ciphertext, err = pgp.EncryptFor(string(publicKey), plain)
		if err != nil {
			return "", fmt.Errorf("encrypt security report with project PGP key: %w", err)
		}
		encryption = "pgp"
	} else {
		key, decodeErr := base64.StdEncoding.DecodeString(h.Config.Server.Security.EncryptionKey)
		if decodeErr != nil || len(key) != 32 {
			return "", fmt.Errorf("security report encryption key is unavailable")
		}
		ciphertext, err = security.EncryptWithSecret(key, plain, "security-reports")
		if err != nil {
			return "", fmt.Errorf("encrypt security report: %w", err)
		}
	}
	creditName := ""
	switch req.CreditPreference {
	case "real_name":
		creditName = req.Name
	case "handle":
		creditName = req.Handle
	}
	if creditName != "" {
		if h.Config == nil {
			return "", fmt.Errorf("researcher credit encryption key is unavailable")
		}
		creditKey, decodeErr := base64.StdEncoding.DecodeString(h.Config.Server.Security.EncryptionKey)
		if decodeErr != nil || len(creditKey) != 32 {
			return "", fmt.Errorf("researcher credit encryption key is unavailable")
		}
		creditName, err = security.EncryptSecurityCredit(creditKey, creditName)
		if err != nil {
			return "", err
		}
	}
	if err := security.StoreSecurityReport(h.DB, security.SecurityReportMetadata{
		TrackingID: trackingID, Ciphertext: ciphertext, Encryption: encryption,
		Severity: req.Severity, AffectedComponent: req.AffectedComponent,
		CreditPreference: req.CreditPreference, CreditName: creditName,
		ShortCredit: "Security vulnerability report", AccessTokenHash: accessTokenHash,
	}); err != nil {
		return "", err
	}
	if ack != "" && h.EmailMgr != nil && h.EmailMgr.IsEnabled() {
		if sendErr := h.EmailMgr.SendDirect(&email.Message{To: []string{req.Email}, Subject: translateRequest(r, "security.report_email_subject", "tracking_id", trackingID), Body: ack}); sendErr != nil && h.SecurityLogger != nil {
			h.SecurityLogger("security.report_acknowledgment_failed tracking_id="+trackingID, clientIP(r))
		}
	}
	if resolved.Email != "" && h.EmailMgr != nil && h.EmailMgr.IsEnabled() {
		notification := &email.Message{To: []string{resolved.Email}, Subject: translateWithLocale("en", "security.report_notification_subject", "tracking_id", trackingID), Body: string(ciphertext)}
		if encryption == "aes-256-gcm" {
			notification.Body = translateWithLocale("en", "security.report_notification_body")
			notification.Attachments = []email.Attachment{{Filename: trackingID + ".enc", ContentType: "application/octet-stream", Data: ciphertext}}
		}
		if sendErr := h.EmailMgr.SendDirect(notification); sendErr != nil && h.SecurityLogger != nil {
			h.SecurityLogger("security.report_notification_failed tracking_id="+trackingID, clientIP(r))
		}
	}
	if h.SecurityLogger != nil {
		h.SecurityLogger("security.report_received tracking_id="+trackingID+" severity="+req.Severity+" component="+security.SanitizeReportComponent(req.AffectedComponent), clientIP(r))
	}
	return trackingID, nil
}

func encryptResearcherAcknowledgment(publicArmor, message string) (string, error) {
	data, err := pgp.EncryptFor(publicArmor, []byte(message))
	if err != nil {
		return "", fmt.Errorf("validate or encrypt researcher acknowledgment key: %w", err)
	}
	return string(data), nil
}

func validCreditPreference(value string) bool {
	switch value {
	case "real_name", "handle", "no", "anonymous":
		return true
	default:
		return false
	}
}

func validSecuritySeverity(value string) bool {
	switch value {
	case "critical", "high", "medium", "low", "informational":
		return true
	default:
		return false
	}
}

func (h *PagesHandler) renderContactError(w http.ResponseWriter, r *http.Request, status int) {
	data := h.NewPageData(r)
	data.ContactError = translateRequest(r, "contact.submit_error")
	if candidate := r.FormValue("security_id"); candidate != "" {
		if valid, err := h.validSecurityID(candidate); err == nil && valid {
			data.SecurityReportMode = true
			data.SecurityID = candidate
		}
	}
	data.CaptchaProvider, data.CaptchaQuestion, data.CaptchaToken = h.newContactCaptcha(r, time.Now())
	if data.CaptchaProvider != "simple" && h.Config != nil {
		data.CaptchaSiteKey = h.Config.Pages.Contact.CaptchaSiteKey
	}
	w.WriteHeader(status)
	form := buildContactFormResponse()
	form.CaptchaQuestion, form.CaptchaToken = data.CaptchaQuestion, data.CaptchaToken
	form.CaptchaProvider, form.CaptchaSiteKey = data.CaptchaProvider, data.CaptchaSiteKey
	form.SecurityReportMode = data.SecurityReportMode
	h.renderNegotiated(w, r, "contact.tmpl", data, form)
}

func translateRequest(r *http.Request, key string, replacements ...string) string {
	lang := i18n.DetectLocale(r)
	return translateWithLocale(lang, key, replacements...)
}

func translateWithLocale(lang, key string, replacements ...string) string {
	ctx := i18n.WithLang(context.Background(), lang)
	message := i18n.T(ctx, key)
	for index := 0; index+1 < len(replacements); index += 2 {
		message = strings.ReplaceAll(message, "{"+replacements[index]+"}", replacements[index+1])
	}
	return message
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
func (h *PagesHandler) dispatchContactSubmission(r *http.Request, req ContactRequest) {
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
		if err := h.EmailMgr.SendDirect(&email.Message{
			To:      []string{resolved.Email},
			Subject: subject,
			Body:    body,
		}); err != nil {
			log.Printf("contact email delivery failed: request_id=%s method=%s path=%s ip=%s err=%v",
				r.Header.Get("X-Request-ID"), r.Method, r.URL.Path, clientIP(r), err)
		}
	}
}

// ServerTermsHandler serves /server/terms under the PART 14 frontend dispatch.
func (h *PagesHandler) ServerTermsHandler(w http.ResponseWriter, r *http.Request) {
	h.renderNegotiated(w, r, "terms.tmpl", h.NewPageData(r), buildTermsResponse(h.BuildDate))
}

// TermsResponse for JSON API
type TermsResponse struct {
	Sections []struct {
		Title   string `json:"title"`
		Content string `json:"content"`
	} `json:"sections"`
	LastUpdated string `json:"last_updated"`
}

// buildTermsResponse returns the terms sections shared by the /server/terms
// page dispatch and its /api/{api_version}/server/terms JSON twin.
func buildTermsResponse(lastUpdated string) TermsResponse {
	return TermsResponse{
		LastUpdated: lastUpdated,
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
}

// APIV1ServerTermsHandler serves /api/v1/server/terms (JSON)
func (h *PagesHandler) APIV1ServerTermsHandler(w http.ResponseWriter, r *http.Request) {
	terms := buildTermsResponse(h.BuildDate)
	SendAPIResponseOK(w, terms, nil)
}

// ServerSecurityHandler serves /server/security under the PART 14 frontend dispatch.
func (h *PagesHandler) ServerSecurityHandler(w http.ResponseWriter, r *http.Request) {
	response := h.buildSecurityResponse(r)
	data := struct {
		PageData
		SecurityResponse
	}{PageData: h.NewPageData(r), SecurityResponse: response}
	h.renderNegotiated(w, r, "security.tmpl", data, response)
}

// ServerSecurityPolicyHandler serves the default coordinated-disclosure policy.
func (h *PagesHandler) ServerSecurityPolicyHandler(w http.ResponseWriter, r *http.Request) {
	pageData := h.NewPageData(r)
	response := buildSecurityPolicyResponse(pageData.Lang, h.securityPolicyMarkdown())
	data := struct {
		PageData
		SecurityPolicyResponse
	}{PageData: pageData, SecurityPolicyResponse: response}
	h.renderNegotiated(w, r, "security_policy.tmpl", data, response)
}

// APIV1ServerSecurityPolicyHandler serves the disclosure policy as JSON.
func (h *PagesHandler) APIV1ServerSecurityPolicyHandler(w http.ResponseWriter, r *http.Request) {
	SendAPIResponseOK(w, buildSecurityPolicyResponse(i18n.DetectLocale(r), h.securityPolicyMarkdown()), nil)
}

// SecurityPolicyResponse describes the official service's disclosure policy.
type SecurityPolicyResponse struct {
	DisclosureWindow string   `json:"disclosure_window"`
	InScope          []string `json:"in_scope"`
	OutOfScope       []string `json:"out_of_scope"`
	SafeHarbor       string   `json:"safe_harbor"`
	PolicyMarkdown   string   `json:"policy_markdown,omitempty"`
}

// buildSecurityPolicyResponse returns the public policy in the requested locale.
func buildSecurityPolicyResponse(lang, customPolicy string) SecurityPolicyResponse {
	ctx := i18n.WithLang(context.Background(), lang)
	if strings.TrimSpace(customPolicy) != "" {
		return SecurityPolicyResponse{PolicyMarkdown: customPolicy}
	}
	return SecurityPolicyResponse{
		DisclosureWindow: i18n.T(ctx, "security.policy_window"),
		InScope:          []string{i18n.T(ctx, "security.policy_scope_official")},
		OutOfScope: []string{
			i18n.T(ctx, "security.policy_out_scope_self_hosted"),
			i18n.T(ctx, "security.policy_out_scope_disruption"),
			i18n.T(ctx, "security.policy_out_scope_third_party"),
		},
		SafeHarbor: i18n.T(ctx, "security.policy_safe_harbor_text"),
	}
}

func (h *PagesHandler) securityPolicyMarkdown() string {
	if h.Config == nil {
		return ""
	}
	return h.Config.Web.Security.Policy
}

// ServerSecurityThanksHandler serves the current public acknowledgments list.
func (h *PagesHandler) ServerSecurityThanksHandler(w http.ResponseWriter, r *http.Request) {
	response, err := h.securityThanksResponse(r)
	if err != nil {
		h.renderErrorPage(w, r, http.StatusInternalServerError, i18n.T(r.Context(), "errors.server_error"))
		return
	}
	data := struct {
		PageData
		SecurityThanksResponse
	}{PageData: h.NewPageData(r), SecurityThanksResponse: response}
	h.renderNegotiated(w, r, "security_thanks.tmpl", data, response)
}

// APIV1ServerSecurityThanksHandler serves public acknowledgments as JSON.
func (h *PagesHandler) APIV1ServerSecurityThanksHandler(w http.ResponseWriter, r *http.Request) {
	response, err := h.securityThanksResponse(r)
	if err != nil {
		SendAPIResponseError(w, http.StatusInternalServerError, "SERVER_ERROR", i18n.T(r.Context(), "errors.server_error"), nil)
		return
	}
	SendAPIResponseOK(w, response, nil)
}

func (h *PagesHandler) securityThanksResponse(r *http.Request) (SecurityThanksResponse, error) {
	response := SecurityThanksResponse{Researchers: []SecurityAcknowledgment{}}
	if h.DB == nil {
		return response, nil
	}
	readCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	rows, err := h.DB.QueryContext(readCtx, `SELECT credit_preference, credit_name,
		COALESCE(disclosed_year, CAST(strftime('%Y', created_at, 'unixepoch') AS INTEGER)), short_credit
		FROM security_reports WHERE status = 'Disclosed' AND credit_preference IN ('real_name', 'handle', 'anonymous')
		ORDER BY COALESCE(disclosed_year, CAST(strftime('%Y', created_at, 'unixepoch') AS INTEGER)), created_at`)
	if err != nil {
		return response, h.securityThanksError(r, fmt.Errorf("query disclosed acknowledgments: %w", err))
	}
	anonymous := 0
	var creditKey []byte
	var keyDecodeErr error
	if h.Config != nil {
		creditKey, keyDecodeErr = base64.StdEncoding.DecodeString(h.Config.Server.Security.EncryptionKey)
	}
	for rows.Next() {
		var preference, name, credit string
		var year int
		if err := rows.Scan(&preference, &name, &year, &credit); err != nil {
			_ = rows.Close()
			return response, h.securityThanksError(r, fmt.Errorf("scan disclosed acknowledgment: %w", err))
		}
		if preference == "anonymous" {
			anonymous++
			name = fmt.Sprintf("Anonymous Researcher #%d", anonymous)
		} else {
			if keyDecodeErr != nil {
				_ = rows.Close()
				return response, h.securityThanksError(r, fmt.Errorf("decode security credit encryption key: %w", keyDecodeErr))
			}
			if len(creditKey) != 32 {
				_ = rows.Close()
				return response, h.securityThanksError(r, errors.New("security credit encryption key is unavailable or invalid"))
			}
			name, err = security.DecryptSecurityCredit(creditKey, name)
			if err != nil {
				_ = rows.Close()
				return response, h.securityThanksError(r, fmt.Errorf("decrypt disclosed acknowledgment: %w", err))
			}
		}
		if name == "" {
			continue
		}
		response.Researchers = append(response.Researchers, SecurityAcknowledgment{Name: name, Year: year, Credit: credit})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return response, h.securityThanksError(r, fmt.Errorf("iterate disclosed acknowledgments: %w", err))
	}
	if err := rows.Close(); err != nil {
		return response, h.securityThanksError(r, fmt.Errorf("close disclosed acknowledgments: %w", err))
	}
	return response, nil
}

func (h *PagesHandler) securityThanksError(r *http.Request, err error) error {
	log.Printf("security acknowledgments unavailable: request_id=%s method=%s path=%s ip=%s err=%v",
		r.Header.Get("X-Request-ID"), r.Method, r.URL.Path, clientIP(r), err)
	return err
}

// SecurityThanksResponse contains researchers who consented to public credit.
type SecurityThanksResponse struct {
	Researchers []SecurityAcknowledgment `json:"researchers"`
}

// SecurityAcknowledgment is a public, consented researcher credit.
type SecurityAcknowledgment struct {
	Name   string `json:"name"`
	Year   int    `json:"year"`
	Credit string `json:"credit"`
}

// SecurityResponse for JSON API
type SecurityResponse struct {
	SecurityEmail     string                   `json:"security_email,omitempty"`
	PolicyURL         string                   `json:"policy_url"`
	SecurityTxt       string                   `json:"security_txt"`
	ReportURL         string                   `json:"report_url"`
	ReportFormURL     string                   `json:"report_form_url"`
	Expires           string                   `json:"expires"`
	EncryptionURL     string                   `json:"encryption_url,omitempty"`
	Fingerprint       string                   `json:"fingerprint,omitempty"`
	ReportingChannels []SecurityContactChannel `json:"reporting_channels"`
}

type SecurityContactChannel struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// buildSecurityResponse assembles the security-contact view shared by the
// /server/security page dispatch and its /api/{api_version}/server/security twin.
func (h *PagesHandler) buildSecurityResponse(r *http.Request) SecurityResponse {
	data := h.NewPageData(r)
	appURL := strings.TrimSuffix(netutil.BuildURL(r, h.Trust, ""), "/")
	reportURL := "https://github.com/apimgr/ipgaze/security/advisories/new"
	formURL := appURL + "/server/contact?security_id={security_id}"
	expires := time.Now().UTC().AddDate(1, 0, 0).Format("2006-01-02T15:04:05.000Z")
	response := SecurityResponse{
		SecurityEmail: data.SecurityEmail,
		PolicyURL:     appURL + "/server/security/policy",
		SecurityTxt:   appURL + "/.well-known/security.txt",
		ReportURL:     reportURL,
		ReportFormURL: formURL,
		Expires:       expires,
		ReportingChannels: []SecurityContactChannel{
			{Type: "GitHub private vulnerability reporting", URL: reportURL},
			{Type: "Deployed instance security report form", URL: formURL},
		},
	}
	if data.SecurityEmail != "" {
		response.ReportingChannels = append(response.ReportingChannels, SecurityContactChannel{Type: "Email", URL: "mailto:" + data.SecurityEmail})
	}
	if data.PGPKeyAvailable {
		response.EncryptionURL = appURL + "/.well-known/pgp-key.asc"
	}
	if h.PGPFingerprint != nil {
		if fingerprint := h.PGPFingerprint(); isValidPGPFingerprint(fingerprint) {
			response.Fingerprint = fingerprint
		}
	}
	return response
}

// APIV1ServerSecurityHandler serves /api/v1/server/security (JSON)
func (h *PagesHandler) APIV1ServerSecurityHandler(w http.ResponseWriter, r *http.Request) {
	resp := h.buildSecurityResponse(r)
	SendAPIResponseOK(w, resp, nil)
}

// ServerSecurityReportHandler presents the current triage status after
// consuming the report owner's single-use-per-day access token.
func (h *PagesHandler) ServerSecurityReportHandler(w http.ResponseWriter, r *http.Request, trackingID string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if h.DB == nil {
		h.renderErrorPage(w, r, http.StatusNotFound, i18n.T(r.Context(), "errors.not_found"))
		return
	}
	status, err := security.ConsumeSecurityAccessToken(h.DB, trackingID, r.URL.Query().Get("token"), time.Now())
	if err != nil {
		h.renderErrorPage(w, r, http.StatusNotFound, i18n.T(r.Context(), "errors.not_found"))
		return
	}
	data := struct {
		PageData
		SecurityReportStatus security.SecurityReportStatus
	}{PageData: h.NewPageData(r), SecurityReportStatus: status}
	h.renderNegotiated(w, r, "security_report_status.tmpl", data, nil)
}

// safeRedirectTarget validates a client-supplied redirect target (e.g. from the Referer
// header) and returns it only if it is a same-origin relative path, preventing open
// redirect attacks. Falls back to "/" for anything absolute, protocol-relative, or
// pointing at a different host.
func safeRedirectTarget(r *http.Request, target string) string {
	if target == "" || strings.ContainsAny(target, "\r\n") {
		return "/"
	}
	// Reject protocol-relative URLs ("//evil.com") and anything not starting with "/".
	if !strings.HasPrefix(target, "/") || strings.HasPrefix(target, "//") || strings.HasPrefix(target, "/\\") {
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

func preferencesRedirectTarget(r *http.Request, trust *netutil.TrustResolver) string {
	if target, ok := validPreferencesRedirect(r.URL.Query().Get("redirect")); ok {
		return target
	}
	if referer := r.Referer(); referer != "" {
		if strings.HasPrefix(referer, "/") {
			if target, ok := validPreferencesRedirect(referer); ok {
				return target
			}
		}
		ref, err := url.Parse(referer)
		if err == nil {
			origin, originErr := url.Parse(netutil.BuildURL(r, trust, "/"))
			if originErr == nil && strings.EqualFold(ref.Scheme, origin.Scheme) && strings.EqualFold(ref.Host, origin.Host) {
				candidate := ref.EscapedPath()
				if ref.RawQuery != "" {
					candidate += "?" + ref.RawQuery
				}
				if target, ok := validPreferencesRedirect(candidate); ok {
					return target
				}
			}
		}
	}
	return "/"
}

func validPreferencesRedirect(target string) (string, bool) {
	if target == "" || !strings.HasPrefix(target, "/") || strings.HasPrefix(target, "//") || strings.HasPrefix(target, "/\\") || strings.ContainsAny(target, "\r\n") {
		return "", false
	}
	u, err := url.Parse(target)
	if err != nil || u.IsAbs() || u.Host != "" {
		return "", false
	}
	if u.Path == "/server/preferences" || u.Path == "/server/preferences/import" || u.Path == "/server/preferences/export" {
		return "", false
	}
	path := u.EscapedPath()
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	return path, true
}

// ConsentHandler handles POST /server/consent — records the user's cookie consent choice.
// This is the no-JS fallback path (AI.md PART 16 "Cookie Consent Banner"): JS clients write
// the cookie_consent cookie directly via document.cookie (writeConsentCookie in app.js) and
// never hit this endpoint. The value is a JSON object of granular categories + timestamp,
// matching the client-side shape exactly, stored in a first-party "cookie_consent" cookie
// (1-year expiry, SameSite=Lax). HttpOnly is false so the same client-side JS can also read it.
func (h *PagesHandler) ConsentHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.renderErrorPage(w, r, http.StatusMethodNotAllowed, i18n.T(r.Context(), "errors.method_not_allowed"))
		return
	}
	// The preferences page submits granular=1 with one checkbox per category
	// (AI.md PART 16: consent categories must be changeable from
	// /server/preferences, not only from the first-visit banner). The banner
	// itself keeps submitting the coarse accept/decline choice.
	var preferences, analytics bool
	if r.FormValue("granular") != "" {
		preferences = isCheckboxChecked(r.FormValue("preferences"))
		analytics = isCheckboxChecked(r.FormValue("analytics"))
	} else {
		choice := r.FormValue("choice")
		if choice != "accept" && choice != "decline" {
			choice = "decline"
		}
		accepted := choice == "accept"
		preferences, analytics = accepted, accepted
	}
	consent := struct {
		Essential   bool  `json:"essential"`
		Preferences bool  `json:"preferences"`
		Analytics   bool  `json:"analytics"`
		Timestamp   int64 `json:"timestamp"`
	}{
		Essential:   true,
		Preferences: preferences,
		Analytics:   analytics,
		Timestamp:   time.Now().UnixMilli(),
	}
	value, err := json.Marshal(consent)
	if err != nil {
		h.renderErrorPage(w, r, http.StatusInternalServerError, i18n.T(r.Context(), "errors.server_error"))
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
		Secure:   isSecurePreferenceRequest(r, h.Trust),
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
		h.renderErrorPage(w, r, http.StatusMethodNotAllowed, i18n.T(r.Context(), "errors.method_not_allowed"))
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

// ServerPreferencesUpdateHandler handles POST /server/preferences — the target
// of both the theme toggle (AI.md PART 16 "Theme Toggle" -> "HTML Structure")
// and the preferences page's theme/language selectors (AI.md PART 16
// "Client-Side Preferences": the page must be editable, not read-only). Both
// are real form submits, so switching works identically with and without
// JavaScript; the JS enhancement intercepts the submit only to avoid a full
// page reload. A field that was not submitted is left untouched, so the theme
// toggle never resets the visitor's language and vice versa.
func (h *PagesHandler) ServerPreferencesUpdateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.renderErrorPage(w, r, http.StatusMethodNotAllowed, i18n.T(r.Context(), "errors.method_not_allowed"))
		return
	}
	if submitted := r.FormValue("theme"); isValidTheme(submitted) {
		setThemeCookie(w, r, h.Trust, normalizeThemeValue(submitted))
	}
	if submitted := r.FormValue("lang"); submitted != "" {
		if canonical := canonicalPreferenceLanguage(submitted); canonical != "" {
			setLangPreferenceCookie(w, r, h.Trust, canonical)
		}
	}
	if submitted := r.FormValue(lookupWidgetPreferenceCookie); submitted != "" {
		setLookupWidgetPreference(w, r, h.Trust, submitted)
	}
	ref := preferencesRedirectTarget(r, h.Trust)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Location", ref)
	w.WriteHeader(http.StatusSeeOther)
}

// normalizeThemeValue validates a submitted theme against the allowed enum
// (AI.md PART 16 "Client-Side Preferences"), falling back to the project
// default for anything unknown or malformed.
func isValidTheme(theme string) bool {
	return theme == "light" || theme == "dark" || theme == "auto"
}

func normalizeThemeValue(theme string) string {
	switch theme {
	case "light", "dark", "auto":
		return theme
	default:
		return "dark"
	}
}

// setThemeCookie writes the visitor's theme cookie. Shared by the web form
// handler and its JSON API mirror so both persist the preference identically.
func setThemeCookie(w http.ResponseWriter, r *http.Request, trust *netutil.TrustResolver, theme string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "theme",
		Value:    theme,
		Path:     "/",
		MaxAge:   365 * 24 * 60 * 60,
		HttpOnly: false,
		SameSite: http.SameSiteLaxMode,
		Secure:   isSecurePreferenceRequest(r, trust),
	})
}

func setLangPreferenceCookie(w http.ResponseWriter, r *http.Request, trust *netutil.TrustResolver, lang string) {
	http.SetCookie(w, &http.Cookie{
		Name: "lang", Value: lang, Path: "/", MaxAge: 365 * 24 * 60 * 60,
		SameSite: http.SameSiteLaxMode, Secure: isSecurePreferenceRequest(r, trust),
	})
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
	// ConsentPreferences and ConsentAnalytics are the visitor's current
	// cookie-consent category choices, so the page can render them as
	// pre-checked toggles the visitor can change here rather than only from
	// the first-visit banner (AI.md PART 16 "Client-Side Preferences").
	ConsentPreferences bool
	ConsentAnalytics   bool
}

// isCheckboxChecked reports whether a submitted checkbox field means "on".
// An unchecked box is omitted from the form body entirely, so the empty string
// is the normal "off" case; anything else goes through the project's shared
// truthy parser, and an unrecognized value fails closed.
func isCheckboxChecked(value string) bool {
	if value == "" {
		return false
	}
	checked, err := config.ParseBool(value, false)
	return err == nil && checked
}

// consentCategories reads the granular category flags out of the
// cookie_consent cookie. A missing, malformed, or URL-escaped-but-unparseable
// cookie reports both categories as off — the fail-closed default the consent
// banner itself starts from.
func consentCategories(r *http.Request) (preferences, analytics bool) {
	c, err := r.Cookie("cookie_consent")
	if err != nil || c.Value == "" {
		return false, false
	}
	raw, err := url.QueryUnescape(c.Value)
	if err != nil {
		return false, false
	}
	var stored struct {
		Preferences bool `json:"preferences"`
		Analytics   bool `json:"analytics"`
	}
	if err := json.Unmarshal([]byte(raw), &stored); err != nil {
		return false, false
	}
	return stored.Preferences, stored.Analytics
}

// ServerPreferencesHandler serves GET /server/preferences — a minimal
// server-rendered page showing the visitor's current theme/lang and a link
// to the export action (No-JS-first: the export link/copy button works
// without JavaScript; JS only adds copy-to-clipboard convenience).
func (h *PagesHandler) ServerPreferencesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	base := h.NewPageData(r)
	export := h.buildPreferencesExport(r)
	consentPreferences, consentAnalytics := consentCategories(r)
	data := PreferencesPageData{
		PageData:              base,
		PreferencesExportURL:  export.URL,
		PreferencesExportCode: export.Code,
		ConsentPreferences:    consentPreferences,
		ConsentAnalytics:      consentAnalytics,
	}
	h.renderNegotiated(w, r, "preferences.tmpl", data, PreferencesResponse{
		Theme: export.Theme,
		Lang:  export.Lang,
		Prefs: export.Prefs,
	})
}

// PreferencesResponse is the JSON shape for GET
// /api/{api_version}/server/preferences.
type PreferencesResponse struct {
	Theme   string            `json:"theme"`
	Lang    string            `json:"lang"`
	Prefs   map[string]string `json:"prefs"`
	Applied []string          `json:"applied,omitempty"`
	Ignored []string          `json:"ignored,omitempty"`
}

// APIV1ServerPreferencesHandler serves /api/{api_version}/server/preferences (JSON).
func (h *PagesHandler) APIV1ServerPreferencesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	export := h.buildPreferencesExport(r)
	SendAPIResponseOK(w, PreferencesResponse{
		Theme: export.Theme,
		Lang:  export.Lang,
		Prefs: export.Prefs,
	}, nil)
}

// APIV1ServerPreferencesUpdateHandler serves POST
// /api/{api_version}/server/preferences — the JSON mirror of the web form
// POST /server/preferences (AI.md PART 14 "Frontend Must Match Backend").
// It accepts either a JSON body or a form-encoded body, persists the theme
// cookie exactly as the web handler does, and answers with the updated
// preferences instead of a redirect.
func (h *PagesHandler) APIV1ServerPreferencesUpdateHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var submitted struct {
		Theme string            `json:"theme"`
		Lang  string            `json:"lang"`
		Prefs map[string]string `json:"prefs"`
	}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		var fields map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&fields); err == nil {
			encoded, _ := json.Marshal(fields)
			_ = json.Unmarshal(encoded, &submitted)
			if raw, ok := fields[lookupWidgetPreferenceCookie]; ok {
				var value string
				if json.Unmarshal(raw, &value) == nil {
					if submitted.Prefs == nil {
						submitted.Prefs = map[string]string{}
					}
					submitted.Prefs["widget"] = value
				}
			}
		}
	} else {
		submitted.Theme = r.FormValue("theme")
		submitted.Lang = r.FormValue("lang")
		if value := r.FormValue(lookupWidgetPreferenceCookie); value != "" {
			submitted.Prefs = map[string]string{"widget": value}
		}
	}
	theme, lang := h.currentTheme(r), i18n.DetectLocale(r)
	prefs := currentLookupPreferences(r)
	appliedNames := []string{}
	ignored := []string{}
	if submitted.Theme != "" {
		if isValidTheme(submitted.Theme) {
			theme = submitted.Theme
			setThemeCookie(w, r, h.Trust, theme)
			appliedNames = append(appliedNames, "theme")
		} else {
			ignored = append(ignored, "theme")
		}
	}
	if submitted.Lang != "" {
		if canonical := canonicalPreferenceLanguage(submitted.Lang); canonical != "" {
			lang = canonical
			setLangPreferenceCookie(w, r, h.Trust, lang)
			appliedNames = append(appliedNames, "lang")
		} else {
			ignored = append(ignored, "lang")
		}
	}
	for key, value := range submitted.Prefs {
		if key == "widget" && validLookupWidget(value) {
			prefs[key] = value
			setLookupWidgetPreference(w, r, h.Trust, value)
			appliedNames = append(appliedNames, lookupWidgetPreferenceCookie)
		} else {
			ignored = append(ignored, "ipgaze_pref_"+key)
		}
	}
	if len(appliedNames) == 0 {
		SendAPIResponseError(w, http.StatusBadRequest, "VALIDATION_FAILED", "No valid preference values were supplied", nil)
		return
	}
	SendAPIResponseOK(w, PreferencesResponse{
		Theme: theme, Lang: lang, Prefs: prefs, Applied: appliedNames, Ignored: ignored,
	}, nil)
}

// preferencesExport holds the two representations of the visitor's
// exportable preferences (theme + lang only), shared by the web export page
// and its JSON API mirror.
type preferencesExport struct {
	Theme string
	Lang  string
	Prefs map[string]string
	URL   string
	Code  string
}

// buildPreferencesExport reads the visitor's current theme/lang cookies and
// renders both the full import URL and its base64url-encoded short code
// (AI.md PART 16 "Cross-device preference sync").
func (h *PagesHandler) buildPreferencesExport(r *http.Request) preferencesExport {
	return h.buildPreferencesExportFor(r, h.currentTheme(r), i18n.DetectLocale(r), currentLookupPreferences(r))
}

// buildPreferencesExportFor renders the export representations for an
// explicit theme/lang pair rather than the request's current cookies. The
// preference-update API mirror needs this: the cookie it just set is on the
// response, so re-reading the request would still report the old value.
func (h *PagesHandler) buildPreferencesExportFor(r *http.Request, theme, lang string, prefs map[string]string) preferencesExport {
	values := url.Values{"theme": {theme}, "lang": {lang}}
	for key, value := range prefs {
		if key == "widget" && validLookupWidget(value) {
			values.Set(lookupWidgetPreferenceCookie, value)
		}
	}
	query := values.Encode()
	fullURL := netutil.BuildURL(r, h.Trust, "/server/preferences/import?"+query)
	code := base64.RawURLEncoding.EncodeToString([]byte(query))
	return preferencesExport{Theme: theme, Lang: lang, Prefs: prefs, URL: fullURL, Code: code}
}

// ServerPreferencesExportHandler serves GET /server/preferences/export — the
// same preferences.tmpl page as ServerPreferencesHandler (it already shows
// the export URL/code), so a direct link to the export sub-route lands on
// working, No-JS-first content rather than a JSON-only response (AI.md PART
// 16 "Cross-device preference sync" -> "Export").
func (h *PagesHandler) ServerPreferencesExportHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	export := h.buildPreferencesExport(r)
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		SendAPIResponseOK(w, PreferencesExportResponse(export), nil)
		return
	}
	if strings.Contains(accept, "text/plain") && !strings.Contains(accept, "text/html") {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = fmt.Fprintf(w, "URL: %s\nCode: %s\n", export.URL, export.Code)
		return
	}
	h.ServerPreferencesHandler(w, r)
}

// APIV1ServerPreferencesExportHandler serves
// /api/{api_version}/server/preferences/export (JSON).
func (h *PagesHandler) APIV1ServerPreferencesExportHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	export := h.buildPreferencesExport(r)
	SendAPIResponseOK(w, PreferencesExportResponse(export), nil)
}

type PreferencesExportResponse struct {
	Theme string            `json:"theme"`
	Lang  string            `json:"lang"`
	Prefs map[string]string `json:"prefs"`
	URL   string            `json:"url"`
	Code  string            `json:"code"`
}

func currentLookupPreferences(r *http.Request) map[string]string {
	cookie, err := r.Cookie(lookupWidgetPreferenceCookie)
	if err != nil || !validLookupWidget(cookie.Value) {
		return map[string]string{}
	}
	return map[string]string{"widget": cookie.Value}
}

// decodePreferencesCode decodes a base64url short code produced by
// buildPreferencesExport back into its theme/lang query values. Returns an
// empty url.Values on any decode failure — malformed codes are simply
// treated as carrying no preferences to import, never a hard error.
func decodePreferencesCode(code string) url.Values {
	raw, err := base64.RawURLEncoding.DecodeString(code)
	if err != nil {
		raw, err = base64.URLEncoding.DecodeString(code)
		if err != nil {
			return url.Values{}
		}
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
func (h *PagesHandler) resolvePreferencesImport(r *http.Request) (theme, lang string, prefs map[string]string, applied, ignored []string) {
	q := r.URL.Query()
	if code := strings.TrimSpace(q.Get("code")); code != "" {
		if len(code) > 2048 {
			ignored = append(ignored, "code")
		} else {
			if idx := strings.Index(code, "?"); idx >= 0 {
				code = code[idx+1:]
			}
			decoded := url.Values{}
			firstKey := strings.SplitN(code, "=", 2)[0]
			isPlainQuery := strings.Contains(code, "&") || firstKey == "theme" || firstKey == "lang" || strings.HasPrefix(firstKey, "ipgaze_pref_") || (strings.Contains(code, "=") && !strings.HasSuffix(code, "="))
			if isPlainQuery {
				decoded, _ = url.ParseQuery(code)
			} else if code != "" {
				decoded = decodePreferencesCode(code)
			}
			if len(decoded) == 0 {
				ignored = append(ignored, "code")
			}
			for key, values := range decoded {
				if _, exists := q[key]; !exists && len(values) > 0 {
					q.Set(key, values[0])
				}
			}
		}
	}
	keys := make([]string, 0, len(q))
	for key := range q {
		if key != "code" && key != "redirect" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	if len(keys) > 32 {
		ignored = append(ignored, keys[32:]...)
		keys = keys[:32]
	}
	theme, lang = h.currentTheme(r), i18n.DetectLocale(r)
	prefs = currentLookupPreferences(r)
	for _, key := range keys {
		values := q[key]
		if len(values) == 0 {
			ignored = append(ignored, key)
			continue
		}
		value := values[0]
		if len(value) > 64 {
			ignored = append(ignored, key)
			continue
		}
		switch key {
		case "theme":
			if isValidTheme(value) {
				theme = value
				applied = append(applied, key)
			} else {
				ignored = append(ignored, key)
			}
		case "lang":
			canonical := canonicalPreferenceLanguage(value)
			if canonical != "" {
				lang = canonical
				applied = append(applied, key)
			} else {
				ignored = append(ignored, key)
			}
		case lookupWidgetPreferenceCookie:
			if validLookupWidget(value) {
				prefs["widget"] = value
				applied = append(applied, key)
			} else {
				ignored = append(ignored, key)
			}
		default:
			ignored = append(ignored, key)
		}
	}
	if applied == nil {
		applied = []string{}
	}
	if ignored == nil {
		ignored = []string{}
	}
	return theme, lang, prefs, applied, ignored
}

func canonicalPreferenceLanguage(candidate string) string {
	for _, supported := range i18n.AvailableLanguages() {
		if strings.EqualFold(candidate, supported.Code) {
			return supported.Code
		}
	}
	if base, _, ok := strings.Cut(candidate, "-"); ok {
		for _, supported := range i18n.AvailableLanguages() {
			if strings.EqualFold(base, supported.Code) {
				return supported.Code
			}
		}
	}
	return ""
}

func containsPreference(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
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
	theme, lang, prefs, applied, _ := h.resolvePreferencesImport(r)
	secure := isSecurePreferenceRequest(r, h.Trust)
	if containsPreference(applied, "theme") {
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
	if containsPreference(applied, "lang") {
		setLangPreferenceCookie(w, r, h.Trust, lang)
	}
	if containsPreference(applied, lookupWidgetPreferenceCookie) {
		if value := prefs["widget"]; value != "" {
			setLookupWidgetPreference(w, r, h.Trust, value)
		}
	}
	ref := preferencesRedirectTarget(r, h.Trust)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Location", ref)
	w.WriteHeader(http.StatusSeeOther)
}

// PreferencesImportResponse is the JSON shape for GET
// /api/{api_version}/server/preferences/import — confirms which values were
// actually applied (empty string means the corresponding param was missing,
// unknown, or malformed and was dropped).
type PreferencesImportResponse struct {
	Theme   string            `json:"theme"`
	Lang    string            `json:"lang"`
	Prefs   map[string]string `json:"prefs"`
	Applied []string          `json:"applied"`
	Ignored []string          `json:"ignored"`
}

// APIV1ServerPreferencesImportHandler serves
// /api/{api_version}/server/preferences/import (JSON). Unlike the web path
// it does not redirect — it sets whichever cookies validated and returns a
// JSON confirmation of what was applied.
func (h *PagesHandler) APIV1ServerPreferencesImportHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	theme, lang, prefs, applied, ignored := h.resolvePreferencesImport(r)
	secure := isSecurePreferenceRequest(r, h.Trust)
	if containsPreference(applied, "theme") {
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
	if containsPreference(applied, "lang") {
		setLangPreferenceCookie(w, r, h.Trust, lang)
	}
	if containsPreference(applied, lookupWidgetPreferenceCookie) {
		if value := prefs["widget"]; value != "" {
			setLookupWidgetPreference(w, r, h.Trust, value)
		}
	}
	SendAPIResponseOK(w, PreferencesImportResponse{Theme: theme, Lang: lang, Prefs: prefs, Applied: applied, Ignored: ignored}, nil)
}

// DismissAnnouncementHandler handles POST /announcements/dismiss.
// Appends the given announcement ID to the "dismissed_announcements" cookie.
// JS path: responds 204 No Content so JS can remove the banner without a page reload.
// No-JS path: detects text/html Accept header and redirects (PRG pattern) back to referrer.
func (h *PagesHandler) DismissAnnouncementHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.renderErrorPage(w, r, http.StatusMethodNotAllowed, i18n.T(r.Context(), "errors.method_not_allowed"))
		return
	}
	id := strings.TrimSpace(r.FormValue("id"))
	if id == "" {
		h.renderErrorPage(w, r, http.StatusBadRequest, i18n.T(r.Context(), "errors.bad_request"))
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
