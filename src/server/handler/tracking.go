package handler

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/apimgr/ipgaze/src/config"
	"github.com/apimgr/ipgaze/src/netutil"
)

func (h *PagesHandler) analyticsTracking(r *http.Request) (bool, string) {
	if h.Config == nil {
		return false, ""
	}
	tracking := h.Config.Server.Tracking
	if err := config.ValidateTracking(&tracking); err != nil || tracking.Type == "" || tracking.Type == "none" {
		return false, ""
	}
	if !h.analyticsConsentAllowed(r) {
		return false, ""
	}

	sourceURL := analyticsScriptURL(tracking)
	if sourceURL == "" || !analyticsSourceAllowed(r, h.Trust, h.Config.Web.CSP, sourceURL) {
		return false, ""
	}
	return true, sourceURL
}

func (h *PagesHandler) analyticsNoScriptAllowed(r *http.Request) bool {
	if h.Config == nil || !strings.EqualFold(strings.TrimSpace(h.Config.Server.Tracking.Type), "simple") || !h.analyticsConsentAllowed(r) {
		return false
	}
	const pixelURL = "https://queue.simpleanalyticscdn.com/noscript.gif"
	parsed, err := url.Parse(pixelURL)
	if err != nil {
		return false
	}
	origin, err := url.Parse(netutil.BuildURL(r, h.Trust, ""))
	if err != nil {
		return false
	}
	sameOrigin := strings.EqualFold(parsed.Scheme, origin.Scheme) && strings.EqualFold(parsed.Host, origin.Host)
	if netutil.IsTorRequest(r, h.Trust) {
		return sameOrigin
	}
	if parsed.Scheme != "https" && !sameOrigin {
		return false
	}
	csp := h.Config.Web.CSP
	if !csp.Enabled || strings.EqualFold(strings.TrimSpace(csp.Mode), "report-only") {
		return true
	}
	sources := strings.TrimSpace(csp.ImgSrcOverride)
	if sources == "" {
		sources = "'self' data: blob: https: " + csp.ImgSrcExtra
	}
	for _, sourceRule := range strings.Fields(sources) {
		if sourceRule == "*" || sourceRule == "https:" && parsed.Scheme == "https" ||
			sourceRule == "'self'" && sameOrigin || cspHostSourceMatches(sourceRule, parsed) {
			return true
		}
	}
	return false
}

func (h *PagesHandler) analyticsConsentAllowed(r *http.Request) bool {
	if h.Config == nil || !h.Config.Server.Privacy.Cookies.Analytics.Enabled || hasCCPAOptOutCookie(r) || strings.TrimSpace(r.Header.Get("Sec-GPC")) == "1" || !hasConsentCookie(r) {
		return false
	}
	_, analytics := consentCategories(r)
	return analytics
}

func analyticsScriptURL(tracking config.TrackingConfig) string {
	base := strings.TrimRight(tracking.URL, "/")
	switch tracking.Type {
	case "google":
		if strings.HasPrefix(tracking.ID, "G-") {
			return "https://www.googletagmanager.com/gtag/js"
		}
		return "https://www.google-analytics.com/analytics.js"
	case "matomo", "piwik":
		return base + "/matomo.js"
	case "owa":
		return base + "/modules/base/js/owa.tracker-combined-min.js"
	case "fathom":
		if base != "" {
			return base + "/tracker.js"
		}
		return "https://cdn.usefathom.com/script.js"
	case "plausible":
		if base != "" {
			return base + "/js/script.js"
		}
		return "https://plausible.io/js/script.js"
	case "umami":
		return base + "/script.js"
	case "simple":
		return "https://scripts.simpleanalyticscdn.com/latest.js"
	case "cloudflare":
		return "https://static.cloudflareinsights.com/beacon.min.js"
	default:
		return ""
	}
}

func analyticsSourceAllowed(r *http.Request, trust *netutil.TrustResolver, csp config.CSPConfig, source string) bool {
	parsed, err := url.Parse(source)
	if err != nil || !parsed.IsAbs() || parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return false
	}
	origin, err := url.Parse(netutil.BuildURL(r, trust, ""))
	if err != nil {
		return false
	}
	sameOrigin := strings.EqualFold(parsed.Scheme, origin.Scheme) && strings.EqualFold(parsed.Host, origin.Host)
	if netutil.IsTorRequest(r, trust) {
		return sameOrigin
	}
	if parsed.Scheme != "https" && !sameOrigin {
		return false
	}
	if !csp.Enabled || strings.EqualFold(strings.TrimSpace(csp.Mode), "report-only") {
		return true
	}
	sources := strings.TrimSpace(csp.ScriptSrcOverride)
	if sources == "" {
		sources = "'self' " + csp.ScriptSrcExtra
	}
	for _, sourceRule := range strings.Fields(sources) {
		if sourceRule == "*" || sourceRule == "https:" && parsed.Scheme == "https" ||
			sourceRule == "'self'" && sameOrigin || cspHostSourceMatches(sourceRule, parsed) {
			return true
		}
	}
	return false
}

func cspHostSourceMatches(sourceRule string, source *url.URL) bool {
	if sourceRule == "" || strings.HasPrefix(sourceRule, "'") || sourceRule == "data:" || sourceRule == "blob:" {
		return false
	}
	rule, err := url.Parse(sourceRule)
	if err != nil || !rule.IsAbs() || rule.Hostname() == "" || rule.User != nil || rule.RawQuery != "" || rule.Fragment != "" || !strings.EqualFold(rule.Scheme, source.Scheme) {
		return false
	}
	ruleHost := strings.ToLower(rule.Hostname())
	sourceHost := strings.ToLower(source.Hostname())
	if strings.HasPrefix(ruleHost, "*.") {
		suffix := strings.TrimPrefix(ruleHost, "*")
		if !strings.HasSuffix(sourceHost, suffix) || sourceHost == strings.TrimPrefix(suffix, ".") {
			return false
		}
	} else if !strings.EqualFold(rule.Hostname(), source.Hostname()) {
		return false
	}
	if rule.Port() != "" && rule.Port() != source.Port() {
		return false
	}
	rulePath := rule.EscapedPath()
	if rulePath != "" && rulePath != "/" {
		sourcePath := source.EscapedPath()
		if strings.HasSuffix(rulePath, "/") {
			if !strings.HasPrefix(sourcePath, rulePath) {
				return false
			}
		} else if sourcePath != rulePath {
			return false
		}
	}
	return true
}
