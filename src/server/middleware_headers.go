package server

import (
	"net/http"
	"sort"
	"strings"

	"github.com/apimgr/ipgaze/src/config"
)

// cspExtraOverride pairs the *_extra and *_override config values for one
// CSP directive so they can be applied in a single pass.
type cspExtraOverride struct {
	extra    string
	override string
}

// SecurityHeaderConfigFromApp overlays the operator's server.yml `web.*`
// security settings on top of the AI.md PART 11 defaults. A nil config (or an
// unset field) leaves the corresponding default in place, so a fresh install
// with zero config still emits the full spec-mandated header set.
func SecurityHeaderConfigFromApp(cfg *config.AppConfig) SecurityHeaderConfig {
	headerCfg := DefaultSecurityHeaderConfig()
	if cfg == nil {
		return headerCfg
	}

	applyHSTSConfig(&headerCfg, cfg.Web.HSTS)
	applyCSPConfig(&headerCfg, cfg.Web.CSP)
	applyPermissionsPolicyConfig(&headerCfg, cfg.Web.PermissionsPolicy)
	applyMiscHeaderConfig(&headerCfg, cfg.Web.Headers)
	applyNELConfig(&headerCfg, cfg.Web.Headers.NEL)

	return headerCfg
}

// applyHSTSConfig overlays web.hsts. MaxAgeSeconds of 0 keeps the default,
// since a zero max-age would silently disable HSTS on an unset key.
func applyHSTSConfig(target *SecurityHeaderConfig, hsts config.HSTSConfig) {
	target.HSTS.Enabled = hsts.Enabled
	target.HSTS.IncludeSubdomains = hsts.IncludeSubdomains
	target.HSTS.Preload = hsts.Preload
	if hsts.MaxAgeSeconds > 0 {
		target.HSTS.MaxAgeSeconds = hsts.MaxAgeSeconds
	}
}

// applyCSPConfig overlays web.csp: the mode plus the per-directive
// *_extra / *_override keys, and drops the reporting directives when
// reports_enabled is false.
func applyCSPConfig(target *SecurityHeaderConfig, csp config.CSPConfig) {
	target.CSP.Enabled = csp.Enabled
	target.CSP.Mode = csp.Mode

	adjustments := map[string]cspExtraOverride{
		"script-src":  {csp.ScriptSrcExtra, csp.ScriptSrcOverride},
		"style-src":   {csp.StyleSrcExtra, csp.StyleSrcOverride},
		"img-src":     {csp.ImgSrcExtra, csp.ImgSrcOverride},
		"font-src":    {csp.FontSrcExtra, csp.FontSrcOverride},
		"connect-src": {csp.ConnectSrcExtra, csp.ConnectSrcOverride},
		"frame-src":   {csp.FrameSrcExtra, csp.FrameSrcOverride},
		"form-action": {csp.FormActionExtra, csp.FormActionOverride},
	}

	directives := make([]CSPDirective, 0, len(target.CSP.Directives))
	for _, directive := range target.CSP.Directives {
		if !csp.ReportsEnabled && (directive.Name == "report-to" || directive.Name == "report-uri") {
			continue
		}
		if adjustment, ok := adjustments[directive.Name]; ok {
			directive.Extra = strings.TrimSpace(adjustment.extra)
			directive.Override = strings.TrimSpace(adjustment.override)
		}
		directives = append(directives, directive)
	}
	target.CSP.Directives = directives
}

// applyPermissionsPolicyConfig replaces the default feature list with the
// operator's map, emitted in a stable alphabetical order. An empty map keeps
// the defaults so a truncated config cannot silently drop the whole header.
func applyPermissionsPolicyConfig(target *SecurityHeaderConfig, features map[string]string) {
	if len(features) == 0 {
		return
	}
	names := make([]string, 0, len(features))
	for name := range features {
		names = append(names, name)
	}
	sort.Strings(names)

	policy := make([]PermissionsPolicyFeature, 0, len(names))
	for _, name := range names {
		policy = append(policy, PermissionsPolicyFeature{Feature: name, Value: features[name]})
	}
	target.PermissionsPolicy = policy
}

// applyMiscHeaderConfig overlays web.headers. Empty string values are honoured
// as "omit this header" per AI.md PART 11's generation rule.
func applyMiscHeaderConfig(target *SecurityHeaderConfig, headers config.SecurityHeadersConfig) {
	target.Headers.ContentTypeOptions = headers.ContentTypeOptions
	target.Headers.FrameOptions = headers.FrameOptions
	target.Headers.XSSProtection = headers.XSSProtection
	target.Headers.ReferrerPolicy = headers.ReferrerPolicy
	target.Headers.COOP = headers.COOP
	target.Headers.COEP = headers.COEP
	target.Headers.CORP = headers.CORP
	target.Headers.OriginAgentCluster = headers.OriginAgentCluster
	target.Headers.CrossDomainPolicies = headers.CrossDomainPolicies
	target.Headers.DNSPrefetchControl = headers.DNSPrefetchControl
}

// applyNELConfig overlays web.headers.nel. As with HSTS, a zero max_age keeps
// the default rather than publishing an immediately-expiring policy.
func applyNELConfig(target *SecurityHeaderConfig, nel config.NELConfig) {
	target.NEL.Enabled = nel.Enabled
	target.NEL.IncludeSubdomains = nel.IncludeSubdomains
	if nel.MaxAgeSeconds > 0 {
		target.NEL.MaxAgeSeconds = nel.MaxAgeSeconds
	}
	if nel.SampleRate > 0 && nel.SampleRate <= 1.0 {
		target.NEL.SampleRate = nel.SampleRate
	}
}

// onionLocationWriter withdraws a pre-set Onion-Location header once the real
// status and content type are known. The header is only valid on 2xx HTML
// document responses, never on redirects, errors, or non-HTML bodies
// (AI.md PART 31 "Onion-Location Advertisement").
type onionLocationWriter struct {
	http.ResponseWriter
	wroteHeader bool
}

// WriteHeader drops the advertisement unless the response really is 2xx HTML.
func (w *onionLocationWriter) WriteHeader(statusCode int) {
	if !w.wroteHeader {
		w.wroteHeader = true
		contentType := w.Header().Get("Content-Type")
		htmlResponse := strings.HasPrefix(strings.ToLower(contentType), "text/html")
		if statusCode < 200 || statusCode >= 300 || !htmlResponse {
			w.Header().Del("Onion-Location")
		}
	}
	w.ResponseWriter.WriteHeader(statusCode)
}

// Flush forwards to the wrapped writer so streaming responses keep working.
func (w *onionLocationWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// isOnionLocationCandidate reports whether the request is a clearnet top-level
// navigation that may carry the advertisement. Requests already arriving over
// the hidden service, API calls, and subresource fetches are excluded.
func isOnionLocationCandidate(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	host := strings.ToLower(r.Host)
	if idx := strings.IndexByte(host, ':'); idx >= 0 {
		host = host[:idx]
	}
	if strings.HasSuffix(host, ".onion") {
		return false
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		return false
	}
	switch dest := r.Header.Get("Sec-Fetch-Dest"); dest {
	case "document", "iframe", "frame":
		return true
	case "":
		return strings.Contains(r.Header.Get("Accept"), "text/html")
	default:
		return false
	}
}

// OnionLocationMiddleware advertises the hidden service on clearnet HTML
// document responses (AI.md PART 31 "Onion-Location Advertisement"). The
// address is resolved per request so it appears as soon as the hidden service
// finishes publishing, without a restart. The value always uses http:// —
// onion addresses are already authenticated and encrypted by the Tor protocol.
func OnionLocationMiddleware(onionAddress func() string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			address := ""
			if onionAddress != nil {
				address = strings.TrimSpace(onionAddress())
			}
			if address == "" || !isOnionLocationCandidate(r) {
				next.ServeHTTP(w, r)
				return
			}
			target := "http://" + address + r.URL.RequestURI()
			w.Header().Set("Onion-Location", target)
			next.ServeHTTP(&onionLocationWriter{ResponseWriter: w}, r)
		})
	}
}

// resolveOnionAddress returns the live hidden-service hostname, or "" when Tor
// is not running. It reads TorStatus rather than config.Tor.OnionAddress
// because that config field is never populated once the service publishes.
func (s *Server) resolveOnionAddress() string {
	if s.TorStatus == nil || !s.TorStatus.IsAvailable() || !s.TorStatus.IsRunning() {
		return ""
	}
	return s.TorStatus.GetHostname()
}
