package server

import (
	"net/http"
	"strings"

	"github.com/apimgr/ipgaze/src/config"
	"github.com/apimgr/ipgaze/src/netutil"
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
	applyContactCaptchaCSP(&headerCfg, cfg.Pages.Contact.Captcha)
	applyMiscHeaderConfig(&headerCfg, cfg.Web.Headers)
	applyNELConfig(&headerCfg, cfg.Web.Headers.NEL)

	return headerCfg
}

func applyContactCaptchaCSP(target *SecurityHeaderConfig, provider string) {
	var hosts string
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "recaptcha":
		hosts = "https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/ https://www.recaptcha.net/recaptcha/"
	case "hcaptcha":
		hosts = "https://hcaptcha.com https://*.hcaptcha.com"
	default:
		return
	}
	for i := range target.CSP.Directives {
		switch target.CSP.Directives[i].Name {
		case "script-src", "frame-src", "connect-src":
			target.CSP.Directives[i].Extra = strings.TrimSpace(target.CSP.Directives[i].Extra + " " + hosts)
		}
	}
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

// Write preserves net/http's implicit status and content-type detection while
// applying the advertisement's response checks.
func (w *onionLocationWriter) Write(body []byte) (int, error) {
	if !w.wroteHeader {
		if w.Header().Get("Content-Type") == "" && len(body) > 0 {
			probe := body
			if len(probe) > 512 {
				probe = probe[:512]
			}
			w.Header().Set("Content-Type", http.DetectContentType(probe))
		}
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(body)
}

// Flush forwards to the wrapped writer so streaming responses keep working.
func (w *onionLocationWriter) Flush() {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
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
			onionRequest := r.Clone(r.Context())
			onionRequest.Host = address
			target := netutil.BuildURL(onionRequest, &netutil.TrustResolver{OnionAddress: address}, r.URL.RequestURI())
			w.Header().Set("Onion-Location", target)
			wrapped := &onionLocationWriter{ResponseWriter: w}
			next.ServeHTTP(wrapped, r)
			if !wrapped.wroteHeader {
				w.Header().Del("Onion-Location")
			}
		})
	}
}

// resolveOnionAddress returns the published hidden-service hostname only when
// the operator enabled onion-address exposure.
func (s *Server) resolveOnionAddress() string {
	if s.config == nil || !s.config.Server.Tor.Expose || s.TorStatus == nil || !s.TorStatus.IsAvailable() || !s.TorStatus.IsRunning() {
		return ""
	}
	return strings.TrimSpace(s.config.Tor.OnionAddress)
}
