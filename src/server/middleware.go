package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/apimgr/ipgaze/src/common/i18n"
	applog "github.com/apimgr/ipgaze/src/log"
	"github.com/apimgr/ipgaze/src/netutil"
	paths "github.com/apimgr/ipgaze/src/path"
	"github.com/google/uuid"
)

// sanitizeLogValue strips CR/LF and other control characters from a client-supplied
// string before it is written to any log sink (stdout, access log, structured/audit
// log). Without this a header such as User-Agent or Referer containing "\n" can forge
// extra log lines (log injection / log forging). Non-printable bytes are dropped
// rather than escaped to keep log lines simple to parse; the value is also truncated
// to a sane length so a single header can't blow up log line size.
func sanitizeLogValue(s string) string {
	if s == "" {
		return s
	}
	const maxLogValueLen = 512
	b := make([]rune, 0, len(s))
	for _, r := range s {
		if r == '\n' || r == '\r' || (r < 0x20 && r != '\t') || r == 0x7f {
			continue
		}
		b = append(b, r)
		if len(b) >= maxLogValueLen {
			break
		}
	}
	return string(b)
}

// langContextKey is the context key for the resolved locale string.
type langContextKey struct{}

// requestIDContextKey is the context key for the per-request UUID.
type requestIDContextKey struct{}

// RequestIDMiddleware reads X-Request-ID from the incoming request or generates a fresh UUID,
// stores it in the request context, and echoes it back in the response header.
// This MUST be step 2 in the middleware chain (after URLNormalize, before PathSecurity),
// so that every downstream middleware and the logger can read the same ID.
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}
		ctx := context.WithValue(r.Context(), requestIDContextKey{}, requestID)
		w.Header().Set("X-Request-ID", requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequestIDFromContext retrieves the request ID stored by RequestIDMiddleware.
// Returns an empty string if the middleware was not in the chain.
func RequestIDFromContext(ctx context.Context) string {
	if id, ok := ctx.Value(requestIDContextKey{}).(string); ok {
		return id
	}
	return ""
}

// recoverResponseWriter wraps http.ResponseWriter to record whether a status
// line (and therefore any response bytes) has already gone out, so
// RecoverMiddleware knows whether it is still safe to write its own fallback
// response after a recovered panic.
type recoverResponseWriter struct {
	http.ResponseWriter
	wroteHeader bool
}

func (rw *recoverResponseWriter) WriteHeader(code int) {
	rw.wroteHeader = true
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *recoverResponseWriter) Write(b []byte) (int, error) {
	rw.wroteHeader = true
	return rw.ResponseWriter.Write(b)
}

// RecoverMiddleware is the backend mirror of the service worker's
// guaranteed-Response rule (AI.md PART 9 / PART 16): every request MUST
// terminate in a rendered response, and the failure path itself must never
// be what breaks the site. Without this middleware a panic in a handler is
// only recovered by Go's stdlib http.Server, which logs it and closes the
// connection with no response body at all — the client sees a dropped
// connection, not an error page. This middleware recovers the panic, logs
// it server-side with full request context, and — as long as no bytes have
// been written yet — falls back to a minimal, hardcoded, content-negotiated
// error response (never a template render, which could itself fail).
func RecoverMiddleware(lm *applog.Manager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rw := &recoverResponseWriter{ResponseWriter: w}
			defer recoverAndRespond(lm, rw, w, r)
			next.ServeHTTP(rw, r)
		})
	}
}

// recoverAndRespond is RecoverMiddleware's deferred body. Every panic is
// recorded in error.log with the request ID, method, path, and a sanitized
// panic value (AI.md PART 11 "error.log") before the guaranteed fallback
// response is emitted. The log write can never prevent that response.
func recoverAndRespond(lm *applog.Manager, rw *recoverResponseWriter, w http.ResponseWriter, r *http.Request) {
	rec := recover()
	if rec == nil {
		return
	}
	requestID := RequestIDFromContext(r.Context())
	detail := fmt.Sprintf("request_id=%s method=%s path=%s panic=%s",
		sanitizeLogValue(requestID), sanitizeLogValue(r.Method),
		sanitizeLogValue(r.URL.Path), sanitizeLogValue(fmt.Sprint(rec)))
	log.Printf("panic recovered: %s ip=%s", detail, r.RemoteAddr)
	if lm != nil {
		lm.WriteError("error", "panic recovered: "+detail)
	}
	if rw.wroteHeader {
		// Handler already streamed part of a response; writing a second status
		// line would be a no-op or corrupt the response further, so there is
		// nothing safe left to do.
		return
	}
	if detectClientType(r) != "html" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"ok":false,"error":"SERVER_ERROR","message":"Internal Server Error"}`+"\n")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprint(w, "<!DOCTYPE html><html><head><title>500 Internal Server Error</title></head>"+
		"<body><h1>500</h1><p>Internal Server Error</p><a href=\"/\">Home</a></body></html>")
}

// LangMiddleware detects the request locale using the priority chain from AI.md PART 30:
// ?lang= query param (sets cookie) → lang cookie → Accept-Language → "en".
// The resolved locale is stored in the request context for downstream handlers.
func LangMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lang := i18n.DetectLocale(r)

		// If ?lang= was present and valid, persist as cookie (1 year)
		if q := r.URL.Query().Get("lang"); q != "" && i18n.IsSupported(q) {
			i18n.SetLangCookie(w, r, q)
		}

		ctx := context.WithValue(r.Context(), langContextKey{}, lang)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// LangFromContext retrieves the locale resolved by LangMiddleware.
// Returns "en" if the middleware was not in the chain.
func LangFromContext(ctx context.Context) string {
	if lang, ok := ctx.Value(langContextKey{}).(string); ok && lang != "" {
		return lang
	}
	return "en"
}

// URLNormalizeMiddleware normalizes URL paths for consistent routing.
// When the normalized path differs from the original a 301 redirect is issued so
// clients and search engines always land on the canonical URL form.
// This MUST be the first middleware in the chain.
func URLNormalizeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		normalized := paths.NormalizeURLPath(r.URL.Path)
		if normalized != r.URL.Path {
			u := *r.URL
			u.Path = normalized
			http.Redirect(w, r, u.String(), http.StatusMovedPermanently)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// PathSecurityMiddleware blocks path traversal attempts.
// This MUST be third in the middleware chain (after URLNormalize and RequestID).
func PathSecurityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for path traversal patterns
		if !paths.IsPathSafe(r.URL.Path) {
			lang := i18n.DetectLocale(r)
			http.Error(w, i18n.T(i18n.WithLang(r.Context(), lang), "errors.bad_request"), http.StatusBadRequest)
			return
		}

		// Also check raw URI for encoded attacks
		if !paths.IsPathSafe(r.URL.RawPath) && r.URL.RawPath != "" {
			lang := i18n.DetectLocale(r)
			http.Error(w, i18n.T(i18n.WithLang(r.Context(), lang), "errors.bad_request"), http.StatusBadRequest)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// timingResponseWriter is a buffering http.ResponseWriter used in debug mode only.
// It captures the status code and body so that Server-Timing can be injected into the
// real response headers before any bytes are flushed to the client.
type timingResponseWriter struct {
	// wrapped is the real downstream ResponseWriter.
	wrapped http.ResponseWriter
	// buf holds the buffered response body.
	buf bytes.Buffer
	// status is the HTTP status code captured from WriteHeader.
	status int
	// headerMap is the header map captured from the inner handler.
	headerMap http.Header
}

// newTimingResponseWriter creates a timingResponseWriter that wraps w.
func newTimingResponseWriter(w http.ResponseWriter) *timingResponseWriter {
	return &timingResponseWriter{
		wrapped:   w,
		status:    http.StatusOK,
		headerMap: make(http.Header),
	}
}

// Header returns the captured header map so inner handlers write to it.
func (t *timingResponseWriter) Header() http.Header {
	return t.headerMap
}

// WriteHeader captures the status code; the real WriteHeader is deferred until flush.
func (t *timingResponseWriter) WriteHeader(code int) {
	t.status = code
}

// Write buffers the response body; the real Write is deferred until flush.
func (t *timingResponseWriter) Write(b []byte) (int, error) {
	return t.buf.Write(b)
}

// flush copies all buffered headers and body to the real ResponseWriter.
func (t *timingResponseWriter) flush() {
	dst := t.wrapped.Header()
	for k, vv := range t.headerMap {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
	t.wrapped.WriteHeader(t.status)
	_, _ = t.wrapped.Write(t.buf.Bytes())
}

// setHeaderIfSet writes a response header only when the configured value is
// non-empty; an empty value means "omit the header, browser default applies".
func setHeaderIfSet(w http.ResponseWriter, name, value string) {
	if value == "" {
		return
	}
	w.Header().Set(name, value)
}

// CSPDirective is one Content-Security-Policy directive.
// Value is the built-in default; Extra is appended to it and Override replaces
// it entirely, mirroring the web.csp.*_extra / web.csp.*_override config keys
// in AI.md PART 11. A directive with an empty resolved value (and no default)
// is emitted bare, which is how valueless directives such as
// upgrade-insecure-requests are expressed.
type CSPDirective struct {
	Name     string
	Value    string
	Extra    string
	Override string
}

// resolved returns the directive rendered as it appears in the header.
func (d CSPDirective) resolved() string {
	value := d.Value
	if d.Override != "" {
		value = d.Override
	}
	if d.Extra != "" {
		if value == "" {
			value = d.Extra
		} else {
			value += " " + d.Extra
		}
	}
	if value == "" {
		return d.Name
	}
	return d.Name + " " + value
}

// CSPHeaderConfig controls the Content-Security-Policy header per AI.md PART 11.
type CSPHeaderConfig struct {
	// Enabled emits the header at all. Default true.
	Enabled bool
	// Mode is "enforce", "report-only", or "" for automatic
	// (report-only in development/debug, enforcing otherwise).
	Mode string
	// Directives are emitted in slice order, joined with "; ".
	Directives []CSPDirective
}

// PermissionsPolicyFeature is one Permissions-Policy feature and its allowlist.
// An empty Value skips the feature entirely so the browser default applies
// (AI.md PART 11 "Generation rule").
type PermissionsPolicyFeature struct {
	Feature string
	Value   string
}

// HSTSHeaderConfig controls Strict-Transport-Security per AI.md PART 11.
type HSTSHeaderConfig struct {
	Enabled           bool
	MaxAgeSeconds     int
	IncludeSubdomains bool
	Preload           bool
}

// NELHeaderConfig controls the Network Error Logging header per AI.md PART 11.
type NELHeaderConfig struct {
	Enabled           bool
	MaxAgeSeconds     int
	IncludeSubdomains bool
	// SampleRate is 0.0..1.0 and maps to NEL's failure_fraction. It is only
	// emitted when it differs from the browser default of 1.0.
	SampleRate float64
}

// MiscHeaderConfig holds the remaining fixed-value security headers.
type MiscHeaderConfig struct {
	ContentTypeOptions  string
	FrameOptions        string
	XSSProtection       string
	ReferrerPolicy      string
	COOP                string
	COEP                string
	CORP                string
	OriginAgentCluster  bool
	CrossDomainPolicies string
	// DNSPrefetchControl is omitted when empty (browser default applies).
	DNSPrefetchControl string
}

// SecurityHeaderConfig is the full set of values SecurityHeadersMiddleware
// emits. DefaultSecurityHeaderConfig returns the spec defaults; the server
// overlays operator config from server.yml on top of it.
type SecurityHeaderConfig struct {
	HSTS              HSTSHeaderConfig
	CSP               CSPHeaderConfig
	PermissionsPolicy []PermissionsPolicyFeature
	Headers           MiscHeaderConfig
	NEL               NELHeaderConfig
	// ReportsPath is the path prefix of the public reports endpoints.
	ReportsPath string
	// ReportToMaxAgeSeconds is the Report-To group lifetime (~126 days).
	ReportToMaxAgeSeconds int
}

// DefaultSecurityHeaderConfig returns the AI.md PART 11 defaults.
func DefaultSecurityHeaderConfig() SecurityHeaderConfig {
	return SecurityHeaderConfig{
		HSTS: HSTSHeaderConfig{
			Enabled:           true,
			MaxAgeSeconds:     63072000,
			IncludeSubdomains: true,
			Preload:           true,
		},
		CSP: CSPHeaderConfig{
			Enabled: true,
			Directives: []CSPDirective{
				{Name: "default-src", Value: "'self'"},
				{Name: "script-src", Value: "'self'"},
				{Name: "style-src", Value: "'self' 'unsafe-inline'"},
				{Name: "img-src", Value: "'self' data: blob: https:"},
				{Name: "font-src", Value: "'self' https:"},
				{Name: "connect-src", Value: "'self'"},
				{Name: "media-src", Value: "'self' blob:"},
				{Name: "worker-src", Value: "'self' blob:"},
				{Name: "manifest-src", Value: "'self'"},
				{Name: "frame-src", Value: "'self' https://www.openstreetmap.org"},
				{Name: "frame-ancestors", Value: "'self'"},
				{Name: "base-uri", Value: "'self'"},
				{Name: "form-action", Value: "'self'"},
				{Name: "object-src", Value: "'none'"},
				{Name: "upgrade-insecure-requests"},
				{Name: "report-to", Value: "default"},
				{Name: "report-uri", Value: "/api/v1/server/reports/csp"},
			},
		},
		PermissionsPolicy: []PermissionsPolicyFeature{
			{Feature: "accelerometer", Value: "()"},
			{Feature: "ambient-light-sensor", Value: "()"},
			{Feature: "attribution-reporting", Value: "()"},
			{Feature: "autoplay", Value: "(self)"},
			{Feature: "battery", Value: "()"},
			{Feature: "browsing-topics", Value: "()"},
			{Feature: "camera", Value: "()"},
			{Feature: "cross-origin-isolated", Value: "()"},
			{Feature: "display-capture", Value: "()"},
			{Feature: "document-domain", Value: "()"},
			{Feature: "encrypted-media", Value: "(self)"},
			{Feature: "execution-while-not-rendered", Value: "()"},
			{Feature: "execution-while-out-of-viewport", Value: "()"},
			{Feature: "fullscreen", Value: "(self)"},
			{Feature: "geolocation", Value: "()"},
			{Feature: "gyroscope", Value: "()"},
			{Feature: "interest-cohort", Value: "()"},
			{Feature: "keyboard-map", Value: "()"},
			{Feature: "magnetometer", Value: "()"},
			{Feature: "microphone", Value: "()"},
			{Feature: "midi", Value: "()"},
			{Feature: "navigation-override", Value: "()"},
			{Feature: "payment", Value: "(self)"},
			{Feature: "picture-in-picture", Value: "(self)"},
			{Feature: "publickey-credentials-get", Value: "(self)"},
			{Feature: "screen-wake-lock", Value: "()"},
			{Feature: "storage-access", Value: "(self)"},
			{Feature: "sync-xhr", Value: "()"},
			{Feature: "usb", Value: "()"},
			{Feature: "web-share", Value: "(self)"},
			{Feature: "xr-spatial-tracking", Value: "()"},
		},
		Headers: MiscHeaderConfig{
			ContentTypeOptions: "nosniff",
			FrameOptions:       "SAMEORIGIN",
			XSSProtection:      "1; mode=block",
			ReferrerPolicy:     "strict-origin-when-cross-origin",
			// Default cross-origin isolation values per AI.md PART 11.
			// Tighten only when IDEA.md declares SharedArrayBuffer / WASM threads usage.
			COOP:                "unsafe-none",
			COEP:                "unsafe-none",
			CORP:                "cross-origin",
			OriginAgentCluster:  true,
			CrossDomainPolicies: "none",
		},
		NEL: NELHeaderConfig{
			Enabled:           true,
			MaxAgeSeconds:     2592000,
			IncludeSubdomains: true,
			SampleRate:        1.0,
		},
		ReportsPath:           "/api/v1/server/reports",
		ReportToMaxAgeSeconds: 10886400,
	}
}

// cspHeaderValue joins the configured directives into a policy string.
func (c CSPHeaderConfig) cspHeaderValue() string {
	parts := make([]string, 0, len(c.Directives))
	for _, d := range c.Directives {
		parts = append(parts, d.resolved())
	}
	return strings.Join(parts, "; ")
}

// cspHeaderName resolves enforce vs report-only. An explicit mode always wins;
// with no explicit mode, development/debug runs report-only so violations are
// logged without breaking the app (AI.md PART 11 "Report-Only Mode").
func (c CSPHeaderConfig) cspHeaderName(debug bool) string {
	switch strings.ToLower(strings.TrimSpace(c.Mode)) {
	case "enforce":
		return "Content-Security-Policy"
	case "report-only", "report_only", "reportonly":
		return "Content-Security-Policy-Report-Only"
	}
	if debug {
		return "Content-Security-Policy-Report-Only"
	}
	return "Content-Security-Policy"
}

// permissionsPolicyValue joins the configured features, skipping empty values.
func permissionsPolicyValue(features []PermissionsPolicyFeature) string {
	parts := make([]string, 0, len(features))
	for _, f := range features {
		if f.Value == "" {
			continue
		}
		parts = append(parts, f.Feature+"="+f.Value)
	}
	return strings.Join(parts, ", ")
}

// hstsHeaderValue renders Strict-Transport-Security from config.
func (h HSTSHeaderConfig) hstsHeaderValue() string {
	value := "max-age=" + strconv.Itoa(h.MaxAgeSeconds)
	if h.IncludeSubdomains {
		value += "; includeSubDomains"
	}
	if h.Preload {
		value += "; preload"
	}
	return value
}

// nelHeaderValue renders the NEL policy JSON from config.
func (n NELHeaderConfig) nelHeaderValue() string {
	value := fmt.Sprintf(`{"report_to":"default","max_age":%d,"include_subdomains":%t`,
		n.MaxAgeSeconds, n.IncludeSubdomains)
	if n.SampleRate >= 0 && n.SampleRate < 1.0 {
		value += fmt.Sprintf(`,"failure_fraction":%g`, n.SampleRate)
	}
	return value + "}"
}

// SecurityHeadersMiddleware adds security headers to all responses.
// Per AI.md PART 11, all responses MUST include these headers; every value is
// built from cfg so operator config in server.yml can adjust them without
// touching this code.
// When debug is true the Server-Timing header is also emitted (AI.md PART 13 D3);
// in production it is NEVER emitted, and CSP switches to report-only unless the
// operator pinned web.csp.mode to enforce.
func SecurityHeadersMiddleware(cfg SecurityHeaderConfig, sslEnabled, debug bool) func(http.Handler) http.Handler {
	cspValue := cfg.CSP.cspHeaderValue()
	cspName := cfg.CSP.cspHeaderName(debug)
	permissionsPolicy := permissionsPolicyValue(cfg.PermissionsPolicy)
	hsts := cfg.HSTS.hstsHeaderValue()
	nel := cfg.NEL.nelHeaderValue()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Required security headers per AI.md
			setHeaderIfSet(w, "X-Content-Type-Options", cfg.Headers.ContentTypeOptions)
			setHeaderIfSet(w, "X-Frame-Options", cfg.Headers.FrameOptions)
			setHeaderIfSet(w, "X-XSS-Protection", cfg.Headers.XSSProtection)
			setHeaderIfSet(w, "Referrer-Policy", cfg.Headers.ReferrerPolicy)
			if cfg.CSP.Enabled && cspValue != "" {
				w.Header().Set(cspName, cspValue)
			}
			setHeaderIfSet(w, "Permissions-Policy", permissionsPolicy)
			setHeaderIfSet(w, "X-Permitted-Cross-Domain-Policies", cfg.Headers.CrossDomainPolicies)
			setHeaderIfSet(w, "X-DNS-Prefetch-Control", cfg.Headers.DNSPrefetchControl)
			if cfg.Headers.OriginAgentCluster {
				w.Header().Set("Origin-Agent-Cluster", "?1")
			}
			setHeaderIfSet(w, "Cross-Origin-Opener-Policy", cfg.Headers.COOP)
			setHeaderIfSet(w, "Cross-Origin-Embedder-Policy", cfg.Headers.COEP)
			setHeaderIfSet(w, "Cross-Origin-Resource-Policy", cfg.Headers.CORP)

			// Reporting-Endpoints per AI.md PART 11.
			// Report-To max_age=10886400 (~126 days) and NEL max_age=2592000 (30 days).
			reportsEndpoint := `"https://` + r.Host + cfg.ReportsPath + `/default"`
			w.Header().Set("Reporting-Endpoints", `default=`+reportsEndpoint)
			w.Header().Set("Report-To", fmt.Sprintf(`{"group":"default","max_age":%d,"endpoints":[{"url":%s}]}`,
				cfg.ReportToMaxAgeSeconds, reportsEndpoint))
			if cfg.NEL.Enabled {
				w.Header().Set("NEL", nel)
			}

			// HSTS per AI.md PART 11: max-age=63072000 (2 years), includeSubDomains + preload.
			// Preload is ON by default (zero-config secure = commit to TLS); operators opt out
			// via web.hsts.preload: false if not yet ready for the public preload list.
			if sslEnabled && cfg.HSTS.Enabled {
				w.Header().Set("Strict-Transport-Security", hsts)
			}

			// Server-Timing header in debug mode only (AI.md D3).
			// A buffering writer captures the full inner response so the timing
			// header can be injected before any bytes reach the client.
			if debug {
				tw := newTimingResponseWriter(w)
				start := time.Now()
				next.ServeHTTP(tw, r)
				elapsed := time.Since(start)
				tw.headerMap.Set("Server-Timing", fmt.Sprintf("total;dur=%.3f", float64(elapsed.Microseconds())/1000.0))
				tw.flush()
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ChainMiddleware chains multiple middleware functions together.
// Middleware is applied in order: first middleware wraps outermost.
func ChainMiddleware(h http.Handler, middlewares ...func(http.Handler) http.Handler) http.Handler {
	// Apply in reverse order so first middleware is outermost
	for i := len(middlewares) - 1; i >= 0; i-- {
		h = middlewares[i](h)
	}
	return h
}

// healthCheckPaths are the endpoints whose successful responses are kept out
// of access.log per AI.md PART 11 "Health-Check Log Suppression" — a 10-second
// container healthcheck would otherwise write ~8,640 identical lines per day.
var healthCheckPaths = map[string]bool{
	"/api/v1/server/healthz": true,
	"/server/healthz":        true,
	"/healthz":               true,
}

// suppressAccessLog reports whether this request must be omitted from
// access.log. Only successful (2xx) GET/HEAD health checks are suppressed;
// any failure, and every request while debug is enabled, is always logged.
func suppressAccessLog(r *http.Request, status int, debug bool) bool {
	if debug {
		return false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if status < 200 || status > 299 {
		return false
	}
	return healthCheckPaths[r.URL.Path]
}

// LoggingMiddleware returns middleware that logs HTTP requests in Apache Combined Log Format.
// Client IP is resolved through trusted proxy headers when the peer is in tr per AI.md PART 11/15.
// When lm is non-nil, each request is written to access.log via the log Manager
// in the operator's configured format (apache, nginx or json).
// stdout fallback via log.Printf is always active so no request is ever lost.
// Format: IP - - [timestamp] "METHOD path protocol" status bytes "referer" "user-agent" request-id
func LoggingMiddleware(tr *netutil.TrustResolver, lm *applog.Manager, debug bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Create a response writer wrapper to capture status code and bytes
			wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			next.ServeHTTP(wrapped, r)

			// Publish request count and latency to /debug/vars (AI.md PART 12).
			// errors_total counts server-side failures only: a 4xx is the
			// client's mistake and would drown out the operator's error signal.
			recordExpvarRequest(time.Since(start))
			if wrapped.statusCode >= http.StatusInternalServerError {
				recordExpvarError()
			}

			// Resolve client IP through trusted proxy headers only.
			clientIP := netutil.GetClientIdentifier(r, tr)

			// Get referer and user-agent (use "-" if empty). Sanitized so a client
			// cannot inject CR/LF into the log stream to forge extra log lines.
			referer := sanitizeLogValue(r.Header.Get("Referer"))
			if referer == "" {
				referer = "-"
			}
			userAgent := sanitizeLogValue(r.Header.Get("User-Agent"))
			if userAgent == "" {
				userAgent = "-"
			}

			requestURI := sanitizeLogValue(r.URL.RequestURI())
			requestID := sanitizeLogValue(RequestIDFromContext(r.Context()))

			debugLogRequest(lm, debug, r, wrapped.statusCode, time.Since(start), wrapped.bytesWritten)

			suppressed := suppressAccessLog(r, wrapped.statusCode, debug)
			if lm != nil && !suppressed {
				// File-based access log in the configured format per AI.md PART 11.
				lm.WriteAccessRequest(applog.AccessEntry{
					IP:        clientIP,
					Method:    r.Method,
					Path:      requestURI,
					Proto:     r.Proto,
					Status:    wrapped.statusCode,
					Bytes:     wrapped.bytesWritten,
					Referer:   referer,
					UserAgent: userAgent,
					RequestID: requestID,
				})
			}
			if suppressed {
				return
			}

			// Apache Combined Log Format with request ID appended — always echo to stdout.
			// Format: IP - - [timestamp] "METHOD path protocol" status bytes "referer" "user-agent" request-id
			timestamp := start.Format("[02/Jan/2006:15:04:05 -0700]")
			log.Printf("%s - - %s \"%s %s %s\" %d %d \"%s\" \"%s\" %s",
				clientIP,
				timestamp,
				r.Method,
				requestURI,
				r.Proto,
				wrapped.statusCode,
				wrapped.bytesWritten,
				referer,
				userAgent,
				requestID,
			)
		})
	}
}

// responseWriter wraps http.ResponseWriter to capture status code and bytes written
type responseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.bytesWritten += n
	return n, err
}

// SanitizeInput trims whitespace from input strings.
func SanitizeInput(s string) string {
	return strings.TrimSpace(s)
}

// failedAuthFloor is the minimum wall-clock time a rejected authentication
// attempt takes. AI.md PART 11 requires failed-auth responses to be padded to a
// fixed floor so that latency alone never reveals which check rejected the
// request: a malformed header returns early, a wrong token runs the whole
// hash-and-compare path, and both must look identical from outside.
const failedAuthFloor = 100 * time.Millisecond

// padFailedAuth sleeps until failedAuthFloor has elapsed since start.
// Already-slow failures are not delayed further.
func padFailedAuth(start time.Time) {
	if remaining := failedAuthFloor - time.Since(start); remaining > 0 {
		time.Sleep(remaining)
	}
}

// writeUnauthorized emits the 401 body in the format the caller asked for.
// http.Error always labels its body text/plain, so a JSON envelope written
// through it ships with the wrong Content-Type; this picks the media type and
// the matching body together. The message is identical either way — AI.md
// PART 11 forbids revealing which check rejected the request.
func writeUnauthorized(w http.ResponseWriter, r *http.Request) {
	lang := i18n.DetectLocale(r)
	message := i18n.T(i18n.WithLang(r.Context(), lang), "errors.unauthorized")
	if apiNotFoundWantsText(r) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintln(w, message) //nolint:errcheck
		return
	}
	w.Header().Set("Content-Type", jsonMediaType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusUnauthorized)
	body := struct {
		OK      bool   `json:"ok"`
		Error   string `json:"error"`
		Message string `json:"message"`
	}{false, "UNAUTHORIZED", message}
	_ = json.NewEncoder(w).Encode(body)
}

// RequireOperatorToken returns a middleware that enforces operator token authentication.
// Per AI.md PART 11: the inbound Bearer token is SHA-256-hashed and compared against the
// cached hash with crypto/subtle.ConstantTimeCompare to prevent timing oracles.
// Identical error message regardless of failure reason (PART 11: no enumeration),
// and every rejection is padded to failedAuthFloor so the reason cannot be
// inferred from response latency either.
func (s *Server) RequireOperatorToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		auth := r.Header.Get("Authorization")
		rawToken := strings.TrimPrefix(auth, "Bearer ")
		reason := "invalid_token"
		if rawToken == auth {
			// No "Bearer " prefix — treated as a missing token. The hash and
			// constant-time compare below still run on the empty string, so
			// this path costs the same as a wrong-token path.
			rawToken = ""
			reason = "missing_token"
		}
		if !s.ValidateOperatorToken(rawToken) {
			s.logManager.WriteAuthFailure(sanitizeLogValue(s.authClientIP(r)),
				sanitizeLogValue(r.URL.Path), reason)
			padFailedAuth(start)
			writeUnauthorized(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// authClientIP resolves the client IP for auth logging, honouring proxy
// headers only when the peer is trusted (AI.md PART 11/15).
func (s *Server) authClientIP(r *http.Request) string {
	return netutil.GetClientIdentifier(r, s.getTrust())
}
