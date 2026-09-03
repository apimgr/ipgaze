package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/apimgr/ipgaze/src/common/i18n"
	applog "github.com/apimgr/ipgaze/src/log"
)

// CSRFConfig holds CSRF middleware configuration per AI.md PART 16.
type CSRFConfig struct {
	// Enabled controls whether CSRF protection is active. Default: true.
	Enabled bool
	// TokenLength is the number of random bytes in the token. Default: 32.
	TokenLength int
	// CookieName is the name of the CSRF cookie. Default: "csrf_token".
	CookieName string
	// HeaderName is the header used for AJAX requests. Default: "X-CSRF-Token".
	HeaderName string
	// FormField is the hidden form field name. Default: "csrf_token".
	FormField string
	// Secure sets the Secure flag on the cookie. Default: auto (true if HTTPS).
	Secure *bool
	// SameSite sets the SameSite attribute. Default: Strict.
	SameSite http.SameSite
	// ExemptPaths is a list of path patterns exempt from CSRF validation.
	// Supports glob patterns (e.g., /api/v1/webhooks/*).
	ExemptPaths []string
}

// DefaultCSRFConfig returns the default CSRF configuration per AI.md.
func DefaultCSRFConfig() CSRFConfig {
	return CSRFConfig{
		Enabled:     true,
		TokenLength: 32,
		CookieName:  "csrf_token",
		HeaderName:  "X-CSRF-Token",
		FormField:   "csrf_token",
		Secure:      nil,
		SameSite:    http.SameSiteStrictMode,
		ExemptPaths: []string{
			// Webhook callbacks — third-party services send these without browser context.
			"/api/v1/webhooks/*",
			// Browser report-to endpoints — browsers send CSP/NEL/Deprecation reports
			// without CSRF tokens; these are machine-initiated, not user-form submissions.
			"/api/v1/server/reports/*",
			// Debug endpoints — only exposed in debug mode, not user-facing browser forms.
			"/debug/*",
			// Cookie consent — public endpoint, no session to protect; sets only a
			// non-sensitive preference cookie. Cross-site forging this has no impact.
			"/server/consent",
			// Announcement dismiss — public endpoint, sets only a non-sensitive preference
			// cookie. Cross-site forging this has no impact.
			"/announcements/dismiss",
		},
	}
}

// csrfContextKey is the context key for the CSRF token.
type csrfContextKey struct{}

// CSRFMiddleware implements double-submit cookie CSRF protection per AI.md PART 16.
//
// CSRF protects cookie-authenticated browser forms from cross-site forgery.
// It does NOT apply to:
//   - Bearer/API-token requests (Authorization header present)
//   - Public endpoints (no auth required)
//   - Read-only methods (GET, HEAD, OPTIONS)
//   - WebSocket upgrade requests
//   - Endpoints in the explicit exempt_paths list
//
// There is deliberately NO Origin-based bypass (AI.md PART 16): Origin/Referer
// can be absent or spoofed by non-browser clients, so every mutating browser
// request must present the double-submit token regardless of same-origin status.
func CSRFMiddleware(cfg CSRFConfig, sslEnabled bool, lm *applog.Manager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip if CSRF is disabled
			if !cfg.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			// Determine secure flag based on protocol if auto
			secure := sslEnabled
			if cfg.Secure != nil {
				secure = *cfg.Secure
			}

			// Bypass: WebSocket upgrade requests
			if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
				next.ServeHTTP(w, r)
				return
			}

			// Bypass: Safe methods (GET, HEAD, OPTIONS) per RFC 9110
			method := strings.ToUpper(r.Method)
			if method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions {
				// Still set/refresh the token cookie for subsequent form submissions,
				// and store the token in the request context so a page rendered on
				// THIS same response (GetCSRFToken -> NewPageData -> nav/contact/
				// privacy templates) can embed a valid hidden csrf_token field even
				// on a visitor's very first request — the Set-Cookie header on this
				// response hasn't round-tripped to the browser yet, so r.Cookie()
				// alone would find nothing and every first-visit form would submit
				// with an empty token and fail validation.
				token := ensureCSRFCookie(w, r, cfg, secure)
				ctx := withCSRFToken(r.Context(), token)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// Bypass: Bearer or API token auth (not cookie-based)
			if hasBearerAuth(r) {
				next.ServeHTTP(w, r)
				return
			}

			// Bypass: Exempt paths (webhooks, callbacks, etc.)
			if isExemptPath(r.URL.Path, cfg.ExemptPaths) {
				next.ServeHTTP(w, r)
				return
			}

			// No Origin-based bypass per AI.md PART 16 "CSRF Protection": Origin/Referer
			// can be absent or spoofed by non-browser clients, so a same-origin Origin
			// header never skips token validation — every mutating browser request
			// presents the double-submit token.

			// For state-changing methods with cookie-based auth: validate CSRF token.
			// start anchors the failed-rejection timing floor below so a missing
			// token and a mismatched token take the same observable time.
			start := time.Now()

			// Get token from cookie
			cookieToken := ""
			if cookie, err := r.Cookie(cfg.CookieName); err == nil {
				cookieToken = cookie.Value
			}

			// Get token from header or form
			submittedToken := r.Header.Get(cfg.HeaderName)
			if submittedToken == "" {
				// Try form field (ParseForm is idempotent)
				if err := r.ParseForm(); err == nil {
					submittedToken = r.FormValue(cfg.FormField)
				}
			}

			// Validate: both must be present and match
			if cookieToken == "" || submittedToken == "" {
				csrfError(w, r, lm, "missing_token", start)
				return
			}

			// Constant-time comparison per AI.md security requirements
			if subtle.ConstantTimeCompare([]byte(cookieToken), []byte(submittedToken)) != 1 {
				csrfError(w, r, lm, "token_mismatch", start)
				return
			}

			// Token valid — regenerate for next request (prevent replay).
			// Store validated token in context so templates can read it via GetCSRFToken.
			newToken := generateCSRFToken(cfg.TokenLength)
			setCSRFCookieWithToken(w, cfg, secure, newToken)
			ctx := r.Context()
			ctx = withCSRFToken(ctx, newToken)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ensureCSRFCookie sets a CSRF cookie if one doesn't exist, and returns the
// token now in effect (the pre-existing cookie's value, or the freshly
// generated one) so the caller can expose it via request context for
// same-response template rendering.
func ensureCSRFCookie(w http.ResponseWriter, r *http.Request, cfg CSRFConfig, secure bool) string {
	if cookie, err := r.Cookie(cfg.CookieName); err == nil {
		return cookie.Value
	}
	token := generateCSRFToken(cfg.TokenLength)
	setCSRFCookieWithToken(w, cfg, secure, token)
	return token
}

// setCSRFCookieWithToken sets a specific token value as the CSRF cookie.
func setCSRFCookieWithToken(w http.ResponseWriter, cfg CSRFConfig, secure bool, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.CookieName,
		Value:    token,
		Path:     "/",
		Secure:   secure,
		HttpOnly: false,
		SameSite: cfg.SameSite,
	})
}

// withCSRFToken stores the current CSRF token in the request context.
func withCSRFToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, csrfContextKey{}, token)
}

// generateCSRFToken creates a cryptographically random token.
func generateCSRFToken(length int) string {
	if length <= 0 {
		length = 32
	}
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		// Fallback should never happen, but panic is acceptable for crypto failure
		panic("csrf: failed to generate random token: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// hasBearerAuth checks if the request uses Bearer token or API token auth.
func hasBearerAuth(r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return true
	}
	if r.Header.Get("X-API-Token") != "" {
		return true
	}
	return false
}

// extractHost extracts the host portion from a URL string.
func extractHost(urlStr string) string {
	// Remove scheme
	if idx := strings.Index(urlStr, "://"); idx != -1 {
		urlStr = urlStr[idx+3:]
	}
	// Remove path
	if idx := strings.Index(urlStr, "/"); idx != -1 {
		urlStr = urlStr[:idx]
	}
	// Remove port for comparison if present
	// Actually keep port for exact host:port match
	return urlStr
}

// isExemptPath checks if the request path matches any exempt pattern.
func isExemptPath(requestPath string, exemptPaths []string) bool {
	for _, pattern := range exemptPaths {
		if matchPath(pattern, requestPath) {
			return true
		}
	}
	return false
}

// matchPath performs glob-style path matching.
// Supports * for single segment and ** for multiple segments.
func matchPath(pattern, requestPath string) bool {
	// Normalize paths
	pattern = path.Clean("/" + pattern)
	requestPath = path.Clean("/" + requestPath)

	// Exact match
	if pattern == requestPath {
		return true
	}

	// Simple wildcard at end: /api/v1/webhooks/*
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		if strings.HasPrefix(requestPath, prefix+"/") {
			return true
		}
	}

	// Double wildcard: /api/**/webhooks
	if strings.Contains(pattern, "/**") {
		parts := strings.Split(pattern, "/**")
		if len(parts) == 2 {
			if strings.HasPrefix(requestPath, parts[0]) && strings.HasSuffix(requestPath, parts[1]) {
				return true
			}
		}
	}

	return false
}

// csrfError returns a 403 Forbidden with the canonical error body per AI.md PART 14.
// start is when token validation began; the response is padded to the shared
// failed-auth floor so the reason for rejection is not observable as latency.
func csrfError(w http.ResponseWriter, r *http.Request, lm *applog.Manager, reason string, start time.Time) {
	lang := i18n.DetectLocale(r)

	// Log to audit.log as security.csrf_failure per AI.md PART 11/16, with
	// IP, endpoint, and reason as structured details. WriteAuditEvent is a
	// documented no-op on a nil manager (e.g. in unit tests).
	// Trust-resolved IP only. Reading X-Forwarded-For unconditionally would let
	// any client forge the address written to security.log, which fail2ban acts
	// on — turning a log line into a remote ban primitive (AI.md PART 12
	// "Trusted Proxies").
	clientIP := ""
	if ip := extractIP(r); ip != nil {
		clientIP = ip.String()
	}
	lm.WriteAuditEvent("", "security.csrf_failure", "security", "warn", "failure", clientIP, map[string]any{
		"endpoint": r.URL.Path,
		"reason":   reason,
	})

	// Fail2ban-consumable record of the rejection (AI.md PART 11).
	lm.WriteSecurity("CSRF validation failed", sanitizeLogValue(clientIP))

	padFailedAuth(start)

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)

	// Canonical error body per AI.md PART 14
	msg := i18n.T(i18n.WithLang(r.Context(), lang), "errors.csrf_failed")
	if msg == "" || msg == "errors.csrf_failed" {
		msg = "CSRF token validation failed"
	}
	// Marshalled, never concatenated: a translated message containing a quote
	// or backslash would otherwise produce a malformed body.
	body, err := json.Marshal(map[string]any{
		"ok":      false,
		"error":   "CSRF_FAILED",
		"message": msg,
	})
	if err != nil {
		body = []byte(`{"ok":false,"error":"CSRF_FAILED","message":"CSRF token validation failed"}`)
	}
	_, _ = w.Write(body)
}

// GetCSRFToken returns the current CSRF token for use in templates and responses.
// Reads from the request context first (set by CSRFMiddleware after validation),
// then falls back to the cookie value for unauthenticated/GET requests.
func GetCSRFToken(r *http.Request, cookieName string) string {
	if t, ok := r.Context().Value(csrfContextKey{}).(string); ok && t != "" {
		return t
	}
	if cookieName == "" {
		cookieName = "csrf_token"
	}
	if cookie, err := r.Cookie(cookieName); err == nil {
		return cookie.Value
	}
	return ""
}
