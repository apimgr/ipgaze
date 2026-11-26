package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	htmltemplate "html/template"
	"log"
	"net/http"
	"strings"

	"github.com/apimgr/ipgaze/src/common/httputil"
	i18n "github.com/apimgr/ipgaze/src/common/i18n"
)

// bufferedResponseWriter captures a rendered response in memory so it can be
// post-processed before anything reaches the client. AI.md PART 9 requires the
// error/render path to buffer first and swap into the live response only on
// success, so a template failure falls through to the plain fallback instead of
// corrupting a partially written response.
type bufferedResponseWriter struct {
	headers http.Header
	body    bytes.Buffer
	status  int
}

// newBufferedResponseWriter returns a buffered writer with an empty header map.
func newBufferedResponseWriter() *bufferedResponseWriter {
	return &bufferedResponseWriter{headers: make(http.Header)}
}

// Header implements http.ResponseWriter.
func (b *bufferedResponseWriter) Header() http.Header { return b.headers }

// Write implements http.ResponseWriter, appending to the in-memory buffer.
func (b *bufferedResponseWriter) Write(p []byte) (int, error) { return b.body.Write(p) }

// WriteHeader implements http.ResponseWriter, recording the status only.
func (b *bufferedResponseWriter) WriteHeader(status int) { b.status = status }

// renderNegotiated renders a frontend page under the AI.md PART 14 "Smart
// Content Negotiation" rules:
//
// Explicit Accept preferences take priority: JSON, HTML, then plain text.
// Without an explicit preference, our CLI receives API-shaped JSON, text
// browsers receive server-rendered HTML, HTTP tools receive converted text,
// and unknown clients are treated as browsers.
func (h *PagesHandler) renderNegotiated(w http.ResponseWriter, r *http.Request, page string, data interface{}, apiData interface{}) {
	ua := r.Header.Get("User-Agent")
	accept := r.Header.Get("Accept")

	if strings.Contains(accept, "application/json") {
		payload := apiData
		if payload == nil {
			payload = data
		}
		SendAPIResponseOK(w, payload, nil)
		return
	}

	explicitHTML := strings.Contains(accept, "text/html")
	wantsText := strings.Contains(accept, "text/plain") && !explicitHTML
	if !wantsText && !explicitHTML && httputil.IsOurCliClient(ua) {
		payload := apiData
		if payload == nil {
			payload = data
		}
		SendAPIResponseOK(w, payload, nil)
		return
	}
	if !wantsText && !explicitHTML {
		wantsText = httputil.IsNonInteractiveClient(ua)
	}
	if wantsText {
		buf := newBufferedResponseWriter()
		if err := h.Render(buf, r, page, data); err != nil {
			log.Printf("page render failed: status=%d method=%s path=%s err=%v", http.StatusInternalServerError, r.Method, r.URL.Path, err)
			writeHandlerFallback(w, r, http.StatusInternalServerError, i18n.T(r.Context(), "errors.server_error"), true)
			return
		}
		// Carry over cookies and any other headers the renderer set, but never
		// its Content-Type — the body is being converted to plain text.
		for key, values := range buf.headers {
			if strings.EqualFold(key, "Content-Type") {
				continue
			}
			for _, v := range values {
				w.Header().Add(key, v)
			}
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if buf.status != 0 && buf.status != http.StatusOK {
			w.WriteHeader(buf.status)
		}
		// Write errors are unrecoverable once headers are sent; log is not actionable here.
		w.Write([]byte(httputil.HTML2TextConverter(buf.body.String(), 80))) //nolint:errcheck
		return
	}

	if err := h.Render(w, r, page, data); err != nil {
		log.Printf("page render failed: status=%d method=%s path=%s err=%v", http.StatusInternalServerError, r.Method, r.URL.Path, err)
		writeHandlerFallback(w, r, http.StatusInternalServerError, i18n.T(r.Context(), "errors.server_error"), false)
	}
}

// writeHandlerFallback guarantees a response when a page template cannot be
// rendered, without relying on the template system that just failed.
func writeHandlerFallback(w http.ResponseWriter, r *http.Request, status int, msg string, plain bool) {
	accept := r.Header.Get("Accept")
	isAPI := strings.HasPrefix(r.URL.Path, "/api/")
	apiWantsText := strings.HasSuffix(r.URL.Path, ".txt") ||
		strings.Contains(accept, "text/plain") ||
		(strings.TrimSpace(accept) == "" && httputil.IsNonInteractiveClient(r.Header.Get("User-Agent")))
	apiTxt := isAPI && strings.HasSuffix(r.URL.Path, ".txt")
	if (strings.Contains(accept, "application/json") && !apiTxt) || (isAPI && !apiWantsText) {
		body, err := json.Marshal(struct {
			OK      bool   `json:"ok"`
			Error   string `json:"error"`
			Message string `json:"message"`
		}{false, ErrorCodeForStatus(status), msg})
		if err == nil {
			w.Header().Set("Content-Type", jsonMediaType)
			w.WriteHeader(status)
			_, _ = w.Write(append(body, '\n'))
			return
		}
	}
	if !isAPI && strings.Contains(accept, "text/html") {
		WriteErrorHTML(w, r, status, msg)
		return
	}
	if apiWantsText || plain || strings.Contains(accept, "text/plain") || (strings.TrimSpace(accept) == "" && httputil.IsNonInteractiveClient(r.Header.Get("User-Agent"))) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(msg + "\n"))
		return
	}
	WriteErrorHTML(w, r, status, msg)
}

// WriteErrorHTML serves the guaranteed minimal browser error document used
// when a regular page renderer cannot safely be called.
func WriteErrorHTML(w http.ResponseWriter, r *http.Request, status int, message string) {
	lang := i18n.DetectLocale(r)
	dir := string(i18n.LocaleDirection(lang))
	themeName := "dark"
	if cookie, err := r.Cookie("theme"); err == nil {
		switch cookie.Value {
		case "dark", "light", "auto":
			themeName = cookie.Value
		}
	}
	title := fmt.Sprintf("%d %s", status, http.StatusText(status))
	csrfToken := ""
	if cookie, err := r.Cookie("csrf_token"); err == nil {
		csrfToken = cookie.Value
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Vary", "Accept-Language")
	w.WriteHeader(status)
	page := struct {
		Lang, Dir, Theme, Title, Message, CSRFToken                             string
		SkipContent, SkipNavigation, Navigation, Home, Preferences, ThemeToggle string
		NextTheme                                                               string
	}{
		Lang: lang, Dir: dir, Theme: themeName, Title: title, Message: message,
		CSRFToken: csrfToken, NextTheme: NextTheme(themeName),
		SkipContent:    i18n.T(i18n.WithLang(r.Context(), lang), "accessibility.skip_to_content"),
		SkipNavigation: i18n.T(i18n.WithLang(r.Context(), lang), "nav.skip_to_navigation"),
		Navigation:     i18n.T(i18n.WithLang(r.Context(), lang), "nav.main_navigation"),
		Home:           i18n.T(i18n.WithLang(r.Context(), lang), "nav.home"),
		Preferences:    i18n.T(i18n.WithLang(r.Context(), lang), "nav.preferences"),
		ThemeToggle:    i18n.T(i18n.WithLang(r.Context(), lang), "theme.toggle"),
	}
	const source = `<!DOCTYPE html>
<html lang="{{.Lang}}" dir="{{.Dir}}" class="theme-{{.Theme}}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{.Title}}</title><link rel="stylesheet" href="/theme.css"><link rel="stylesheet" href="/static/css/common.css"><link rel="stylesheet" href="/static/css/components.css"><link rel="stylesheet" href="/static/css/public.css"></head>
<body><a href="#main-content" class="skip-link">{{.SkipContent}}</a><a href="#navigation" class="skip-link">{{.SkipNavigation}}</a><input type="checkbox" id="nav-toggle" class="nav-checkbox" aria-expanded="false" aria-controls="nav-panel">
<header id="navigation" class="header" role="banner"><a href="/" class="site-brand">IPGaze</a><nav class="nav-links" aria-label="{{.Navigation}}"><a href="/">{{.Home}}</a></nav><label for="nav-toggle" class="nav-burger" aria-label="{{.Navigation}}">☰</label><div class="header-actions"><a href="/server/preferences" class="header-link" aria-label="{{.Preferences}}"><svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8Zm9 4a7.9 7.9 0 0 0-.1-1.2l2-1.5-2-3.5-2.4 1a8.6 8.6 0 0 0-2-1.2L16.1 3h-4.2l-.4 2.6a8.6 8.6 0 0 0-2 1.2l-2.4-1-2 3.5 2 1.5a7.9 7.9 0 0 0 0 2.4l-2 1.5 2 3.5 2.4-1a8.6 8.6 0 0 0 2 1.2l.4 2.6h4.2l.4-2.6a8.6 8.6 0 0 0 2-1.2l2.4 1 2-3.5-2-1.5A7.9 7.9 0 0 0 21 12Z" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/></svg></a><form action="/server/preferences" method="post" class="theme-toggle-form"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><input type="hidden" name="theme" value="{{.NextTheme}}"><button type="submit" class="btn btn-icon theme-button" aria-label="{{.ThemeToggle}}"><svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><circle cx="12" cy="12" r="8" fill="none" stroke="currentColor" stroke-width="2"/></svg></button></form></div></header>
<main id="main-content" role="main"><div class="container container-sm error-card"><section class="section-card" aria-labelledby="error-title"><h1 id="error-title" class="page-title">{{.Title}}</h1><p>{{.Message}}</p><a href="/" class="btn btn-primary">{{.Home}}</a></section></div></main><nav class="nav-panel" id="nav-panel" aria-label="{{.Navigation}}"><a href="/">{{.Home}}</a></nav><label for="nav-toggle" class="nav-overlay" aria-hidden="true"></label><footer class="footer" role="contentinfo"><p><a href="/server/about">IPGaze</a></p></footer></body></html>`
	tmpl, err := htmltemplate.New("error").Parse(source)
	if err != nil {
		_, _ = fmt.Fprintf(w, "<html><body><h1>%s</h1></body></html>", html.EscapeString(title))
		return
	}
	if err := tmpl.Execute(w, page); err != nil {
		return
	}
}

// ErrorCodeForStatus maps an HTTP status to the UPPERCASE_SNAKE_CASE error code
// AI.md PART 9's error-code table pairs with it. It is the single definition of
// that mapping; the server package's error envelope delegates here rather than
// keeping a second copy that could drift.
//
// Statuses that PART 9 maps to more than one code (403 is both FORBIDDEN and
// CSRF_FAILED) resolve to the generic one; a caller needing the specific code
// supplies it itself.
func ErrorCodeForStatus(code int) string {
	switch code {
	case http.StatusBadRequest:
		return "BAD_REQUEST"
	case http.StatusUnauthorized:
		return "UNAUTHORIZED"
	case http.StatusForbidden:
		return "FORBIDDEN"
	case http.StatusNotFound:
		return "NOT_FOUND"
	case http.StatusMethodNotAllowed:
		return "METHOD_NOT_ALLOWED"
	case http.StatusConflict:
		return "CONFLICT"
	case http.StatusUnprocessableEntity:
		return "UNPROCESSABLE_ENTITY"
	case http.StatusTooManyRequests:
		return "RATE_LIMITED"
	case http.StatusRequestEntityTooLarge:
		return "PAYLOAD_TOO_LARGE"
	case http.StatusInternalServerError:
		return "SERVER_ERROR"
	case http.StatusBadGateway:
		return "BAD_GATEWAY"
	case http.StatusServiceUnavailable:
		return "MAINTENANCE"
	default:
		return "SERVER_ERROR"
	}
}

// WriteAPIError writes the canonical AI.md PART 9 error envelope
// {"ok": false, "error": "CODE", "message": "..."} with the given status.
//
// For API-only endpoints that have no page to render — a handler whose every
// client is a tool or script rather than a browser. Frontend handlers use
// PagesHandler.renderErrorPage instead, which negotiates the themed page.
//
// errorCode may be empty to take the status-derived default.
func WriteAPIError(w http.ResponseWriter, code int, errorCode, msg string) {
	if msg == "" {
		msg = http.StatusText(code)
	}
	if errorCode == "" {
		errorCode = ErrorCodeForStatus(code)
	}
	body, err := json.MarshalIndent(struct {
		OK      bool   `json:"ok"`
		Error   string `json:"error"`
		Message string `json:"message"`
	}{false, errorCode, msg}, "", "  ")
	if err != nil {
		// Marshalling three plain strings cannot realistically fail, but the
		// request must still terminate in a response rather than a blank body
		// (AI.md 24426).
		w.Header().Set("Content-Type", jsonMediaType)
		w.WriteHeader(code)
		_, _ = w.Write([]byte(`{"ok":false,"error":"SERVER_ERROR","message":"Internal server error"}` + "\n"))
		return
	}
	w.Header().Set("Content-Type", jsonMediaType)
	w.WriteHeader(code)
	w.Write(append(body, '\n')) //nolint:errcheck
}

// renderErrorPage terminates a frontend request with a content-negotiated
// error response. AI.md 24407 requires that "ALL error pages MUST use the site
// theme system. No plain/unstyled error pages", with 24411-24417 listing
// 400/401/403/404/500/502/503 as theme-required, and 24426 requiring the error
// path itself to honor content negotiation — HTML for browsers, JSON for API
// clients — while never failing the request.
//
// Handlers in this package must use this instead of http.Error for any of those
// statuses: http.Error emits an unstyled text/plain body to every client alike.
// Statuses outside that table (405, for instance) are not error *pages* and may
// still use http.Error.
//
// The themed page is rendered into a buffer first, so a template failure falls
// through to the guaranteed plain-text response with nothing yet written to w.
func (h *PagesHandler) renderErrorPage(w http.ResponseWriter, r *http.Request, code int, msg string) {
	if msg == "" {
		msg = http.StatusText(code)
	}
	ua := r.Header.Get("User-Agent")

	// API clients and our own CLI get the canonical JSON error envelope
	// (AI.md PART 9 "{"ok": false, "error": "CODE", "message": "..."}").
	wantsJSON := strings.Contains(r.Header.Get("Accept"), jsonMediaType) ||
		httputil.IsOurCliClient(ua) ||
		strings.HasPrefix(r.URL.Path, "/api/")
	if wantsJSON {
		body, err := json.MarshalIndent(struct {
			OK      bool   `json:"ok"`
			Error   string `json:"error"`
			Message string `json:"message"`
		}{false, ErrorCodeForStatus(code), msg}, "", "  ")
		if err == nil {
			w.Header().Set("Content-Type", jsonMediaType)
			w.WriteHeader(code)
			w.Write(append(body, '\n')) //nolint:errcheck
			return
		}
	}

	// Browsers (graphical and text alike) get the themed error page.
	if !wantsJSON && !httputil.IsNonInteractiveClient(ua) && h.Render != nil {
		data := h.NewPageData(r)
		data.Code = code
		data.Title = http.StatusText(code)
		data.Message = msg
		buf := newBufferedResponseWriter()
		if err := h.Render(buf, r, "error_page.tmpl", data); err == nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(code)
			w.Write(buf.body.Bytes()) //nolint:errcheck
			return
		} else {
			log.Printf("error page render failed: status=%d method=%s path=%s err=%v", code, r.Method, r.URL.Path, err)
		}
	}

	// Guaranteed fallback: HTTP tools receive text, while browser clients
	// receive a minimal HTML document if the themed renderer failed.
	writeHandlerFallback(w, r, code, msg, false)
}
