package handler

import (
	"bytes"
	"encoding/json"
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
//  1. Our CLI client is INTERACTIVE — it receives JSON and renders its own
//     TUI/GUI, so it is never sent HTML or pre-formatted text. apiData is the
//     payload its matching /api/{api_version}/... route would return.
//  2. Text browsers (lynx, w3m, links) are INTERACTIVE without JavaScript and
//     receive the server-rendered HTML. This project's pages are already usable
//     without JS (PART 16's JS Necessity Gate), so they share branch 4's output.
//  3. HTTP tools (curl, wget, httpie) are NON-INTERACTIVE and receive the page
//     converted to 80-column plain text via HTML2TextConverter.
//  4. Regular browsers receive the full HTML page.
//
// An explicit Accept: text/plain selects branch 3 for any client except our own
// CLI, matching AI.md's Accept-header table.
func (h *PagesHandler) renderNegotiated(w http.ResponseWriter, r *http.Request, page string, data interface{}, apiData interface{}) {
	ua := r.Header.Get("User-Agent")

	if httputil.IsOurCliClient(ua) && apiData != nil {
		b, err := json.MarshalIndent(apiData, "", "  ")
		if err != nil {
			http.Error(w, i18n.T(r.Context(), "errors.server_error"), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", jsonMediaType)
		// Write errors are unrecoverable once headers are sent; log is not actionable here.
		w.Write(b)            //nolint:errcheck
		w.Write([]byte("\n")) //nolint:errcheck
		return
	}

	wantsText := httputil.IsNonInteractiveClient(ua) ||
		strings.Contains(r.Header.Get("Accept"), "text/plain")
	if wantsText {
		buf := newBufferedResponseWriter()
		if err := h.Render(buf, r, page, data); err != nil {
			http.Error(w, i18n.T(r.Context(), "errors.server_error"), http.StatusInternalServerError)
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
		http.Error(w, i18n.T(r.Context(), "errors.server_error"), http.StatusInternalServerError)
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
		http.Error(w, msg, code)
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
		}
	}

	// Guaranteed fallback: HTTP tools, and any client whose themed render failed.
	http.Error(w, msg, code)
}
