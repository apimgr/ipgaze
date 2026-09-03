package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	i18n "github.com/apimgr/ipgaze/src/common/i18n"
	applog "github.com/apimgr/ipgaze/src/log"
	"github.com/apimgr/ipgaze/src/server/handler"
)

// errorPageExecute renders "error_page.tmpl" (layout+partials applied) into
// an io.Writer for the current build's asset stamp. Injected at server
// startup (http.go, once PagesHandler/AssetStamp are available) so
// appHandler.ServeHTTP — a package-level function type with no access to a
// *handler.PagesHandler instance — can still render the full themed error
// page (AI.md PART 16 "Error Pages (MUST Match Theme)") without threading a
// PagesHandler through every appHandler call site. Mirrors the DetectTheme
// injection pattern in theme.go. Left nil in contexts that never call the
// route-setup code (e.g. some unit tests constructing appHandler directly),
// in which case ServeHTTP falls back to the guaranteed plain-text response.
var errorPageExecute func(w io.Writer, page string, data interface{}) error

// errorPageData builds the shared PageData (theme, nav, footer, consent,
// branding) for the current request. Injected alongside errorPageExecute.
var errorPageData func(r *http.Request) handler.PageData

// errorPageAssetStamp is the running build's AssetStamp, injected alongside
// errorPageExecute so the themed error-page path can apply the same
// version-change purge (AI.md PART 9) as the other HTML response paths.
var errorPageAssetStamp string

// errorLogManager receives every 5xx so it lands in error.log, which AI.md
// PART 11 "Log Files" designates as the destination for error messages.
// Injected at server startup for the same reason as errorPageExecute:
// appHandler is a bare function type with no access to server state.
var errorLogManager *applog.Manager

// SetErrorLogManager injects the log Manager used for the error.log 5xx
// stream. Called once during server startup; nil leaves the stdout log as
// the only sink.
func SetErrorLogManager(lm *applog.Manager) {
	errorLogManager = lm
}

type appError struct {
	Error       error
	Message     string
	Code        int
	ContentType string
}

func internalServerError(err error) *appError {
	return &appError{
		Error: err,
		Code:  http.StatusInternalServerError,
	}
}

func notFound(err error) *appError {
	return &appError{Error: err, Code: http.StatusNotFound}
}

func badRequest(err error) *appError {
	return &appError{Error: err, Code: http.StatusBadRequest}
}

func (e *appError) AsJSON() *appError {
	e.ContentType = jsonMediaType
	return e
}

func (e *appError) WithMessage(message string) *appError {
	e.Message = message
	return e
}

func (e *appError) IsJSON() bool {
	return e.ContentType == jsonMediaType
}

// appHandler is a handler function that returns an appError
type appHandler func(http.ResponseWriter, *http.Request) *appError

// ServeHTTP implements http.Handler for appHandler
func (fn appHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	e := fn(w, r)
	if e == nil {
		return
	}
	// Per AI.md PART 9, server errors must be logged with request context
	// (request id, status, method, path, client address) — never bare — so
	// a 5xx can be correlated to the originating request. The full internal
	// error stays server-side; the client still receives only the sanitized
	// message resolved below.
	if e.Code/100 == 5 {
		detail := fmt.Sprintf("server error: request_id=%s http_status=%d method=%s path=%s ip=%s internal=%v",
			RequestIDFromContext(r.Context()), e.Code, r.Method, r.URL.Path, r.RemoteAddr, e.Error)
		log.Print(detail)
		if errorLogManager != nil {
			errorLogManager.WriteError("error", detail)
		}
	}
	// Resolve default message via i18n when not explicitly set
	msg := e.Message
	if msg == "" {
		switch e.Code {
		case http.StatusNotFound:
			msg = i18n.T(r.Context(), "errors.not_found")
		case http.StatusMethodNotAllowed:
			msg = i18n.T(r.Context(), "errors.method_not_allowed")
		case http.StatusBadRequest:
			msg = i18n.T(r.Context(), "errors.bad_request")
		case http.StatusUnauthorized:
			msg = i18n.T(r.Context(), "errors.unauthorized")
		case http.StatusForbidden:
			msg = i18n.T(r.Context(), "errors.forbidden")
		case http.StatusTooManyRequests:
			msg = i18n.T(r.Context(), "errors.rate_limited")
		default:
			msg = i18n.T(r.Context(), "errors.server_error")
		}
	}
	// For HTML clients, render the full themed error page (AI.md PART 16
	// "Error Pages (MUST Match Theme)") instead of the bare plain-text
	// fallback below. Rendered into a buffer first so a template failure
	// never corrupts a partially-written response — on failure we log it
	// and fall straight through to the guaranteed plain-text response,
	// untouched, since nothing has been written to w yet.
	if !e.IsJSON() && detectClientType(r) == "html" && errorPageExecute != nil && errorPageData != nil {
		pd := errorPageData(r)
		pd.Code = e.Code
		pd.Title = http.StatusText(e.Code)
		pd.Message = msg
		pd.RequestID = RequestIDFromContext(r.Context())
		var buf bytes.Buffer
		err := errorPageExecute(&buf, "error_page.tmpl", pd)
		if err == nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			// Version-change purge (AI.md PART 9 "Version-Change Purge
			// (Clear-Site-Data)"): evict a stale browser cache/service worker
			// in one shot when the client's build cookie disagrees with this
			// build. errorPageAssetStamp is injected alongside errorPageExecute.
			applyVersionPurge(w, r, errorPageAssetStamp)
			w.WriteHeader(e.Code)
			buf.WriteTo(w) //nolint:errcheck
			return
		}
		log.Printf("error page render failed: request_id=%s http_status=%d err=%v",
			RequestIDFromContext(r.Context()), e.Code, err)
	}
	// When Content-Type for error is JSON, marshal the response as JSON.
	// Format per AI.md PART 9: {"ok": false, "error": "ERROR_CODE", "message": "Human text"}
	if e.IsJSON() {
		data := struct {
			OK      bool   `json:"ok"`
			Error   string `json:"error"`
			Message string `json:"message"`
		}{false, httpStatusToErrorCode(e.Code), msg}
		b, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			panic(err)
		}
		msg = string(b) + "\n"
	}
	// Set Content-Type of response if set in error
	if e.ContentType != "" {
		w.Header().Set("Content-Type", e.ContentType)
	}
	w.WriteHeader(e.Code)
	fmt.Fprint(w, msg)
}

// httpStatusToErrorCode maps an HTTP status code to an UPPERCASE_SNAKE_CASE error code.
// Per AI.md PART 9: error codes must be UPPERCASE_SNAKE_CASE strings.
func httpStatusToErrorCode(code int) string {
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

// NotFoundHandler returns a 404 error response.
// r.NotFound is the single catch-all for the entire router (API and
// frontend paths alike), so it must branch on the path itself rather than
// assuming one negotiation rule fits both halves of the site.
func NotFoundHandler(w http.ResponseWriter, r *http.Request) *appError {
	err := notFound(nil)
	if strings.HasPrefix(r.URL.Path, "/api/") {
		// Per AI.md PART 14 API content-negotiation priority, unmatched
		// /api/** paths default to the JSON error envelope for every
		// client except a `.txt` suffix, an explicit `Accept: text/plain`,
		// or a recognized non-interactive HTTP tool (curl/wget/httpie) —
		// the same rule already implemented correctly for the sibling
		// BAD_REQUEST paths (which hardcode .AsJSON()) and for
		// apiHealthWantsText in handler/health.go.
		if !apiNotFoundWantsText(r) {
			err = err.AsJSON()
		}
		return err
	}
	if r.Header.Get("accept") == jsonMediaType {
		err = err.AsJSON()
	}
	return err
}

// apiNotFoundWantsText mirrors handler.apiHealthWantsText's priority order,
// reusing handler.IsNonInteractiveHTTPTool for the tool-detection step so the
// two content-negotiation checks never drift out of sync:
//  1. `.txt` extension on the path -> text (always wins)
//  2. `Accept: text/plain` header -> text
//  3. Non-interactive HTTP tool detected (curl, wget, httpie) -> text
//  4. Default (browsers, API clients, `Accept: application/json`, empty UA) -> JSON
func apiNotFoundWantsText(r *http.Request) bool {
	if strings.HasSuffix(r.URL.Path, ".txt") {
		return true
	}
	if strings.Contains(r.Header.Get("Accept"), "text/plain") {
		return true
	}
	return handler.IsNonInteractiveHTTPTool(r.Header.Get("User-Agent"))
}
