package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCSRFMiddleware_SafeMethods_NoValidation(t *testing.T) {
	cfg := DefaultCSRFConfig()
	handler := CSRFMiddleware(cfg, false, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	methods := []string{http.MethodGet, http.MethodHead, http.MethodOptions}
	for _, method := range methods {
		req := httptest.NewRequest(method, "/test", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("%s request should pass without CSRF token, got %d", method, rec.Code)
		}
	}
}

func TestCSRFMiddleware_SafeMethods_SetsCookie(t *testing.T) {
	cfg := DefaultCSRFConfig()
	handler := CSRFMiddleware(cfg, false, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	cookies := rec.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == cfg.CookieName {
			found = true
			if c.Value == "" {
				t.Error("CSRF cookie should have a value")
			}
		}
	}
	if !found {
		t.Error("GET request should set CSRF cookie for subsequent forms")
	}
}

func TestCSRFMiddleware_POST_NoCookie_Fails(t *testing.T) {
	cfg := DefaultCSRFConfig()
	handler := CSRFMiddleware(cfg, false, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/submit", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("POST without CSRF token should fail, got %d", rec.Code)
	}
}

func TestCSRFMiddleware_POST_WithValidToken_Passes(t *testing.T) {
	cfg := DefaultCSRFConfig()
	handler := CSRFMiddleware(cfg, false, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Simulate having a CSRF token
	token := generateCSRFToken(32)

	// POST with matching cookie and header
	req := httptest.NewRequest(http.MethodPost, "/submit", nil)
	req.AddCookie(&http.Cookie{Name: cfg.CookieName, Value: token})
	req.Header.Set(cfg.HeaderName, token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("POST with valid CSRF token should pass, got %d", rec.Code)
	}
}

func TestCSRFMiddleware_POST_WithMismatchedToken_Fails(t *testing.T) {
	cfg := DefaultCSRFConfig()
	handler := CSRFMiddleware(cfg, false, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	cookieToken := generateCSRFToken(32)
	headerToken := generateCSRFToken(32)

	req := httptest.NewRequest(http.MethodPost, "/submit", nil)
	req.AddCookie(&http.Cookie{Name: cfg.CookieName, Value: cookieToken})
	req.Header.Set(cfg.HeaderName, headerToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("POST with mismatched token should fail, got %d", rec.Code)
	}
}

func TestCSRFMiddleware_POST_WithFormField_Passes(t *testing.T) {
	cfg := DefaultCSRFConfig()
	handler := CSRFMiddleware(cfg, false, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	token := generateCSRFToken(32)

	// POST with token in form field instead of header
	body := strings.NewReader("csrf_token=" + token)
	req := httptest.NewRequest(http.MethodPost, "/submit", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: cfg.CookieName, Value: token})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("POST with valid form token should pass, got %d", rec.Code)
	}
}

func TestCSRFMiddleware_BearerAuth_Bypasses(t *testing.T) {
	cfg := DefaultCSRFConfig()
	handler := CSRFMiddleware(cfg, false, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/data", nil)
	req.Header.Set("Authorization", "Bearer some-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("POST with Bearer auth should bypass CSRF, got %d", rec.Code)
	}
}

func TestCSRFMiddleware_APIToken_Bypasses(t *testing.T) {
	cfg := DefaultCSRFConfig()
	handler := CSRFMiddleware(cfg, false, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/data", nil)
	req.Header.Set("X-API-Token", "some-api-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("POST with X-API-Token should bypass CSRF, got %d", rec.Code)
	}
}

func TestCSRFMiddleware_WebSocket_Bypasses(t *testing.T) {
	cfg := DefaultCSRFConfig()
	handler := CSRFMiddleware(cfg, false, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	req.Header.Set("Upgrade", "websocket")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("WebSocket upgrade should bypass CSRF, got %d", rec.Code)
	}
}

func TestCSRFMiddleware_ExemptPath_Bypasses(t *testing.T) {
	cfg := DefaultCSRFConfig()
	cfg.ExemptPaths = []string{"/api/v1/webhooks/*", "/callback"}
	handler := CSRFMiddleware(cfg, false, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	paths := []string{"/api/v1/webhooks/github", "/api/v1/webhooks/stripe", "/callback"}
	for _, p := range paths {
		req := httptest.NewRequest(http.MethodPost, p, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("POST to exempt path %s should pass, got %d", p, rec.Code)
		}
	}
}

func TestCSRFMiddleware_NonExemptPath_RequiresToken(t *testing.T) {
	cfg := DefaultCSRFConfig()
	cfg.ExemptPaths = []string{"/api/v1/webhooks/*"}
	handler := CSRFMiddleware(cfg, false, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Path that looks similar but isn't exempt
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("POST to non-exempt path should require token, got %d", rec.Code)
	}
}

func TestCSRFMiddleware_Disabled_AllowsAll(t *testing.T) {
	cfg := DefaultCSRFConfig()
	cfg.Enabled = false
	handler := CSRFMiddleware(cfg, false, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/submit", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Disabled CSRF should allow POST, got %d", rec.Code)
	}
}

func TestCSRFMiddleware_DELETE_RequiresToken(t *testing.T) {
	cfg := DefaultCSRFConfig()
	handler := CSRFMiddleware(cfg, false, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodDelete, "/resource/123", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("DELETE without token should fail, got %d", rec.Code)
	}
}

func TestCSRFMiddleware_PUT_RequiresToken(t *testing.T) {
	cfg := DefaultCSRFConfig()
	handler := CSRFMiddleware(cfg, false, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPut, "/resource/123", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("PUT without token should fail, got %d", rec.Code)
	}
}

func TestCSRFMiddleware_PATCH_RequiresToken(t *testing.T) {
	cfg := DefaultCSRFConfig()
	handler := CSRFMiddleware(cfg, false, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPatch, "/resource/123", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("PATCH without token should fail, got %d", rec.Code)
	}
}

func TestGenerateCSRFToken_UniqueTokens(t *testing.T) {
	tokens := make(map[string]bool)
	for i := 0; i < 100; i++ {
		token := generateCSRFToken(32)
		if tokens[token] {
			t.Error("Generated duplicate CSRF token")
		}
		tokens[token] = true
	}
}

func TestGenerateCSRFToken_ValidLength(t *testing.T) {
	// 32 bytes = 43 base64 chars (without padding)
	token := generateCSRFToken(32)
	if len(token) < 40 {
		t.Errorf("Token too short: %d chars", len(token))
	}
}

func TestMatchPath_ExactMatch(t *testing.T) {
	if !matchPath("/callback", "/callback") {
		t.Error("Exact match should return true")
	}
}

func TestMatchPath_WildcardSuffix(t *testing.T) {
	pattern := "/api/v1/webhooks/*"
	cases := []struct {
		path  string
		match bool
	}{
		{"/api/v1/webhooks/github", true},
		{"/api/v1/webhooks/stripe", true},
		{"/api/v1/webhooks", false},
		{"/api/v1/users", false},
	}
	for _, tc := range cases {
		if matchPath(pattern, tc.path) != tc.match {
			t.Errorf("matchPath(%q, %q) = %v, want %v", pattern, tc.path, !tc.match, tc.match)
		}
	}
}

func TestExtractHost(t *testing.T) {
	cases := []struct {
		url  string
		host string
	}{
		{"https://example.com/path", "example.com"},
		{"http://localhost:8080/api", "localhost:8080"},
		{"https://api.example.com:443", "api.example.com:443"},
		{"example.com/path", "example.com"},
	}
	for _, tc := range cases {
		got := extractHost(tc.url)
		if got != tc.host {
			t.Errorf("extractHost(%q) = %q, want %q", tc.url, got, tc.host)
		}
	}
}

func TestHasBearerAuth(t *testing.T) {
	cases := []struct {
		authHeader string
		apiToken   string
		want       bool
	}{
		{"Bearer abc123", "", true},
		{"", "api-key-123", true},
		{"Basic dXNlcjpwYXNz", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if tc.authHeader != "" {
			req.Header.Set("Authorization", tc.authHeader)
		}
		if tc.apiToken != "" {
			req.Header.Set("X-API-Token", tc.apiToken)
		}
		got := hasBearerAuth(req)
		if got != tc.want {
			t.Errorf("hasBearerAuth(Auth=%q, Token=%q) = %v, want %v",
				tc.authHeader, tc.apiToken, got, tc.want)
		}
	}
}

func TestGetCSRFToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "test-token-123"})

	token := GetCSRFToken(req, "")
	if token != "test-token-123" {
		t.Errorf("GetCSRFToken() = %q, want %q", token, "test-token-123")
	}

	// Custom cookie name
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.AddCookie(&http.Cookie{Name: "custom_csrf", Value: "custom-value"})
	token2 := GetCSRFToken(req2, "custom_csrf")
	if token2 != "custom-value" {
		t.Errorf("GetCSRFToken(custom) = %q, want %q", token2, "custom-value")
	}

	// Missing cookie
	req3 := httptest.NewRequest(http.MethodGet, "/", nil)
	token3 := GetCSRFToken(req3, "")
	if token3 != "" {
		t.Errorf("GetCSRFToken(missing) = %q, want empty", token3)
	}
}

func TestCSRFMiddleware_SameOrigin_NoBypass_RequiresToken(t *testing.T) {
	cfg := DefaultCSRFConfig()
	cfg.SameSite = http.SameSiteStrictMode
	handler := CSRFMiddleware(cfg, false, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/submit", nil)
	req.Host = "example.com"
	req.Header.Set("Origin", "https://example.com")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// AI.md PART 16 "CSRF Protection": "There is NO Origin-based bypass." A
	// same-origin Origin header must never skip token validation.
	if rec.Code != http.StatusForbidden {
		t.Errorf("Same-origin POST without a token must still be rejected, got %d", rec.Code)
	}
}

func TestCSRFMiddleware_CrossOrigin_RequiresToken(t *testing.T) {
	cfg := DefaultCSRFConfig()
	handler := CSRFMiddleware(cfg, false, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/submit", nil)
	req.Host = "example.com"
	req.Header.Set("Origin", "https://evil.com")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("Cross-origin POST should require CSRF token, got %d", rec.Code)
	}
}

// A CSRF rejection is content-negotiated like every other error: a JSON client
// gets the canonical envelope, a browser gets the themed 403 page (AI.md 24407
// "ALL error pages MUST use the site theme system", 24413 listing 403 as
// theme-required, 24426 "honoring content negotiation - HTML for browsers, JSON
// for API clients"). It must not hand a raw JSON body to a form-posting browser.
func TestCSRFMiddleware_ErrorResponse_JSON(t *testing.T) {
	cfg := DefaultCSRFConfig()
	handler := CSRFMiddleware(cfg, false, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/submit", nil)
	req.Header.Set("Accept", jsonMediaType)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("Expected 403, got %d", rec.Code)
	}

	contentType := rec.Header().Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		t.Errorf("Error response should be JSON, got Content-Type: %s", contentType)
	}

	var body struct {
		OK      bool   `json:"ok"`
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("Error response is not valid JSON: %v (%s)", err, rec.Body.String())
	}
	if body.OK {
		t.Errorf("Error response should contain ok:false, got: %s", rec.Body.String())
	}
	// 403 maps to both FORBIDDEN and CSRF_FAILED in AI.md PART 9's error-code
	// table; a CSRF rejection must emit the specific one.
	if body.Error != "CSRF_FAILED" {
		t.Errorf("Expected error code CSRF_FAILED, got %q", body.Error)
	}
}

func TestCSRFMiddleware_ErrorResponse_BrowserIsNotJSON(t *testing.T) {
	cfg := DefaultCSRFConfig()
	handler := CSRFMiddleware(cfg, false, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/submit", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("Expected 403, got %d", rec.Code)
	}
	// The themed page itself needs the server's template set, which a unit test
	// does not wire up, so the render falls through to the guaranteed plain-text
	// response. What must hold either way is that a browser is never handed the
	// raw JSON envelope.
	if strings.Contains(rec.Header().Get("Content-Type"), "application/json") {
		t.Errorf("Browser CSRF rejection should not be JSON, got Content-Type: %s", rec.Header().Get("Content-Type"))
	}
	if strings.Contains(rec.Body.String(), `"error"`) {
		t.Errorf("Browser CSRF rejection leaked the JSON envelope: %s", rec.Body.String())
	}
}
