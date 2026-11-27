package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/apimgr/ipgaze/src/config"
)

func TestContactCaptchaCSPAddsOnlySelectedProviderHosts(t *testing.T) {
	for _, tt := range []struct {
		provider string
		want     string
		reject   string
	}{
		{provider: "recaptcha", want: "www.google.com/recaptcha", reject: "hcaptcha.com"},
		{provider: "hcaptcha", want: "*.hcaptcha.com", reject: "www.google.com/recaptcha"},
		{provider: "simple", reject: "hcaptcha.com"},
	} {
		header := SecurityHeaderConfigFromApp(&config.AppConfig{Pages: config.PagesConfig{Contact: config.ContactPageConfig{Captcha: tt.provider}}})
		var policy strings.Builder
		for _, directive := range header.CSP.Directives {
			if directive.Name == "script-src" || directive.Name == "frame-src" || directive.Name == "connect-src" {
				policy.WriteString(directive.resolved())
			}
		}
		if tt.want != "" && !strings.Contains(policy.String(), tt.want) {
			t.Errorf("provider %s CSP omitted %q: %s", tt.provider, tt.want, policy.String())
		}
		if strings.Contains(policy.String(), tt.reject) {
			t.Errorf("provider %s CSP unexpectedly contains %q", tt.provider, tt.reject)
		}
	}
}

func TestResolveOnionAddressRequiresExposure(t *testing.T) {
	status := &stubTorController{}
	s := &Server{
		TorStatus: status,
		config: &config.AppConfig{
			Tor:    config.TorIdentityConfig{OnionAddress: "configured.onion"},
			Server: config.ServerConfig{Tor: config.TorConfig{Expose: false}},
		},
	}
	if got := s.resolveOnionAddress(); got != "" {
		t.Fatalf("resolveOnionAddress with exposure disabled = %q, want empty", got)
	}
	s.config.Server.Tor.Expose = true
	if got := s.resolveOnionAddress(); got != "configured.onion" {
		t.Fatalf("resolveOnionAddress with exposure enabled = %q, want configured address", got)
	}
	s.config.Tor.OnionAddress = ""
	if got := s.resolveOnionAddress(); got != "" {
		t.Fatalf("resolveOnionAddress without configured address = %q, want empty", got)
	}
}

func TestOnionLocationMiddlewareUsesOnionURLOnlyForHTMLDocuments(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html></html>"))
	})
	middleware := OnionLocationMiddleware(func() string { return "exampleonion.onion" })(next)
	request := httptest.NewRequest(http.MethodGet, "/docs?q=one", nil)
	request.Host = "example.com"
	request.Header.Set("Sec-Fetch-Dest", "document")
	response := httptest.NewRecorder()
	middleware.ServeHTTP(response, request)
	if got, want := response.Header().Get("Onion-Location"), "http://exampleonion.onion/docs?q=one"; got != want {
		t.Fatalf("Onion-Location = %q, want %q", got, want)
	}

	apiRequest := httptest.NewRequest(http.MethodGet, "/api/v1/info", nil)
	apiRequest.Host = "example.com"
	apiRequest.Header.Set("Sec-Fetch-Dest", "document")
	apiResponse := httptest.NewRecorder()
	middleware.ServeHTTP(apiResponse, apiRequest)
	if got := apiResponse.Header().Get("Onion-Location"); got != "" {
		t.Fatalf("API response Onion-Location = %q, want empty", got)
	}
}

func TestPermissionsPolicyIsFixed(t *testing.T) {
	policy := permissionsPolicyValue(DefaultSecurityHeaderConfig().PermissionsPolicy)
	for _, required := range []string{
		"accelerometer=()", "camera=()",
		"display-capture=()", "geolocation=()", "hid=()", "idle-detection=()",
		"microphone=()", "midi=()", "serial=()", "usb=()", "xr-spatial-tracking=()",
		"attribution-reporting=()", "browsing-topics=()",
		"autoplay=(self)", "publickey-credentials-get=(self)",
	} {
		if !strings.Contains(policy, required) {
			t.Errorf("Permissions-Policy missing %q: %s", required, policy)
		}
	}
	for _, unexpected := range []string{"cross-origin-isolated", "document-domain", "sync-xhr", "keyboard-map"} {
		if strings.Contains(policy, unexpected) {
			t.Errorf("Permissions-Policy unexpectedly contains %q: %s", unexpected, policy)
		}
	}
}

func TestSecurityHeadersMiddleware(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("without SSL", func(t *testing.T) {
		middleware := SecurityHeadersMiddleware(DefaultSecurityHeaderConfig(), false, false)
		wrapped := middleware(handler)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()

		wrapped.ServeHTTP(rec, req)

		// Check required headers
		expectedHeaders := map[string]string{
			"X-Content-Type-Options": "nosniff",
			"X-Frame-Options":        "SAMEORIGIN",
			"X-XSS-Protection":       "1; mode=block",
			"Referrer-Policy":        "strict-origin-when-cross-origin",
		}

		for header, expected := range expectedHeaders {
			got := rec.Header().Get(header)
			if got != expected {
				t.Errorf("Header %s = %q, want %q", header, got, expected)
			}
		}

		// HSTS should NOT be set when SSL is disabled
		if hsts := rec.Header().Get("Strict-Transport-Security"); hsts != "" {
			t.Errorf("HSTS header should not be set when SSL disabled, got %q", hsts)
		}

		// Server-Timing MUST NOT be set in non-debug mode
		if st := rec.Header().Get("Server-Timing"); st != "" {
			t.Errorf("Server-Timing header must not be set in production mode, got %q", st)
		}
	})

	t.Run("with SSL", func(t *testing.T) {
		middleware := SecurityHeadersMiddleware(DefaultSecurityHeaderConfig(), true, false)
		wrapped := middleware(handler)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()

		wrapped.ServeHTTP(rec, req)

		// HSTS SHOULD be set when SSL is enabled per AI.md PART 11 (2-year, preload ON by default).
		hsts := rec.Header().Get("Strict-Transport-Security")
		expected := "max-age=63072000; includeSubDomains; preload"
		if hsts != expected {
			t.Errorf("HSTS header = %q, want %q", hsts, expected)
		}
	})

	t.Run("debug mode emits Server-Timing", func(t *testing.T) {
		middleware := SecurityHeadersMiddleware(DefaultSecurityHeaderConfig(), false, true)
		wrapped := middleware(handler)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()

		wrapped.ServeHTTP(rec, req)

		// Server-Timing MUST be present in debug mode
		if st := rec.Header().Get("Server-Timing"); st == "" {
			t.Error("Server-Timing header must be set in debug mode")
		}
	})
}

func TestURLNormalizeMiddleware(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		inputPath      string
		expectedPath   string
		expectRedirect bool
		wantStatus     int
	}{
		{"double slashes", http.MethodGet, "/api//v1//test", "/api/v1/test", true, http.StatusMovedPermanently},
		{"trailing slash", http.MethodGet, "/api/v1/", "/api/v1", true, http.StatusMovedPermanently},
		{"head trailing slash", http.MethodHead, "/api/v1/", "/api/v1", true, http.StatusMovedPermanently},
		{"post trailing slash", http.MethodPost, "/api/v1/", "/api/v1", true, http.StatusPermanentRedirect},
		{"put trailing slash", http.MethodPut, "/api/v1/", "/api/v1", true, http.StatusPermanentRedirect},
		{"root path", http.MethodGet, "/", "/", false, 0},
		{"already normalized", http.MethodGet, "/api/v1", "/api/v1", false, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedPath string
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedPath = r.URL.Path
				w.WriteHeader(http.StatusOK)
			})

			wrapped := URLNormalizeMiddleware(handler)

			req := httptest.NewRequest(tt.method, tt.inputPath, strings.NewReader("request body"))
			rec := httptest.NewRecorder()

			wrapped.ServeHTTP(rec, req)

			if tt.expectRedirect {
				if rec.Code != tt.wantStatus {
					t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
				}
				loc := rec.Header().Get("Location")
				if loc != tt.expectedPath {
					t.Errorf("Location header = %q, want %q", loc, tt.expectedPath)
				}
			} else if capturedPath != tt.expectedPath {
				t.Errorf("Normalized path = %q, want %q", capturedPath, tt.expectedPath)
			}
		})
	}
}

func TestPathSecurityMiddleware(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := PathSecurityMiddleware(handler)

	tests := []struct {
		name       string
		path       string
		wantStatus int
	}{
		{"valid path", "/api/v1/test", http.StatusOK},
		{"valid with dots", "/api/.config", http.StatusOK},
		{"traversal attempt", "/api/../etc/passwd", http.StatusBadRequest},
		{"encoded traversal", "/api/%2e%2e/etc", http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			rec := httptest.NewRecorder()

			wrapped.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("Status = %d, want %d", rec.Code, tt.wantStatus)
			}
		})
	}
}

func TestChainMiddleware(t *testing.T) {
	// Track the order middleware is applied
	var order []string

	m1 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "m1-before")
			next.ServeHTTP(w, r)
			order = append(order, "m1-after")
		})
	}

	m2 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "m2-before")
			next.ServeHTTP(w, r)
			order = append(order, "m2-after")
		})
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		order = append(order, "handler")
	})

	wrapped := ChainMiddleware(handler, m1, m2)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	// First middleware (m1) should be outermost
	expected := []string{"m1-before", "m2-before", "handler", "m2-after", "m1-after"}
	if len(order) != len(expected) {
		t.Errorf("Order length = %d, want %d", len(order), len(expected))
		return
	}

	for i, v := range expected {
		if order[i] != v {
			t.Errorf("Order[%d] = %q, want %q", i, order[i], v)
		}
	}
}

func TestSanitizeInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"no whitespace", "hello", "hello"},
		{"leading space", "  hello", "hello"},
		{"trailing space", "hello  ", "hello"},
		{"both spaces", "  hello  ", "hello"},
		{"internal spaces preserved", "hello world", "hello world"},
		{"tabs", "\thello\t", "hello"},
		{"newlines", "\nhello\n", "hello"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeInput(tt.input)
			if got != tt.want {
				t.Errorf("SanitizeInput() = %q, want %q", got, tt.want)
			}
		})
	}
}
