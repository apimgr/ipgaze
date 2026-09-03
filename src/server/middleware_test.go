package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

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
		inputPath      string
		expectedPath   string
		expectRedirect bool
	}{
		{"double slashes", "/api//v1//test", "/api/v1/test", true},
		{"trailing slash", "/api/v1/", "/api/v1", true},
		{"root path", "/", "/", false},
		{"already normalized", "/api/v1", "/api/v1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedPath string
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedPath = r.URL.Path
				w.WriteHeader(http.StatusOK)
			})

			wrapped := URLNormalizeMiddleware(handler)

			req := httptest.NewRequest(http.MethodGet, tt.inputPath, nil)
			rec := httptest.NewRecorder()

			wrapped.ServeHTTP(rec, req)

			if tt.expectRedirect {
				// Should redirect to normalized path with 301.
				if rec.Code != http.StatusMovedPermanently {
					t.Errorf("status = %d, want %d (301 redirect)", rec.Code, http.StatusMovedPermanently)
				}
				loc := rec.Header().Get("Location")
				if loc != tt.expectedPath {
					t.Errorf("Location header = %q, want %q", loc, tt.expectedPath)
				}
			} else {
				// Should pass through to handler with unchanged path.
				if capturedPath != tt.expectedPath {
					t.Errorf("Normalized path = %q, want %q", capturedPath, tt.expectedPath)
				}
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
