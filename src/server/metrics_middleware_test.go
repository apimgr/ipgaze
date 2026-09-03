package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"/api/v1/users", "/api/v1/users"},
		{"/api/v1/users/123", "/api/v1/users/:id"},
		{"/api/v1/users/456/posts", "/api/v1/users/:id/posts"},
		{"/api/v1/items/550e8400-e29b-41d4-a716-446655440000", "/api/v1/items/:id"},
		{"/static/file.js", "/static/file.js"},
	}
	for _, tt := range tests {
		got := normalizePath(tt.input)
		if got != tt.want {
			t.Errorf("normalizePath(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestMetricsResponseWriter(t *testing.T) {
	rec := httptest.NewRecorder()
	mw := newMetricsResponseWriter(rec)

	if mw.statusCode != http.StatusOK {
		t.Errorf("default statusCode = %d, want 200", mw.statusCode)
	}

	mw.WriteHeader(http.StatusNotFound)
	if mw.statusCode != http.StatusNotFound {
		t.Errorf("statusCode = %d, want 404", mw.statusCode)
	}

	n, err := mw.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != 5 {
		t.Errorf("Write returned %d, want 5", n)
	}
	if mw.bytesWritten != 5 {
		t.Errorf("bytesWritten = %d, want 5", mw.bytesWritten)
	}
}

func TestMetricsMiddlewareDisabled(t *testing.T) {
	s := &Server{}

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := s.metricsMiddleware(next)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ip", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("expected next handler to be called when metrics disabled")
	}
}

func TestMetricsMiddlewareEnabled(t *testing.T) {
	s := &Server{metricsEnabled: true}

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := s.metricsMiddleware(next)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ip", nil)
	req.ContentLength = 42
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("expected next handler to be called when metrics enabled")
	}
}
