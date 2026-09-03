package server

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewAllowlistLookup(t *testing.T) {
	entries := []AllowlistEntry{
		{CIDR: "192.168.1.0/24", Description: "local network"},
		{CIDR: "10.0.0.1", Description: "single IP"},
		{CIDR: "::1", Description: "IPv6 loopback"},
		{CIDR: "", Description: "empty — skipped"},
		{CIDR: "not-a-cidr", Description: "invalid — skipped"},
	}
	al := NewAllowlistLookup(entries)
	if al == nil {
		t.Fatal("expected non-nil AllowlistLookup")
	}
}

func TestAllowlistLookupContains(t *testing.T) {
	al := NewAllowlistLookup([]AllowlistEntry{
		{CIDR: "192.168.1.0/24"},
		{CIDR: "10.0.0.5"},
	})

	tests := []struct {
		ip   string
		want bool
	}{
		{"192.168.1.1", true},
		{"192.168.1.254", true},
		{"192.168.2.1", false},
		{"10.0.0.5", true},
		{"10.0.0.6", false},
		{"8.8.8.8", false},
	}
	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		got := al.Contains(ip)
		if got != tt.want {
			t.Errorf("Contains(%s) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func TestAllowlistLookupContainsNil(t *testing.T) {
	al := NewAllowlistLookup(nil)
	if al.Contains(nil) {
		t.Error("Contains(nil) should return false")
	}
}

func TestAllowlistMiddlewareNilPassthrough(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := AllowlistMiddleware(nil)(next)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("expected next handler to be called when allowlist is nil")
	}
}

func TestAllowlistMiddlewareSetsContext(t *testing.T) {
	al := NewAllowlistLookup([]AllowlistEntry{
		{CIDR: "192.168.1.0/24"},
	})

	var wasAllowlisted bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wasAllowlisted = IsAllowlisted(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := AllowlistMiddleware(al)(next)

	t.Run("allowlisted IP sets flag", func(t *testing.T) {
		wasAllowlisted = false
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "192.168.1.5:1234"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if !wasAllowlisted {
			t.Error("expected allowlisted flag to be set for allowlisted IP")
		}
	})

	t.Run("non-allowlisted IP does not set flag", func(t *testing.T) {
		wasAllowlisted = false
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "8.8.8.8:1234"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if wasAllowlisted {
			t.Error("expected allowlisted flag NOT to be set for non-allowlisted IP")
		}
	})
}

func TestIsAllowlistedFalseByDefault(t *testing.T) {
	ctx := context.Background()
	if IsAllowlisted(ctx) {
		t.Error("expected IsAllowlisted to be false on fresh context")
	}
}

func TestExtractIP(t *testing.T) {
	tests := []struct {
		remoteAddr string
		want       string
	}{
		{"192.0.2.1:8080", "192.0.2.1"},
		{"[::1]:8080", "::1"},
		{"10.0.0.5:9000", "10.0.0.5"},
	}
	for _, tt := range tests {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = tt.remoteAddr
		ip := extractIP(req)
		if ip == nil {
			t.Errorf("extractIP(%s) = nil, want %s", tt.remoteAddr, tt.want)
			continue
		}
		if ip.String() != tt.want {
			t.Errorf("extractIP(%s) = %s, want %s", tt.remoteAddr, ip.String(), tt.want)
		}
	}
}
