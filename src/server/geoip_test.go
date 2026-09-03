package server

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/apimgr/ipgaze/src/iputil/geo"
)

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.0.1", true},
		{"192.168.255.255", true},
		{"169.254.0.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"203.0.113.5", false},
	}
	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		got := isPrivateIP(ip)
		if got != tt.want {
			t.Errorf("isPrivateIP(%s) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func TestGeoIPMiddlewareNilReader(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := GeoIPMiddleware(nil, []string{"CN"}, nil)(next)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("expected next handler to be called when geo reader is nil")
	}
}

func TestGeoIPMiddlewareEmptyLists(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	gr := &testDb{}
	handler := GeoIPMiddleware(gr, nil, nil)(next)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "8.8.8.8:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("expected next handler when no country rules configured")
	}
}

func TestGeoIPMiddlewareDenyCountry(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	gr := &testDb{}
	handler := GeoIPMiddleware(gr, []string{"EB"}, nil)(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "8.8.8.8:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for denied country", rec.Code)
	}
}

func TestGeoIPMiddlewareAllowCountryNotListed(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	gr := &testDb{}
	handler := GeoIPMiddleware(gr, nil, []string{"US"})(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "8.8.8.8:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for country not in allowlist", rec.Code)
	}
}

func TestGeoIPMiddlewareAllowCountryMatches(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	gr := &testDb{}
	handler := GeoIPMiddleware(gr, nil, []string{"EB"})(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "8.8.8.8:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 for country in allowlist", rec.Code)
	}
}

func TestGeoIPMiddlewarePrivateIPBypass(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	gr := &testDb{}
	handler := GeoIPMiddleware(gr, []string{"EB"}, nil)(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("expected private IP to bypass country blocking")
	}
}

func TestGeoIPMiddlewareAllowlistedBypass(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	gr := &testDb{}
	handler := GeoIPMiddleware(gr, []string{"EB"}, nil)(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "8.8.8.8:1234"
	ctx := context.WithValue(req.Context(), ctxKeyAllowlisted, true)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("expected allowlisted IP to bypass country blocking")
	}
}

type emptyGeoReader struct{}

func (e *emptyGeoReader) Country(net.IP) (geo.Country, error) { return geo.Country{}, nil }
func (e *emptyGeoReader) City(net.IP) (geo.City, error)       { return geo.City{}, nil }
func (e *emptyGeoReader) ASN(net.IP) (geo.ASN, error)         { return geo.ASN{}, nil }
func (e *emptyGeoReader) IsEmpty() bool                       { return true }

func TestGeoIPMiddlewareEmptyReader(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := GeoIPMiddleware(&emptyGeoReader{}, []string{"CN"}, nil)(next)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("expected next handler to be called when geo reader is empty")
	}
}
