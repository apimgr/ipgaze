package server

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/apimgr/ipgaze/src/config"
	"github.com/apimgr/ipgaze/src/db"
	"github.com/apimgr/ipgaze/src/netutil"
)

func newAbuseTestDB(t *testing.T) *sql.DB {
	t.Helper()
	conn, err := db.OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	conn.SetMaxOpenConns(1)
	if err := db.EnsureSchema(conn); err != nil {
		_ = conn.Close()
		t.Fatalf("ensure test schema: %v", err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Errorf("close test database: %v", err)
		}
	})
	return conn
}

func TestAbuseMiddlewarePermanentBlockAndAllowlistPrecedence(t *testing.T) {
	conn := newAbuseTestDB(t)
	policy := AbusePolicy{Permanent: []config.BlockedIPEntry{{CIDR: "198.51.100.0/24"}}}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	handler := AbuseMiddleware(conn, policy, nil, nil, nil, nil)(next)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "198.51.100.12:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("blocked request status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	allowlist := NewAllowlistLookup([]AllowlistEntry{{CIDR: "198.51.100.12"}})
	handler = AbuseMiddleware(conn, policy, nil, allowlist, nil, nil)(next)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("allowlisted request status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if err := persistTemporaryIPBlock(context.Background(), conn, "198.51.100.12", time.Now().Add(time.Hour), 1); err != nil {
		t.Fatalf("insert temporary block: %v", err)
	}
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	var remaining int
	if err := conn.QueryRow(`SELECT COUNT(*) FROM ip_blocks WHERE ip = ?`, "198.51.100.12").Scan(&remaining); err != nil {
		t.Fatalf("check temporary block cleanup: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("allowlisted temporary block rows = %d, want 0", remaining)
	}
}

func TestAbuseMiddlewarePermanentBlockSupportsIPv4AndIPv6(t *testing.T) {
	policy := AbusePolicy{Permanent: []config.BlockedIPEntry{
		{CIDR: "198.51.100.0/24"},
		{CIDR: "2001:db8:1234::/48"},
	}}
	handler := AbuseMiddleware(nil, policy, nil, nil, nil, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	for _, address := range []string{"198.51.100.12:1234", "[2001:db8:1234::12]:1234"} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = address
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("blocked request from %s status = %d, want %d", address, rec.Code, http.StatusForbidden)
		}
	}
}

func TestAbuseMiddlewareFloodPersistsTemporaryBlock(t *testing.T) {
	conn := newAbuseTestDB(t)
	limits := DefaultRateLimitConfig()
	limits.Write.Limit = 1
	limits.Global.Limit = 100
	policy := AbusePolicy{
		Enabled:       true,
		AutoBlockIP:   true,
		Multiplier:    1,
		Window:        time.Minute,
		BlockDuration: time.Hour,
		Limits:        limits,
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	handler := AbuseMiddleware(conn, policy, nil, nil, nil, nil)(next)
	makeRequest := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/server/contact", nil)
		req.RemoteAddr = "203.0.113.10:1234"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	if got := makeRequest().Code; got != http.StatusNoContent {
		t.Fatalf("first request status = %d, want %d", got, http.StatusNoContent)
	}
	if got := makeRequest().Code; got != http.StatusForbidden {
		t.Fatalf("flood request status = %d, want %d", got, http.StatusForbidden)
	}
	var autoBlocked int
	if err := conn.QueryRowContext(context.Background(), `SELECT auto_blocked FROM ip_blocks WHERE ip = ?`, "203.0.113.10").Scan(&autoBlocked); err != nil {
		t.Fatalf("read persisted block: %v", err)
	}
	if autoBlocked != 1 {
		t.Fatalf("auto_blocked = %d, want 1", autoBlocked)
	}
}

func TestAbuseMiddlewareSkipsOverlayRequests(t *testing.T) {
	policy := AbusePolicy{
		Enabled:     true,
		AutoBlockIP: true,
		Multiplier:  1,
		Limits:      RateLimitConfig{Write: RateLimitBucket{Limit: 1, Window: time.Minute}},
		Permanent:   []config.BlockedIPEntry{{CIDR: "127.0.0.1/32"}},
	}
	handler := AbuseMiddleware(nil, policy, &netutil.TrustResolver{I2PAddress: "test.b32.i2p", OnionAddress: "example.onion"}, nil, nil, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	for _, host := range []string{"test.b32.i2p", "example.onion"} {
		req := httptest.NewRequest(http.MethodPost, "http://"+host+"/", nil)
		req.RemoteAddr = "127.0.0.1:5678"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Errorf("overlay host %q status = %d, want %d", host, rec.Code, http.StatusNoContent)
		}
	}
}
