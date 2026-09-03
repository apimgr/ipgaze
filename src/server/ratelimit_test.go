package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/apimgr/ipgaze/src/config"
	"github.com/apimgr/ipgaze/src/netutil"
)

func TestDefaultRateLimitConfig(t *testing.T) {
	cfg := DefaultRateLimitConfig()
	cases := []struct {
		name  string
		got   RateLimitBucket
		limit int
	}{
		{"read", cfg.Read, 120},
		{"write", cfg.Write, 10},
		{"health", cfg.Health, 120},
		{"global", cfg.Global, 240},
	}
	for _, c := range cases {
		if c.got.Limit != c.limit {
			t.Errorf("%s limit = %d, want %d", c.name, c.got.Limit, c.limit)
		}
		if c.got.Window != time.Minute {
			t.Errorf("%s window = %v, want 1m", c.name, c.got.Window)
		}
	}
}

func TestNewRateLimiter(t *testing.T) {
	cfg := RateLimitConfig{Read: RateLimitBucket{Limit: 10, Window: time.Second, Burst: 5}}
	rl := NewRateLimiter(cfg, netutil.NewTrustResolver(config.TrustedProxiesConfig{}, ""))
	defer rl.Stop()

	if rl.config.Read.Limit != 10 {
		t.Errorf("config.Read.Limit = %d, want 10", rl.config.Read.Limit)
	}
	// Unset classes fall back to the spec defaults so a partial config never
	// silently disables enforcement.
	if rl.config.Write.Limit != 10 {
		t.Errorf("config.Write.Limit = %d, want 10 (default)", rl.config.Write.Limit)
	}
	if rl.config.Global.Limit != 240 {
		t.Errorf("config.Global.Limit = %d, want 240 (default)", rl.config.Global.Limit)
	}
}

func TestRateLimiterAllow(t *testing.T) {
	cfg := RateLimitConfig{Read: RateLimitBucket{Limit: 100, Window: time.Second, Burst: 100}}
	rl := NewRateLimiter(cfg, netutil.NewTrustResolver(config.TrustedProxiesConfig{}, ""))
	defer rl.Stop()

	if !rl.Allow("192.0.2.1") {
		t.Error("expected Allow to return true for first request")
	}
}

func TestRateLimiterStop(t *testing.T) {
	cfg := DefaultRateLimitConfig()
	rl := NewRateLimiter(cfg, netutil.NewTrustResolver(config.TrustedProxiesConfig{}, ""))
	rl.Stop()
}

func TestRateLimiterCleanup(t *testing.T) {
	cfg := RateLimitConfig{Read: RateLimitBucket{Limit: 10, Window: time.Second, Burst: 5}}
	rl := &RateLimiter{
		limiters:        make(map[string]*clientLimiter),
		config:          cfg,
		cleanupInterval: 10 * time.Minute,
		stopCleanup:     make(chan struct{}),
	}

	key := "192.0.2.1|read"
	rl.getLimiter("192.0.2.1", rateClassRead)

	rl.mu.Lock()
	rl.limiters[key].lastSeen = time.Now().Add(-20 * time.Minute)
	rl.mu.Unlock()

	rl.cleanup()

	rl.mu.RLock()
	_, exists := rl.limiters[key]
	rl.mu.RUnlock()

	if exists {
		t.Error("expected stale limiter to be cleaned up")
	}
}

func TestRateLimitMiddlewareAllows(t *testing.T) {
	cfg := RateLimitConfig{Read: RateLimitBucket{Limit: 100, Window: time.Second, Burst: 100}}
	rl := NewRateLimiter(cfg, netutil.NewTrustResolver(config.TrustedProxiesConfig{}, ""))
	defer rl.Stop()

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := RateLimitMiddleware(rl)(next)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.0.2.5:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("expected next handler to be called")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestRateLimitMiddlewareBlocks(t *testing.T) {
	cfg := RateLimitConfig{Read: RateLimitBucket{Limit: 1, Window: time.Hour, Burst: 1}}
	rl := NewRateLimiter(cfg, netutil.NewTrustResolver(config.TrustedProxiesConfig{}, ""))
	defer rl.Stop()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := RateLimitMiddleware(rl)(next)
	clientIP := "192.0.2.99:9999"

	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.RemoteAddr = clientIP
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = clientIP
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusTooManyRequests {
		t.Errorf("second request: status = %d, want 429", rec2.Code)
	}
	if rec2.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header on rate-limited response")
	}
}

func TestRateLimitMiddlewareBlocks_InvokesOnBlocked(t *testing.T) {
	cfg := RateLimitConfig{Read: RateLimitBucket{Limit: 1, Window: time.Hour, Burst: 1}}
	rl := NewRateLimiter(cfg, netutil.NewTrustResolver(config.TrustedProxiesConfig{}, ""))
	defer rl.Stop()

	var gotIP string
	calls := 0
	rl.OnBlocked = func(clientIP string) {
		gotIP = clientIP
		calls++
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := RateLimitMiddleware(rl)(next)
	clientIP := "192.0.2.100:8888"

	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.RemoteAddr = clientIP
	handler.ServeHTTP(httptest.NewRecorder(), req1)

	if calls != 0 {
		t.Errorf("OnBlocked called %d times on first (allowed) request, want 0", calls)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = clientIP
	handler.ServeHTTP(httptest.NewRecorder(), req2)

	if calls != 1 {
		t.Fatalf("OnBlocked called %d times, want 1", calls)
	}
	if gotIP != "192.0.2.100" {
		t.Errorf("OnBlocked clientIP = %q, want %q", gotIP, "192.0.2.100")
	}
}

// TestRateLimitBodyOmitsRetryAfter locks in AI.md PART 12: the 429 body carries
// only ok/error/message and the wait time travels in the header alone.
func TestRateLimitBodyOmitsRetryAfter(t *testing.T) {
	cfg := RateLimitConfig{Read: RateLimitBucket{Limit: 1, Window: time.Hour, Burst: 1}}
	rl := NewRateLimiter(cfg, netutil.NewTrustResolver(config.TrustedProxiesConfig{}, ""))
	defer rl.Stop()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	handler := RateLimitMiddleware(rl)(next)

	var rec *httptest.ResponseRecorder
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "192.0.2.77:1111"
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("Retry-After header missing")
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if _, present := body["retry_after"]; present {
		t.Error("429 body must not contain a retry_after field")
	}
	if body["error"] != "RATE_LIMITED" {
		t.Errorf("error = %v, want RATE_LIMITED", body["error"])
	}
}

// TestRateLimitWriteClassExhaustsFirst verifies POSTs are metered against the
// write bucket (10/min) while GETs still pass on the far larger read bucket.
func TestRateLimitWriteClassExhaustsFirst(t *testing.T) {
	rl := NewRateLimiter(DefaultRateLimitConfig(), netutil.NewTrustResolver(config.TrustedProxiesConfig{}, ""))
	defer rl.Stop()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	handler := RateLimitMiddleware(rl)(next)
	const addr = "192.0.2.88:2222"

	var lastWrite int
	for i := 0; i < 11; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/anything", nil)
		req.RemoteAddr = addr
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		lastWrite = rec.Code
	}
	if lastWrite != http.StatusTooManyRequests {
		t.Errorf("11th POST status = %d, want 429", lastWrite)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/anything", nil)
	req.RemoteAddr = addr
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code == http.StatusTooManyRequests {
		t.Error("GET was rejected even though the read bucket is untouched")
	}
}

// TestClassifyRequest covers the AI.md PART 12 endpoint classes.
func TestClassifyRequest(t *testing.T) {
	tests := []struct {
		method string
		path   string
		want   rateClass
	}{
		{http.MethodGet, "/api/v1/ip", rateClassRead},
		{http.MethodHead, "/api/v1/ip", rateClassRead},
		{http.MethodPost, "/api/v1/ip", rateClassWrite},
		{http.MethodDelete, "/api/v1/ip", rateClassWrite},
		{http.MethodGet, "/healthz", rateClassHealth},
		{http.MethodGet, "/api/v1/server/healthz", rateClassHealth},
	}
	for _, tt := range tests {
		req := httptest.NewRequest(tt.method, tt.path, nil)
		if got := classifyRequest(req); got != tt.want {
			t.Errorf("classifyRequest(%s %s) = %q, want %q", tt.method, tt.path, got, tt.want)
		}
	}
}

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		xri        string
		want       string
	}{
		// 192.0.2.x is TEST-NET-1 — not in any trusted CIDR, so proxy headers are ignored.
		{"remote addr only", "192.0.2.1:1234", "", "", "192.0.2.1"},
		// 10.x.x.x is RFC 1918 private — always trusted; proxy headers are honored.
		{"x-forwarded-for single", "10.0.0.1:1234", "1.2.3.4", "", "1.2.3.4"},
		{"x-forwarded-for multiple", "10.0.0.1:1234", "1.2.3.4,5.6.7.8", "", "1.2.3.4"},
		{"x-real-ip", "10.0.0.1:1234", "", "9.9.9.9", "9.9.9.9"},
		// AI.md PART 15 lists X-Real-IP ahead of X-Forwarded-For, so it wins.
		{"x-real-ip wins over xff", "10.0.0.1:1234", "1.1.1.1", "9.9.9.9", "9.9.9.9"},
	}
	rl := NewRateLimiter(DefaultRateLimitConfig(), netutil.NewTrustResolver(config.TrustedProxiesConfig{}, ""))
	defer rl.Stop()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.xri != "" {
				req.Header.Set("X-Real-IP", tt.xri)
			}
			got := rl.getClientIP(req)
			if got != tt.want {
				t.Errorf("getClientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}
