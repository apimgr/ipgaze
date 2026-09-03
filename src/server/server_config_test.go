package server

import (
	"io"
	"log"
	"net/http/httptest"
	"testing"

	"github.com/apimgr/ipgaze/src/blocklist"
	"github.com/apimgr/ipgaze/src/config"
	"github.com/apimgr/ipgaze/src/netutil"
)

func TestSetConfig(t *testing.T) {
	s := &Server{}
	type myConfig struct{ Name string }
	cfg := myConfig{Name: "test"}
	s.SetConfig(cfg)
	if s.cfg == nil {
		t.Error("expected cfg to be set")
	}
}

func TestSetMetricsConfig(t *testing.T) {
	s := &Server{}

	t.Run("per-service tokens retained", func(t *testing.T) {
		cfg := config.MetricsConfig{Enabled: true}
		cfg.Auth.Tokens.Prometheus = "ptok"
		cfg.Auth.Tokens.Grafana = "gtok"
		cfg.Auth.Tokens.Loki = "ltok"
		s.SetMetricsConfig(cfg)
		if !s.metricsEnabled {
			t.Error("expected metricsEnabled to be true")
		}
		tokens := s.metricsConfig.Auth.Tokens
		if tokens.Prometheus != "ptok" || tokens.Grafana != "gtok" || tokens.Loki != "ltok" {
			t.Errorf("metricsConfig tokens = %+v, want ptok/gtok/ltok", tokens)
		}
	})

	t.Run("zero loki block gets spec defaults", func(t *testing.T) {
		s2 := &Server{}
		s2.SetMetricsConfig(config.MetricsConfig{Enabled: true})
		if s2.metricsConfig.Loki.MaxEntries != 1000 {
			t.Errorf("Loki.MaxEntries = %d, want 1000", s2.metricsConfig.Loki.MaxEntries)
		}
		if s2.metricsConfig.Loki.MaxAge != "1h" {
			t.Errorf("Loki.MaxAge = %q, want 1h", s2.metricsConfig.Loki.MaxAge)
		}
	})
}

func TestSetAllowlist(t *testing.T) {
	s := &Server{}
	al := NewAllowlistLookup(nil)
	s.SetAllowlist(al)
	if s.allowlistLookup == nil {
		t.Error("expected allowlistLookup to be set")
	}
}

func TestSetRateLimiter(t *testing.T) {
	s := &Server{}
	rl := NewRateLimiter(DefaultRateLimitConfig(), netutil.NewTrustResolver(config.TrustedProxiesConfig{}, ""))
	defer rl.Stop()
	s.SetRateLimiter(rl)
	if s.rateLimiter == nil {
		t.Error("expected rateLimiter to be set")
	}
}

func TestSetBlocklistLookup(t *testing.T) {
	s := &Server{}
	bl := &blocklist.Lookup{}
	s.SetBlocklistLookup(bl)
	if s.blocklistLookup == nil {
		t.Error("expected blocklistLookup to be set")
	}
}

func TestSetGeoIPCountries(t *testing.T) {
	s := &Server{}
	s.SetGeoIPCountries([]string{"CN", "RU"}, []string{"US", "DE"})
	if len(s.geoipDenyCountries) != 2 {
		t.Errorf("geoipDenyCountries len = %d, want 2", len(s.geoipDenyCountries))
	}
	if len(s.geoipAllowCountries) != 2 {
		t.Errorf("geoipAllowCountries len = %d, want 2", len(s.geoipAllowCountries))
	}
}

func TestNew(t *testing.T) {
	log.SetOutput(io.Discard)
	cache := NewCache(100)
	gr := &testDb{}
	s := NewHTTPServer(gr, cache)
	if s == nil {
		t.Fatal("expected non-nil Server")
	}
	if s.cache != cache {
		t.Error("expected cache to be set")
	}
	if s.gr != gr {
		t.Error("expected geo reader to be set")
	}
	if s.StartTime.IsZero() {
		t.Error("expected StartTime to be set")
	}
}

func TestCacheStats(t *testing.T) {
	c := NewCache(50)
	stats := c.Stats()
	if stats.Capacity != 50 {
		t.Errorf("Capacity = %d, want 50", stats.Capacity)
	}
	if stats.Size != 0 {
		t.Errorf("Size = %d, want 0", stats.Size)
	}
	if stats.Evictions != 0 {
		t.Errorf("Evictions = %d, want 0", stats.Evictions)
	}
}

func TestContextHelpers(t *testing.T) {
	t.Run("LangFromContext default", func(t *testing.T) {
		ts := httptest.NewServer(testServer().Handler())
		out, _, err := httpGet(ts.URL+"/ip", "", "")
		if err != nil {
			t.Fatal(err)
		}
		if out == "" {
			t.Error("expected non-empty response")
		}
	})
}

func TestDebugLogNoop(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	// Should not panic when debug is disabled.
	debugLogRequest(nil, false, r, 200, 0, 0)
}

func TestDebugLogActive(t *testing.T) {
	r := httptest.NewRequest("GET", "/test", nil)
	// Should not panic when debug is enabled and no log manager is attached.
	debugLogRequest(nil, true, r, 200, 0, 0)
}

func TestDebugMemoryHandler(t *testing.T) {
	log.SetOutput(io.Discard)
	t.Setenv("DEBUG", "true")
	srv := testServer()
	cfg := &config.AppConfig{Server: config.ServerConfig{Debug: config.DebugConfig{RuntimeEndpoints: true}}}
	srv.SetConfig(cfg)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	out, status, err := httpGet(ts.URL+"/debug/memory", "application/json", "")
	if err != nil {
		t.Fatal(err)
	}
	if status != 200 {
		t.Errorf("status = %d, want 200", status)
	}
	if len(out) == 0 {
		t.Error("expected non-empty debug memory response")
	}
}
