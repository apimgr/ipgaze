package handler

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/apimgr/ipgaze/src/config"
	"github.com/apimgr/ipgaze/src/server/metrics"
)

func TestIsLoopback_True(t *testing.T) {
	tests := []struct {
		remoteAddr string
	}{
		{"127.0.0.1:1234"},
		{"[::1]:5678"},
	}
	for _, tt := range tests {
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		req.RemoteAddr = tt.remoteAddr
		if !IsLoopbackRequest(req) {
			t.Errorf("IsLoopbackRequest(%q) = false, want true", tt.remoteAddr)
		}
	}
}

func TestIsLoopback_False(t *testing.T) {
	tests := []struct {
		remoteAddr string
	}{
		{"203.0.113.5:1234"},
		{"[2001:db8::1]:5678"},
		{"10.0.0.1:80"},
	}
	for _, tt := range tests {
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		req.RemoteAddr = tt.remoteAddr
		if IsLoopbackRequest(req) {
			t.Errorf("IsLoopbackRequest(%q) = true, want false", tt.remoteAddr)
		}
	}
}

func TestIsLoopback_NoPort(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.RemoteAddr = "127.0.0.1"
	if !IsLoopbackRequest(req) {
		t.Errorf("IsLoopbackRequest(127.0.0.1 without port) = false, want true")
	}
}

// metricsTestConfig builds a PART 20 metrics config with the given tokens.
func metricsTestConfig(prom, grafana, loki string) config.MetricsConfig {
	return config.MetricsConfig{
		Enabled: true,
		Root:    config.MetricsRootConfig{Enabled: true},
		Auth: config.MetricsAuthConfig{
			Tokens: config.MetricsTokensConfig{
				Prometheus: prom,
				Grafana:    grafana,
				Loki:       loki,
			},
		},
		Loki: config.MetricsLokiConfig{MaxEntries: 10, MaxAge: "1h"},
	}
}

// recordingRouter captures the patterns RegisterMetricsRoutes mounts.
type recordingRouter struct {
	routes map[string]http.HandlerFunc
}

func newRecordingRouter() *recordingRouter {
	return &recordingRouter{routes: map[string]http.HandlerFunc{}}
}

func (r *recordingRouter) Get(pattern string, h http.HandlerFunc) {
	r.routes[pattern] = h
}

func TestRegisterMetricsRoutes_AllAliasesMounted(t *testing.T) {
	rr := newRecordingRouter()
	RegisterMetricsRoutes(rr, metricsTestConfig("ptok", "gtok", "ltok"), "ipgaze")

	prefixes := []string{
		"/server/metrics",
		"/api/v1/server/metrics",
		"/api/metrics",
		"/metrics",
	}
	for _, prefix := range prefixes {
		for _, suffix := range []string{"", "/prometheus", "/grafana", "/loki"} {
			path := prefix + suffix
			if rr.routes[path] == nil {
				t.Errorf("route %q not mounted", path)
			}
		}
	}
	if len(rr.routes) != len(prefixes)*4 {
		t.Errorf("mounted %d routes, want %d", len(rr.routes), len(prefixes)*4)
	}
}

func TestRegisterMetricsRoutes_RootAliasDisabled(t *testing.T) {
	cfg := metricsTestConfig("ptok", "gtok", "ltok")
	cfg.Root.Enabled = false
	rr := newRecordingRouter()
	RegisterMetricsRoutes(rr, cfg, "ipgaze")

	if rr.routes["/metrics"] != nil {
		t.Error("/metrics mounted while root.enabled is false")
	}
	if rr.routes["/server/metrics"] == nil {
		t.Error("/server/metrics must stay mounted when root.enabled is false")
	}
}

func TestRegisterMetricsRoutes_AliasesShareOneHandler(t *testing.T) {
	rr := newRecordingRouter()
	RegisterMetricsRoutes(rr, metricsTestConfig("ptok", "gtok", "ltok"), "ipgaze")

	for _, path := range []string{"/server/metrics", "/api/v1/server/metrics", "/api/metrics", "/metrics"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer ptok")
		w := httptest.NewRecorder()
		rr.routes[path](w, req)
		res := w.Result()
		if res.StatusCode != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", path, res.StatusCode)
		}
		if loc := res.Header.Get("Location"); loc != "" {
			t.Errorf("%s: alias redirected to %q, want same handler", path, loc)
		}
	}
}

func TestMetricsAuth_EmptyTokenDisablesService(t *testing.T) {
	h := MetricsAuth(metricsTestConfig("", "", ""), "", okHandler())
	req := httptest.NewRequest(http.MethodGet, "/server/metrics", nil)
	req.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", res.StatusCode)
	}
	body, _ := io.ReadAll(res.Body)
	if len(body) != 0 {
		t.Errorf("body = %q, want empty", string(body))
	}
}

func TestMetricsAuth_WrongTokenUnauthorized(t *testing.T) {
	h := MetricsAuth(metricsTestConfig("secret", "", ""), "secret", okHandler())
	req := httptest.NewRequest(http.MethodGet, "/server/metrics", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Result().StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Result().StatusCode)
	}
}

func TestMetricsAuth_MissingHeaderUnauthorized(t *testing.T) {
	h := MetricsAuth(metricsTestConfig("secret", "", ""), "secret", okHandler())
	req := httptest.NewRequest(http.MethodGet, "/server/metrics", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Result().StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Result().StatusCode)
	}
}

func TestMetricsAuth_QueryStringTokenRejected(t *testing.T) {
	h := MetricsAuth(metricsTestConfig("secret", "", ""), "secret", okHandler())
	req := httptest.NewRequest(http.MethodGet, "/server/metrics?token=secret", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Result().StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (query-string tokens are forbidden)", w.Result().StatusCode)
	}
}

func TestMetricsAuth_ValidTokenAllowed(t *testing.T) {
	h := MetricsAuth(metricsTestConfig("secret", "", ""), "secret", okHandler())
	req := httptest.NewRequest(http.MethodGet, "/server/metrics", nil)
	req.Header.Set("Authorization", "Bearer secret")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Result().StatusCode)
	}
}

func TestMetricsAuth_AllowUnauthenticatedBypass(t *testing.T) {
	cfg := metricsTestConfig("", "", "")
	cfg.Auth.AllowUnauthenticated = true
	h := MetricsAuth(cfg, "", okHandler())
	req := httptest.NewRequest(http.MethodGet, "/server/metrics", nil)
	req.RemoteAddr = "203.0.113.5:4444"
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 with allow_unauthenticated", w.Result().StatusCode)
	}
}

func TestGrafanaDashboardHandler_ImportableJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/server/metrics/grafana", nil)
	w := httptest.NewRecorder()
	GrafanaDashboardHandler("ipgaze").ServeHTTP(w, req)

	res := w.Result()
	if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var doc map[string]any
	if err := json.NewDecoder(res.Body).Decode(&doc); err != nil {
		t.Fatalf("dashboard is not valid JSON: %v", err)
	}
	panels, ok := doc["panels"].([]any)
	if !ok || len(panels) == 0 {
		t.Fatal("dashboard has no panels")
	}
	templating, ok := doc["templating"].(map[string]any)
	if !ok {
		t.Fatal("dashboard has no templating block")
	}
	list, ok := templating["list"].([]any)
	if !ok || len(list) == 0 {
		t.Fatal("datasource must be a template variable")
	}
}

func TestLokiStreamsHandler_ServesBufferedEntries(t *testing.T) {
	buf := metrics.NewLogBuffer(10)
	buf.Append(metrics.LogEntry{Time: time.Now(), Level: "info", Line: "hello"})

	req := httptest.NewRequest(http.MethodGet, "/server/metrics/loki", nil)
	w := httptest.NewRecorder()
	LokiStreamsHandler(config.MetricsLokiConfig{MaxEntries: 10, MaxAge: "1h"}, buf, "ipgaze").ServeHTTP(w, req)

	var payload metrics.LokiPayload
	if err := json.NewDecoder(w.Result().Body).Decode(&payload); err != nil {
		t.Fatalf("loki payload is not valid JSON: %v", err)
	}
	if len(payload.Streams) != 1 {
		t.Fatalf("streams = %d, want 1", len(payload.Streams))
	}
	if payload.Streams[0].Stream["level"] != "info" {
		t.Errorf("level label = %q, want info", payload.Streams[0].Stream["level"])
	}
	if len(payload.Streams[0].Values) != 1 || payload.Streams[0].Values[0][1] != "hello" {
		t.Errorf("values = %v, want one entry with line hello", payload.Streams[0].Values)
	}
}

func TestLokiStreamsHandler_EmptyBufferIsEmptyStreamArray(t *testing.T) {
	buf := metrics.NewLogBuffer(10)
	req := httptest.NewRequest(http.MethodGet, "/server/metrics/loki", nil)
	w := httptest.NewRecorder()
	LokiStreamsHandler(config.MetricsLokiConfig{MaxEntries: 10, MaxAge: "1h"}, buf, "ipgaze").ServeHTTP(w, req)

	body, _ := io.ReadAll(w.Result().Body)
	if strings.TrimSpace(string(body)) != `{"streams":[]}` {
		t.Errorf("body = %q, want {\"streams\":[]}", strings.TrimSpace(string(body)))
	}
}

// okHandler is the downstream handler used to prove auth let a request through.
func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}
