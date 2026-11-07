package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/apimgr/ipgaze/src/config"
	applog "github.com/apimgr/ipgaze/src/log"
	"github.com/apimgr/ipgaze/src/netutil"
)

// newTestLogManager builds a Manager writing into a temp dir and returns it
// alongside that directory.
func newTestLogManager(t *testing.T) (*applog.Manager, string) {
	t.Helper()
	dir := t.TempDir()
	m, err := applog.NewManager(dir, applog.DefaultConfig())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { m.Close() })
	return m, dir
}

func readLogFile(t *testing.T, dir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		if os.IsNotExist(err) {
			return ""
		}
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// serveThrough runs one request through LoggingMiddleware.
func serveThrough(t *testing.T, lm *applog.Manager, debug bool, method, path string) {
	t.Helper()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	tr := netutil.NewTrustResolver(config.TrustedProxiesConfig{}, "")
	handler := LoggingMiddleware(tr, lm, debug)(next)
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = "192.0.2.10:1234"
	handler.ServeHTTP(httptest.NewRecorder(), req)
}

// TestHealthCheckSuppressedFromAccessLog covers AI.md PART 11: a successful
// health poll writes no access-log entry.
func TestHealthCheckSuppressedFromAccessLog(t *testing.T) {
	lm, dir := newTestLogManager(t)
	serveThrough(t, lm, false, http.MethodGet, "/healthz")
	lm.Close()

	if got := readLogFile(t, dir, "access.log"); strings.Contains(got, "/healthz") {
		t.Errorf("healthz poll was logged: %q", got)
	}
}

// TestHealthCheckNotSuppressedInDebug covers the debug-mode carve-out.
func TestHealthCheckNotSuppressedInDebug(t *testing.T) {
	lm, dir := newTestLogManager(t)
	serveThrough(t, lm, true, http.MethodGet, "/healthz")
	lm.Close()

	if got := readLogFile(t, dir, "access.log"); !strings.Contains(got, "/healthz") {
		t.Errorf("healthz poll must be logged in debug mode, got %q", got)
	}
}

// TestNonHealthRequestIsLogged guards against over-broad suppression.
func TestNonHealthRequestIsLogged(t *testing.T) {
	lm, dir := newTestLogManager(t)
	serveThrough(t, lm, false, http.MethodGet, "/api/v1/ip")
	lm.Close()

	if got := readLogFile(t, dir, "access.log"); !strings.Contains(got, "/api/v1/ip") {
		t.Errorf("ordinary request was not logged, got %q", got)
	}
}

func TestRequestURIForLogRedactsSensitiveQueryValues(t *testing.T) {
	lm, dir := newTestLogManager(t)
	serveThrough(t, lm, false, http.MethodGet, "/server/security/report/sec_test?token=one-shot-secret&security_id=rotating-secret&keep=visible")
	lm.Close()
	logged := readLogFile(t, dir, "access.log")
	for _, secret := range []string{"one-shot-secret", "rotating-secret"} {
		if strings.Contains(logged, secret) {
			t.Errorf("access log contains sensitive query value %q: %s", secret, logged)
		}
	}
	for _, redacted := range []string{"token=xxxxx", "security_id=xxxxx", "keep=visible"} {
		if !strings.Contains(logged, redacted) {
			t.Errorf("access log does not contain %q: %s", redacted, logged)
		}
	}
	if got := sanitizeLogQuery("%74oken=hidden&api-key=another-secret&keep=visible"); got != "%74oken=xxxxx&api-key=xxxxx&keep=visible" {
		t.Errorf("sanitizeLogQuery() = %q", got)
	}
	debugConfig := applog.DefaultConfig()
	debugConfig.Debug.Enabled = true
	debugDir := t.TempDir()
	debugManager, err := applog.NewManager(debugDir, debugConfig)
	if err != nil {
		t.Fatal(err)
	}
	debugRequest := httptest.NewRequest(http.MethodGet, "/server/security/report/sec_test?token=one-shot-secret", nil)
	debugLogRequest(debugManager, true, debugRequest, http.StatusOK, time.Millisecond, 0)
	debugManager.Close()
	debugLog := readLogFile(t, debugDir, "debug.log")
	if strings.Contains(debugLog, "one-shot-secret") || !strings.Contains(debugLog, "query=token=xxxxx") {
		t.Errorf("debug log failed to redact query token: %s", debugLog)
	}
}

func TestSuppressAccessLog(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
		status int
		debug  bool
		want   bool
	}{
		{"healthy poll", http.MethodGet, "/healthz", 200, false, true},
		{"api healthz", http.MethodGet, "/api/v1/server/healthz", 200, false, true},
		{"failing poll", http.MethodGet, "/healthz", 503, false, false},
		{"debug mode", http.MethodGet, "/healthz", 200, true, false},
		{"post to healthz", http.MethodPost, "/healthz", 200, false, false},
		{"other path", http.MethodGet, "/api/v1/ip", 200, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			if got := suppressAccessLog(req, tt.status, tt.debug); got != tt.want {
				t.Errorf("suppressAccessLog = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestFailedAuthTimingFloor covers AI.md PART 11: a rejected operator token
// takes at least the fixed floor so latency reveals nothing about which check
// failed.
func TestFailedAuthTimingFloor(t *testing.T) {
	srv := testServer()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler must not run for a rejected token")
	})
	handler := srv.RequireOperatorToken(next)

	cases := []struct {
		name   string
		header string
	}{
		{"missing token", ""},
		{"wrong token", "Bearer not-the-right-token"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/server/config", nil)
			req.RemoteAddr = "192.0.2.11:1234"
			if c.header != "" {
				req.Header.Set("Authorization", c.header)
			}
			rec := httptest.NewRecorder()
			start := time.Now()
			handler.ServeHTTP(rec, req)
			elapsed := time.Since(start)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", rec.Code)
			}
			if elapsed < failedAuthFloor {
				t.Errorf("rejection took %v, below the %v floor", elapsed, failedAuthFloor)
			}
		})
	}
}
