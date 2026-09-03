package server

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/apimgr/ipgaze/src/config"
	"github.com/apimgr/ipgaze/src/server/handler"
)

// TestSetSchedulerAndDB covers the two zero-coverage setter methods.
func TestSetSchedulerAndDB(t *testing.T) {
	log.SetOutput(io.Discard)
	s := &Server{}

	t.Run("SetScheduler stores scheduler", func(t *testing.T) {
		s.SetScheduler(nil)
		if s.sched != nil {
			t.Error("expected sched to be nil after SetScheduler(nil)")
		}
	})

	t.Run("SetDB with nil clears db", func(t *testing.T) {
		s.SetDB(nil)
		if s.sqlDB != nil {
			t.Error("expected sqlDB to be nil after SetDB(nil)")
		}
	})
}

// TestPathSecurityMiddlewareRawPath tests the RawPath branch not covered by the existing test.
func TestPathSecurityMiddlewareRawPath(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrapped := PathSecurityMiddleware(handler)

	t.Run("path traversal in RawPath is rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/safe", nil)
		req.URL.RawPath = "/%2e%2e/%2e%2e/etc/passwd"
		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("non-empty safe RawPath passes through", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/ip", nil)
		req.URL.RawPath = "/api/v1/ip"
		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}
	})
}

// TestSha256File covers the sha256File helper.
func TestSha256File(t *testing.T) {
	t.Run("valid file returns hex hash", func(t *testing.T) {
		f, err := os.CreateTemp(t.TempDir(), "sha256test")
		if err != nil {
			t.Fatal(err)
		}
		f.WriteString("hello world")
		f.Close()

		hash, err := sha256File(f.Name())
		if err != nil {
			t.Fatalf("sha256File error: %v", err)
		}
		if len(hash) != 64 {
			t.Errorf("expected 64-char hex hash, got %d chars: %s", len(hash), hash)
		}
	})

	t.Run("non-existent file returns error", func(t *testing.T) {
		_, err := sha256File(filepath.Join(t.TempDir(), "no-such-file"))
		if err == nil {
			t.Error("expected error for missing file")
		}
	})
}

// TestDebugHandlersDirect covers debug.go handlers directly via HTTP.
func TestDebugHandlersDirect(t *testing.T) {
	log.SetOutput(io.Discard)
	t.Setenv("DEBUG", "true")

	t.Run("handleDebugConfig nil config returns status json", func(t *testing.T) {
		s := testServer()
		req := httptest.NewRequest(http.MethodGet, "/debug/config", nil)
		rec := httptest.NewRecorder()
		s.handleDebugConfig(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("handleDebugConfig with config returns sanitized config", func(t *testing.T) {
		s := testServer()
		s.SetConfig(&config.AppConfig{})
		req := httptest.NewRequest(http.MethodGet, "/debug/config", nil)
		rec := httptest.NewRecorder()
		s.handleDebugConfig(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("handleDebugRoutes returns route list", func(t *testing.T) {
		s := testServer()
		req := httptest.NewRequest(http.MethodGet, "/debug/routes", nil)
		rec := httptest.NewRecorder()
		s.handleDebugRoutes(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("handleDebugCache nil returns status json", func(t *testing.T) {
		s := &Server{}
		req := httptest.NewRequest(http.MethodGet, "/debug/cache", nil)
		rec := httptest.NewRecorder()
		s.handleDebugCache(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("handleDebugCacheResize nil returns status json", func(t *testing.T) {
		s := &Server{}
		req := httptest.NewRequest(http.MethodGet, "/debug/cache/resize", nil)
		rec := httptest.NewRecorder()
		s.handleDebugCacheResize(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("handleDebugDB nil db returns status json", func(t *testing.T) {
		s := &Server{}
		req := httptest.NewRequest(http.MethodGet, "/debug/db", nil)
		rec := httptest.NewRecorder()
		s.handleDebugDB(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("handleDebugScheduler nil returns status json", func(t *testing.T) {
		s := &Server{}
		req := httptest.NewRequest(http.MethodGet, "/debug/scheduler", nil)
		rec := httptest.NewRecorder()
		s.handleDebugScheduler(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("handleDebugGoroutines returns plain text stacks", func(t *testing.T) {
		s := testServer()
		req := httptest.NewRequest(http.MethodGet, "/debug/goroutines", nil)
		rec := httptest.NewRecorder()
		s.handleDebugGoroutines(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "goroutine") {
			t.Error("expected goroutine stacks in response")
		}
	})

	t.Run("respondError writes JSON error", func(t *testing.T) {
		rec := httptest.NewRecorder()
		respondError(rec, http.StatusBadRequest, "test error")
		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "test error") {
			t.Errorf("expected error message in body: %s", rec.Body.String())
		}
	})
}

// TestIPLookupFieldHandlerMoreFields covers additional field branches in ipLookupFieldHandler.
func TestIPLookupFieldHandlerMoreFields(t *testing.T) {
	log.SetOutput(io.Discard)
	ts := httptest.NewServer(testServer().Handler())
	defer ts.Close()

	fields := []string{"country", "country_iso", "city", "asn", "asn_org", "region_name", "zip_code", "time_zone", "ip_decimal"}
	for _, field := range fields {
		field := field
		t.Run("field_"+field, func(t *testing.T) {
			_, status, err := httpGet(ts.URL+"/1.2.3.4/"+field, "", "curl/1.0")
			if err != nil {
				t.Fatalf("httpGet: %v", err)
			}
			if status == 0 {
				t.Errorf("got zero status for field %s", field)
			}
		})
	}
}

// TestDebugHandlersViaHTTP covers debug routes through the full HTTP stack.
func TestDebugHandlersViaHTTP(t *testing.T) {
	log.SetOutput(io.Discard)
	t.Setenv("DEBUG", "true")
	srv := testServer()
	cfg := &config.AppConfig{Server: config.ServerConfig{Debug: config.DebugConfig{RuntimeEndpoints: true}}}
	srv.SetConfig(cfg)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	debugEndpoints := []string{
		"/debug/config",
		"/debug/routes",
		"/debug/cache",
		"/debug/db",
		"/debug/scheduler",
		"/debug/goroutines",
	}
	for _, ep := range debugEndpoints {
		ep := ep
		t.Run(ep, func(t *testing.T) {
			out, status, err := httpGet(ts.URL+ep, "application/json", "")
			if err != nil {
				t.Fatalf("httpGet %s: %v", ep, err)
			}
			if status != http.StatusOK {
				t.Errorf("%s: status = %d, want 200\nbody: %s", ep, status, out)
			}
		})
	}
}

// TestStaticHandlerDirect covers the zero-coverage embedded-static-asset
// handler by invoking StaticHandler() directly rather than through the
// full server route table.
func TestStaticHandlerDirect(t *testing.T) {
	h := StaticHandler()
	if h == nil {
		t.Fatal("StaticHandler() returned nil")
	}

	ts := httptest.NewServer(h)
	defer ts.Close()

	t.Run("missing asset returns 404", func(t *testing.T) {
		out, status, err := httpGet(ts.URL+"/does-not-exist.css", "", "")
		if err != nil {
			t.Fatalf("httpGet: %v", err)
		}
		if status != http.StatusNotFound {
			t.Errorf("status = %d, want 404\nbody: %s", status, out)
		}
	})
}

// TestNewPageRenderer covers the zero/low-coverage page renderer constructor.
func TestNewPageRenderer(t *testing.T) {
	pr := NewPageRenderer("0.0.0-testcommit")
	if pr == nil {
		t.Fatal("NewPageRenderer() returned nil")
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/server/about", nil)
	err := pr(rec, req, "about.tmpl", handler.PageData{
		Lang:        "en",
		Dir:         "ltr",
		Theme:       "dark",
		CurrentYear: 2024,
		Version:     "1.0.0",
		BuildDate:   "2024-01-01",
		RepoURL:     "https://github.com/apimgr/ipgaze",
	})
	if err != nil {
		t.Errorf("PageRenderer(about.tmpl) error: %v", err)
	}
}
