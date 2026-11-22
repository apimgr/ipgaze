package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/apimgr/ipgaze/src/blocklist"
)

func TestBlocklistMiddlewareNilPassthrough(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := BlocklistMiddleware(nil, nil)(next)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "8.8.8.8:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("expected next handler to be called when blocklist is nil")
	}
}

func TestBlocklistMiddlewareAllowlistedBypass(t *testing.T) {
	bl := &blocklist.Lookup{}

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := BlocklistMiddleware(bl, nil)(next)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "8.8.8.8:1234"
	ctx := context.WithValue(req.Context(), ctxKeyAllowlisted, true)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("expected allowlisted request to bypass blocklist check")
	}
}

func TestBlocklistMiddlewareNotBlockedIP(t *testing.T) {
	bl := &blocklist.Lookup{}

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := BlocklistMiddleware(bl, nil)(next)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "8.8.8.8:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("expected next handler to be called for non-blocked IP")
	}
}

func TestBlocklistMiddlewarePrivateIPExempt(t *testing.T) {
	tmpDir, err := os.MkdirTemp(os.TempDir(), "ipgaze-blocklist-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// A bogon-style list that (as real lists such as firehol_level1 do)
	// intentionally includes loopback and RFC 1918 ranges.
	listFile := filepath.Join(tmpDir, "bogons.txt")
	list := "127.0.0.0/8\n10.0.0.0/8\n192.168.0.0/16\n"
	if err := os.WriteFile(listFile, []byte(list), 0o644); err != nil {
		t.Fatal(err)
	}

	bl := &blocklist.Lookup{}
	if err := bl.LoadDir(tmpDir); err != nil {
		t.Fatalf("LoadDir: %v", err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := BlocklistMiddleware(bl, nil)(next)

	for _, remoteAddr := range []string{"127.0.0.1:1234", "10.0.0.5:1234", "192.168.1.1:1234"} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = remoteAddr
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("remoteAddr %s: status = %d, want 200 (private IPs must never be blocklisted)", remoteAddr, rec.Code)
		}
	}
}

func TestBlocklistMiddlewareBlockedIP(t *testing.T) {
	tmpDir, err := os.MkdirTemp(os.TempDir(), "ipgaze-blocklist-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	listFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(listFile, []byte("1.2.3.4\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	bl := &blocklist.Lookup{}
	if err := bl.LoadDir(tmpDir); err != nil {
		t.Fatalf("LoadDir: %v", err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := BlocklistMiddleware(bl, nil)(next)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for blocked IP", rec.Code)
	}
}

func TestBlocklistMiddlewareUsesSubmittedDomainTargetsAndRestoresBody(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "domains.txt"), []byte("blocked.example\nxn--mnich-kva.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	lookup := &blocklist.Lookup{}
	if err := lookup.LoadDirWithTypes(dir, map[string]string{"domains": "domain"}); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		method      string
		path        string
		contentType string
		body        string
		origin      string
		referer     string
		wantStatus  int
	}{
		{name: "server host is not a match target", method: http.MethodGet, path: "/", wantStatus: http.StatusOK},
		{name: "origin takes precedence", method: http.MethodGet, path: "/", origin: "https://safe.example", referer: "https://blocked.example/page", wantStatus: http.StatusOK},
		{name: "referer fallback", method: http.MethodGet, path: "/", referer: "https://blocked.example/page", wantStatus: http.StatusForbidden},
		{name: "submitted email", method: http.MethodPost, path: "/", contentType: "application/x-www-form-urlencoded", body: "email=user%40blocked.example", wantStatus: http.StatusForbidden},
		{name: "unicode email domain", method: http.MethodPost, path: "/", contentType: "application/json", body: `{"email":"user@münich.example"}`, wantStatus: http.StatusForbidden},
		{name: "submitted URL", method: http.MethodPost, path: "/", contentType: "application/json", body: `{"url":"https://blocked.example/hook"}`, wantStatus: http.StatusForbidden},
		{name: "plain text URL target", method: http.MethodPost, path: "/", contentType: "text/plain", body: "https://blocked.example/hook", wantStatus: http.StatusForbidden},
		{name: "unrelated JSON text mentioning URL", method: http.MethodPost, path: "/", contentType: "application/json", body: `{"comment":"The docs mention https://blocked.example/hook"}`, wantStatus: http.StatusOK},
		{name: "unrelated query text mentioning URL", method: http.MethodGet, path: "/?comment=see+https%3A%2F%2Fblocked.example%2Fhook", wantStatus: http.StatusOK},
		{name: "submitted query URL", method: http.MethodGet, path: "/?url=https%3A%2F%2Fblocked.example%2Fhook", wantStatus: http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			req.Host = "blocked.example"
			req.Header.Set("Origin", tt.origin)
			req.Header.Set("Referer", tt.referer)
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			called := false
			handler := BlocklistMiddleware(lookup, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				got, _ := io.ReadAll(r.Body)
				if string(got) != tt.body {
					t.Errorf("request body = %q, want %q", got, tt.body)
				}
				w.WriteHeader(http.StatusOK)
			}))
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
			if recorder.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", recorder.Code, tt.wantStatus)
			}
			if called != (tt.wantStatus == http.StatusOK) {
				t.Errorf("next handler called = %v, status %d", called, recorder.Code)
			}
		})
	}
}
