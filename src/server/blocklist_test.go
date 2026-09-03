package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
	defer os.RemoveAll(tmpDir)

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
	defer os.RemoveAll(tmpDir)

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
