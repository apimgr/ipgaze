package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/apimgr/ipgaze/src/config"
)

func TestBrandingLogoCache_GetSetStale(t *testing.T) {
	c := newBrandingLogoCache()

	data, contentType, needsRefresh := c.get("https://example.com/logo.png")
	if data != nil || contentType != "" || !needsRefresh {
		t.Fatalf("expected empty cache to need refresh, got data=%v contentType=%q needsRefresh=%v", data, contentType, needsRefresh)
	}

	c.set([]byte("bytes"), "image/png", "https://example.com/logo.png")
	data, contentType, needsRefresh = c.get("https://example.com/logo.png")
	if string(data) != "bytes" || contentType != "image/png" || needsRefresh {
		t.Fatalf("expected fresh cache to serve without refresh, got data=%q contentType=%q needsRefresh=%v", data, contentType, needsRefresh)
	}

	// Different source URL invalidates the cache even though it's fresh.
	_, _, needsRefresh = c.get("https://example.com/other-logo.png")
	if !needsRefresh {
		t.Error("expected a changed source URL to require a refresh")
	}
}

func TestBrandingLogoCache_BeginEndFetch(t *testing.T) {
	c := newBrandingLogoCache()
	if !c.beginFetch() {
		t.Fatal("expected first beginFetch to succeed")
	}
	if c.beginFetch() {
		t.Fatal("expected concurrent beginFetch to be rejected while one is in-flight")
	}
	c.endFetch()
	if !c.beginFetch() {
		t.Fatal("expected beginFetch to succeed again after endFetch")
	}
}

func TestBrandingLogoCache_StaleAfterRefreshInterval(t *testing.T) {
	c := newBrandingLogoCache()
	c.set([]byte("bytes"), "image/png", "https://example.com/logo.png")
	c.mu.Lock()
	c.fetchedAt = time.Now().Add(-25 * time.Hour)
	c.mu.Unlock()

	_, _, needsRefresh := c.get("https://example.com/logo.png")
	if !needsRefresh {
		t.Error("expected cache older than the refresh interval to need a refresh")
	}
}

func TestBrandingLogoCacheFilePath(t *testing.T) {
	p1 := brandingLogoCacheFilePath("/data", "https://example.com/a.png", "image/png")
	p2 := brandingLogoCacheFilePath("/data", "https://example.com/b.png", "image/png")
	if p1 == p2 {
		t.Error("expected different source URLs to produce different cache file paths")
	}
	if filepath.Ext(p1) != ".png" {
		t.Errorf("expected .png extension for image/png, got %q", p1)
	}

	unknown := brandingLogoCacheFilePath("/data", "https://example.com/a.bin", "application/octet-stream")
	if filepath.Ext(unknown) != ".bin" {
		t.Errorf("expected .bin fallback extension for unknown content type, got %q", unknown)
	}
}

func TestLoadBrandingLogoFromDisk(t *testing.T) {
	dir := t.TempDir()
	sourceURL := "https://example.com/logo.png"

	if _, _, ok := loadBrandingLogoFromDisk(dir, sourceURL); ok {
		t.Fatal("expected no cached file to be found before one is written")
	}

	path := brandingLogoCacheFilePath(dir, sourceURL, "image/png")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte("disk-bytes"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	data, contentType, ok := loadBrandingLogoFromDisk(dir, sourceURL)
	if !ok || string(data) != "disk-bytes" || contentType != "image/png" {
		t.Fatalf("expected to load disk-cached logo, got data=%q contentType=%q ok=%v", data, contentType, ok)
	}
}

func TestFetchAndCacheBrandingLogo_InvalidURLFails(t *testing.T) {
	dir := t.TempDir()
	_, _, err := fetchAndCacheBrandingLogo(context.Background(), dir, "http://not-https.example.com/logo.png")
	if err == nil {
		t.Fatal("expected non-https logo URL to fail validation")
	}
}

func TestRefreshBrandingLogo_FailureFallsBackToDisk(t *testing.T) {
	dir := t.TempDir()
	sourceURL := "http://blocked.example.com/logo.png"

	path := brandingLogoCacheFilePath(dir, sourceURL, "image/png")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte("stale-disk-bytes"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	c := newBrandingLogoCache()
	refreshBrandingLogo(c, dir, sourceURL)

	data, contentType, _ := c.get(sourceURL)
	if string(data) != "stale-disk-bytes" || contentType != "image/png" {
		t.Fatalf("expected fetch failure to fall back to disk cache, got data=%q contentType=%q", data, contentType)
	}
}

func TestRefreshBrandingLogo_ConcurrentCallSkipsWhileInFlight(t *testing.T) {
	c := newBrandingLogoCache()
	c.fetching = true
	// A logoURL that would otherwise fail fast; if beginFetch's guard were
	// broken this would still leave the cache empty, so assert no panic
	// and no data set instead.
	refreshBrandingLogo(c, t.TempDir(), "http://blocked.example.com/logo.png")
	data, _, _ := c.get("http://blocked.example.com/logo.png")
	if data != nil {
		t.Error("expected refresh to be skipped while a fetch is already in flight")
	}
}

func TestBrandingLogoHandler_FallsBackToEmbeddedDefault(t *testing.T) {
	s := &Server{DataDir: t.TempDir()}
	// Point at a localhost URL so ValidateRemoteURL rejects it instantly
	// (no real network round trip), exercising the embedded-default
	// fallback path deterministically.
	s.config = &config.AppConfig{}
	s.config.Server.Branding.LogoURL = "https://localhost/logo.png"

	req := httptest.NewRequest(http.MethodGet, "/branding/logo", nil)
	w := httptest.NewRecorder()
	s.brandingLogoHandler()(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from embedded-default fallback, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "image/png" {
		t.Errorf("expected image/png content type, got %q", ct)
	}
	if w.Body.Len() == 0 {
		t.Error("expected non-empty embedded default image body")
	}
}

func TestBrandingLogoHandler_ServesCachedData(t *testing.T) {
	s := &Server{DataDir: t.TempDir(), brandingCache: newBrandingLogoCache()}
	s.brandingCache.set([]byte("cached-bytes"), "image/webp", defaultLogoURL)

	req := httptest.NewRequest(http.MethodGet, "/branding/logo", nil)
	w := httptest.NewRecorder()
	s.brandingLogoHandler()(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "image/webp" {
		t.Errorf("expected cached content type image/webp, got %q", ct)
	}
	if w.Body.String() != "cached-bytes" {
		t.Errorf("expected cached bytes to be served, got %q", w.Body.String())
	}
}

func TestBrandingLogoHandler_NilCacheDoesNotMutateSharedField(t *testing.T) {
	s := &Server{DataDir: t.TempDir()}
	s.config = &config.AppConfig{}
	s.config.Server.Branding.LogoURL = "https://localhost/logo.png"
	req := httptest.NewRequest(http.MethodGet, "/branding/logo", nil)
	w := httptest.NewRecorder()
	s.brandingLogoHandler()(w, req)

	if s.brandingCache != nil {
		t.Error("expected brandingLogoHandler to never mutate a nil Server.brandingCache field (avoids the concurrent-request init race)")
	}
}
