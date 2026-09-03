package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/apimgr/ipgaze/src/common/urlutil"
)

// brandingLogoRefreshInterval is how often a configured remote logo URL is
// re-fetched, per AI.md "Branding & SEO" → "Image Scaling" → "Scaling Rules"
// ("Re-fetch remote URLs periodically (configurable, default: daily)").
const brandingLogoRefreshInterval = 24 * time.Hour

// brandingLogoCacheSubdir is the directory (under DataDir) where the fetched
// sponsor/branding logo is cached locally, per AI.md "Branding & SEO" →
// "Remote URL Fetching" (never hotlink a remote URL directly in a page).
const brandingLogoCacheSubdir = "branding"

// brandingLogoMIMEExt maps the content types FetchRemoteImage accepts to a
// file extension used for the on-disk cache and the Content-Type served back.
var brandingLogoMIMEExt = map[string]string{
	"image/png":    "png",
	"image/jpeg":   "jpg",
	"image/gif":    "gif",
	"image/webp":   "webp",
	"image/x-icon": "ico",
}

// brandingLogoCache holds the in-memory copy of the currently served logo so
// that most requests never touch disk. It is safe for concurrent use.
type brandingLogoCache struct {
	mu          sync.RWMutex
	data        []byte
	contentType string
	fetchedAt   time.Time
	sourceURL   string
	fetching    bool
}

// newBrandingLogoCache returns an empty cache; the embedded default is served
// until the first successful remote fetch populates it.
func newBrandingLogoCache() *brandingLogoCache {
	return &brandingLogoCache{}
}

// get returns the currently cached image (if any) and whether a refresh is
// warranted (empty, or older than brandingLogoRefreshInterval, or the
// configured source URL changed).
func (c *brandingLogoCache) get(logoURL string) (data []byte, contentType string, needsRefresh bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	stale := c.data == nil || c.sourceURL != logoURL || time.Since(c.fetchedAt) > brandingLogoRefreshInterval
	return c.data, c.contentType, stale && !c.fetching
}

// beginFetch marks a fetch as in-flight, returning false if one is already
// running (so callers never stack concurrent fetches of the same URL).
func (c *brandingLogoCache) beginFetch() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fetching {
		return false
	}
	c.fetching = true
	return true
}

func (c *brandingLogoCache) endFetch() {
	c.mu.Lock()
	c.fetching = false
	c.mu.Unlock()
}

func (c *brandingLogoCache) set(data []byte, contentType, sourceURL string) {
	c.mu.Lock()
	c.data = data
	c.contentType = contentType
	c.sourceURL = sourceURL
	c.fetchedAt = time.Now()
	c.mu.Unlock()
}

// brandingLogoCacheFilePath returns the on-disk cache path for a given
// source URL and content type, keyed by a hash of the URL so switching the
// configured logo URL never serves a stale file from a previous one.
func brandingLogoCacheFilePath(dataDir, sourceURL, contentType string) string {
	ext := brandingLogoMIMEExt[contentType]
	if ext == "" {
		ext = "bin"
	}
	sum := sha256.Sum256([]byte(sourceURL))
	name := "logo-" + hex.EncodeToString(sum[:8]) + "." + ext
	return filepath.Join(dataDir, brandingLogoCacheSubdir, name)
}

// loadBrandingLogoFromDisk reads a previously-cached logo for sourceURL, if
// present, regardless of how stale it is (used as a fallback while a fresh
// fetch is attempted).
func loadBrandingLogoFromDisk(dataDir, sourceURL string) (data []byte, contentType string, ok bool) {
	for ct, ext := range brandingLogoMIMEExt {
		path := filepath.Join(dataDir, brandingLogoCacheSubdir, "logo-"+brandingLogoURLHash(sourceURL)+"."+ext)
		if b, err := os.ReadFile(path); err == nil {
			return b, ct, true
		}
	}
	return nil, "", false
}

func brandingLogoURLHash(sourceURL string) string {
	sum := sha256.Sum256([]byte(sourceURL))
	return hex.EncodeToString(sum[:8])
}

// fetchAndCacheBrandingLogo fetches logoURL via the SSRF-safe urlutil helper
// (AI.md "Remote URL Fetching") and persists it to DataDir/branding/, per
// "Scaling Rules" → "Cache scaled versions locally".
func fetchAndCacheBrandingLogo(ctx context.Context, dataDir, logoURL string) (data []byte, contentType string, err error) {
	cfg := urlutil.DefaultFetchRemoteImageConfig()
	data, contentType, err = urlutil.FetchRemoteImage(ctx, logoURL, cfg)
	if err != nil {
		return nil, "", err
	}

	path := brandingLogoCacheFilePath(dataDir, logoURL, contentType)
	if mkErr := os.MkdirAll(filepath.Dir(path), 0o755); mkErr != nil {
		return data, contentType, nil
	}
	tmp := path + ".tmp"
	if writeErr := os.WriteFile(tmp, data, 0o644); writeErr == nil {
		_ = os.Rename(tmp, path)
	}
	return data, contentType, nil
}

// refreshBrandingLogo fetches logoURL (falling back to any on-disk cache on
// failure) and stores the result in cache. Errors are logged but never
// propagated — callers always have the embedded default as a last resort.
func refreshBrandingLogo(cache *brandingLogoCache, dataDir, logoURL string) {
	if !cache.beginFetch() {
		return
	}
	defer cache.endFetch()

	ctx, cancel := context.WithTimeout(context.Background(), urlutil.DefaultFetchRemoteImageConfig().Timeout)
	defer cancel()

	data, contentType, err := fetchAndCacheBrandingLogo(ctx, dataDir, logoURL)
	if err != nil {
		slog.Warn("branding logo fetch failed, using cached/default", "url", logoURL, "error", err.Error())
		if diskData, diskCT, ok := loadBrandingLogoFromDisk(dataDir, logoURL); ok {
			cache.set(diskData, diskCT, logoURL)
		}
		return
	}
	cache.set(data, contentType, logoURL)
}

// brandingLogoHandler serves the locally cached sponsor/branding logo,
// fetching it on first use and periodically refreshing it thereafter, per
// AI.md "Branding & SEO". It never exposes the remote URL to the browser —
// the page's <img src> always points here. Falls back to the embedded
// default icon if no remote logo has ever been fetched successfully.
func (s *Server) brandingLogoHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logoURL := defaultLogoURL
		if s.config != nil && s.config.Server.Branding.LogoURL != "" {
			logoURL = s.config.Server.Branding.LogoURL
		}

		// NewHTTPServer always allocates brandingCache; this only guards a
		// Server built without it (e.g. a test stub), never mutating the
		// shared field here to avoid the concurrent-request init race.
		cache := s.brandingCache
		if cache == nil {
			cache = newBrandingLogoCache()
		}

		data, contentType, needsRefresh := cache.get(logoURL)
		if needsRefresh {
			if data == nil {
				// Cold start: fetch synchronously so the first page load
				// still gets a real image instead of a default icon.
				refreshBrandingLogo(cache, s.DataDir, logoURL)
				data, contentType, _ = cache.get(logoURL)
			} else {
				// Serve the stale copy now, refresh in the background.
				go refreshBrandingLogo(cache, s.DataDir, logoURL)
			}
		}

		if data == nil {
			// No successful fetch yet (offline, invalid URL, blocked by
			// SSRF checks, etc.) — fall back to the embedded default.
			w.Header().Set("Content-Type", "image/png")
			w.Header().Set("Cache-Control", "public, max-age=3600")
			if b, err := staticFS.ReadFile("static/icons/icon-192.png"); err == nil {
				_, _ = w.Write(b)
				return
			}
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_, _ = w.Write(data)
	}
}
