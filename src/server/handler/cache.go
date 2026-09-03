// Package handler contains HTTP handlers organized by domain
// Per AI.md: handler/ for HTTP request handlers, route handlers, request/response logic
package handler

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	i18n "github.com/apimgr/ipgaze/src/common/i18n"
)

// CacheManager provides cache operations for handlers
type CacheManager interface {
	Resize(capacity int) error
	GetStats() (size, capacity int, evictions uint64)
}

// CacheHandler handles cache-related routes
type CacheHandler struct {
	cache CacheManager
}

// NewCacheHandler creates a new CacheHandler
func NewCacheHandler(cache CacheManager) *CacheHandler {
	return &CacheHandler{cache: cache}
}

// CacheResizeHandler handles cache resize requests
func (h *CacheHandler) CacheResizeHandler(w http.ResponseWriter, r *http.Request) {
	// Cap at 64 bytes — a valid capacity integer is at most a few digits.
	body, err := io.ReadAll(io.LimitReader(r.Body, 64))
	if err != nil {
		lang := i18n.DetectLocale(r)
		http.Error(w, i18n.T(i18n.WithLang(r.Context(), lang), "errors.bad_request"), http.StatusBadRequest)
		return
	}
	capacity, err := strconv.Atoi(string(body))
	if err != nil {
		lang := i18n.DetectLocale(r)
		http.Error(w, i18n.T(i18n.WithLang(r.Context(), lang), "errors.bad_request"), http.StatusBadRequest)
		return
	}
	if err := h.cache.Resize(capacity); err != nil {
		lang := i18n.DetectLocale(r)
		http.Error(w, i18n.T(i18n.WithLang(r.Context(), lang), "errors.bad_request"), http.StatusBadRequest)
		return
	}
	data := struct {
		Message  string `json:"message"`
		Capacity int    `json:"capacity"`
	}{i18n.T(r.Context(), "app.cache_resized"), capacity}
	b, _ := json.MarshalIndent(data, "", "  ")
	w.Header().Set("Content-Type", "application/json")
	// Write errors are unrecoverable once headers are sent; log is not actionable here.
	w.Write(b)            //nolint:errcheck
	w.Write([]byte("\n")) //nolint:errcheck
}

// CacheStatsHandler returns cache statistics
func (h *CacheHandler) CacheStatsHandler(w http.ResponseWriter, r *http.Request) {
	size, capacity, evictions := h.cache.GetStats()
	data := struct {
		Size      int    `json:"size"`
		Capacity  int    `json:"capacity"`
		Evictions uint64 `json:"evictions"`
	}{size, capacity, evictions}
	b, _ := json.MarshalIndent(data, "", "  ")
	w.Header().Set("Content-Type", "application/json")
	// Write errors are unrecoverable once headers are sent; log is not actionable here.
	w.Write(b)            //nolint:errcheck
	w.Write([]byte("\n")) //nolint:errcheck
}
