package handler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// stubCacheManager is a test double for CacheManager.
type stubCacheManager struct {
	resizeErr error
	size      int
	capacity  int
	evictions uint64
}

func (s *stubCacheManager) Resize(capacity int) error {
	if s.resizeErr != nil {
		return s.resizeErr
	}
	s.capacity = capacity
	return nil
}

func (s *stubCacheManager) GetStats() (size, capacity int, evictions uint64) {
	return s.size, s.capacity, s.evictions
}

func TestCacheStatsHandler(t *testing.T) {
	stub := &stubCacheManager{size: 5, capacity: 100, evictions: 3}
	h := NewCacheHandler(stub)
	req := httptest.NewRequest(http.MethodGet, "/cache/stats", nil)
	w := httptest.NewRecorder()

	h.CacheStatsHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", res.StatusCode, http.StatusOK)
	}
	ct := res.Header.Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}
	body := w.Body.String()
	if !strings.Contains(body, `"size"`) {
		t.Errorf("body missing size field: %q", body)
	}
	if !strings.Contains(body, `"capacity"`) {
		t.Errorf("body missing capacity field: %q", body)
	}
	if !strings.Contains(body, `"evictions"`) {
		t.Errorf("body missing evictions field: %q", body)
	}
}

func TestCacheResizeHandler_Success(t *testing.T) {
	stub := &stubCacheManager{capacity: 10}
	h := NewCacheHandler(stub)
	body := strings.NewReader("50")
	req := httptest.NewRequest(http.MethodPost, "/cache/resize", body)
	w := httptest.NewRecorder()

	h.CacheResizeHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", res.StatusCode, http.StatusOK)
	}
	if stub.capacity != 50 {
		t.Errorf("capacity = %d, want 50", stub.capacity)
	}
}

func TestCacheResizeHandler_InvalidBody(t *testing.T) {
	stub := &stubCacheManager{}
	h := NewCacheHandler(stub)
	body := strings.NewReader("notanumber")
	req := httptest.NewRequest(http.MethodPost, "/cache/resize", body)
	w := httptest.NewRecorder()

	h.CacheResizeHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("StatusCode = %d, want %d", res.StatusCode, http.StatusBadRequest)
	}
}

func TestCacheResizeHandler_ResizeError(t *testing.T) {
	stub := &stubCacheManager{resizeErr: fmt.Errorf("capacity must be positive")}
	h := NewCacheHandler(stub)
	body := strings.NewReader("10")
	req := httptest.NewRequest(http.MethodPost, "/cache/resize", body)
	w := httptest.NewRecorder()

	h.CacheResizeHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("StatusCode = %d, want %d", res.StatusCode, http.StatusBadRequest)
	}
}
