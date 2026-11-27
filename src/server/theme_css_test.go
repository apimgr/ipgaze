package server

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/apimgr/ipgaze/src/config"
)

func TestThemeCSSHandlerUsesConfiguredToastDurations(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.Notifications.WebUI.Duration = 7
	cfg.Server.Notifications.WebUI.WarningDuration = 11
	s := &Server{config: cfg, Version: "1.0.0", CommitID: "abc123"}
	recorder := httptest.NewRecorder()
	s.themeCSSHandler()(recorder, httptest.NewRequest("GET", "/theme.css?v=1.0.0-abc123", nil))
	if recorder.Code != 200 {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-cache" {
		t.Fatalf("Cache-Control = %q, want no-cache", got)
	}
	for _, want := range []string{"--toast-duration: 7s", "--toast-duration-warning: 11s"} {
		if !strings.Contains(recorder.Body.String(), want) {
			t.Errorf("stylesheet missing %q", want)
		}
	}

	conditional := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/theme.css", nil)
	req.Header.Set("If-None-Match", recorder.Header().Get("ETag"))
	s.themeCSSHandler()(conditional, req)
	if conditional.Code != 304 {
		t.Fatalf("conditional status = %d, want 304", conditional.Code)
	}
}
