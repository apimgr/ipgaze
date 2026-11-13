package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRenderNegotiatedAcceptAndClientPriority(t *testing.T) {
	h := &PagesHandler{Render: func(w http.ResponseWriter, _ *http.Request, _ string, _ interface{}) error {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, err := w.Write([]byte("<html><body><p>Page body</p></body></html>"))
		return err
	}}
	tests := []struct {
		name, accept, ua, contentType string
	}{
		{"explicit JSON overrides curl", "application/json", "curl/8.5.0", "application/json"},
		{"explicit HTML overrides CLI", "text/html", "ipgaze-cli/1.0", "text/html; charset=utf-8"},
		{"explicit text overrides CLI", "text/plain", "ipgaze-cli/1.0", "text/plain; charset=utf-8"},
		{"curl defaults to text", "", "curl/8.5.0", "text/plain; charset=utf-8"},
		{"unknown client defaults to HTML", "", "custom-agent/1.0", "text/html; charset=utf-8"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/about", nil)
			r.Header.Set("Accept", tt.accept)
			r.Header.Set("User-Agent", tt.ua)
			w := httptest.NewRecorder()
			h.renderNegotiated(w, r, "about.tmpl", map[string]string{"page": "data"}, map[string]string{"api": "data"})
			if got := w.Result().Header.Get("Content-Type"); got != tt.contentType {
				t.Fatalf("Content-Type = %q, want %q", got, tt.contentType)
			}
			if tt.contentType == "application/json" && !strings.Contains(w.Body.String(), "api") {
				t.Errorf("JSON response did not use API data: %s", w.Body.String())
			}
			if tt.contentType == "text/html; charset=utf-8" && !strings.Contains(w.Body.String(), "Page body") {
				t.Errorf("HTML response body missing page: %s", w.Body.String())
			}
		})
	}
}
