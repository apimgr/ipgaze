package server

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/apimgr/ipgaze/src/config"
)

func TestFeedHandlerServesEmptyFeedsAndConditionalRequests(t *testing.T) {
	s := testServer()
	s.BuildDate = "2026-11-13T12:00:00Z"
	for _, test := range []struct {
		path        string
		atom        bool
		contentType string
	}{
		{path: "/feed.xml", atom: true, contentType: "application/atom+xml; charset=utf-8"},
		{path: "/rss.xml", contentType: "application/rss+xml; charset=utf-8"},
	} {
		t.Run(test.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://example.test"+test.path, nil)
			rec := httptest.NewRecorder()
			s.feedHandler(test.atom)(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
			}
			if got := rec.Header().Get("Content-Type"); got != test.contentType {
				t.Errorf("Content-Type = %q, want %q", got, test.contentType)
			}
			if got := rec.Header().Get("Cache-Control"); got != "public, max-age=300" {
				t.Errorf("Cache-Control = %q", got)
			}
			if err := xml.Unmarshal(rec.Body.Bytes(), new(any)); err != nil {
				t.Fatalf("feed is not valid XML: %v", err)
			}
			if strings.Contains(rec.Body.String(), "<entry>") || strings.Contains(rec.Body.String(), "<item>") {
				t.Errorf("feed should be empty: %s", rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "https://example.test"+test.path) {
				t.Errorf("feed URL is not request-derived: %s", rec.Body.String())
			}
			conditional := httptest.NewRequest(http.MethodGet, "https://example.test"+test.path, nil)
			conditional.Header.Set("If-None-Match", rec.Header().Get("ETag"))
			conditionalRec := httptest.NewRecorder()
			s.feedHandler(test.atom)(conditionalRec, conditional)
			if conditionalRec.Code != http.StatusNotModified {
				t.Errorf("conditional status = %d, want 304", conditionalRec.Code)
			}
		})
	}
}

func TestFeedHandlerHeadAndDisabled(t *testing.T) {
	s := testServer()
	s.BuildDate = time.Now().UTC().Format(time.RFC3339)
	for _, tc := range []struct {
		name   string
		method string
		config config.FeedConfig
		status int
	}{
		{name: "head", method: http.MethodHead, config: config.DefaultSEOConfig().Feed, status: http.StatusOK},
		{name: "disabled", method: http.MethodGet, config: config.FeedConfig{Enabled: false}, status: http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s.config = &config.AppConfig{}
			s.config.Server.SEO.Feed = tc.config
			req := httptest.NewRequest(tc.method, "https://example.test/feed.xml", nil)
			rec := httptest.NewRecorder()
			s.feedHandler(true)(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d", rec.Code, tc.status)
			}
			if tc.method == http.MethodHead && rec.Body.Len() != 0 {
				t.Errorf("HEAD returned body: %s", rec.Body.String())
			}
		})
	}
}
