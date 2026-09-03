package server

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSitemapXML asserts /sitemap.xml is served, carries the sitemaps.org
// namespace and the homepage entry, and never leaks an /api/ path
// (AI.md PART 24 "Sitemap Generation Rules").
func TestSitemapXML(t *testing.T) {
	log.SetOutput(io.Discard)
	ts := httptest.NewServer(testServer().Handler())
	defer ts.Close()

	out, status, err := httpGet(ts.URL+"/sitemap.xml", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if !strings.Contains(out, sitemapNamespace) {
		t.Errorf("sitemap missing namespace: %s", out)
	}
	if !strings.Contains(out, "<priority>1.0</priority>") {
		t.Errorf("sitemap missing homepage entry: %s", out)
	}
	if strings.Contains(out, "/api/") {
		t.Errorf("sitemap must never list an API path: %s", out)
	}
}

// TestAPITextSuffixForcesPlainText asserts the `.txt` suffix works on an
// arbitrary /api/v1 route, not only the endpoints that register a second
// literal path (AI.md PART 14 content-negotiation priority 1).
func TestAPITextSuffixForcesPlainText(t *testing.T) {
	log.SetOutput(io.Discard)
	ts := httptest.NewServer(testServer().Handler())
	defer ts.Close()

	out, status, err := httpGet(ts.URL+"/api/v1/ip.txt", "application/json", "")
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if strings.Contains(out, "{") {
		t.Errorf("`.txt` request returned JSON: %s", out)
	}
	if !strings.Contains(out, "127.0.0.1") {
		t.Errorf("response missing IP: %s", out)
	}
}
