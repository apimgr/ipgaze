package server

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/apimgr/ipgaze/src/server/handler"
)

// imgTagPattern matches a complete image tag so each one can be checked for
// an alt attribute, as required by AI.md PART 30.
var imgTagPattern = regexp.MustCompile(`(?is)<img\b[^>]*>`)

// accessibilityMarkers are the WCAG 2.1 AA structural requirements from
// AI.md PART 30 that every rendered page must carry: both skip links as the
// first focusable elements, and the banner/navigation/main/contentinfo
// landmark set.
var accessibilityMarkers = []struct {
	name    string
	snippet string
}{
	{"skip link to main content", `href="#main-content" class="skip-link"`},
	{"skip link to navigation", `href="#navigation" class="skip-link"`},
	{"banner landmark", `role="banner"`},
	{"navigation landmark", `role="navigation"`},
	{"navigation skip target", `id="navigation"`},
	{"main landmark", `role="main"`},
	{"main skip target", `id="main-content"`},
	{"contentinfo landmark", `role="contentinfo"`},
}

// assertAccessibleDocument checks one rendered HTML document against the
// PART 30 requirements: language and direction attributes, skip links,
// landmarks and image alt text.
func assertAccessibleDocument(t *testing.T, page, body string) {
	t.Helper()

	if !strings.Contains(body, `lang="en"`) {
		t.Errorf("%s: missing lang attribute on the html element", page)
	}
	if !strings.Contains(body, `dir="ltr"`) {
		t.Errorf("%s: missing dir attribute on the html element", page)
	}

	for _, marker := range accessibilityMarkers {
		if !strings.Contains(body, marker.snippet) {
			t.Errorf("%s: missing %s [%s]", page, marker.name, marker.snippet)
		}
	}

	// The skip links must precede the navigation they skip past, otherwise
	// they are not the first focusable elements in the document.
	firstSkip := strings.Index(body, `class="skip-link"`)
	navStart := strings.Index(body, `id="navigation"`)
	if firstSkip < 0 || navStart < 0 || firstSkip > navStart {
		t.Errorf("%s: skip links must appear before the navigation landmark", page)
	}

	for _, tag := range imgTagPattern.FindAllString(body, -1) {
		if !strings.Contains(tag, "alt=") {
			t.Errorf("%s: image without alt text: %s", page, tag)
		}
	}
}

// testPageData builds the minimum PageData needed to render a layout page.
func testPageData() handler.PageData {
	return handler.PageData{
		Lang:        "en",
		Dir:         "ltr",
		Theme:       "dark",
		CurrentYear: 2024,
		ProjectName: "ipgaze",
		Version:     "1.0.0",
		BuildDate:   "2024-01-01",
		RepoURL:     "https://github.com/apimgr/ipgaze",
	}
}

// TestAccessibility is the automated accessibility check required by
// AI.md PART 30 Testing Requirements.
func TestAccessibility(t *testing.T) {
	log.SetOutput(io.Discard)

	t.Run("landing page", func(t *testing.T) {
		ts := httptest.NewServer(testServer().Handler())
		defer ts.Close()

		req, err := http.NewRequest(http.MethodGet, ts.URL+"/", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Accept", "text/html")
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible browser)")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}

		assertAccessibleDocument(t, "index.tmpl", string(body))
	})

	t.Run("layout pages", func(t *testing.T) {
		render := NewPageRenderer("0.0.0-testcommit")
		if render == nil {
			t.Fatal("NewPageRenderer returned nil")
		}

		for _, page := range []string{"terms.tmpl", "help.tmpl", "contact.tmpl"} {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/server/"+strings.TrimSuffix(page, ".tmpl"), nil)
			if err := render(rec, req, page, testPageData()); err != nil {
				t.Fatalf("render %s: %v", page, err)
			}
			assertAccessibleDocument(t, page, rec.Body.String())
		}
	})
}
