package handler

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestNewSpecialHandler_Default(t *testing.T) {
	h := NewSpecialHandler("")
	if h.OfficialSite != "https://ifcfg.us" {
		t.Errorf("OfficialSite = %q, want default https://ifcfg.us", h.OfficialSite)
	}
}

func TestNewSpecialHandler_Custom(t *testing.T) {
	h := NewSpecialHandler("https://example.com")
	if h.OfficialSite != "https://example.com" {
		t.Errorf("OfficialSite = %q, want %q", h.OfficialSite, "https://example.com")
	}
}

func TestRobotsTxtHandler(t *testing.T) {
	h := NewSpecialHandler("")
	req := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
	w := httptest.NewRecorder()

	h.RobotsTxtHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", res.StatusCode, http.StatusOK)
	}
	ct := res.Header.Get("Content-Type")
	if ct != "text/plain" {
		t.Errorf("Content-Type = %q, want %q", ct, "text/plain")
	}
	body := w.Body.String()
	if !strings.Contains(body, "User-agent: *") {
		t.Errorf("body missing User-agent directive: %q", body)
	}
	if !strings.Contains(body, "Allow: /") {
		t.Errorf("body missing Allow: /: %q", body)
	}
	if !strings.Contains(body, "Disallow: /debug") {
		t.Errorf("body missing Disallow: /debug: %q", body)
	}
}

func TestSecurityTxtHandler(t *testing.T) {
	h := NewSpecialHandler("https://mysite.example")
	req := httptest.NewRequest(http.MethodGet, "/.well-known/security.txt", nil)
	w := httptest.NewRecorder()

	h.SecurityTxtHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", res.StatusCode, http.StatusOK)
	}
	ct := res.Header.Get("Content-Type")
	if ct != "text/plain" {
		t.Errorf("Content-Type = %q, want %q", ct, "text/plain")
	}
	body := w.Body.String()
	if !strings.Contains(body, "Contact: mailto:") {
		t.Errorf("body missing Contact field: %q", body)
	}
	if !strings.Contains(body, "Expires:") {
		t.Errorf("body missing Expires field: %q", body)
	}
	if !strings.Contains(body, "https://mysite.example") {
		t.Errorf("body missing canonical URL with OfficialSite: %q", body)
	}
}

func TestIsTorRequest(t *testing.T) {
	h := NewSpecialHandler("")

	// No onion address configured: never a Tor request.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "example.onion"
	if h.isTorRequest(req) {
		t.Error("isTorRequest with no OnionAddress configured = true, want false")
	}

	h.OnionAddress = "example.onion"

	// Host matches the configured onion address (case-insensitive).
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Host = "EXAMPLE.onion"
	if !h.isTorRequest(req2) {
		t.Error("isTorRequest with matching Host = false, want true")
	}

	// Host does not match.
	req3 := httptest.NewRequest(http.MethodGet, "/", nil)
	req3.Host = "clearnet.example.com"
	if h.isTorRequest(req3) {
		t.Error("isTorRequest with non-matching Host = true, want false")
	}
}

func TestHasPGPKey(t *testing.T) {
	h := NewSpecialHandler("")

	// Disabled by default.
	if h.hasPGPKey() {
		t.Error("hasPGPKey with default handler = true, want false")
	}

	// Enabled but no path configured.
	h.PublishPGPKey = true
	if h.hasPGPKey() {
		t.Error("hasPGPKey with empty PGPPublicKeyPath = true, want false")
	}

	// Enabled with a path that doesn't exist on disk.
	h.PGPPublicKeyPath = "/nonexistent/path/pgp.asc"
	if h.hasPGPKey() {
		t.Error("hasPGPKey with nonexistent path = true, want false")
	}

	// Enabled with a path that does exist.
	f, err := os.CreateTemp(t.TempDir(), "pgp-*.asc")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	h.PGPPublicKeyPath = f.Name()
	if !h.hasPGPKey() {
		t.Error("hasPGPKey with existing file = false, want true")
	}
}

func TestManifestHandler(t *testing.T) {
	h := NewSpecialHandler("")
	req := httptest.NewRequest(http.MethodGet, "/manifest.json", nil)
	w := httptest.NewRecorder()

	h.ManifestHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", res.StatusCode, http.StatusOK)
	}
	ct := res.Header.Get("Content-Type")
	if ct != "application/manifest+json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/manifest+json")
	}
	body := w.Body.String()
	if !strings.Contains(body, `"name"`) {
		t.Errorf("manifest body missing name field: %q", body)
	}
	if !strings.Contains(body, `"start_url"`) {
		t.Errorf("manifest body missing start_url field: %q", body)
	}
}

func TestOfflineHandler_DefaultEnglish(t *testing.T) {
	h := NewSpecialHandler("")
	req := httptest.NewRequest(http.MethodGet, "/offline.html", nil)
	w := httptest.NewRecorder()

	h.OfflineHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", res.StatusCode, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, `lang="en" dir="ltr"`) {
		t.Errorf("offline page missing lang/dir attrs: %q", body)
	}
	if !strings.Contains(body, "You are offline") {
		t.Errorf("offline page missing translated title: %q", body)
	}
	if !strings.Contains(body, "Try again") {
		t.Errorf("offline page missing translated button: %q", body)
	}
}

func TestOfflineHandler_TranslatesViaLangCookie(t *testing.T) {
	h := NewSpecialHandler("")
	req := httptest.NewRequest(http.MethodGet, "/offline.html", nil)
	req.AddCookie(&http.Cookie{Name: "lang", Value: "fr"})
	w := httptest.NewRecorder()

	h.OfflineHandler(w, req)

	body := w.Body.String()
	if !strings.Contains(body, `lang="fr" dir="ltr"`) {
		t.Errorf("offline page missing lang=fr attr: %q", body)
	}
	if !strings.Contains(body, "Vous êtes hors ligne") {
		t.Errorf("offline page missing French translation: %q", body)
	}
}

func TestOfflineHandler_RTLDirection(t *testing.T) {
	h := NewSpecialHandler("")
	req := httptest.NewRequest(http.MethodGet, "/offline.html", nil)
	req.AddCookie(&http.Cookie{Name: "lang", Value: "ar"})
	w := httptest.NewRecorder()

	h.OfflineHandler(w, req)

	body := w.Body.String()
	if !strings.Contains(body, `lang="ar" dir="rtl"`) {
		t.Errorf("offline page missing lang=ar dir=rtl attrs: %q", body)
	}
}

func TestServiceWorkerHandler(t *testing.T) {
	h := NewSpecialHandler("")
	req := httptest.NewRequest(http.MethodGet, "/sw.js", nil)
	w := httptest.NewRecorder()

	h.ServiceWorkerHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", res.StatusCode, http.StatusOK)
	}
	ct := res.Header.Get("Content-Type")
	if ct != "application/javascript" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/javascript")
	}
	body := w.Body.String()
	if !strings.Contains(body, "Service Worker") {
		t.Errorf("body missing 'Service Worker': %q", body)
	}
	if !strings.Contains(body, "self.addEventListener") {
		t.Errorf("body missing event listeners: %q", body)
	}
}

// The emitted worker must obey AI.md PART 16's service-worker rules: only
// same-origin GET is intercepted, /offline.html is actually precached (not
// filtered back out), and a SKIP_WAITING message activates a waiting worker.
func TestServiceWorkerHandler_SpecContract(t *testing.T) {
	h := NewSpecialHandler("")
	req := httptest.NewRequest(http.MethodGet, "/sw.js", nil)
	w := httptest.NewRecorder()

	h.ServiceWorkerHandler(w, req)
	body := w.Body.String()

	required := []string{
		"event.request.method !== 'GET'",
		"url.origin !== self.location.origin",
		"self.addEventListener('message'",
		"event.data.type === 'SKIP_WAITING'",
		"self.skipWaiting()",
		"cache.addAll(PRECACHE_ASSETS)",
		"'/offline.html'",
	}
	for _, want := range required {
		if !strings.Contains(body, want) {
			t.Errorf("service worker missing %q", want)
		}
	}
	if strings.Contains(body, "PRECACHE_ASSETS.filter") {
		t.Error("service worker filters /offline.html back out of the precache list")
	}
}

// The offline page must render without JavaScript: the CSP blocks inline
// event handlers, so the retry control has to be a plain link (AI.md PART 16).
func TestOfflineHandler_NoInlineHandlers(t *testing.T) {
	h := NewSpecialHandler("")
	req := httptest.NewRequest(http.MethodGet, "/offline.html", nil)
	w := httptest.NewRecorder()

	h.OfflineHandler(w, req)
	body := w.Body.String()

	if strings.Contains(body, "onclick") {
		t.Errorf("offline page contains an inline onclick handler: %q", body)
	}
	if strings.Contains(body, "<script") {
		t.Errorf("offline page contains a script block: %q", body)
	}
	if !strings.Contains(body, `<a class="btn" href="/">`) {
		t.Errorf("offline page missing no-JS retry link: %q", body)
	}
}

func TestLLMsTxtHandler(t *testing.T) {
	h := NewSpecialHandler("")
	req := httptest.NewRequest(http.MethodGet, "/.well-known/llms.txt", nil)
	w := httptest.NewRecorder()

	h.LLMsTxtHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", res.StatusCode, http.StatusOK)
	}
	ct := res.Header.Get("Content-Type")
	if ct != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type = %q, want %q", ct, "text/plain; charset=utf-8")
	}
	body := w.Body.String()
	if !strings.Contains(body, "# IPGaze") {
		t.Errorf("body missing '# IPGaze' header: %q", body)
	}
	if !strings.Contains(body, "## API") {
		t.Errorf("body missing '## API' section: %q", body)
	}
	if !strings.Contains(body, "## Endpoints") {
		t.Errorf("body missing '## Endpoints' section: %q", body)
	}
	if !strings.Contains(body, "## Capabilities") {
		t.Errorf("body missing '## Capabilities' section: %q", body)
	}
	if !strings.Contains(body, "GET /health") {
		t.Errorf("body missing health endpoint: %q", body)
	}
}
