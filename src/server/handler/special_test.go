package handler

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/apimgr/ipgaze/src/config"
	"github.com/apimgr/ipgaze/src/netutil"
	"github.com/apimgr/ipgaze/src/swagger"
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

func TestSecurityTxtHandlerIncludesPGPFingerprintComment(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "pgp.pub.asc")
	if err := os.WriteFile(keyPath, []byte("public key"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := NewSpecialHandler("https://mysite.example")
	h.PublishPGPKey = true
	h.PGPPublicKeyPath = keyPath
	h.PGPFingerprint = func() string { return strings.Repeat("a", 64) }
	w := httptest.NewRecorder()
	h.SecurityTxtHandler(w, httptest.NewRequest(http.MethodGet, "/.well-known/security.txt", nil))
	if !strings.Contains(w.Body.String(), "# PGP Fingerprint: "+strings.Repeat("a", 64)) {
		t.Fatalf("security.txt omitted the full PGP fingerprint comment: %s", w.Body.String())
	}
}

func TestSecurityTxtHandlerOmitsInvalidPGPFingerprint(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "pgp.pub.asc")
	if err := os.WriteFile(keyPath, []byte("public key"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := NewSpecialHandler("https://mysite.example")
	h.PublishPGPKey = true
	h.PGPPublicKeyPath = keyPath
	h.PGPFingerprint = func() string { return "invalid\nContact: mailto:attacker@example.test" }
	w := httptest.NewRecorder()
	h.SecurityTxtHandler(w, httptest.NewRequest(http.MethodGet, "/.well-known/security.txt", nil))
	if strings.Contains(w.Body.String(), "attacker@example.test") {
		t.Fatalf("invalid fingerprint injected a security.txt field: %s", w.Body.String())
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

func TestIsTorRequestUsesLiveTrustAddress(t *testing.T) {
	h := NewSpecialHandler("")
	h.Trust = netutil.NewTrustResolver(config.TrustedProxiesConfig{}, "")
	h.Trust.SetOnionAddress("generated.onion")
	request := httptest.NewRequest(http.MethodGet, "http://generated.onion/.well-known/security.txt", nil)
	if !h.isTorRequest(request) {
		t.Fatal("isTorRequest did not recognize the onion address published after async startup")
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
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
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

// The emitted worker keeps navigation caches limited to explicitly public pages
// and always synthesizes a translated offline response when no public copy exists.
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
		"response.headers.get('X-Offline-Cache') === 'public'",
		"return cache.delete(event.request)",
		"const STRINGS_CACHE = 'ipgaze-offline-strings'",
		"cache.match('/offline-strings.json')",
		"function offlineFallbackResponse()",
		"new Response(",
	}
	for _, want := range required {
		if !strings.Contains(body, want) {
			t.Errorf("service worker missing %q", want)
		}
	}
	if strings.Contains(body, "/offline.html") {
		t.Error("service worker depends on a static offline page")
	}
	if !strings.Contains(body, "if (response.ok && !response.redirected && response.headers.get('X-Offline-Cache') === 'public')") {
		t.Error("service worker navigation cache is not restricted to successful public responses")
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
	if !strings.Contains(body, "GET /api/v1/server/healthz") {
		t.Errorf("body missing generated health API endpoint: %q", body)
	}
	if !strings.Contains(body, "GET /api/v1/ip/{ip}") {
		t.Errorf("body missing generated IP lookup API endpoint: %q", body)
	}
	for _, endpoint := range []string{"GET /", "GET /{ip}", "GET /country", "GET /port/{port}", "GET /api/graphql", "GET /server/healthz", "GET /server/about"} {
		if !strings.Contains(body, endpoint) {
			t.Errorf("body missing generated public endpoint %q: %q", endpoint, body)
		}
	}
	for _, endpoint := range []string{"GET /static/{path}"} {
		if strings.Contains(body, endpoint) {
			t.Errorf("body unexpectedly lists non-API route %q: %q", endpoint, body)
		}
	}
	if !strings.Contains(body, "Versioned API base URL: http://example.com/api/v1") {
		t.Errorf("body missing request-resolved API base URL: %q", body)
	}
}

func TestLLMCustomSectionValidationAndLinkSafety(t *testing.T) {
	sections := []config.LLMCustomSection{
		{Title: "Valid", Content: "[secure](https://example.test) and [relative](./guide)"},
		{Title: "", Content: "invalid"},
		{Title: "Unsafe", Content: "[bad](javascript:alert(1)) <script>"},
	}
	valid := validLLMCustomSections(sections)
	if len(valid) != 2 {
		t.Fatalf("validLLMCustomSections() returned %d sections, want 2", len(valid))
	}
	got := safeLLMMarkdown(valid[1].Content)
	if strings.Contains(got, "<script>") || strings.Contains(got, "javascript:") || !strings.Contains(got, "](#)") {
		t.Fatalf("unsafe section content = %q", got)
	}
}

func TestLLMsReadRateLimitUsesConfiguration(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.AppConfig
		want string
	}{
		{name: "default fallback", want: "120 requests per 1 minute per IP"},
		{name: "configured bucket", cfg: func() *config.AppConfig {
			cfg := config.DefaultConfig()
			cfg.Server.RateLimit.Read.Requests = 25
			cfg.Server.RateLimit.Read.Window = 30
			return cfg
		}(), want: "25 requests per 30 seconds per IP"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := llmsReadRateLimit(tt.cfg); got != tt.want {
				t.Fatalf("llmsReadRateLimit() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLLMsAPIEndpointsRespectActiveRuntimeRegistry(t *testing.T) {
	spec := swagger.GenerateSpec(swagger.SwaggerHandlerConfig{}, "https://example.com/api/v1", "en")
	active := map[string]struct{}{"v1Healthz": {}}
	endpoints := llmsAPIEndpoints(spec.Paths, active)
	joined := strings.Join(endpoints, "\n")
	if !strings.Contains(joined, "GET /api/v1/server/healthz") {
		t.Fatal("active health endpoint missing from llms.txt endpoint list")
	}
	if strings.Contains(joined, "GET /api/v1/server/about") {
		t.Fatal("unregistered API operation listed in llms.txt")
	}
	if !strings.Contains(joined, "GET /") || !strings.Contains(joined, "GET /{ip}") {
		t.Fatal("runtime filtering removed echoip-compatible root routes")
	}
}

func TestLLMsAPIRoutesUseListedRegistryValues(t *testing.T) {
	routes := []swagger.RouteDefinition{
		{Method: "GET", Path: "/api/v1/visible", OperationID: "visible", Summary: "Visible endpoint", Listed: true},
		{Method: "GET", Path: "/api/v1/hidden", OperationID: "hidden", Summary: "Hidden endpoint", Listed: false},
		{Method: "GET", Path: "/api/v1/internal", OperationID: "internal", Summary: "Internal endpoint", Listed: true, Internal: true},
	}
	got := llmsAPIRoutes(routes, nil)
	if len(got) != 1 || got[0] != "GET /api/v1/visible — Visible endpoint" {
		t.Fatalf("llmsAPIRoutes() = %#v", got)
	}
}
