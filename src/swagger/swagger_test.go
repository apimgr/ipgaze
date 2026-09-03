package swagger

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGenerateSpec_BasicShape(t *testing.T) {
	cfg := SwaggerHandlerConfig{Version: "1.2.3", CommitID: "abc123"}
	spec := GenerateSpec(cfg, "https://example.com", "en")

	if spec == nil {
		t.Fatal("GenerateSpec returned nil")
	}
	if spec.OpenAPI != "3.0.0" {
		t.Errorf("OpenAPI = %q, want %q", spec.OpenAPI, "3.0.0")
	}
	if spec.Info.Version != "1.2.3" {
		t.Errorf("Info.Version = %q, want %q", spec.Info.Version, "1.2.3")
	}
	if spec.Info.Title != "IPGaze API" {
		t.Errorf("Info.Title = %q, want %q", spec.Info.Title, "IPGaze API")
	}
}

func TestGenerateSpec_ServersBaseURL(t *testing.T) {
	cfg := SwaggerHandlerConfig{Version: "0.1.0"}
	spec := GenerateSpec(cfg, "https://api.example.com", "en")

	if len(spec.Servers) == 0 {
		t.Fatal("Servers list is empty")
	}
	if spec.Servers[0].URL != "https://api.example.com" {
		t.Errorf("Servers[0].URL = %q, want %q", spec.Servers[0].URL, "https://api.example.com")
	}
}

func TestGenerateSpec_ContactEmail(t *testing.T) {
	cfg := SwaggerHandlerConfig{Version: "1.0.0"}
	spec := GenerateSpec(cfg, "https://example.com", "en")

	if spec.Info.Contact == nil {
		t.Fatal("Contact is nil")
	}
	if !strings.Contains(spec.Info.Contact.Email, "example.com") {
		t.Errorf("Contact.Email = %q, want to contain %q", spec.Info.Contact.Email, "example.com")
	}
}

func TestGenerateSpec_RequiredPaths(t *testing.T) {
	cfg := SwaggerHandlerConfig{Version: "1.0.0"}
	spec := GenerateSpec(cfg, "http://localhost", "en")

	requiredPaths := []string{
		"/",
		"/server/healthz",
		"/json",
		"/ip",
		"/{ip}",
		"/country",
		"/country-iso",
		"/city",
		"/coordinates",
		"/asn",
		"/asn-org",
		"/api/v1",
		"/api/v1/ip",
		"/api/v1/ip/{ip}",
		"/api/v1/country",
		"/api/v1/city",
		"/api/v1/asn",
		"/api/v1/server/healthz",
		"/port/{port}",
	}

	for _, path := range requiredPaths {
		if _, ok := spec.Paths[path]; !ok {
			t.Errorf("missing path %q in spec", path)
		}
	}
}

func TestGenerateSpec_Components(t *testing.T) {
	cfg := SwaggerHandlerConfig{Version: "1.0.0"}
	spec := GenerateSpec(cfg, "http://localhost", "en")

	requiredSchemas := []string{"IPResponse", "PortResponse", "Error"}
	for _, name := range requiredSchemas {
		if _, ok := spec.Components.Schemas[name]; !ok {
			t.Errorf("missing component schema %q", name)
		}
	}
}

func TestGenerateSpec_IsValidJSON(t *testing.T) {
	cfg := SwaggerHandlerConfig{Version: "1.0.0", CommitID: "deadbeef"}
	spec := GenerateSpec(cfg, "https://example.com", "en")

	data, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("json.Marshal spec: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("marshaled spec is empty")
	}

	var roundtrip OpenAPISpec
	if err := json.Unmarshal(data, &roundtrip); err != nil {
		t.Fatalf("json.Unmarshal roundtrip: %v", err)
	}
}

func TestHandler_ServeJSON_ByAcceptHeader(t *testing.T) {
	cfg := SwaggerHandlerConfig{Version: "2.0.0", CommitID: "abc"}
	h := Handler(cfg)

	req := httptest.NewRequest(http.MethodGet, "/server/docs/swagger", nil)
	req.Header.Set("Accept", "application/json")
	req.Host = "example.com"
	rec := httptest.NewRecorder()

	h(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var spec OpenAPISpec
	if err := json.NewDecoder(rec.Body).Decode(&spec); err != nil {
		t.Fatalf("decode JSON response: %v", err)
	}
	if spec.OpenAPI != "3.0.0" {
		t.Errorf("spec.OpenAPI = %q, want %q", spec.OpenAPI, "3.0.0")
	}
}

func TestHandler_ServeSwaggerUI_DefaultDark(t *testing.T) {
	cfg := SwaggerHandlerConfig{Version: "1.0.0"}
	h := Handler(cfg)

	req := httptest.NewRequest(http.MethodGet, "/swagger", nil)
	req.Host = "example.com"
	rec := httptest.NewRecorder()

	h(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "swagger-ui") {
		t.Error("HTML body does not contain swagger-ui reference")
	}
	if !strings.Contains(body, "<!DOCTYPE html>") {
		t.Error("HTML body missing DOCTYPE")
	}
}

func TestHandler_ServeSwaggerUI_LightThemeCookie(t *testing.T) {
	cfg := SwaggerHandlerConfig{Version: "1.0.0"}
	h := Handler(cfg)

	req := httptest.NewRequest(http.MethodGet, "/swagger", nil)
	req.Host = "example.com"
	req.AddCookie(&http.Cookie{Name: "theme", Value: "light"})
	rec := httptest.NewRecorder()

	h(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "#ffffff") {
		t.Error("light theme body should contain light background color #ffffff")
	}
}

func TestHandler_ServeSwaggerUI_DarkThemeCookie(t *testing.T) {
	cfg := SwaggerHandlerConfig{Version: "1.0.0"}
	h := Handler(cfg)

	req := httptest.NewRequest(http.MethodGet, "/swagger", nil)
	req.Host = "example.com"
	req.AddCookie(&http.Cookie{Name: "theme", Value: "dark"})
	rec := httptest.NewRecorder()

	h(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "#282a36") {
		t.Error("dark theme body should contain dark background color #282a36")
	}
}

func TestHandler_ServeSwaggerUI_InvalidThemeCookieDefaultsDark(t *testing.T) {
	cfg := SwaggerHandlerConfig{Version: "1.0.0"}
	h := Handler(cfg)

	req := httptest.NewRequest(http.MethodGet, "/swagger", nil)
	req.Host = "example.com"
	req.AddCookie(&http.Cookie{Name: "theme", Value: "invalid-value"})
	rec := httptest.NewRecorder()

	h(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "#282a36") {
		t.Error("invalid theme cookie should fall back to dark (#282a36)")
	}
}

func TestHandler_BuildBaseURL_HTTP(t *testing.T) {
	cfg := SwaggerHandlerConfig{Version: "1.0.0"}
	h := Handler(cfg)

	req := httptest.NewRequest(http.MethodGet, "/server/docs/swagger", nil)
	req.Header.Set("Accept", "application/json")
	req.Host = "myhost:8080"
	rec := httptest.NewRecorder()

	h(rec, req)

	var spec OpenAPISpec
	json.NewDecoder(rec.Body).Decode(&spec)
	if len(spec.Servers) == 0 {
		t.Fatal("no servers in spec")
	}
	if spec.Servers[0].URL != "http://myhost:8080" {
		t.Errorf("Server URL = %q, want %q", spec.Servers[0].URL, "http://myhost:8080")
	}
}

func TestHandler_BuildBaseURL_XForwardedProto(t *testing.T) {
	cfg := SwaggerHandlerConfig{Version: "1.0.0"}
	h := Handler(cfg)

	req := httptest.NewRequest(http.MethodGet, "/server/docs/swagger", nil)
	req.Header.Set("Accept", "application/json")
	req.Host = "example.com"
	// Loopback address is always trusted, so X-Forwarded-Proto is honored.
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()

	h(rec, req)

	var spec OpenAPISpec
	json.NewDecoder(rec.Body).Decode(&spec)
	if len(spec.Servers) == 0 {
		t.Fatal("no servers in spec")
	}
	if spec.Servers[0].URL != "https://example.com" {
		t.Errorf("Server URL = %q, want %q", spec.Servers[0].URL, "https://example.com")
	}
}

func TestHandler_BuildBaseURL_XForwardedHost(t *testing.T) {
	cfg := SwaggerHandlerConfig{Version: "1.0.0"}
	h := Handler(cfg)

	req := httptest.NewRequest(http.MethodGet, "/server/docs/swagger", nil)
	req.Header.Set("Accept", "application/json")
	req.Host = "internal-host"
	// Loopback address is always trusted, so X-Forwarded-Host is honored.
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-Host", "public.example.com")
	rec := httptest.NewRecorder()

	h(rec, req)

	var spec OpenAPISpec
	json.NewDecoder(rec.Body).Decode(&spec)
	if len(spec.Servers) == 0 {
		t.Fatal("no servers in spec")
	}
	if spec.Servers[0].URL != "http://public.example.com" {
		t.Errorf("Server URL = %q, want %q", spec.Servers[0].URL, "http://public.example.com")
	}
}

func TestExtractHost(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"http://example.com", "example.com"},
		{"https://example.com", "example.com"},
		{"https://example.com:443", "example.com"},
		{"http://example.com:8080/path", "example.com"},
		{"example.com", "example.com"},
		{"example.com:9000", "example.com"},
	}

	for _, tc := range tests {
		got := extractHost(tc.input)
		if got != tc.want {
			t.Errorf("extractHost(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestGetTheme_NoCookie(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	got := getTheme(req)
	if got != "dark" {
		t.Errorf("getTheme (no cookie) = %q, want %q", got, "dark")
	}
}

func TestGetTheme_ValidCookies(t *testing.T) {
	themes := []string{"light", "dark", "auto"}
	for _, theme := range themes {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: "theme", Value: theme})
		got := getTheme(req)
		if got != theme {
			t.Errorf("getTheme (cookie=%q) = %q, want %q", theme, got, theme)
		}
	}
}

func TestGetTheme_InvalidCookie(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "theme", Value: "hacker"})
	got := getTheme(req)
	if got != "dark" {
		t.Errorf("getTheme (invalid cookie) = %q, want %q", got, "dark")
	}
}

func TestGetSwaggerThemeCSS_Dark(t *testing.T) {
	css := getSwaggerThemeCSS("dark")
	if !strings.Contains(css, "#282a36") {
		t.Error("dark theme CSS missing expected background color #282a36")
	}
}

func TestGetSwaggerThemeCSS_Light(t *testing.T) {
	css := getSwaggerThemeCSS("light")
	if !strings.Contains(css, "#ffffff") {
		t.Error("light theme CSS missing expected background color #ffffff")
	}
}

func TestGetSwaggerThemeCSS_AutoFallbackToDark(t *testing.T) {
	css := getSwaggerThemeCSS("auto")
	if !strings.Contains(css, "#282a36") {
		t.Error("auto theme CSS should fall back to dark (#282a36)")
	}
}

func TestGetSwaggerThemeCSS_UnknownFallbackToDark(t *testing.T) {
	css := getSwaggerThemeCSS("anything-else")
	if !strings.Contains(css, "#282a36") {
		t.Error("unknown theme should fall back to dark (#282a36)")
	}
}

func TestIPResponseSchema_RequiredFields(t *testing.T) {
	cfg := SwaggerHandlerConfig{Version: "1.0.0"}
	spec := GenerateSpec(cfg, "http://localhost", "en")

	ipSchema, ok := spec.Components.Schemas["IPResponse"]
	if !ok {
		t.Fatal("IPResponse schema not found")
	}

	required := []string{"ip", "country", "country_iso", "city", "latitude", "longitude", "asn", "asn_org"}
	for _, field := range required {
		if _, ok := ipSchema.Properties[field]; !ok {
			t.Errorf("IPResponse schema missing property %q", field)
		}
	}
}

func TestPortResponseSchema(t *testing.T) {
	cfg := SwaggerHandlerConfig{Version: "1.0.0"}
	spec := GenerateSpec(cfg, "http://localhost", "en")

	portSchema, ok := spec.Components.Schemas["PortResponse"]
	if !ok {
		t.Fatal("PortResponse schema not found")
	}

	required := []string{"ip", "port", "reachable"}
	for _, field := range required {
		if _, ok := portSchema.Properties[field]; !ok {
			t.Errorf("PortResponse schema missing property %q", field)
		}
	}
}
