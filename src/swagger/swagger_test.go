package swagger

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	i18n "github.com/apimgr/ipgaze/src/common/i18n"
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

func TestAPIV1RouteDefinitionsMatchOpenAPI(t *testing.T) {
	definitions := APIV1RouteDefinitions()
	spec := GenerateSpec(SwaggerHandlerConfig{}, "https://example.com/api/v1", "en")
	documented := make(map[string]string)
	for path, item := range spec.Paths {
		for method, operation := range map[string]*Operation{
			"GET": item.Get, "POST": item.Post, "PUT": item.Put,
			"PATCH": item.Patch, "DELETE": item.Delete,
		} {
			if strings.HasPrefix(path, "/api/v1") && operation != nil {
				documented[operation.OperationID] = method + " " + path
			}
		}
	}
	listed := 0
	for _, definition := range definitions {
		if definition.Listed {
			listed++
		}
	}
	if listed != len(documented) {
		t.Fatalf("APIV1RouteDefinitions() has %d listed entries, OpenAPI has %d versioned operations", listed, len(documented))
	}
	seen := make(map[string]bool, len(definitions))
	for _, definition := range definitions {
		if definition.OperationID == "" || seen[definition.OperationID] {
			t.Errorf("invalid or duplicate API operation ID %q", definition.OperationID)
			continue
		}
		if strings.Contains(definition.OperationID, "_") {
			t.Errorf("operation ID %q is not camelCase", definition.OperationID)
		}
		if definition.Summary == "" {
			t.Errorf("operation %q has no registry summary", definition.OperationID)
		}
		if definition.Auth == "" {
			t.Errorf("operation %q has no registry auth policy", definition.OperationID)
		}
		if definition.Auth == "operator" && definition.Listed {
			t.Errorf("operator-only operation %q is listed for public discovery", definition.OperationID)
		}
		if definition.Auth != "operator" && definition.Auth != "service" && !definition.Listed {
			t.Errorf("public or token operation %q is absent from public discovery", definition.OperationID)
		}
		if definition.Internal {
			t.Errorf("internal operation %q reached the public route registry", definition.OperationID)
		}
		seen[definition.OperationID] = true
		want := definition.Method + " " + definition.Path
		got := documented[definition.OperationID]
		if definition.Listed && got != want {
			t.Errorf("operation %q definition = %q, OpenAPI = %q", definition.OperationID, want, got)
		}
		if !definition.Listed && got != "" {
			t.Errorf("unlisted operation %q was included in OpenAPI as %q", definition.OperationID, got)
		}
		if definition.RuntimeAlias && definition.RuntimePath == "" {
			t.Errorf("runtime alias %q has no runtime path", definition.OperationID)
		}
	}
	if spec.Paths["/api/v1/server/auth/check"].Get != nil {
		t.Fatal("operator-only route was included in OpenAPI")
	}
}

func TestOpenAPIUsesActiveRouteRegistry(t *testing.T) {
	routes := APIV1RouteDefinitions()
	for i := range routes {
		if routes[i].OperationID == "v1Ip" {
			routes[i].Handler = func(http.ResponseWriter, *http.Request) {}
		}
	}
	spec := GenerateSpec(SwaggerHandlerConfig{
		RegisteredRoutes: func() []Route { return routes },
	}, "https://example.com", "en")
	if spec.Paths["/api/v1/ip"].Get == nil {
		t.Fatal("active route missing from OpenAPI")
	}
	if spec.Paths["/api/v1/server/healthz"].Get != nil {
		t.Fatal("route without an active handler was included in OpenAPI")
	}
}

func TestOpenAPIUsesRegisteredUnversionedAPIAliases(t *testing.T) {
	routes := APIRouteDefinitions()
	for i := range routes {
		routes[i].Handler = func(http.ResponseWriter, *http.Request) {}
	}
	spec := GenerateSpec(SwaggerHandlerConfig{
		RegisteredRoutes: func() []Route { return routes },
	}, "https://example.com", "en")
	for _, path := range []string{"/api/healthz", "/api/swagger", "/api/graphql", "/api/mcp", "/mcp"} {
		if _, ok := spec.Paths[path]; !ok {
			t.Errorf("registered API alias %q missing from OpenAPI", path)
		}
	}
}

func TestRegistryPublishesRuntimeRouteMetadata(t *testing.T) {
	var registry Registry
	registry.Add(Route{
		method:       http.MethodGet,
		path:         "/static/{path}",
		id:           "staticAsset",
		runtimePath:  "/static/*",
		runtimeAlias: true,
	})
	route := registry.Routes()[0]
	if route.RuntimePath != "/static/*" {
		t.Errorf("runtime path = %q, want /static/*", route.RuntimePath)
	}
	if !route.RuntimeAlias {
		t.Error("runtime alias metadata was not published")
	}
}

func TestOpenAPISchemasUseRouteRequestAndResponseModels(t *testing.T) {
	type requestModel struct {
		Address string `json:"address"`
		Limit   int    `json:"limit"`
	}
	type responseModel struct {
		Address string `json:"address"`
		Valid   bool   `json:"valid"`
	}
	var registry Registry
	registry.Add(Route{
		Method:      http.MethodPost,
		Path:        "/api/v1/test-lookups",
		OperationID: "testLookups",
		Summary:     "Create lookup",
		Auth:        "none",
		Request:     requestModel{},
		Response:    responseModel{},
	})
	route := registry.Routes()[0]
	operation := OperationForRoute(route, "en")
	if operation == nil || operation.RequestBody == nil {
		t.Fatal("operation did not include its route request model")
	}
	requestSchema := operation.RequestBody.Content["application/json"].Schema
	if requestSchema == nil || requestSchema.Properties["address"].Type != "string" || requestSchema.Properties["limit"].Type != "integer" {
		t.Fatalf("request schema did not reflect Request fields: %+v", requestSchema)
	}
	responseSchema := operation.Responses["200"].Content["application/json"].Schema
	if responseSchema == nil || responseSchema.Properties["address"].Type != "string" || responseSchema.Properties["valid"].Type != "boolean" {
		t.Fatalf("response schema did not reflect Response fields: %+v", responseSchema)
	}
}

func TestOpenAPISchemaModelsPreserveIPAndTimeScalarTypes(t *testing.T) {
	spec := GenerateSpec(SwaggerHandlerConfig{}, "https://example.com", "en")
	resolve := func(schema *Schema) Schema {
		if schema != nil && strings.HasPrefix(schema.Ref, "#/components/schemas/") {
			return spec.Components.Schemas[strings.TrimPrefix(schema.Ref, "#/components/schemas/")]
		}
		if schema == nil {
			return Schema{}
		}
		return *schema
	}
	var ipRoute Route
	for _, route := range APIV1RouteDefinitions() {
		if route.OperationID == "v1Info" {
			ipRoute = route
			break
		}
	}
	operation := OperationForRoute(ipRoute, "en")
	if operation == nil {
		t.Fatal("IP route has no OpenAPI operation")
	}
	schema := resolve(operation.Responses["200"].Content["application/json"].Schema)
	if schema.Properties["ip"].Type != "string" || schema.Properties["ip_decimal"].Type != "integer" {
		t.Fatalf("IP response scalar types are incorrect: %+v", schema)
	}

	var healthRoute Route
	for _, route := range APIV1RouteDefinitions() {
		if route.OperationID == "v1Healthz" {
			healthRoute = route
			break
		}
	}
	health := resolve(OperationForRoute(healthRoute, "en").Responses["200"].Content["application/json"].Schema)
	if health.Properties["timestamp"].Type != "string" || health.Properties["timestamp"].Format != "date-time" {
		t.Fatalf("health timestamp schema is incorrect: %+v", health)
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

func TestHandler_RenderUIErrorReturnsInternalServerError(t *testing.T) {
	h := Handler(SwaggerHandlerConfig{RenderUI: func(http.ResponseWriter, *http.Request, string) error {
		return errors.New("template render failed")
	}})
	req := httptest.NewRequest(http.MethodGet, "/server/docs/swagger", nil)
	req.Header.Set("Accept-Language", "fr")
	rec := httptest.NewRecorder()

	h(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if rec.Body.Len() == 0 {
		t.Fatal("render failure returned an empty response")
	}
	want := i18n.T(i18n.WithLang(req.Context(), i18n.DetectLocale(req)), "errors.server_error")
	if strings.TrimSpace(rec.Body.String()) != want {
		t.Fatalf("render error body = %q, want translated %q", strings.TrimSpace(rec.Body.String()), want)
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
	if !strings.Contains(body, "/server/docs/swagger/theme.css?") || !strings.Contains(body, "theme=light") {
		t.Error("light theme stylesheet should be linked")
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
	if !strings.Contains(body, "/server/docs/swagger/theme.css?") || !strings.Contains(body, "theme=dark") {
		t.Error("dark theme stylesheet should be linked")
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
	if !strings.Contains(body, "/server/docs/swagger/theme.css?") || !strings.Contains(body, "theme=dark") {
		t.Error("invalid theme cookie should fall back to the dark stylesheet")
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
	if err := json.NewDecoder(rec.Body).Decode(&spec); err != nil {
		t.Fatalf("decode OpenAPI spec: %v", err)
	}
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
	if err := json.NewDecoder(rec.Body).Decode(&spec); err != nil {
		t.Fatalf("decode OpenAPI spec: %v", err)
	}
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
	if err := json.NewDecoder(rec.Body).Decode(&spec); err != nil {
		t.Fatalf("decode OpenAPI spec: %v", err)
	}
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

func TestGetSwaggerThemeCSS_AutoFollowsSystemPreference(t *testing.T) {
	css := getSwaggerThemeCSS("auto")
	if !strings.Contains(css, "@media (prefers-color-scheme: light)") || !strings.Contains(css, "#282a36") || !strings.Contains(css, "#ffffff") {
		t.Error("auto theme should provide dark defaults and light system overrides")
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
