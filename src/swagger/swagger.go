package swagger

import (
	"encoding/json"
	"net/http"
	"strings"

	i18n "github.com/apimgr/ipgaze/src/common/i18n"
	"github.com/apimgr/ipgaze/src/netutil"
)

// OpenAPISpec represents the OpenAPI 3.0 specification
type OpenAPISpec struct {
	OpenAPI    string              `json:"openapi"`
	Info       Info                `json:"info"`
	Servers    []Server            `json:"servers"`
	Paths      map[string]PathItem `json:"paths"`
	Components Components          `json:"components,omitempty"`
}

// Info holds the API title, description, version, and contact information
type Info struct {
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Version     string   `json:"version"`
	Contact     *Contact `json:"contact,omitempty"`
}

// Contact holds API contact information
type Contact struct {
	Name  string `json:"name,omitempty"`
	URL   string `json:"url,omitempty"`
	Email string `json:"email,omitempty"`
}

// Server holds an API server URL and description
type Server struct {
	URL         string `json:"url"`
	Description string `json:"description,omitempty"`
}

// PathItem holds the HTTP operations for a single API path
type PathItem struct {
	Get    *Operation `json:"get,omitempty"`
	Post   *Operation `json:"post,omitempty"`
	Put    *Operation `json:"put,omitempty"`
	Delete *Operation `json:"delete,omitempty"`
	Patch  *Operation `json:"patch,omitempty"`
}

// Operation holds metadata for a single API operation
type Operation struct {
	Summary     string                 `json:"summary,omitempty"`
	Description string                 `json:"description,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
	Parameters  []Parameter            `json:"parameters,omitempty"`
	RequestBody *RequestBody           `json:"requestBody,omitempty"`
	Responses   map[string]APIResponse `json:"responses"`
}

// Parameter holds an API operation parameter definition
type Parameter struct {
	Name        string  `json:"name"`
	In          string  `json:"in"`
	Description string  `json:"description,omitempty"`
	Required    bool    `json:"required,omitempty"`
	Schema      *Schema `json:"schema,omitempty"`
}

// RequestBody holds an API operation request body definition
type RequestBody struct {
	Description string               `json:"description,omitempty"`
	Required    bool                 `json:"required,omitempty"`
	Content     map[string]MediaType `json:"content"`
}

// APIResponse holds an API operation response definition
type APIResponse struct {
	Description string               `json:"description"`
	Content     map[string]MediaType `json:"content,omitempty"`
}

// MediaType holds a media type definition within a request or response
type MediaType struct {
	Schema *Schema `json:"schema,omitempty"`
}

// Schema holds a JSON schema definition
type Schema struct {
	Type       string            `json:"type,omitempty"`
	Properties map[string]Schema `json:"properties,omitempty"`
	Items      *Schema           `json:"items,omitempty"`
	Example    interface{}       `json:"example,omitempty"`
	Ref        string            `json:"$ref,omitempty"`
}

// Components holds reusable OpenAPI component definitions
type Components struct {
	Schemas map[string]Schema `json:"schemas,omitempty"`
}

// SwaggerHandlerConfig holds swagger handler configuration.
type SwaggerHandlerConfig struct {
	Version  string
	CommitID string
	Trust    *netutil.TrustResolver
}

// GenerateSpec generates the OpenAPI specification for the IPGaze API,
// localized for lang. Path and component definitions live in annotations.go.
func GenerateSpec(cfg SwaggerHandlerConfig, baseURL, lang string) *OpenAPISpec {
	spec := &OpenAPISpec{
		OpenAPI: "3.0.0",
		Info: Info{
			Title:       tr(lang, "swagger.info.title"),
			Description: tr(lang, "swagger.info.description"),
			Version:     cfg.Version,
			Contact: &Contact{
				Name:  "apimgr",
				URL:   "https://github.com/apimgr/ipgaze",
				Email: "noreply@" + extractHost(baseURL),
			},
		},
		Servers: []Server{
			{
				URL:         baseURL,
				Description: tr(lang, "swagger.info.server"),
			},
		},
		Paths:      generatePaths(lang),
		Components: generateComponents(),
	}

	return spec
}

// Handler serves the Swagger UI and OpenAPI spec.
func Handler(cfg SwaggerHandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Build the canonical base URL honoring trusted proxy headers per AI.md PART 15.
		baseURL := buildBaseURL(r, cfg.Trust)

		// Serve the OpenAPI JSON spec when the caller asks for JSON. There is
		// deliberately no `.json` path suffix — AI.md PART 14 states the spec is
		// reachable only at /api/swagger and /api/{api_version}/server/swagger.
		if r.Header.Get("Accept") == "application/json" {
			spec := GenerateSpec(cfg, baseURL, i18n.DetectLocale(r))
			w.Header().Set("Content-Type", "application/json")
			// AI.md PART 14: every JSON response is 2-space indented.
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			enc.Encode(spec)
			return
		}

		// Serve Swagger UI
		serveSwaggerUI(w, r, cfg, baseURL)
	}
}

// JSONHandler serves the OpenAPI spec as JSON unconditionally, regardless of
// the Accept header or path suffix. Per AI.md PART 14/16, `/api/swagger` and
// `/api/{api_version}/server/swagger` are dedicated machine-readable spec
// endpoints, distinct from the interactive `/server/docs/swagger` UI page
// (which alone uses the content-negotiating Handler above).
func JSONHandler(cfg SwaggerHandlerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		baseURL := buildBaseURL(r, cfg.Trust)
		spec := GenerateSpec(cfg, baseURL, i18n.DetectLocale(r))
		w.Header().Set("Content-Type", "application/json")
		// AI.md PART 14: every JSON response is 2-space indented.
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.Encode(spec)
	}
}

// serveSwaggerUI serves the Swagger UI HTML.
// CSS/JS assets are vendored under src/server/static/vendor/swagger-ui/ and
// served from the embedded static FS (no CDN) per AI.md PART 16 — mirrors the
// GraphiQL sibling's self-contained/offline requirement.
func serveSwaggerUI(w http.ResponseWriter, r *http.Request, cfg SwaggerHandlerConfig, baseURL string) {
	// Get theme from cookie or default to dark
	theme := getTheme(r)
	lang := i18n.DetectLocale(r)
	dir := string(i18n.LocaleDirection(lang))

	html := `<!DOCTYPE html>
<html lang="` + lang + `" dir="` + dir + `">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>` + tr(lang, "swagger.ui.title") + `</title>
	<link rel="stylesheet" type="text/css" href="/static/vendor/swagger-ui/swagger-ui.css">
	<style>` + getSwaggerThemeCSS(theme) + `</style>
</head>
<body>
	<div id="swagger-ui" data-spec-url="` + baseURL + `/api/swagger"></div>
	<script src="/static/vendor/swagger-ui/swagger-ui-bundle.js"></script>
	<script src="/static/vendor/swagger-ui/swagger-ui-standalone-preset.js"></script>
	<script src="/static/js/app.js"></script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// buildBaseURL constructs the base URL for the Swagger UI using the canonical netutil helpers.
// Proxy headers are honored only when the immediate peer is a trusted proxy per AI.md PART 15.
func buildBaseURL(r *http.Request, tr *netutil.TrustResolver) string {
	return netutil.BuildURL(r, tr, "")
}

// extractHost extracts hostname from a URL string
func extractHost(url string) string {
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "https://")
	parts := strings.Split(url, "/")
	// strings.Split always returns at least one element
	return strings.Split(parts[0], ":")[0]
}

// getTheme gets the current theme from cookie or defaults to dark.
// Per AI.md PART 16: Themes (NON-NEGOTIABLE - PROJECT-WIDE)
func getTheme(r *http.Request) string {
	if cookie, err := r.Cookie("theme"); err == nil {
		switch cookie.Value {
		case "light", "dark", "auto":
			return cookie.Value
		}
	}
	return "dark"
}
