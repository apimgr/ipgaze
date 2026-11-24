package swagger

import (
	"bytes"
	"encoding/json"
	"log"
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
	OperationID string                 `json:"operationId,omitempty"`
	Summary     string                 `json:"summary,omitempty"`
	Description string                 `json:"description,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
	Parameters  []Parameter            `json:"parameters,omitempty"`
	RequestBody *RequestBody           `json:"requestBody,omitempty"`
	Responses   map[string]APIResponse `json:"responses"`
	Security    []map[string][]string  `json:"security,omitempty"`
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
	Type                 string            `json:"type,omitempty"`
	Properties           map[string]Schema `json:"properties,omitempty"`
	AdditionalProperties *Schema           `json:"additionalProperties,omitempty"`
	Items                *Schema           `json:"items,omitempty"`
	Example              interface{}       `json:"example,omitempty"`
	Ref                  string            `json:"$ref,omitempty"`
}

// Components holds reusable OpenAPI component definitions
type Components struct {
	Schemas         map[string]Schema         `json:"schemas,omitempty"`
	SecuritySchemes map[string]SecurityScheme `json:"securitySchemes,omitempty"`
}

type SecurityScheme struct {
	Type         string `json:"type"`
	Scheme       string `json:"scheme"`
	BearerFormat string `json:"bearerFormat,omitempty"`
}

// SwaggerHandlerConfig holds swagger handler configuration.
type SwaggerHandlerConfig struct {
	Version  string
	CommitID string
	Trust    *netutil.TrustResolver
	RenderUI func(http.ResponseWriter, *http.Request, string) error
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
		if strings.HasSuffix(r.URL.Path, "/theme.css") {
			themeName := r.URL.Query().Get("theme")
			switch themeName {
			case "light", "dark", "auto":
			default:
				themeName = "dark"
			}
			serveSwaggerThemeCSS(w, r, cfg, themeName)
			return
		}
		// Build the canonical base URL honoring trusted proxy headers per AI.md PART 15.
		baseURL := buildBaseURL(r, cfg.Trust)

		// Serve the OpenAPI JSON spec when the caller asks for JSON. There is
		// deliberately no `.json` path suffix — AI.md PART 14 states the spec is
		// reachable only at /api/swagger and /api/{api_version}/server/swagger.
		if r.Header.Get("Accept") == "application/json" {
			spec := GenerateSpec(cfg, baseURL, i18n.DetectLocale(r))
			writeOpenAPISpec(w, r, spec)
			return
		}

		if cfg.RenderUI != nil {
			if err := cfg.RenderUI(w, r, "swagger.tmpl"); err != nil {
				log.Printf("Swagger UI render failed: %v", err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			return
		}
		// Serve a standalone fallback for package-level callers without the
		// application page renderer.
		serveSwaggerUI(w, r, cfg, baseURL)
	}
}

func serveSwaggerThemeCSS(w http.ResponseWriter, r *http.Request, cfg SwaggerHandlerConfig, themeName string) {
	stamp := cfg.Version + "-" + cfg.CommitID
	etag := `"` + stamp + "-" + themeName + `"`
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("ETag", etag)
	if r.URL.Query().Get("v") == stamp {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	if r.Header.Get("If-None-Match") == etag || r.Header.Get("If-None-Match") == "*" {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	_, _ = w.Write([]byte(getSwaggerThemeCSS(themeName)))
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
		writeOpenAPISpec(w, r, spec)
	}
}

func writeOpenAPISpec(w http.ResponseWriter, r *http.Request, spec *OpenAPISpec) {
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	enc.SetIndent("", "  ")
	if err := enc.Encode(spec); err != nil {
		log.Printf("OpenAPI response encoding failed: request_id=%s method=%s path=%s err=%v", r.Header.Get("X-Request-ID"), r.Method, r.URL.Path, err)
		message := i18n.T(r.Context(), "errors.server_error")
		fallback, _ := json.Marshal(struct {
			OK      bool   `json:"ok"`
			Error   string `json:"error"`
			Message string `json:"message"`
		}{false, "SERVER_ERROR", message})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write(append(fallback, '\n'))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body.Bytes())
}

// serveSwaggerUI serves the Swagger UI HTML.
// CSS/JS assets are vendored under src/server/static/vendor/swagger-ui/ and
// served from the embedded static FS (no CDN) per AI.md PART 16 — mirrors the
// GraphiQL sibling's self-contained/offline requirement.
func serveSwaggerUI(w http.ResponseWriter, r *http.Request, cfg SwaggerHandlerConfig, baseURL string) {
	themeName := getTheme(r)
	lang := i18n.DetectLocale(r)
	dir := string(i18n.LocaleDirection(lang))
	assetStamp := cfg.Version + "-" + cfg.CommitID

	html := `<!DOCTYPE html>
<html lang="` + lang + `" dir="` + dir + `" class="theme-` + themeName + `">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>` + tr(lang, "swagger.ui.title") + `</title>
	<link rel="stylesheet" type="text/css" href="/static/vendor/swagger-ui/swagger-ui.css?v=` + assetStamp + `">
	<link rel="stylesheet" href="/theme.css?v=` + assetStamp + `">
	<link rel="stylesheet" href="/static/css/common.css?v=` + assetStamp + `">
	<link rel="stylesheet" href="/server/docs/swagger/theme.css?v=` + assetStamp + `&amp;theme=` + themeName + `">
</head>
<body>
	<a class="skip-link" href="#main-content">` + i18n.T(i18n.WithLang(r.Context(), lang), "accessibility.skip_to_content") + `</a>
	<main id="main-content">
	<h1>` + tr(lang, "swagger.ui.title") + `</h1>
	<div id="swagger-ui" data-spec-url="` + baseURL + `/api/swagger"></div>
	</main>
	<script src="/static/vendor/swagger-ui/swagger-ui-bundle.js?v=` + assetStamp + `"></script>
	<script src="/static/vendor/swagger-ui/swagger-ui-standalone-preset.js?v=` + assetStamp + `"></script>
	<script src="/static/js/app.js?v=` + assetStamp + `"></script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(html))
}

func getTheme(r *http.Request) string {
	if cookie, err := r.Cookie("theme"); err == nil {
		switch cookie.Value {
		case "light", "dark", "auto":
			return cookie.Value
		}
	}
	return "dark"
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
