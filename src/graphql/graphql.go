package graphql

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strings"

	gql "github.com/graphql-go/graphql"

	i18n "github.com/apimgr/ipgaze/src/common/i18n"
	"github.com/apimgr/ipgaze/src/server/handler"
	"github.com/apimgr/ipgaze/src/server/model"
)

// Schema represents the GraphQL schema (populated by InitSchema in schema.go)
var Schema gql.Schema

// GraphQLHandlerConfig holds GraphQL handler configuration.
// Resolver callbacks are optional; a nil callback makes the matching resolver
// return a GraphQL error instead of serving live data. Pass the same server
// methods and page definitions that back REST endpoints (see main.go).
type GraphQLHandlerConfig struct {
	Version  string
	CommitID string
	RenderUI func(http.ResponseWriter, *http.Request, string) error
	// ClientIP extracts the caller's IP from an incoming HTTP request.
	ClientIP func(r *http.Request, allowOverride bool) (net.IP, error)
	// LookupIP resolves GeoIP/ASN/hostname/threat info for ip.
	LookupIP func(ip net.IP) (model.IPLookupResponse, error)
	// CheckPort attempts a live TCP connection check.
	CheckPort func(ip net.IP, port uint64) (bool, error)
	// Health returns the same model.HealthResponse the REST health endpoints
	// render, keeping the GraphQL health query functionally equivalent to REST.
	Health      func() model.HealthResponse
	AuthCheck   func(r *http.Request) (string, error)
	ContactForm func(r *http.Request) (map[string]interface{}, error)
}

// Handler serves the GraphQL endpoint and GraphiQL UI
func Handler(cfg GraphQLHandlerConfig) http.HandlerFunc {
	// Wire resolver dependencies from cfg — see Deps in resolvers.go.
	resolverDeps = Deps{
		ClientIP:    cfg.ClientIP,
		LookupIP:    cfg.LookupIP,
		CheckPort:   cfg.CheckPort,
		Health:      cfg.Health,
		AuthCheck:   cfg.AuthCheck,
		ContactForm: cfg.ContactForm,
	}

	// Initialize schema on first call
	if Schema.QueryType() == nil {
		if err := InitSchema(); err != nil {
			return func(w http.ResponseWriter, r *http.Request) {
				lang := i18n.DetectLocale(r)
				// The GraphQL endpoint answers API clients, so a schema-init
				// failure returns the canonical AI.md PART 9 envelope rather
				// than http.Error's bare text/plain body.
				handler.WriteAPIError(w, http.StatusInternalServerError, "", i18n.T(i18n.WithLang(r.Context(), lang), "errors.server_error"))
			}
		}
	}

	return func(w http.ResponseWriter, r *http.Request) {
		// Handle POST requests (GraphQL queries)
		if r.Method == http.MethodPost {
			handleGraphQLQuery(w, r)
			return
		}

		// Handle GET requests (GraphiQL UI)
		if r.Method == http.MethodGet {
			if strings.HasSuffix(r.URL.Path, "/theme.css") {
				themeName := r.URL.Query().Get("theme")
				switch themeName {
				case "light", "dark", "auto":
				default:
					themeName = "dark"
				}
				serveGraphiQLThemeCSS(w, r, cfg, themeName)
				return
			}
			if cfg.RenderUI != nil {
				if err := cfg.RenderUI(w, r, "graphql.tmpl"); err != nil {
					log.Printf("GraphQL UI render failed: %v", err)
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
				return
			}
			serveGraphiQL(w, r, cfg)
			return
		}

		lang := i18n.DetectLocale(r)
		handler.WriteAPIError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", i18n.T(i18n.WithLang(r.Context(), lang), "errors.method_not_allowed"))
	}
}

func serveGraphiQLThemeCSS(w http.ResponseWriter, r *http.Request, cfg GraphQLHandlerConfig, themeName string) {
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
	_, _ = w.Write([]byte(getGraphiQLThemeCSS(themeName)))
}

// handleGraphQLQuery executes a GraphQL query
func handleGraphQLQuery(w http.ResponseWriter, r *http.Request) {
	var params struct {
		Query         string                 `json:"query"`
		Variables     map[string]interface{} `json:"variables"`
		OperationName string                 `json:"operationName"`
	}

	// Cap the request body to 1 MiB so a hostile client cannot exhaust memory
	// with an oversized query payload (ReadTimeout bounds time, not size).
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		lang := i18n.DetectLocale(r)
		writeGraphQLError(w, i18n.T(i18n.WithLang(r.Context(), lang), "errors.bad_request"), http.StatusBadRequest)
		return
	}

	// Reject overly deep or alias-heavy queries before execution to prevent
	// alias-based and deep-nesting amplification attacks. Every GraphQL
	// response — success or rejection — must stay valid GraphQL-shaped JSON
	// so a GraphQL client (including GraphiQL) can always parse the body
	// instead of choking on a plain-text 400.
	if err := checkQueryComplexity(params.Query); err != nil {
		writeGraphQLError(w, err.Error(), http.StatusBadRequest)
		return
	}

	result := gql.Do(gql.Params{
		Schema:         schemaForLocale(i18n.DetectLocale(r)),
		RequestString:  params.Query,
		VariableValues: params.Variables,
		OperationName:  params.OperationName,
		Context:        withRequest(r.Context(), r),
	})

	w.Header().Set("Content-Type", "application/json")
	// AI.md PART 14: every JSON response is 2-space indented.
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		return
	}
}

// writeGraphQLError writes a rejection (malformed body, complexity limit) in
// the same GraphQL-standard `{"errors":[{"message":...}]}` envelope that
// gql.Do already produces for execution/validation errors, so callers only
// ever need one parser for this endpoint's responses.
func writeGraphQLError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// AI.md PART 14: every JSON response is 2-space indented.
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(map[string]interface{}{
		"data":   nil,
		"errors": []map[string]string{{"message": message}},
	})
}

// serveGraphiQL serves the GraphQL explorer interface.
// All assets are self-contained (no CDN) per AI.md PART 16.
func serveGraphiQL(w http.ResponseWriter, r *http.Request, cfg GraphQLHandlerConfig) {
	// Get theme name from cookie or default to dark
	themeName := getTheme(r)
	lang := i18n.DetectLocale(r)
	dir := string(i18n.LocaleDirection(lang))
	assetStamp := cfg.Version + "-" + cfg.CommitID

	html := `<!DOCTYPE html>
<html lang="` + lang + `" dir="` + dir + `" class="theme-` + themeName + `">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>` + tr(lang, "graphql.ui.title") + `</title>
	<link rel="stylesheet" href="/theme.css?v=` + assetStamp + `">
	<link rel="stylesheet" href="/static/css/common.css?v=` + assetStamp + `">
	<link rel="stylesheet" href="/static/css/graphql.css?v=` + assetStamp + `">
	<link rel="stylesheet" href="/server/docs/graphql/theme.css?v=` + assetStamp + `&amp;theme=` + themeName + `">
</head>
<body>
<a class="skip-link" href="#main-content">` + tr(lang, "accessibility.skip_to_content") + `</a>
<main id="main-content">
<h1>` + tr(lang, "graphql.ui.title") + ` &mdash; ` + cfg.Version + `</h1>
<div id="main">
	<div id="left">
		<label for="query">` + tr(lang, "graphql.ui.query") + `</label>
		<textarea id="query" spellcheck="false">query {
  health {
    status
    version
  }
  myIP {
    ip
    country
    city
    asn
  }
}</textarea>
		<label class="variables-label" for="vars">` + tr(lang, "graphql.ui.variables") + `</label>
		<textarea id="vars" spellcheck="false">{}</textarea>
		<button id="run">&#9654; ` + tr(lang, "graphql.ui.run") + `</button>
	</div>
	<div id="right">
		<h2>` + tr(lang, "graphql.ui.response") + `</h2>
		<div id="result">` + tr(lang, "graphql.ui.placeholder") + `</div>
	</div>
</div>
</main>
<script src="/static/js/app.js?v=` + assetStamp + `"></script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(html))
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
