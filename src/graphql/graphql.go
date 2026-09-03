package graphql

import (
	"encoding/json"
	"net"
	"net/http"

	gql "github.com/graphql-go/graphql"

	i18n "github.com/apimgr/ipgaze/src/common/i18n"
	"github.com/apimgr/ipgaze/src/common/theme"
	"github.com/apimgr/ipgaze/src/server/model"
)

// Schema represents the GraphQL schema (populated by InitSchema in schema.go)
var Schema gql.Schema

// GraphQLHandlerConfig holds GraphQL handler configuration.
// The three lookup callbacks are optional; a nil callback makes the matching
// resolver return a GraphQL error instead of serving live data. Pass the
// *server.Server methods that already back the REST endpoints (see main.go)
// so GraphQL and REST share one implementation.
type GraphQLHandlerConfig struct {
	Version  string
	CommitID string
	// ClientIP extracts the caller's IP from an incoming HTTP request.
	ClientIP func(r *http.Request, allowOverride bool) (net.IP, error)
	// LookupIP resolves GeoIP/ASN/hostname/threat info for ip.
	LookupIP func(ip net.IP) (model.IPLookupResponse, error)
	// CheckPort attempts a live TCP connection check.
	CheckPort func(ip net.IP, port uint64) (bool, error)
	// Health returns the same model.HealthResponse the REST health endpoints
	// render, keeping the GraphQL health query functionally equivalent to REST.
	Health func() model.HealthResponse
}

// Handler serves the GraphQL endpoint and GraphiQL UI
func Handler(cfg GraphQLHandlerConfig) http.HandlerFunc {
	// Wire resolver dependencies from cfg — see Deps in resolvers.go.
	resolverDeps = Deps{
		ClientIP:  cfg.ClientIP,
		LookupIP:  cfg.LookupIP,
		CheckPort: cfg.CheckPort,
		Health:    cfg.Health,
	}

	// Initialize schema on first call
	if Schema.QueryType() == nil {
		if err := InitSchema(); err != nil {
			return func(w http.ResponseWriter, r *http.Request) {
				lang := i18n.DetectLocale(r)
				http.Error(w, i18n.T(i18n.WithLang(r.Context(), lang), "errors.server_error"), http.StatusInternalServerError)
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
			serveGraphiQL(w, r, cfg)
			return
		}

		lang := i18n.DetectLocale(r)
		http.Error(w, i18n.T(i18n.WithLang(r.Context(), lang), "errors.method_not_allowed"), http.StatusMethodNotAllowed)
	}
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
	enc.Encode(result)
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
	enc.Encode(map[string]interface{}{
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

	// Palette per AI.md PART 16 "Themes (NON-NEGOTIABLE)": the same
	// src/common/theme palette used by the web UI and Swagger UI, not a
	// GraphQL-specific color set.
	paletteName := theme.NameDark
	if themeName == "light" {
		paletteName = theme.NameLight
	}
	p := theme.Palette(paletteName)
	bg, fg, border, btnBg, btnHover, resBg, resFg := p.Background, p.Foreground, p.Border, p.Primary, p.Accent, p.SurfaceAlt, p.Foreground
	errColor := p.Error
	btnText := theme.ReadableTextOn(btnBg)

	html := `<!DOCTYPE html>
<html lang="` + lang + `" dir="` + dir + `">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>` + tr(lang, "graphql.ui.title") + `</title>
	<style>
		*{box-sizing:border-box;margin:0;padding:0}
		body{font-family:monospace;background:` + bg + `;color:` + fg + `;height:100vh;display:flex;flex-direction:column}
		h1{font-size:1rem;padding:.5rem 1rem;border-bottom:1px solid ` + border + `;background:` + resBg + `}
		#main{display:flex;flex:1;overflow:hidden}
		#left,#right{display:flex;flex-direction:column;flex:1;overflow:hidden;padding:.5rem}
		#left{border-right:1px solid ` + border + `}
		label{font-size:.75rem;margin-bottom:.25rem;display:block;opacity:.7}
		textarea{flex:1;resize:none;background:` + resBg + `;color:` + resFg + `;border:1px solid ` + border + `;border-radius:4px;padding:.5rem;font-family:monospace;font-size:.85rem;outline:none}
		#vars{height:5rem;margin-top:.5rem}
		button{margin-top:.5rem;padding:.4rem 1rem;background:` + btnBg + `;color:` + btnText + `;border:none;border-radius:4px;cursor:pointer;font-size:.85rem;font-family:monospace}
		button:hover{background:` + btnHover + `}
		#result{flex:1;overflow:auto;background:` + resBg + `;border:1px solid ` + border + `;border-radius:4px;padding:.5rem;font-size:.85rem;white-space:pre;margin-top:.5rem}
		.err{color:` + errColor + `}
	</style>
</head>
<body>
<h1>` + tr(lang, "graphql.ui.title") + ` &mdash; ` + cfg.Version + `</h1>
<div id="main">
	<div id="left">
		<label>` + tr(lang, "graphql.ui.query") + `</label>
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
		<label style="margin-top:.5rem">` + tr(lang, "graphql.ui.variables") + `</label>
		<textarea id="vars" spellcheck="false">{}</textarea>
		<button id="run">&#9654; ` + tr(lang, "graphql.ui.run") + `</button>
	</div>
	<div id="right">
		<label>` + tr(lang, "graphql.ui.response") + `</label>
		<div id="result">` + tr(lang, "graphql.ui.placeholder") + `</div>
	</div>
</div>
<script src="/static/js/app.js"></script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
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
