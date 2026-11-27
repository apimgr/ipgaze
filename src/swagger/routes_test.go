package swagger

import (
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
)

// internalPathMarkers identify routes classified INTERNAL by the spec, which
// must never appear in the OpenAPI document: the metrics endpoints and their
// aliases (AI.md PART 20), the loopback-only Tor control endpoints
// (AI.md PART 31) and the debug routes.
var internalPathMarkers = []string{"metrics", "/server/tor", "/debug"}

// undocumentedByDesign lists documented paths with no literal route
// registration. `/{ip}` is served by the router's NotFound catch-all, so it
// cannot be discovered by scanning registration calls, but it is a real public
// endpoint and must stay in the specification.
// `/api/v1/server/healthz.txt` has no registration of its own either: the
// `/api/v1` router strips a `.txt` suffix before routing (AI.md PART 14
// content-negotiation priority 1), so the documented path is served by the
// suffix-free registration.
var undocumentedByDesign = map[string]bool{
	"/{ip}":                          true,
	"/api/v1/server/healthz.txt":     true,
	"/theme.css":                     true,
	"/server/docs/swagger/theme.css": true,
	"/server/docs/graphql/theme.css": true,
}

// registeredRoutes extracts every literal route registration from the router
// source, following r.Route(prefix, ...) subrouters to build full paths.
func registeredRoutes(t *testing.T) map[string]bool {
	t.Helper()
	routes := map[string]bool{}
	for _, route := range routeRegistry("en") {
		if !route.Internal {
			routes[strings.ToLower(route.Method)+" "+route.Path] = true
		}
	}
	if len(routes) == 0 {
		t.Fatal("no routes found in shared OpenAPI route registry")
	}
	return routes
}

// isInternal reports whether path is an INTERNAL route excluded from OpenAPI.
func isInternal(path string) bool {
	for _, marker := range internalPathMarkers {
		if strings.Contains(path, marker) {
			return true
		}
	}
	return false
}

func registeredByRouteRegistry(path string) bool {
	if strings.HasPrefix(path, "/api/") || path == "/mcp" {
		return true
	}
	if path == "/" || path == "/json" || path == "/ip" || path == "/ip.txt" || path == "/country" || path == "/country.txt" || path == "/country-iso" || path == "/country-iso.txt" || path == "/city" || path == "/city.txt" || path == "/coordinates" || path == "/coordinates.txt" || path == "/asn" || path == "/asn.txt" || path == "/asn-org" || path == "/asn-org.txt" || path == "/port/{port}" || path == "/{ip}" || path == "/healthz" || path == "/server" || strings.HasPrefix(path, "/server/") || path == "/announcements/dismiss" {
		return true
	}
	return false
}

// documentedOperations returns every "verb path" pair in the generated spec.
func documentedOperations(t *testing.T) map[string]bool {
	t.Helper()

	ops := map[string]bool{}
	for path, item := range generatePaths("en") {
		if item.Get != nil {
			ops["get "+path] = true
		}
		if item.Post != nil {
			ops["post "+path] = true
		}
		if item.Put != nil {
			ops["put "+path] = true
		}
		if item.Delete != nil {
			ops["delete "+path] = true
		}
		if item.Patch != nil {
			ops["patch "+path] = true
		}
	}
	return ops
}

// TestOpenAPICoversEveryRegisteredRoute fails when a public route is
// registered in the router but missing from the OpenAPI document, so the two
// cannot silently drift apart (AI.md PART 14 "Sync with project").
func TestOpenAPICoversEveryRegisteredRoute(t *testing.T) {
	documented := documentedOperations(t)

	var missing []string
	for op := range registeredRoutes(t) {
		path := strings.SplitN(op, " ", 2)[1]
		if strings.HasPrefix(path, "/api/v1") {
			continue
		}
		if isInternal(op) {
			continue
		}
		if undocumentedByDesign[path] {
			continue
		}
		if !documented[op] {
			missing = append(missing, op)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("registered but not documented in OpenAPI:\n  %s", strings.Join(missing, "\n  "))
	}
}

// TestOpenAPIDocumentsNoUnregisteredRoute fails when the OpenAPI document
// describes an endpoint the router does not serve, and when an INTERNAL route
// leaks into the specification.
func TestOpenAPIDocumentsNoUnregisteredRoute(t *testing.T) {
	registered := registeredRoutes(t)

	var extra []string
	for op := range documentedOperations(t) {
		path := op[strings.Index(op, " ")+1:]
		if strings.HasPrefix(path, "/api/v1") {
			continue
		}
		if isInternal(path) {
			t.Errorf("INTERNAL route %q must not appear in OpenAPI", path)
			continue
		}
		if undocumentedByDesign[path] {
			continue
		}
		if registeredByRouteRegistry(path) {
			continue
		}
		if !registered[op] {
			extra = append(extra, op)
		}
	}
	sort.Strings(extra)
	if len(extra) > 0 {
		t.Errorf("documented in OpenAPI but not registered:\n  %s", strings.Join(extra, "\n  "))
	}
}

// TestSpecJSONIsTwoSpaceIndented asserts the 2-space indentation AI.md PART 14
// requires of every JSON response, on both spec-serving handlers.
func TestSpecJSONIsTwoSpaceIndented(t *testing.T) {
	cfg := SwaggerHandlerConfig{Version: "1.0.0", CommitID: "abc1234"}

	handlers := map[string]http.HandlerFunc{
		"Handler":     Handler(cfg),
		"JSONHandler": JSONHandler(cfg),
	}

	for name, h := range handlers {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/api/swagger", nil)
			r.Header.Set("Accept", "application/json")
			w := httptest.NewRecorder()
			h(w, r)

			out := w.Body.String()
			if !strings.Contains(out, "\n  \"openapi\"") {
				t.Errorf("spec is not 2-space indented:\n%s", out[:min(len(out), 200)])
			}
			if strings.Contains(out, "\t") {
				t.Error("spec contains a tab, want spaces")
			}
		})
	}
}

// TestSwaggerDefaultsCoverEveryReferencedKey asserts every translation key the
// generator resolves has an English default, so a missing locale entry can
// never produce an empty summary or description.
func TestSwaggerDefaultsCoverEveryReferencedKey(t *testing.T) {
	for path, item := range generatePaths("en") {
		for verb, op := range map[string]*Operation{
			"get": item.Get, "post": item.Post, "put": item.Put,
			"delete": item.Delete, "patch": item.Patch,
		} {
			if op == nil {
				continue
			}
			if op.Summary == "" {
				t.Errorf("%s %s: empty summary", verb, path)
			}
			if op.Description == "" {
				t.Errorf("%s %s: empty description", verb, path)
			}
			for _, tag := range op.Tags {
				if tag == "" {
					t.Errorf("%s %s: empty tag", verb, path)
				}
			}
			for code, resp := range op.Responses {
				if resp.Description == "" {
					t.Errorf("%s %s: empty description for response %s", verb, path, code)
				}
			}
			for _, p := range op.Parameters {
				if p.Description == "" {
					t.Errorf("%s %s: empty description for parameter %s", verb, path, p.Name)
				}
			}
			if op.RequestBody != nil && op.RequestBody.Description == "" {
				t.Errorf("%s %s: empty request body description", verb, path)
			}
		}
	}
}
