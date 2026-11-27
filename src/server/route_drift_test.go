package server

import (
	"bufio"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/apimgr/ipgaze/src/swagger"
	"github.com/go-chi/chi/v5"
)

var (
	markdownCellPath  = regexp.MustCompile("`(/[^`]*)`")
	markdownOperation = regexp.MustCompile("(?i)\\b(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)\\s+(?:\\{base\\})?(/[^`\\s|]+)")
)

func TestRouteInventoryMatchesRuntimeRouterAndOpenAPI(t *testing.T) {
	template, err := readRouteInventory("../../AI.md", false)
	if err != nil {
		t.Fatal(err)
	}
	project, err := readRouteInventory("../../IDEA.md", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(project) == 0 {
		t.Fatal("IDEA.md has no parseable `### API routes` inventory")
	}

	srv := testServer()
	srv.SwaggerHandler = http.NotFound
	srv.SwaggerJSONHandler = http.NotFound
	srv.GraphQLHandler = http.NotFound
	srv.Handler()
	routes := srv.RegisteredAPIRoutes()
	spec := swagger.GenerateSpec(swagger.SwaggerHandlerConfig{RegisteredRoutes: srv.RegisteredAPIRoutes}, "http://localhost", "en")
	actual := make(map[string]bool, len(routes))
	byKey := make(map[string]swagger.Route, len(routes))
	for _, route := range routes {
		key := routeKey(route.Method, route.Path)
		actual[key] = true
		byKey[key] = route
		if route.Internal || !route.Listed {
			if item, ok := spec.Paths[route.Path]; ok && routeOperation(item, route.Method) != nil {
				t.Errorf("internal or unlisted runtime route %s leaked into generated OpenAPI", key)
			}
			continue
		}
		item, ok := spec.Paths[route.Path]
		if !ok || routeOperation(item, route.Method) == nil {
			t.Errorf("runtime route %s is missing from generated OpenAPI", key)
		}
	}

	for _, inventory := range []struct {
		name   string
		routes map[string]bool
	}{{"AI.md template", template}, {"IDEA.md project", project}} {
		for key := range inventory.routes {
			route, mounted := byKey[key]
			if !mounted && optionalTemplateRoute(key) {
				continue
			}
			if !mounted {
				t.Errorf("%s inventory route %s is missing from the runtime router", inventory.name, key)
				continue
			}
			path := route.RuntimePath
			if path == "" {
				path = route.Path
			}
			path = strings.Replace(path, "*", "route-check", 1)
			for strings.Contains(path, "{") {
				start := strings.Index(path, "{")
				end := strings.Index(path[start:], "}")
				if end < 0 {
					break
				}
				path = path[:start] + "route-check" + path[start+end+1:]
			}
			if !srv.router.Match(chi.NewRouteContext(), route.Method, path) {
				t.Errorf("%s inventory route %s is missing from the mounted router", inventory.name, key)
			}
			if route.Internal || !route.Listed {
				if item, ok := spec.Paths[route.Path]; ok && routeOperation(item, route.Method) != nil {
					t.Errorf("%s inventory route %s is internal/unlisted but appears in OpenAPI", inventory.name, key)
				}
				continue
			}
			method, path, _ := strings.Cut(key, " ")
			item, ok := spec.Paths[path]
			if !ok || routeOperation(item, method) == nil {
				t.Errorf("%s inventory route %s is missing from generated OpenAPI", inventory.name, key)
			}
		}
	}
	var undocumented []string
	for key := range actual {
		if template[key] || project[key] {
			continue
		}
		undocumented = append(undocumented, key)
	}
	sort.Strings(undocumented)
	for _, key := range undocumented {
		t.Errorf("runtime route %s is missing from the AI.md/IDEA.md route inventory", key)
	}
}

func readRouteInventory(filename string, idea bool) (map[string]bool, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	routes := map[string]bool{}
	var header []string
	pathColumn, methodColumn := -1, -1
	fenced, inIdeaRoutes := false, !idea
	inlineRouteTable := false
	heading := ""
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "```") || strings.HasPrefix(line, "~~~") {
			fenced = !fenced
			continue
		}
		if fenced {
			continue
		}
		if idea && strings.HasPrefix(line, "### ") {
			inIdeaRoutes = line == "### API routes"
			continue
		}
		if !idea && strings.HasPrefix(line, "#") {
			heading = strings.ToLower(line)
		}
		if !inIdeaRoutes {
			continue
		}
		if !idea {
			if strings.Contains(line, "All browser-emitted reports — CSP, NEL, deprecation, intervention, crash, default") {
				for _, reportType := range []string{"csp", "nel", "deprecation", "intervention", "crash", "default"} {
					addInlineOperations(routes, "POST /api/{api_version}/server/reports/"+reportType)
				}
			}
			for _, operation := range []string{
				"POST /announcements/dismiss", "POST /server/ccpa", "POST /server/consent", "POST /server/contact",
			} {
				if strings.Contains(line, operation) {
					addInlineOperations(routes, operation)
				}
			}
			if strings.Contains(line, "queries server `/api/{api_version}/version`") {
				addInlineOperations(routes, "GET /api/{api_version}/version")
			}
		}
		if !strings.HasPrefix(line, "|") {
			header = nil
			pathColumn, methodColumn = -1, -1
			inlineRouteTable = false
			continue
		}
		cells := splitMarkdownRow(line)
		if len(cells) < 2 {
			continue
		}
		if isMarkdownSeparator(cells) {
			continue
		}
		if inlineRouteTable && !idea && !strings.Contains(heading, "example") && !strings.Contains(heading, "illustrat") {
			for _, cell := range cells {
				addInlineOperations(routes, cell)
			}
			continue
		}
		if header == nil {
			header = cells
			for _, cell := range cells {
				name := strings.ToLower(strings.TrimSpace(cell))
				if name == "web route" || name == "api mirror" {
					inlineRouteTable = true
				}
			}
			for i, cell := range cells {
				name := strings.ToLower(strings.TrimSpace(cell))
				if name == "path" || name == "endpoint" || name == "route" {
					pathColumn = i
				}
				if name == "method" || name == "methods" {
					methodColumn = i
				}
			}
			if !idea && methodColumn < 0 && routeMethodsForTemplateSection(heading) != nil {
				if pathColumn < 0 {
					pathColumn = 0
				}
				methodColumn = -2
				continue
			}
			if pathColumn < 0 || methodColumn < 0 {
				header = nil
				if inlineRouteTable {
					continue
				}
				if !idea && !strings.Contains(heading, "example") && !strings.Contains(heading, "illustrat") {
					addInventoryRow(routes, cells, 0, 1)
				}
			}
			continue
		}
		if methodColumn == -2 {
			addTemplateSectionRow(routes, cells, pathColumn, heading)
			continue
		}
		if pathColumn >= len(cells) || methodColumn >= len(cells) {
			continue
		}
		addInventoryRow(routes, cells, pathColumn, methodColumn)
	}
	return routes, scanner.Err()
}

func routeMethodsForTemplateSection(heading string) []string {
	heading = strings.ToLower(heading)
	switch {
	case strings.Contains(heading, "well-known support matrix"),
		strings.Contains(heading, "static files"),
		strings.Contains(heading, "feeds (/feed.xml"),
		strings.Contains(heading, "/server/ frontend routes"):
		return []string{"GET"}
	default:
		return nil
	}
}

func addTemplateSectionRow(routes map[string]bool, cells []string, pathColumn int, heading string) {
	if pathColumn >= len(cells) {
		return
	}
	paths := markdownCellPath.FindAllStringSubmatch(cells[pathColumn], -1)
	if len(paths) == 0 {
		path := strings.Trim(strings.TrimSpace(cells[pathColumn]), "`")
		if strings.HasPrefix(path, "/") {
			paths = append(paths, []string{path, path})
		}
	}
	for _, match := range paths {
		path := match[1]
		if strings.Contains(path, "*") || strings.Contains(path, "{token}") {
			continue
		}
		for _, expanded := range expandOptionalRoute(path) {
			routes[routeKey("GET", normalizeInventoryPath(expanded))] = true
		}
		if strings.Contains(strings.ToLower(heading), "well-known support matrix") && path == "/.well-known/llms.txt" {
			routes[routeKey("GET", "/llms.txt")] = true
		}
	}
}

func addInventoryRow(routes map[string]bool, cells []string, pathColumn, methodColumn int) {
	if pathColumn >= len(cells) || methodColumn >= len(cells) {
		return
	}
	paths := markdownCellPath.FindAllStringSubmatch(cells[pathColumn], -1)
	methods := parseMethodList(cells[methodColumn])
	for _, match := range paths {
		for _, method := range methods {
			for _, path := range expandOptionalRoute(match[1]) {
				path = normalizeInventoryPath(path)
				if strings.Contains(path, "{resource}") || strings.Contains(path, "{admin_path}") || strings.Contains(path, "{base}") {
					continue
				}
				routes[routeKey(method, path)] = true
			}
		}
	}
}

func addInlineOperations(routes map[string]bool, cell string) {
	for _, match := range markdownOperation.FindAllStringSubmatch(cell, -1) {
		path := normalizeInventoryPath(match[2])
		if strings.Contains(path, "{resource}") || strings.Contains(path, "{admin_path}") || strings.Contains(path, "{base}") {
			continue
		}
		routes[routeKey(match[1], path)] = true
	}
}

func normalizeInventoryPath(path string) string {
	path = strings.ReplaceAll(path, "{api_version}", "v1")
	path = strings.SplitN(path, "?", 2)[0]
	return path
}

func parseMethodList(cell string) []string {
	cell = strings.Trim(strings.TrimSpace(cell), "`")
	parts := strings.FieldsFunc(cell, func(r rune) bool { return r == '/' || r == ',' || r == ' ' || r == '\t' })
	if len(parts) == 0 {
		return nil
	}
	methods := make([]string, 0, len(parts))
	for _, part := range parts {
		method := strings.ToUpper(part)
		switch method {
		case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS":
			methods = append(methods, method)
		default:
			return nil
		}
	}
	return methods
}

func optionalTemplateRoute(key string) bool {
	_, path, _ := strings.Cut(key, " ")
	if strings.HasPrefix(path, "/debug/") || strings.Contains(path, "/metrics") || strings.HasPrefix(path, "/metrics/") {
		return true
	}
	return strings.HasPrefix(path, "/.well-known/") && path != "/.well-known/security.txt" && path != "/.well-known/llms.txt" && path != "/.well-known/pgp-key.asc"
}

func splitMarkdownRow(line string) []string {
	line = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "|"), "|"))
	return strings.Split(line, "|")
}

func isMarkdownSeparator(cells []string) bool {
	for _, cell := range cells {
		cell = strings.TrimSpace(cell)
		if cell == "" || strings.Trim(cell, ":- ") != "" {
			return false
		}
	}
	return true
}

func expandOptionalRoute(path string) []string {
	open := strings.Index(path, "[")
	if open < 0 {
		return []string{path}
	}
	close := strings.Index(path[open:], "]")
	if close < 0 {
		return []string{path}
	}
	close += open
	without := path[:open] + path[close+1:]
	with := path[:open] + path[open+1:close] + path[close+1:]
	return append(expandOptionalRoute(without), expandOptionalRoute(with)...)
}

func routeKey(method, path string) string {
	return strings.ToUpper(method) + " " + path
}
