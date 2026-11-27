package swagger

import (
	"net/http"
	"strings"
)

// Route is the shared API route contract. Runtime registration attaches the
// handler to a copy; documentation and discovery consume the same metadata.
type Route struct {
	Method       string
	Path         string
	OperationID  string
	Summary      string
	Auth         string
	Listed       bool
	Internal     bool
	Request      any
	Response     any
	Primary      string
	Message      string
	Binary       string
	Handler      http.HandlerFunc
	GraphQLField string

	RuntimePath  string
	RuntimeAlias bool

	method       string
	path         string
	id           string
	internal     bool
	runtimePath  string
	runtimeAlias bool

	summaryKey    string
	descKey       string
	tagSlug       string
	params        []Parameter
	okSlug        string
	content       map[string]MediaType
	bodySlug      string
	bodySchema    *Schema
	bodyMediaType string
	bodyOptional  bool
	errs          []apiErr
	statusOK      string
	requiresAuth  bool
	listedSet     bool
}

// APIHandlers binds the implementation functions into the same Route values
// that carry OpenAPI, GraphQL, MCP, discovery, and serializer metadata.
type APIHandlers struct {
	Static, ThemeCSS, BrandingLogo, CLIBinary                                                                         http.HandlerFunc
	Robots, Sitemap, AtomFeed, RSSFeed, Favicon                                                                       http.HandlerFunc
	SecurityTxt, PGPKey, LLMsTxt, WellKnownLLMsTxt                                                                    http.HandlerFunc
	Manifest, ServiceWorker, Locales                                                                                  http.HandlerFunc
	Root, JSONRoot, IPRoot, IPTxtRoot, IPLookupRoot, PortRoot                                                         http.HandlerFunc
	CountryRoot, CountryTxtRoot, CountryISORoot, CountryISOTxtRoot                                                    http.HandlerFunc
	CityRoot, CityTxtRoot, CoordinatesRoot, CoordinatesTxtRoot                                                        http.HandlerFunc
	ASNRoot, ASNTxtRoot, ASNOrgRoot, ASNOrgTxtRoot                                                                    http.HandlerFunc
	Info, JSON, IP, IPLookup                                                                                          http.HandlerFunc
	Country, City, ASN, CountryISO, Coordinates, ASNOrg, PortCheck                                                    http.HandlerFunc
	Health, HealthText, Version                                                                                       http.HandlerFunc
	About, Help, HelpMCP, Privacy, DPO, Terms, Security, SecurityPolicy, SecurityThanks                               http.HandlerFunc
	ContactGet, ContactPost, AuthCheck                                                                                http.HandlerFunc
	Preferences, PreferencesUpdate, PreferencesSync, PreferencesSyncImport                                            http.HandlerFunc
	TokensList, TokensIssue, TokensPrimaryReveal, TokensPrimaryRotate, TokensPrimaryRevoke                            http.HandlerFunc
	TokensLinkedCreate, TokensLinkedReveal, TokensLinkedRotate, TokensLinkedUpdate, TokensLinkedRevoke                http.HandlerFunc
	Swagger, GraphQLGet, GraphQLPost, Consent, CCPA, Dismiss, MCP                                                     http.HandlerFunc
	Healthz, HealthzText, SwaggerAlias, GraphQLGetAlias, GraphQLPostAlias, Autodiscover                               http.HandlerFunc
	MCPAlias, MCPRootAlias                                                                                            http.HandlerFunc
	ReportCSP, ReportNEL, ReportDeprecation, ReportIntervention, ReportCrash, ReportDefault                           http.HandlerFunc
	ServerIndex, ServerAbout, ServerHelp, ServerHelpMCP, ServerPrivacy, ServerDPO                                     http.HandlerFunc
	ServerContactGet, ServerContactPost, ServerTrackingScript, ServerTerms, ServerSecurity                            http.HandlerFunc
	ServerSecurityPolicy, ServerSecurityThanks, ServerSecurityReport, ServerConsent, ServerCCPA                       http.HandlerFunc
	ServerPreferences, ServerPreferencesPost, ServerPreferencesTokens                                                 http.HandlerFunc
	ServerTokenCreate, ServerTokenRestore, ServerTokenReveal, ServerTokenRotate, ServerTokenForget, ServerTokenRevoke http.HandlerFunc
	ServerLinkedTokenCreate, ServerLinkedTokenReveal, ServerLinkedTokenRotate                                         http.HandlerFunc
	ServerLinkedTokenUpdate, ServerLinkedTokenRevoke                                                                  http.HandlerFunc
	ServerPreferencesSync, ServerPreferencesSyncPost, ServerPreferencesSyncImport                                     http.HandlerFunc
	ServerSwagger, ServerGraphQLGet, ServerGraphQLPost                                                                http.HandlerFunc
	ServerHealth, ServerHealthRoot                                                                                    http.HandlerFunc
}

// Registry stores routes in declaration order and rejects duplicate method/path
// pairs and operation IDs, preventing silent divergence between surfaces.
type Registry struct {
	routes []Route
	ids    map[string]struct{}
	pairs  map[string]struct{}
}

// Add registers one Route and derives its public metadata from the single value.
func (r *Registry) Add(route Route) {
	if r.ids == nil {
		r.ids = make(map[string]struct{})
		r.pairs = make(map[string]struct{})
	}
	method, path, id := route.method, route.path, route.id
	if method == "" {
		method = route.Method
	}
	if path == "" {
		path = route.Path
	}
	if id == "" {
		id = route.OperationID
	}
	if id == "" || path == "" || method == "" {
		panic("swagger route requires method, path, and operation ID")
	}
	key := strings.ToUpper(method) + " " + path
	operationID := camelCaseOperationID(id)
	if _, exists := r.ids[operationID]; exists {
		panic("duplicate swagger route operation ID: " + operationID)
	}
	if _, exists := r.pairs[key]; exists {
		panic("duplicate swagger route: " + key)
	}
	r.ids[operationID] = struct{}{}
	r.pairs[key] = struct{}{}
	route.Method = strings.ToUpper(method)
	route.Path = path
	route.OperationID = operationID
	route.RuntimePath = route.runtimePath
	route.RuntimeAlias = route.runtimeAlias
	if route.method == "" {
		route.method = strings.ToLower(method)
	}
	if route.path == "" {
		route.path = path
	}
	if route.id == "" {
		route.id = id
	}
	if route.Summary == "" {
		route.Summary = routeSummary(route)
	}
	if route.Auth == "" {
		route.Auth = routeAuth(route)
	}
	route.Internal = route.Internal || route.internal
	if route.Internal {
		route.Listed = false
	} else if !route.listedSet {
		route.Listed = route.id != "v1_auth_check" && route.Auth != "operator" && route.Auth != "service"
	}
	route.listedSet = true
	if route.Request == nil {
		if route.bodySchema != nil {
			route.Request = route.bodySchema
		}
	}
	if route.Response == nil {
		for _, media := range route.content {
			if media.Schema != nil {
				route.Response = media.Schema
				break
			}
		}
		if route.Response == nil {
			route.Response = map[string]any{}
		}
	}
	if route.Binary == "" && strings.Contains(route.Path, "/cli/binaries/") {
		route.Binary = "application/octet-stream"
	}
	if route.Message == "" {
		route.Message = defaultRouteMessage(route.Method)
	}
	r.routes = append(r.routes, route)
}

func camelCaseOperationID(id string) string {
	parts := strings.Split(id, "_")
	if len(parts) == 1 {
		return id
	}
	for i := 1; i < len(parts); i++ {
		if parts[i] == "" {
			continue
		}
		parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
	}
	return strings.Join(parts, "")
}

func defaultRouteMessage(method string) string {
	switch strings.ToUpper(method) {
	case "GET":
		return "Retrieved successfully"
	case "POST":
		return "Created successfully"
	case "PUT", "PATCH":
		return "Updated successfully"
	case "DELETE":
		return "Deleted successfully"
	default:
		return "OK"
	}
}

// Routes returns a copy so consumers cannot mutate registry state.
func (r *Registry) Routes() []Route {
	return append([]Route(nil), r.routes...)
}

// RouteForOperationID returns the canonical route value for a registered ID.
func RouteForOperationID(operationID string) (Route, bool) {
	for _, route := range routeRegistry("en") {
		if route.OperationID == operationID || route.id == operationID {
			return route, true
		}
	}
	return Route{}, false
}
