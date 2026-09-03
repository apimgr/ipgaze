package swagger

import (
	i18n "github.com/apimgr/ipgaze/src/common/i18n"
)

// swaggerDefaults holds the English source text for every `swagger.*` translation
// key used by this package. It is the single source of truth for the English
// wording and the fallback used when a locale file does not define the key yet,
// so the generated OpenAPI document is always complete (AI.md PART 30 puts
// Swagger/OpenAPI summaries and descriptions in i18n scope).
var swaggerDefaults = map[string]string{
	"swagger.info.title":       "IPGaze API",
	"swagger.info.description": "IP address lookup service with GeoIP information, exposed over REST, GraphQL and a plain-text CLI-friendly interface.",
	"swagger.info.server":      "IPGaze API Server",
	"swagger.ui.title":         "IPGaze API - Swagger UI",

	"swagger.tags.ip_lookup":     "IP Lookup",
	"swagger.tags.geoip":         "GeoIP",
	"swagger.tags.port_check":    "Port Check",
	"swagger.tags.system":        "System",
	"swagger.tags.pages":         "Pages",
	"swagger.tags.api_v1":        "API v1",
	"swagger.tags.documentation": "Documentation",
	"swagger.tags.reports":       "Reports",
	"swagger.tags.assets":        "Assets",
	"swagger.tags.well_known":    "Well-Known",

	"swagger.responses.ok":                "Success",
	"swagger.responses.ip_info":           "IP address information",
	"swagger.responses.text_value":        "Plain text value",
	"swagger.responses.html_page":         "HTML page",
	"swagger.responses.health":            "Server health status",
	"swagger.responses.version":           "Build version information",
	"swagger.responses.port_check":        "Port reachability result",
	"swagger.responses.spec":              "OpenAPI 3.0 specification document",
	"swagger.responses.graphql":           "GraphQL execution result",
	"swagger.responses.asset":             "Static asset content",
	"swagger.responses.manifest":          "Web application manifest",
	"swagger.responses.script":            "JavaScript source",
	"swagger.responses.json_object":       "JSON object",
	"swagger.responses.redirect":          "Redirect to the target page",
	"swagger.responses.accepted":          "Report accepted",
	"swagger.responses.binary":            "Binary file stream",
	"swagger.responses.sitemap":           "XML sitemap document",
	"swagger.responses.invalid_ip":        "Invalid IP address",
	"swagger.responses.invalid_port":      "Invalid port number",
	"swagger.responses.not_found":         "Resource not found",
	"swagger.responses.bad_request":       "Malformed request",
	"swagger.responses.unavailable":       "Server is unhealthy, in maintenance mode, or shutting down",
	"swagger.responses.too_many_requests": "Rate limit exceeded",

	"swagger.params.ip_query":      "Optional IP address to look up; defaults to the caller's IP",
	"swagger.params.ip_path":       "IP address to look up (IPv4 or IPv6)",
	"swagger.params.port_path":     "Port number to check (1-65535)",
	"swagger.params.lang_path":     "BCP 47 locale code, for example en, fr or ja",
	"swagger.params.asset_path":    "Path of the asset below /static/",
	"swagger.params.filename_path": "Command-line client file name, for example ipgaze-linux-amd64",
	"swagger.params.theme_query":   "Theme to apply: dark, light or auto",
	"swagger.params.lang_query":    "Locale to apply, as a BCP 47 code",
	"swagger.params.code_query":    "Base64url-encoded preference code produced by the export endpoint",

	"swagger.bodies.graphql":     "GraphQL query, variables and operation name",
	"swagger.bodies.contact":     "Contact form submission",
	"swagger.bodies.consent":     "Cookie consent selection",
	"swagger.bodies.ccpa":        "CCPA opt-out selection",
	"swagger.bodies.preferences": "Theme and locale preference update",
	"swagger.bodies.report":      "Browser-generated report payload",
	"swagger.bodies.dismiss":     "Announcement identifier to dismiss",

	"swagger.common.txt_variant":  "Plain-text variant of the matching endpoint; the .txt suffix forces a text/plain response regardless of the Accept header.",
	"swagger.common.api_mirror":   "JSON mirror of the matching web page, per the web-route to API-route parity rule.",
	"swagger.common.report_intro": "Accepts a browser-generated report and records it in the server log.",

	"swagger.paths.root.summary":               "Get your IP address",
	"swagger.paths.root.description":           "Returns the caller's IP address. The response format is negotiated: JSON for Accept: application/json, HTML for browsers, and plain text for command-line clients.",
	"swagger.paths.json.summary":               "Get full IP info as JSON",
	"swagger.paths.json.description":           "Returns the complete IP record including GeoIP, ASN, reverse DNS and threat classification fields.",
	"swagger.paths.ip.summary":                 "Get your IP as plain text",
	"swagger.paths.ip.description":             "Returns only the caller's IP address, with no surrounding markup.",
	"swagger.paths.ip_txt.summary":             "Get your IP as plain text (.txt)",
	"swagger.paths.ip_lookup.summary":          "Look up a specific IP address",
	"swagger.paths.ip_lookup.description":      "Returns GeoIP, ASN and reverse DNS information for any IPv4 or IPv6 address supplied in the path. Served by the catch-all route, so any unmatched single path segment that parses as an IP address is treated as a lookup.",
	"swagger.paths.country.summary":            "Get country name",
	"swagger.paths.country.description":        "Returns the country name resolved for the caller's IP address.",
	"swagger.paths.country_txt.summary":        "Get country name (.txt)",
	"swagger.paths.country_iso.summary":        "Get country ISO code",
	"swagger.paths.country_iso.description":    "Returns the ISO 3166-1 alpha-2 country code resolved for the caller's IP address.",
	"swagger.paths.country_iso_txt.summary":    "Get country ISO code (.txt)",
	"swagger.paths.city.summary":               "Get city name",
	"swagger.paths.city.description":           "Returns the city name resolved for the caller's IP address.",
	"swagger.paths.city_txt.summary":           "Get city name (.txt)",
	"swagger.paths.coordinates.summary":        "Get coordinates",
	"swagger.paths.coordinates.description":    "Returns the latitude and longitude resolved for the caller's IP address as comma-separated decimal degrees.",
	"swagger.paths.coordinates_txt.summary":    "Get coordinates (.txt)",
	"swagger.paths.asn.summary":                "Get ASN",
	"swagger.paths.asn.description":            "Returns the Autonomous System Number announcing the caller's IP address.",
	"swagger.paths.asn_txt.summary":            "Get ASN (.txt)",
	"swagger.paths.asn_org.summary":            "Get ASN organization",
	"swagger.paths.asn_org.description":        "Returns the organization name that owns the Autonomous System announcing the caller's IP address.",
	"swagger.paths.asn_org_txt.summary":        "Get ASN organization (.txt)",
	"swagger.paths.port_check.summary":         "Check port reachability",
	"swagger.paths.port_check.description":     "Opens a TCP connection from the server back to the caller's IP address on the requested port and reports whether it succeeded.",
	"swagger.paths.healthz.summary":            "Health check",
	"swagger.paths.healthz.description":        "Returns the full server health record: overall status, project identity, build metadata, uptime, mode, enabled features, subsystem checks and request statistics. The format is negotiated: JSON, HTML for browsers, plain text otherwise.",
	"swagger.paths.healthz_root.summary":       "Health check (root alias)",
	"swagger.paths.healthz_root.description":   "Optional root-level alias for /server/healthz, registered only when the root health alias is enabled in server.yml.",
	"swagger.paths.api_healthz.summary":        "Health check (unversioned API alias)",
	"swagger.paths.api_healthz.description":    "Unversioned API alias for the health check. Always returns JSON, with no content negotiation.",
	"swagger.paths.api_healthz_txt.summary":    "Health check (unversioned API alias, .txt)",
	"swagger.paths.locales.summary":            "Get a translation catalog",
	"swagger.paths.locales.description":        "Returns the JSON translation catalog for the requested locale, used by the web interface to localize client-rendered text.",
	"swagger.paths.static.summary":             "Serve a static asset",
	"swagger.paths.static.description":         "Returns an embedded static asset: stylesheets, scripts, icons, fonts and the vendored Swagger UI files.",
	"swagger.paths.branding_logo.summary":      "Serve the site logo",
	"swagger.paths.branding_logo.description":  "Returns the configured site logo image, cached locally when the logo is configured as a remote URL.",
	"swagger.paths.robots_txt.summary":         "Robots exclusion rules",
	"swagger.paths.robots_txt.description":     "Returns the crawler policy for this server.",
	"swagger.paths.security_txt.summary":       "Security contact policy",
	"swagger.paths.security_txt.description":   "Returns the RFC 9116 security disclosure policy, including the security contact and PGP key location.",
	"swagger.paths.wk_security_txt.summary":    "Security contact policy (well-known)",
	"swagger.paths.wk_pgp_key.summary":         "PGP public key",
	"swagger.paths.wk_pgp_key.description":     "Returns the ASCII-armored PGP public key referenced by the security policy.",
	"swagger.paths.llms_txt.summary":           "Automated agent usage policy",
	"swagger.paths.llms_txt.description":       "Returns the llms.txt policy describing how automated language-model agents may use this service.",
	"swagger.paths.wk_llms_txt.summary":        "Automated agent usage policy (well-known)",
	"swagger.paths.manifest.summary":           "Web application manifest",
	"swagger.paths.manifest.description":       "Returns the progressive web application manifest with the application name, icons, theme colors and display mode.",
	"swagger.paths.service_worker.summary":     "Service worker script",
	"swagger.paths.service_worker.description": "Returns the progressive web application service worker, which caches assets and serves the offline page when the network is unreachable.",
	"swagger.paths.offline.summary":            "Offline fallback page",
	"swagger.paths.offline.description":        "Returns the page the service worker displays when a navigation cannot reach the network.",

	"swagger.paths.docs_swagger.summary":          "Swagger UI",
	"swagger.paths.docs_swagger.description":      "Serves the interactive Swagger user interface, or this OpenAPI document when JSON is requested through the Accept header.",
	"swagger.paths.api_swagger.summary":           "OpenAPI document",
	"swagger.paths.api_swagger.description":       "Returns this OpenAPI 3.0 document as JSON unconditionally, without content negotiation.",
	"swagger.paths.docs_graphql_get.summary":      "GraphQL explorer",
	"swagger.paths.docs_graphql_get.description":  "Serves the self-contained GraphQL explorer interface for composing and running queries.",
	"swagger.paths.docs_graphql_post.summary":     "Execute a GraphQL query",
	"swagger.paths.docs_graphql_post.description": "Executes a GraphQL query against the schema that mirrors the REST API. Queries exceeding the depth or alias limits are rejected with a GraphQL-shaped error body.",
	"swagger.paths.api_graphql_get.summary":       "GraphQL explorer (unversioned API alias)",
	"swagger.paths.api_graphql_post.summary":      "Execute a GraphQL query (unversioned API alias)",
	"swagger.paths.autodiscover.summary":          "Client autodiscovery",
	"swagger.paths.autodiscover.description":      "Returns the server identity, the published command-line client versions and the minimum client version this server accepts.",
	"swagger.paths.cli_binary.summary":            "Download a command-line client binary",
	"swagger.paths.cli_binary.description":        "Streams the command-line client binary for the requested operating system and architecture.",

	"swagger.paths.server_index.summary":                  "Server information index",
	"swagger.paths.server_index.description":              "Redirects to the server about page.",
	"swagger.paths.server_about.summary":                  "About this server",
	"swagger.paths.server_about.description":              "Returns the about page describing the service, its version and its operator.",
	"swagger.paths.server_help.summary":                   "Usage help",
	"swagger.paths.server_help.description":               "Returns the usage page documenting every endpoint with copy-and-paste examples.",
	"swagger.paths.server_privacy.summary":                "Privacy policy",
	"swagger.paths.server_privacy.description":            "Returns the privacy policy, including what is logged, for how long, and the available opt-outs.",
	"swagger.paths.server_contact.summary":                "Contact page",
	"swagger.paths.server_contact.description":            "Returns the contact form for reaching the server operator.",
	"swagger.paths.server_contact_post.summary":           "Submit the contact form",
	"swagger.paths.server_contact_post.description":       "Validates and delivers a contact message to the configured operator address.",
	"swagger.paths.server_terms.summary":                  "Terms of service",
	"swagger.paths.server_terms.description":              "Returns the terms governing use of this service.",
	"swagger.paths.server_consent.summary":                "Record cookie consent",
	"swagger.paths.server_consent.description":            "Stores the visitor's cookie consent choice in a browser cookie. Consent is per-browser and is never persisted server-side.",
	"swagger.paths.server_ccpa.summary":                   "Record a CCPA opt-out",
	"swagger.paths.server_ccpa.description":               "Stores the visitor's CCPA do-not-sell opt-out in a browser cookie.",
	"swagger.paths.server_preferences.summary":            "Preferences page",
	"swagger.paths.server_preferences.description":        "Returns the preferences page for choosing a theme and a locale.",
	"swagger.paths.server_preferences_post.summary":       "Update preferences",
	"swagger.paths.server_preferences_post.description":   "Validates the submitted theme and locale and stores them as browser cookies.",
	"swagger.paths.server_preferences_export.summary":     "Export preferences",
	"swagger.paths.server_preferences_export.description": "Returns the current theme and locale as both a full import URL and a short base64url code, so preferences can be carried to another browser.",
	"swagger.paths.server_preferences_import.summary":     "Import preferences",
	"swagger.paths.server_preferences_import.description": "Decodes and validates the supplied preference values, sets the matching cookies and redirects, so the code never lingers in the visible URL.",
	"swagger.paths.announcements_dismiss.summary":         "Dismiss an announcement",
	"swagger.paths.announcements_dismiss.description":     "Marks a site announcement as dismissed for this browser.",

	"swagger.paths.v1_info.summary":                   "Get full IP info (API v1)",
	"swagger.paths.v1_info.description":               "Returns the complete IP record as JSON, identical to /json.",
	"swagger.paths.v1_ip.summary":                     "Get your IP (API v1)",
	"swagger.paths.v1_ip.description":                 "Returns only the caller's IP address.",
	"swagger.paths.v1_ip_lookup.summary":              "Look up a specific IP (API v1)",
	"swagger.paths.v1_ip_lookup.description":          "Returns GeoIP, ASN and reverse DNS information for any IPv4 or IPv6 address.",
	"swagger.paths.v1_country.summary":                "Get country (API v1)",
	"swagger.paths.v1_country.description":            "Returns the country name resolved for the caller's IP address.",
	"swagger.paths.v1_city.summary":                   "Get city (API v1)",
	"swagger.paths.v1_city.description":               "Returns the city name resolved for the caller's IP address.",
	"swagger.paths.v1_asn.summary":                    "Get ASN (API v1)",
	"swagger.paths.v1_asn.description":                "Returns the Autonomous System Number announcing the caller's IP address.",
	"swagger.paths.v1_healthz.summary":                "Health check (API v1)",
	"swagger.paths.v1_healthz.description":            "Returns the full server health record as JSON. Always JSON, with no content negotiation.",
	"swagger.paths.v1_healthz_txt.summary":            "Health check (API v1, .txt)",
	"swagger.paths.v1_version.summary":                "Get build version",
	"swagger.paths.v1_version.description":            "Returns the running version, the source commit and the build date.",
	"swagger.paths.v1_about.summary":                  "About this server (API v1)",
	"swagger.paths.v1_help.summary":                   "Usage help (API v1)",
	"swagger.paths.v1_privacy.summary":                "Privacy policy (API v1)",
	"swagger.paths.v1_terms.summary":                  "Terms of service (API v1)",
	"swagger.paths.v1_contact.summary":                "Submit the contact form (API v1)",
	"swagger.paths.v1_contact.description":            "Validates and delivers a contact message, returning the result as JSON.",
	"swagger.paths.v1_preferences.summary":            "Get preferences (API v1)",
	"swagger.paths.v1_preferences.description":        "Returns the theme and locale currently stored in the caller's cookies.",
	"swagger.paths.v1_preferences_export.summary":     "Export preferences (API v1)",
	"swagger.paths.v1_preferences_export.description": "Returns the current theme and locale as a full import URL and a short base64url code.",
	"swagger.paths.v1_preferences_import.summary":     "Import preferences (API v1)",
	"swagger.paths.v1_preferences_import.description": "Decodes and validates the supplied preference values and sets the matching cookies.",
	"swagger.paths.v1_swagger.summary":                "OpenAPI document (API v1)",
	"swagger.paths.v1_swagger.description":            "Returns this OpenAPI 3.0 document as JSON from the versioned API path.",
	"swagger.paths.v1_graphql_get.summary":            "GraphQL explorer (API v1)",
	"swagger.paths.v1_graphql_post.summary":           "Execute a GraphQL query (API v1)",
	"swagger.paths.v1_json.summary":                   "Get full IP info as JSON (API v1)",
	"swagger.paths.v1_json.description":               "Returns the complete IP record as JSON, the API mirror of /json.",
	"swagger.paths.v1_country_iso.summary":            "Get country ISO code (API v1)",
	"swagger.paths.v1_country_iso.description":        "Returns the ISO 3166-1 alpha-2 country code resolved for the caller's IP address.",
	"swagger.paths.v1_coordinates.summary":            "Get coordinates (API v1)",
	"swagger.paths.v1_coordinates.description":        "Returns the latitude and longitude resolved for the caller's IP address as comma-separated decimal degrees.",
	"swagger.paths.v1_asn_org.summary":                "Get ASN organization (API v1)",
	"swagger.paths.v1_asn_org.description":            "Returns the organization name that owns the Autonomous System announcing the caller's IP address.",
	"swagger.paths.v1_port_check.summary":             "Check port reachability (API v1)",
	"swagger.paths.v1_port_check.description":         "Opens a TCP connection from the server back to the caller's IP address on the requested port and reports whether it succeeded.",
	"swagger.paths.v1_consent.summary":                "Record cookie consent (API v1)",
	"swagger.paths.v1_consent.description":            "Stores the visitor's cookie consent choice in a browser cookie and answers 204 with no body.",
	"swagger.paths.v1_ccpa.summary":                   "Record a CCPA opt-out (API v1)",
	"swagger.paths.v1_ccpa.description":               "Stores the visitor's CCPA do-not-sell opt-out in a browser cookie and answers 204 with no body.",
	"swagger.paths.v1_dismiss.summary":                "Dismiss an announcement (API v1)",
	"swagger.paths.v1_dismiss.description":            "Marks a site announcement as dismissed for this browser and answers 204 with no body.",
	"swagger.paths.sitemap.summary":                   "Sitemap",
	"swagger.paths.sitemap.description":               "Returns the search-engine sitemap listing every public page of this server.",

	"swagger.paths.report_csp.summary":          "Content Security Policy report",
	"swagger.paths.report_nel.summary":          "Network Error Logging report",
	"swagger.paths.report_deprecation.summary":  "Deprecation report",
	"swagger.paths.report_intervention.summary": "Intervention report",
	"swagger.paths.report_crash.summary":        "Crash report",
	"swagger.paths.report_error.summary":        "Error report",
	"swagger.paths.report_default.summary":      "Default reporting endpoint",
}

// tr returns the localized string for key, falling back to the English default
// declared in swaggerDefaults when the locale files do not define it yet.
// i18n.Translate echoes the key back when it is missing, which is the signal
// used here to fall through to the default.
func tr(lang, key string) string {
	if v := i18n.Translate(lang, key); v != "" && v != key {
		return v
	}
	return swaggerDefaults[key]
}

// apiErr declares a non-2xx response documented for an operation. slug selects
// the swagger.responses.<slug> description key.
type apiErr struct {
	code string
	slug string
}

// routeDoc describes one documented HTTP operation. path and method mirror a
// route registered in src/server/http.go; id selects the swagger.paths.<id>.*
// summary and description keys. descKey overrides the derived description key
// so operations that share wording (the .txt variants, the API mirrors) do not
// duplicate translation strings.
type routeDoc struct {
	path       string
	method     string
	id         string
	descKey    string
	tagSlug    string
	params     []Parameter
	okSlug     string
	content    map[string]MediaType
	bodySlug   string
	bodySchema *Schema
	errs       []apiErr
	statusOK   string
}

// param builds a documented parameter whose description comes from the
// swagger.params.<slug> key.
func param(lang, name, in, slug string, required bool, schema *Schema) Parameter {
	return Parameter{
		Name:        name,
		In:          in,
		Description: tr(lang, "swagger.params."+slug),
		Required:    required,
		Schema:      schema,
	}
}

// jsonRef returns response content referencing a named component schema.
func jsonRef(name string) map[string]MediaType {
	return map[string]MediaType{
		"application/json": {Schema: &Schema{Ref: "#/components/schemas/" + name}},
	}
}

// jsonObject returns response content for a free-form JSON object body.
func jsonObject() map[string]MediaType {
	return map[string]MediaType{
		"application/json": {Schema: &Schema{Type: "object"}},
	}
}

// textPlain returns response content for a plain text body.
func textPlain(example string) map[string]MediaType {
	return map[string]MediaType{
		"text/plain": {Schema: &Schema{Type: "string", Example: example}},
	}
}

// htmlPage returns response content for an HTML page body.
func htmlPage() map[string]MediaType {
	return map[string]MediaType{
		"text/html": {Schema: &Schema{Type: "string"}},
	}
}

// negotiatedHealth returns the content map for the content-negotiating health
// endpoints, which answer with JSON, HTML or plain text depending on Accept.
func negotiatedHealth() map[string]MediaType {
	return map[string]MediaType{
		"application/json": {Schema: &Schema{Ref: "#/components/schemas/HealthResponse"}},
		"text/plain":       {Schema: &Schema{Type: "string", Example: "healthy"}},
		"text/html":        {Schema: &Schema{Type: "string"}},
	}
}

// negotiatedIP returns the content map for the root endpoint, which answers
// with JSON, HTML or plain text depending on the client and Accept header.
func negotiatedIP() map[string]MediaType {
	return map[string]MediaType{
		"application/json": {Schema: &Schema{Ref: "#/components/schemas/IPResponse"}},
		"text/plain":       {Schema: &Schema{Type: "string", Example: "203.0.113.42"}},
		"text/html":        {Schema: &Schema{Type: "string"}},
	}
}

// binaryStream returns response content for an opaque binary body.
func binaryStream() map[string]MediaType {
	return map[string]MediaType{
		"application/octet-stream": {Schema: &Schema{Type: "string"}},
	}
}

// assetContent returns response content for an embedded static asset, whose
// media type varies with the requested file.
func assetContent() map[string]MediaType {
	return map[string]MediaType{
		"*/*": {Schema: &Schema{Type: "string"}},
	}
}

// xmlDocument returns response content for an XML body.
func xmlDocument() map[string]MediaType {
	return map[string]MediaType{
		"application/xml": {Schema: &Schema{Type: "string"}},
	}
}

// scriptContent returns response content for a JavaScript body.
func scriptContent() map[string]MediaType {
	return map[string]MediaType{
		"text/javascript": {Schema: &Schema{Type: "string"}},
	}
}

// stringSchema is the shared schema for string parameters.
func stringSchema() *Schema { return &Schema{Type: "string"} }

// intSchema is the shared schema for integer parameters.
func intSchema() *Schema { return &Schema{Type: "integer"} }

// txtVariantKey is the shared description key used by every `.txt` alias route.
const txtVariantKey = "swagger.common.txt_variant"

// apiMirrorKey is the shared description key used by the `/api/v1` JSON mirrors
// of the public web pages.
const apiMirrorKey = "swagger.common.api_mirror"

// reportIntroKey is the shared description key used by the browser reporting
// endpoints, which differ only in the report type they accept.
const reportIntroKey = "swagger.common.report_intro"

// routeDocs returns the documentation table for every PUBLIC route registered
// in src/server/http.go. INTERNAL routes are deliberately absent: the metrics
// endpoints and their aliases (AI.md PART 20), the loopback-only Tor control
// endpoints (AI.md PART 31) and the debug routes must never appear in OpenAPI.
func routeDocs(lang string) []routeDoc {
	ipQuery := []Parameter{param(lang, "ip", "query", "ip_query", false, stringSchema())}
	ipPath := []Parameter{param(lang, "ip", "path", "ip_path", true, stringSchema())}
	prefsQuery := []Parameter{
		param(lang, "theme", "query", "theme_query", false, stringSchema()),
		param(lang, "lang", "query", "lang_query", false, stringSchema()),
		param(lang, "code", "query", "code_query", false, stringSchema()),
	}

	docs := []routeDoc{
		{path: "/", method: "get", id: "root", tagSlug: "ip_lookup", okSlug: "ip_info", content: negotiatedIP()},
		{path: "/json", method: "get", id: "json", tagSlug: "ip_lookup", params: ipQuery, okSlug: "ip_info", content: jsonRef("IPResponse")},
		{path: "/ip", method: "get", id: "ip", tagSlug: "ip_lookup", okSlug: "text_value", content: textPlain("203.0.113.42")},
		{path: "/ip.txt", method: "get", id: "ip_txt", descKey: txtVariantKey, tagSlug: "ip_lookup", okSlug: "text_value", content: textPlain("203.0.113.42")},
		{path: "/{ip}", method: "get", id: "ip_lookup", tagSlug: "ip_lookup", params: ipPath, okSlug: "ip_info", content: jsonRef("IPResponse"), errs: []apiErr{{"400", "invalid_ip"}, {"404", "not_found"}}},
		{path: "/country", method: "get", id: "country", tagSlug: "geoip", okSlug: "text_value", content: textPlain("United States")},
		{path: "/country.txt", method: "get", id: "country_txt", descKey: txtVariantKey, tagSlug: "geoip", okSlug: "text_value", content: textPlain("United States")},
		{path: "/country-iso", method: "get", id: "country_iso", tagSlug: "geoip", okSlug: "text_value", content: textPlain("US")},
		{path: "/country-iso.txt", method: "get", id: "country_iso_txt", descKey: txtVariantKey, tagSlug: "geoip", okSlug: "text_value", content: textPlain("US")},
		{path: "/city", method: "get", id: "city", tagSlug: "geoip", okSlug: "text_value", content: textPlain("Mountain View")},
		{path: "/city.txt", method: "get", id: "city_txt", descKey: txtVariantKey, tagSlug: "geoip", okSlug: "text_value", content: textPlain("Mountain View")},
		{path: "/coordinates", method: "get", id: "coordinates", tagSlug: "geoip", okSlug: "text_value", content: textPlain("37.422300,-122.084000")},
		{path: "/coordinates.txt", method: "get", id: "coordinates_txt", descKey: txtVariantKey, tagSlug: "geoip", okSlug: "text_value", content: textPlain("37.422300,-122.084000")},
		{path: "/asn", method: "get", id: "asn", tagSlug: "geoip", okSlug: "text_value", content: textPlain("AS15169")},
		{path: "/asn.txt", method: "get", id: "asn_txt", descKey: txtVariantKey, tagSlug: "geoip", okSlug: "text_value", content: textPlain("AS15169")},
		{path: "/asn-org", method: "get", id: "asn_org", tagSlug: "geoip", okSlug: "text_value", content: textPlain("Google LLC")},
		{path: "/asn-org.txt", method: "get", id: "asn_org_txt", descKey: txtVariantKey, tagSlug: "geoip", okSlug: "text_value", content: textPlain("Google LLC")},
		{path: "/port/{port}", method: "get", id: "port_check", tagSlug: "port_check", params: []Parameter{param(lang, "port", "path", "port_path", true, intSchema())}, okSlug: "port_check", content: jsonRef("PortResponse"), errs: []apiErr{{"400", "invalid_port"}}},

		{path: "/server/healthz", method: "get", id: "healthz", tagSlug: "system", okSlug: "health", content: negotiatedHealth(), errs: []apiErr{{"503", "unavailable"}}},
		{path: "/healthz", method: "get", id: "healthz_root", tagSlug: "system", okSlug: "health", content: negotiatedHealth(), errs: []apiErr{{"503", "unavailable"}}},
		{path: "/api/healthz", method: "get", id: "api_healthz", tagSlug: "system", okSlug: "health", content: jsonRef("HealthResponse"), errs: []apiErr{{"503", "unavailable"}}},
		{path: "/api/healthz.txt", method: "get", id: "api_healthz_txt", descKey: txtVariantKey, tagSlug: "system", okSlug: "health", content: textPlain("healthy"), errs: []apiErr{{"503", "unavailable"}}},

		{path: "/locales/{lang}.json", method: "get", id: "locales", tagSlug: "system", params: []Parameter{param(lang, "lang", "path", "lang_path", true, stringSchema())}, okSlug: "json_object", content: jsonObject(), errs: []apiErr{{"404", "not_found"}}},
		{path: "/static/{path}", method: "get", id: "static", tagSlug: "assets", params: []Parameter{param(lang, "path", "path", "asset_path", true, stringSchema())}, okSlug: "asset", content: assetContent(), errs: []apiErr{{"404", "not_found"}}},
		{path: "/branding/logo", method: "get", id: "branding_logo", tagSlug: "assets", okSlug: "asset", content: assetContent()},
		{path: "/cli/binaries/{filename}", method: "get", id: "cli_binary", tagSlug: "assets", params: []Parameter{param(lang, "filename", "path", "filename_path", true, stringSchema())}, okSlug: "binary", content: binaryStream(), errs: []apiErr{{"404", "not_found"}}},

		{path: "/robots.txt", method: "get", id: "robots_txt", tagSlug: "well_known", okSlug: "text_value", content: textPlain("User-agent: *")},
		{path: "/sitemap.xml", method: "get", id: "sitemap", tagSlug: "well_known", okSlug: "sitemap", content: xmlDocument()},
		{path: "/security.txt", method: "get", id: "security_txt", tagSlug: "well_known", okSlug: "text_value", content: textPlain("Contact: mailto:security@example.com")},
		{path: "/.well-known/security.txt", method: "get", id: "wk_security_txt", descKey: "swagger.paths.security_txt.description", tagSlug: "well_known", okSlug: "text_value", content: textPlain("Contact: mailto:security@example.com")},
		{path: "/.well-known/pgp-key.asc", method: "get", id: "wk_pgp_key", tagSlug: "well_known", okSlug: "text_value", content: textPlain("-----BEGIN PGP PUBLIC KEY BLOCK-----")},
		{path: "/llms.txt", method: "get", id: "llms_txt", tagSlug: "well_known", okSlug: "text_value", content: textPlain("# IPGaze")},
		{path: "/.well-known/llms.txt", method: "get", id: "wk_llms_txt", descKey: "swagger.paths.llms_txt.description", tagSlug: "well_known", okSlug: "text_value", content: textPlain("# IPGaze")},
		{path: "/manifest.json", method: "get", id: "manifest", tagSlug: "well_known", okSlug: "manifest", content: jsonObject()},
		{path: "/sw.js", method: "get", id: "service_worker", tagSlug: "well_known", okSlug: "script", content: scriptContent()},
		{path: "/offline.html", method: "get", id: "offline", tagSlug: "well_known", okSlug: "html_page", content: htmlPage()},

		{path: "/server/docs/swagger", method: "get", id: "docs_swagger", tagSlug: "documentation", okSlug: "html_page", content: htmlPage()},
		{path: "/api/swagger", method: "get", id: "api_swagger", tagSlug: "documentation", okSlug: "spec", content: jsonObject()},
		{path: "/server/docs/graphql", method: "get", id: "docs_graphql_get", tagSlug: "documentation", okSlug: "html_page", content: htmlPage()},
		{path: "/server/docs/graphql", method: "post", id: "docs_graphql_post", tagSlug: "documentation", okSlug: "graphql", content: jsonRef("GraphQLResponse"), bodySlug: "graphql", bodySchema: &Schema{Ref: "#/components/schemas/GraphQLRequest"}, errs: []apiErr{{"400", "bad_request"}}},
		{path: "/api/graphql", method: "get", id: "api_graphql_get", descKey: "swagger.paths.docs_graphql_get.description", tagSlug: "documentation", okSlug: "html_page", content: htmlPage()},
		{path: "/api/graphql", method: "post", id: "api_graphql_post", descKey: "swagger.paths.docs_graphql_post.description", tagSlug: "documentation", okSlug: "graphql", content: jsonRef("GraphQLResponse"), bodySlug: "graphql", bodySchema: &Schema{Ref: "#/components/schemas/GraphQLRequest"}, errs: []apiErr{{"400", "bad_request"}}},
		{path: "/api/autodiscover", method: "get", id: "autodiscover", tagSlug: "system", okSlug: "json_object", content: jsonObject()},

		{path: "/server", method: "get", id: "server_index", tagSlug: "pages", okSlug: "redirect", content: htmlPage(), statusOK: "302"},
		{path: "/server/about", method: "get", id: "server_about", tagSlug: "pages", okSlug: "html_page", content: htmlPage()},
		{path: "/server/help", method: "get", id: "server_help", tagSlug: "pages", okSlug: "html_page", content: htmlPage()},
		{path: "/server/privacy", method: "get", id: "server_privacy", tagSlug: "pages", okSlug: "html_page", content: htmlPage()},
		{path: "/server/contact", method: "get", id: "server_contact", tagSlug: "pages", okSlug: "html_page", content: htmlPage()},
		{path: "/server/contact", method: "post", id: "server_contact_post", tagSlug: "pages", okSlug: "html_page", content: htmlPage(), bodySlug: "contact", bodySchema: &Schema{Ref: "#/components/schemas/ContactRequest"}, errs: []apiErr{{"400", "bad_request"}, {"429", "too_many_requests"}}},
		{path: "/server/terms", method: "get", id: "server_terms", tagSlug: "pages", okSlug: "html_page", content: htmlPage()},
		{path: "/server/consent", method: "post", id: "server_consent", tagSlug: "pages", okSlug: "redirect", content: htmlPage(), statusOK: "303", bodySlug: "consent", bodySchema: &Schema{Type: "object"}},
		{path: "/server/ccpa", method: "post", id: "server_ccpa", tagSlug: "pages", okSlug: "redirect", content: htmlPage(), statusOK: "303", bodySlug: "ccpa", bodySchema: &Schema{Type: "object"}},
		{path: "/server/preferences", method: "get", id: "server_preferences", tagSlug: "pages", okSlug: "html_page", content: htmlPage()},
		{path: "/server/preferences", method: "post", id: "server_preferences_post", tagSlug: "pages", okSlug: "redirect", content: htmlPage(), statusOK: "303", bodySlug: "preferences", bodySchema: &Schema{Ref: "#/components/schemas/PreferencesRequest"}, errs: []apiErr{{"400", "bad_request"}}},
		{path: "/server/preferences/export", method: "get", id: "server_preferences_export", tagSlug: "pages", okSlug: "html_page", content: htmlPage()},
		{path: "/server/preferences/import", method: "get", id: "server_preferences_import", tagSlug: "pages", params: prefsQuery, okSlug: "redirect", content: htmlPage(), statusOK: "303", errs: []apiErr{{"400", "bad_request"}}},
		{path: "/announcements/dismiss", method: "post", id: "announcements_dismiss", tagSlug: "pages", okSlug: "redirect", content: htmlPage(), statusOK: "303", bodySlug: "dismiss", bodySchema: &Schema{Type: "object"}},

		{path: "/api/v1", method: "get", id: "v1_info", tagSlug: "api_v1", params: ipQuery, okSlug: "ip_info", content: jsonRef("IPResponse")},
		{path: "/api/v1/ip", method: "get", id: "v1_ip", tagSlug: "api_v1", okSlug: "text_value", content: textPlain("203.0.113.42")},
		{path: "/api/v1/ip/{ip}", method: "get", id: "v1_ip_lookup", tagSlug: "api_v1", params: ipPath, okSlug: "ip_info", content: jsonRef("IPResponse"), errs: []apiErr{{"400", "invalid_ip"}}},
		{path: "/api/v1/country", method: "get", id: "v1_country", tagSlug: "api_v1", okSlug: "text_value", content: textPlain("United States")},
		{path: "/api/v1/city", method: "get", id: "v1_city", tagSlug: "api_v1", okSlug: "text_value", content: textPlain("Mountain View")},
		{path: "/api/v1/asn", method: "get", id: "v1_asn", tagSlug: "api_v1", okSlug: "text_value", content: textPlain("AS15169")},
		{path: "/api/v1/server/healthz", method: "get", id: "v1_healthz", tagSlug: "api_v1", okSlug: "health", content: jsonRef("HealthResponse"), errs: []apiErr{{"503", "unavailable"}}},
		{path: "/api/v1/server/healthz.txt", method: "get", id: "v1_healthz_txt", descKey: txtVariantKey, tagSlug: "api_v1", okSlug: "health", content: textPlain("healthy"), errs: []apiErr{{"503", "unavailable"}}},
		{path: "/api/v1/version", method: "get", id: "v1_version", tagSlug: "api_v1", okSlug: "version", content: jsonRef("VersionResponse")},
		{path: "/api/v1/server/about", method: "get", id: "v1_about", descKey: apiMirrorKey, tagSlug: "api_v1", okSlug: "json_object", content: jsonObject()},
		{path: "/api/v1/server/help", method: "get", id: "v1_help", descKey: apiMirrorKey, tagSlug: "api_v1", okSlug: "json_object", content: jsonObject()},
		{path: "/api/v1/server/privacy", method: "get", id: "v1_privacy", descKey: apiMirrorKey, tagSlug: "api_v1", okSlug: "json_object", content: jsonObject()},
		{path: "/api/v1/server/terms", method: "get", id: "v1_terms", descKey: apiMirrorKey, tagSlug: "api_v1", okSlug: "json_object", content: jsonObject()},
		{path: "/api/v1/server/contact", method: "post", id: "v1_contact", tagSlug: "api_v1", okSlug: "json_object", content: jsonObject(), bodySlug: "contact", bodySchema: &Schema{Ref: "#/components/schemas/ContactRequest"}, errs: []apiErr{{"400", "bad_request"}, {"429", "too_many_requests"}}},
		{path: "/api/v1/server/preferences", method: "get", id: "v1_preferences", tagSlug: "api_v1", okSlug: "json_object", content: jsonRef("PreferencesResponse")},
		{path: "/api/v1/server/preferences/export", method: "get", id: "v1_preferences_export", tagSlug: "api_v1", okSlug: "json_object", content: jsonRef("PreferencesExportResponse")},
		{path: "/api/v1/server/preferences/import", method: "get", id: "v1_preferences_import", tagSlug: "api_v1", params: prefsQuery, okSlug: "json_object", content: jsonRef("PreferencesResponse"), errs: []apiErr{{"400", "bad_request"}}},
		{path: "/api/v1/server/swagger", method: "get", id: "v1_swagger", tagSlug: "api_v1", okSlug: "spec", content: jsonObject()},
		{path: "/api/v1/server/graphql", method: "get", id: "v1_graphql_get", descKey: "swagger.paths.docs_graphql_get.description", tagSlug: "api_v1", okSlug: "html_page", content: htmlPage()},
		{path: "/api/v1/json", method: "get", id: "v1_json", tagSlug: "api_v1", params: ipQuery, okSlug: "ip_info", content: jsonRef("IPResponse")},
		{path: "/api/v1/country-iso", method: "get", id: "v1_country_iso", tagSlug: "api_v1", okSlug: "json_object", content: jsonObject()},
		{path: "/api/v1/coordinates", method: "get", id: "v1_coordinates", tagSlug: "api_v1", okSlug: "json_object", content: jsonObject()},
		{path: "/api/v1/asn-org", method: "get", id: "v1_asn_org", tagSlug: "api_v1", okSlug: "json_object", content: jsonObject()},
		{path: "/api/v1/port/{port}", method: "get", id: "v1_port_check", tagSlug: "api_v1", params: []Parameter{param(lang, "port", "path", "port_path", true, intSchema())}, okSlug: "port_check", content: jsonRef("PortResponse"), errs: []apiErr{{"400", "invalid_port"}}},
		{path: "/api/v1/server/consent", method: "post", id: "v1_consent", tagSlug: "api_v1", okSlug: "accepted", statusOK: "204", bodySlug: "consent", bodySchema: &Schema{Type: "object"}},
		{path: "/api/v1/server/ccpa", method: "post", id: "v1_ccpa", tagSlug: "api_v1", okSlug: "accepted", statusOK: "204", bodySlug: "ccpa", bodySchema: &Schema{Type: "object"}},
		{path: "/api/v1/announcements/dismiss", method: "post", id: "v1_dismiss", tagSlug: "api_v1", okSlug: "accepted", statusOK: "204", bodySlug: "dismiss", bodySchema: &Schema{Type: "object"}},
		{path: "/api/v1/server/graphql", method: "post", id: "v1_graphql_post", descKey: "swagger.paths.docs_graphql_post.description", tagSlug: "api_v1", okSlug: "graphql", content: jsonRef("GraphQLResponse"), bodySlug: "graphql", bodySchema: &Schema{Ref: "#/components/schemas/GraphQLRequest"}, errs: []apiErr{{"400", "bad_request"}}},
	}

	// Browser reporting endpoints — identical shape, one per report type.
	reports := []struct {
		suffix string
		id     string
	}{
		{"csp", "report_csp"},
		{"nel", "report_nel"},
		{"deprecation", "report_deprecation"},
		{"intervention", "report_intervention"},
		{"crash", "report_crash"},
		{"error", "report_error"},
		{"default", "report_default"},
	}
	for _, rep := range reports {
		docs = append(docs, routeDoc{
			path:       "/api/v1/server/reports/" + rep.suffix,
			method:     "post",
			id:         rep.id,
			descKey:    reportIntroKey,
			tagSlug:    "reports",
			okSlug:     "accepted",
			statusOK:   "204",
			bodySlug:   "report",
			bodySchema: &Schema{Type: "object"},
		})
	}

	return docs
}

// buildOperation renders one routeDoc into an OpenAPI Operation with every
// human-readable string resolved for lang.
func buildOperation(lang string, d routeDoc) *Operation {
	descKey := d.descKey
	if descKey == "" {
		descKey = "swagger.paths." + d.id + ".description"
	}

	okStatus := d.statusOK
	if okStatus == "" {
		okStatus = "200"
	}

	responses := map[string]APIResponse{
		okStatus: {
			Description: tr(lang, "swagger.responses."+d.okSlug),
			Content:     d.content,
		},
	}
	for _, e := range d.errs {
		responses[e.code] = APIResponse{
			Description: tr(lang, "swagger.responses."+e.slug),
			Content:     jsonRef("Error"),
		}
	}

	op := &Operation{
		Summary:     tr(lang, "swagger.paths."+d.id+".summary"),
		Description: tr(lang, descKey),
		Tags:        []string{tr(lang, "swagger.tags."+d.tagSlug)},
		Parameters:  d.params,
		Responses:   responses,
	}
	if d.bodySchema != nil {
		op.RequestBody = &RequestBody{
			Description: tr(lang, "swagger.bodies."+d.bodySlug),
			Required:    true,
			Content:     map[string]MediaType{"application/json": {Schema: d.bodySchema}},
		}
	}
	return op
}

// generatePaths generates every documented API endpoint for the OpenAPI
// specification, localized for lang. The path set mirrors the PUBLIC routes
// registered in src/server/http.go — see routeDocs for the INTERNAL exclusions.
func generatePaths(lang string) map[string]PathItem {
	paths := make(map[string]PathItem)

	for _, d := range routeDocs(lang) {
		op := buildOperation(lang, d)
		item := paths[d.path]
		switch d.method {
		case "get":
			item.Get = op
		case "post":
			item.Post = op
		case "put":
			item.Put = op
		case "delete":
			item.Delete = op
		case "patch":
			item.Patch = op
		}
		paths[d.path] = item
	}

	return paths
}

// generateComponents generates reusable component schemas for the OpenAPI specification.
func generateComponents() Components {
	return Components{
		Schemas: map[string]Schema{
			"IPResponse": {
				Type: "object",
				Properties: map[string]Schema{
					"ip":          {Type: "string", Example: "203.0.113.42"},
					"ip_decimal":  {Type: "integer", Example: 3405803818},
					"country":     {Type: "string", Example: "United States"},
					"country_iso": {Type: "string", Example: "US"},
					"country_eu":  {Type: "boolean", Example: false},
					"region_name": {Type: "string", Example: "California"},
					"region_code": {Type: "string", Example: "CA"},
					"metro_code":  {Type: "integer", Example: 807},
					"zip_code":    {Type: "string", Example: "94043"},
					"city":        {Type: "string", Example: "Mountain View"},
					"latitude":    {Type: "number", Example: 37.4223},
					"longitude":   {Type: "number", Example: -122.084},
					"time_zone":   {Type: "string", Example: "America/Los_Angeles"},
					"asn":         {Type: "string", Example: "AS15169"},
					"asn_org":     {Type: "string", Example: "Google LLC"},
					"hostname":    {Type: "string", Example: "dns.google"},
					"user_agent": {
						Type: "object",
						Properties: map[string]Schema{
							"product":   {Type: "string", Example: "curl"},
							"version":   {Type: "string", Example: "7.88.1"},
							"raw_value": {Type: "string", Example: "curl/7.88.1"},
						},
					},
					"is_vpn":   {Type: "boolean", Example: false},
					"is_proxy": {Type: "boolean", Example: false},
					"is_tor":   {Type: "boolean", Example: false},
				},
			},
			"PortResponse": {
				Type: "object",
				Properties: map[string]Schema{
					"ip":        {Type: "string", Example: "203.0.113.42"},
					"port":      {Type: "integer", Example: 443},
					"reachable": {Type: "boolean", Example: true},
				},
			},
			"HealthResponse": {
				Type: "object",
				Properties: map[string]Schema{
					"project": {
						Type: "object",
						Properties: map[string]Schema{
							"name":        {Type: "string", Example: "IPGaze"},
							"tagline":     {Type: "string"},
							"description": {Type: "string"},
						},
					},
					"status":          {Type: "string", Example: "healthy"},
					"pending_restart": {Type: "boolean", Example: false},
					"restart_reason": {
						Type:  "array",
						Items: &Schema{Type: "string"},
					},
					"version":    {Type: "string", Example: "1.0.0"},
					"go_version": {Type: "string", Example: "go1.25.0"},
					"build": {
						Type: "object",
						Properties: map[string]Schema{
							"commit": {Type: "string", Example: "a1b2c3d"},
							"date":   {Type: "string", Example: "2026-01-15T10:30:00Z"},
						},
					},
					"uptime":    {Type: "string", Example: "72h13m5s"},
					"mode":      {Type: "string", Example: "production"},
					"timestamp": {Type: "string", Example: "2026-01-15T10:30:00Z"},
					"features": {
						Type: "object",
						Properties: map[string]Schema{
							"tor":   {Ref: "#/components/schemas/TorInfo"},
							"i2p":   {Ref: "#/components/schemas/I2PInfo"},
							"geoip": {Type: "boolean", Example: true},
						},
					},
					"checks": {
						Type: "object",
						Properties: map[string]Schema{
							"database":  {Type: "string", Example: "ok"},
							"cache":     {Type: "string", Example: "ok"},
							"disk":      {Type: "string", Example: "ok"},
							"scheduler": {Type: "string", Example: "ok"},
							"tor":       {Type: "string", Example: "ok"},
							"i2p":       {Type: "string", Example: "ok"},
						},
					},
					"stats": {
						Type: "object",
						Properties: map[string]Schema{
							"requests_total":     {Type: "integer", Example: 128401},
							"requests_24h":       {Type: "integer", Example: 4210},
							"active_connections": {Type: "integer", Example: 7},
						},
					},
				},
			},
			"TorInfo": {
				Type: "object",
				Properties: map[string]Schema{
					"enabled":  {Type: "boolean", Example: false},
					"running":  {Type: "boolean", Example: false},
					"status":   {Type: "string", Example: "disabled"},
					"hostname": {Type: "string"},
				},
			},
			"I2PInfo": {
				Type: "object",
				Properties: map[string]Schema{
					"enabled":  {Type: "boolean", Example: false},
					"running":  {Type: "boolean", Example: false},
					"status":   {Type: "string", Example: "disabled"},
					"hostname": {Type: "string"},
					"provider": {Type: "string", Example: "none"},
				},
			},
			"VersionResponse": {
				Type: "object",
				Properties: map[string]Schema{
					"version": {Type: "string", Example: "1.0.0"},
					"commit":  {Type: "string", Example: "a1b2c3d"},
					"date":    {Type: "string", Example: "2026-01-15T10:30:00Z"},
				},
			},
			"GraphQLRequest": {
				Type: "object",
				Properties: map[string]Schema{
					"query":         {Type: "string", Example: "query { myIP { ip country } }"},
					"variables":     {Type: "object"},
					"operationName": {Type: "string"},
				},
			},
			"GraphQLResponse": {
				Type: "object",
				Properties: map[string]Schema{
					"data": {Type: "object"},
					"errors": {
						Type: "array",
						Items: &Schema{
							Type: "object",
							Properties: map[string]Schema{
								"message": {Type: "string"},
							},
						},
					},
				},
			},
			"ContactRequest": {
				Type: "object",
				Properties: map[string]Schema{
					"name":    {Type: "string", Example: "Ada Lovelace"},
					"email":   {Type: "string", Example: "ada@example.com"},
					"subject": {Type: "string", Example: "Question about the API"},
					"message": {Type: "string"},
				},
			},
			"PreferencesRequest": {
				Type: "object",
				Properties: map[string]Schema{
					"theme": {Type: "string", Example: "dark"},
					"lang":  {Type: "string", Example: "en"},
				},
			},
			"PreferencesResponse": {
				Type: "object",
				Properties: map[string]Schema{
					"theme": {Type: "string", Example: "dark"},
					"lang":  {Type: "string", Example: "en"},
				},
			},
			"PreferencesExportResponse": {
				Type: "object",
				Properties: map[string]Schema{
					"url":  {Type: "string", Example: "https://ifcfg.us/server/preferences/import?theme=dark&lang=fr"},
					"code": {Type: "string", Example: "dGhlbWU9ZGFyayZsYW5nPWZy"},
				},
			},
			"Error": {
				Type: "object",
				Properties: map[string]Schema{
					"ok":      {Type: "boolean", Example: false},
					"error":   {Type: "string", Example: "BAD_REQUEST"},
					"message": {Type: "string", Example: "Invalid IP address"},
					"details": {Type: "object"},
				},
			},
		},
	}
}
