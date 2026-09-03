package graphql

import (
	i18n "github.com/apimgr/ipgaze/src/common/i18n"
)

// graphqlDefaults holds the English source text for every `graphql.*`
// translation key used by this package: schema type and field descriptions
// plus the explorer interface labels. It is the single source of truth for the
// English wording and the fallback used when a locale file does not define the
// key yet, so the schema is always fully described (AI.md PART 30 puts GraphQL
// descriptions in i18n scope).
var graphqlDefaults = map[string]string{
	"graphql.types.UserAgent.description":        "Parsed user agent information",
	"graphql.types.UserAgent.fields.product":     "User agent product, for example curl or wget",
	"graphql.types.UserAgent.fields.version":     "User agent version",
	"graphql.types.UserAgent.fields.rawValue":    "Raw user agent string",
	"graphql.types.IPResponse.description":       "IP address lookup response with GeoIP information",
	"graphql.types.IPResponse.fields.ip":         "IP address",
	"graphql.types.IPResponse.fields.ipDecimal":  "IP address as a decimal number",
	"graphql.types.IPResponse.fields.country":    "Country name",
	"graphql.types.IPResponse.fields.countryIso": "ISO 3166-1 alpha-2 country code",
	"graphql.types.IPResponse.fields.countryEu":  "Whether the country is in the European Union",
	"graphql.types.IPResponse.fields.regionName": "Region or state name",
	"graphql.types.IPResponse.fields.regionCode": "Region or state code",
	"graphql.types.IPResponse.fields.metroCode":  "Metro code",
	"graphql.types.IPResponse.fields.zipCode":    "Postal or ZIP code",
	"graphql.types.IPResponse.fields.city":       "City name",
	"graphql.types.IPResponse.fields.latitude":   "Latitude coordinate",
	"graphql.types.IPResponse.fields.longitude":  "Longitude coordinate",
	"graphql.types.IPResponse.fields.timezone":   "Timezone, for example America/Los_Angeles",
	"graphql.types.IPResponse.fields.asn":        "Autonomous System Number, for example AS15169",
	"graphql.types.IPResponse.fields.asnOrg":     "Autonomous System organization name",
	"graphql.types.IPResponse.fields.hostname":   "Reverse DNS hostname",
	"graphql.types.IPResponse.fields.userAgent":  "Parsed user agent information",
	"graphql.types.IPResponse.fields.isVpn":      "True when the IP is associated with a known VPN or hosting provider",
	"graphql.types.IPResponse.fields.isProxy":    "True when the IP is a known open proxy or data-center proxy",
	"graphql.types.IPResponse.fields.isTor":      "True when the IP is a known Tor exit node",

	"graphql.types.PortResponse.description":      "Port reachability check response",
	"graphql.types.PortResponse.fields.ip":        "IP address the check was made against",
	"graphql.types.PortResponse.fields.port":      "Port number",
	"graphql.types.PortResponse.fields.reachable": "Whether the port is reachable",

	"graphql.types.ProjectInfo.description":        "Project identity reported by the server",
	"graphql.types.ProjectInfo.fields.name":        "Project name",
	"graphql.types.ProjectInfo.fields.tagline":     "Short project tagline",
	"graphql.types.ProjectInfo.fields.description": "Longer project description",
	"graphql.types.BuildInfo.description":          "Build metadata for the running binary",
	"graphql.types.BuildInfo.fields.commit":        "Source commit the binary was built from",
	"graphql.types.BuildInfo.fields.date":          "Build timestamp",
	"graphql.types.TorInfo.description":            "Tor hidden service status",
	"graphql.types.TorInfo.fields.enabled":         "Whether the Tor hidden service is enabled in the configuration",
	"graphql.types.TorInfo.fields.running":         "Whether the Tor hidden service is currently running",
	"graphql.types.TorInfo.fields.status":          "Human-readable Tor status",
	"graphql.types.TorInfo.fields.hostname":        "Published .onion hostname",
	"graphql.types.I2PInfo.description":            "I2P eepsite status",
	"graphql.types.I2PInfo.fields.enabled":         "Whether the I2P eepsite is enabled in the configuration",
	"graphql.types.I2PInfo.fields.running":         "Whether the I2P eepsite is currently running",
	"graphql.types.I2PInfo.fields.status":          "Human-readable I2P status",
	"graphql.types.I2PInfo.fields.hostname":        "Published .i2p hostname",
	"graphql.types.I2PInfo.fields.provider":        "Eepsite backend in use: i2pd, sam or none",
	"graphql.types.FeaturesInfo.description":       "Optional feature availability",
	"graphql.types.FeaturesInfo.fields.tor":        "Tor hidden service status",
	"graphql.types.FeaturesInfo.fields.i2p":        "I2P eepsite status",
	"graphql.types.FeaturesInfo.fields.geoip":      "Whether GeoIP databases are loaded",
	"graphql.types.ChecksInfo.description":         "Individual subsystem health results",
	"graphql.types.ChecksInfo.fields.database":     "Database check result",
	"graphql.types.ChecksInfo.fields.cache":        "Cache check result",
	"graphql.types.ChecksInfo.fields.disk":         "Disk check result",
	"graphql.types.ChecksInfo.fields.scheduler":    "Scheduler check result",
	"graphql.types.ChecksInfo.fields.tor":          "Tor subsystem check result",
	"graphql.types.ChecksInfo.fields.i2p":          "I2P subsystem check result",
	"graphql.types.StatsInfo.description":          "Aggregate request counters",
	"graphql.types.StatsInfo.fields.requestsTotal": "Requests served since start",
	"graphql.types.StatsInfo.fields.requests24h":   "Requests served in the last 24 hours",
	"graphql.types.StatsInfo.fields.activeConns":   "Currently active connections",

	"graphql.types.HealthResponse.description":           "Server health record, mirroring the REST health endpoint field for field",
	"graphql.types.HealthResponse.fields.project":        "Project identity",
	"graphql.types.HealthResponse.fields.status":         "Overall status: healthy, degraded, restart_required, unhealthy, maintenance or shutting_down",
	"graphql.types.HealthResponse.fields.pendingRestart": "Whether a configuration change is waiting for a restart",
	"graphql.types.HealthResponse.fields.restartReason":  "Reasons a restart is pending",
	"graphql.types.HealthResponse.fields.version":        "Application version",
	"graphql.types.HealthResponse.fields.goVersion":      "Go runtime version the binary was built with",
	"graphql.types.HealthResponse.fields.build":          "Build metadata",
	"graphql.types.HealthResponse.fields.uptime":         "Time elapsed since the server started",
	"graphql.types.HealthResponse.fields.mode":           "Operational mode: production or development",
	"graphql.types.HealthResponse.fields.timestamp":      "Time this health record was produced, in RFC 3339 format",
	"graphql.types.HealthResponse.fields.features":       "Optional feature availability",
	"graphql.types.HealthResponse.fields.checks":         "Individual subsystem health results",
	"graphql.types.HealthResponse.fields.stats":          "Aggregate request counters",

	"graphql.query.myIP.description":      "Get your IP address with GeoIP information",
	"graphql.query.lookupIP.description":  "Look up a specific IP address",
	"graphql.query.checkPort.description": "Check whether a port is reachable on your IP address",
	"graphql.query.health.description":    "Get the full server health record",
	"graphql.args.lookupIP.ip":            "IP address to look up (IPv4 or IPv6)",
	"graphql.args.checkPort.port":         "Port number to check (1-65535)",

	"graphql.ui.title":       "IPGaze GraphQL Explorer",
	"graphql.ui.query":       "Query",
	"graphql.ui.variables":   "Variables (JSON)",
	"graphql.ui.run":         "Run",
	"graphql.ui.response":    "Response",
	"graphql.ui.placeholder": "Press Run to execute a query.",
}

// tr returns the localized string for key, falling back to the English default
// declared in graphqlDefaults when the locale files do not define it yet.
// i18n.Translate echoes the key back when it is missing, which is the signal
// used here to fall through to the default.
func tr(lang, key string) string {
	if v := i18n.Translate(lang, key); v != "" && v != key {
		return v
	}
	return graphqlDefaults[key]
}
