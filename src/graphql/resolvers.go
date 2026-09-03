package graphql

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	gql "github.com/graphql-go/graphql"

	"github.com/apimgr/ipgaze/src/server/model"
	"github.com/apimgr/ipgaze/src/useragent"
)

// requestContextKey is the context key used to carry the originating *http.Request
// through a GraphQL resolve chain (set by handleGraphQLQuery in graphql.go).
type requestContextKey struct{}

// withRequest returns a context carrying r, so resolvers can recover the HTTP
// request that triggered the query (needed for client-IP detection).
func withRequest(ctx context.Context, r *http.Request) context.Context {
	return context.WithValue(ctx, requestContextKey{}, r)
}

// requestFromContext returns the *http.Request stashed by withRequest, or nil.
func requestFromContext(ctx context.Context) *http.Request {
	if ctx == nil {
		return nil
	}
	r, _ := ctx.Value(requestContextKey{}).(*http.Request)
	return r
}

// Deps declares the callbacks GraphQL resolvers need from the running HTTP server
// so they share the exact lookup logic used by the REST endpoints (/json, /{ip},
// /port/{port}) instead of duplicating it. Populated by Handler() from
// GraphQLHandlerConfig; nil fields make the corresponding resolver return a
// GraphQL error instead of placeholder data.
type Deps struct {
	// ClientIP extracts the caller's IP from an incoming HTTP request.
	// allowOverride mirrors REST semantics: true permits the "?ip=" query
	// override (used by myIP, matching /json); false requires the detected
	// connection IP (used by checkPort, matching /port/{port}).
	ClientIP func(r *http.Request, allowOverride bool) (net.IP, error)
	// LookupIP resolves GeoIP/ASN/hostname/threat info for ip; shared with
	// REST /json and /{ip}.
	LookupIP func(ip net.IP) (model.IPLookupResponse, error)
	// CheckPort attempts a live TCP connection check; shared with REST /port/{port}.
	CheckPort func(ip net.IP, port uint64) (bool, error)
	// Health returns the same model.HealthResponse the REST health endpoints
	// render, so the GraphQL health query is functionally equivalent to REST
	// instead of reporting a reduced view of the server's state.
	Health func() model.HealthResponse
}

// resolverDeps holds the dependencies wired in by Handler(). It is package-level
// because graphql-go resolver functions have a fixed signature and cannot close
// over per-instance state; Handler() is expected to be called once at startup
// with the live *server.Server callbacks.
var resolverDeps Deps

// ipResponseToMap converts a model.IPLookupResponse into the map shape expected
// by the GraphQL IPResponse type. ua overrides resp.UserAgent when non-nil
// (myIP always derives it fresh from the current request).
func ipResponseToMap(resp model.IPLookupResponse, ua *useragent.UserAgent) map[string]interface{} {
	ipDecimal := "0"
	if resp.IPDecimal != nil {
		ipDecimal = resp.IPDecimal.String()
	}
	countryEU := false
	if resp.CountryEU != nil {
		countryEU = *resp.CountryEU
	}
	m := map[string]interface{}{
		"ip":         resp.IP.String(),
		"ipDecimal":  ipDecimal,
		"country":    resp.Country,
		"countryIso": resp.CountryISO,
		"countryEu":  countryEU,
		"regionName": resp.RegionName,
		"regionCode": resp.RegionCode,
		"metroCode":  int(resp.MetroCode),
		"zipCode":    resp.PostalCode,
		"city":       resp.City,
		"latitude":   resp.Latitude,
		"longitude":  resp.Longitude,
		"timezone":   resp.Timezone,
		"asn":        resp.ASN,
		"asnOrg":     resp.ASNOrg,
		"hostname":   resp.Hostname,
		"isVpn":      boolPtrToInterface(resp.IsVPN),
		"isProxy":    boolPtrToInterface(resp.IsProxy),
		"isTor":      boolPtrToInterface(resp.IsTor),
	}
	if ua != nil {
		m["userAgent"] = userAgentToMap(*ua)
	} else if resp.UserAgent != nil {
		m["userAgent"] = userAgentToMap(*resp.UserAgent)
	}
	return m
}

// userAgentToMap converts a useragent.UserAgent into the map shape expected by
// the GraphQL UserAgent type.
func userAgentToMap(ua useragent.UserAgent) map[string]interface{} {
	return map[string]interface{}{
		"product":  ua.Product,
		"version":  ua.Version,
		"rawValue": ua.RawValue,
	}
}

// boolPtrToInterface returns nil for a nil pointer (so the GraphQL field
// resolves to null) or the dereferenced value otherwise.
func boolPtrToInterface(b *bool) interface{} {
	if b == nil {
		return nil
	}
	return *b
}

// resolveMyIP resolves the myIP query — GeoIP/ASN/hostname info for the caller's
// own IP, detected from the incoming HTTP request the same way REST /json does.
func resolveMyIP(p gql.ResolveParams) (interface{}, error) {
	if resolverDeps.ClientIP == nil || resolverDeps.LookupIP == nil {
		return nil, errors.New("myIP is unavailable: GraphQL server dependencies are not configured")
	}
	r := requestFromContext(p.Context)
	if r == nil {
		return nil, errors.New("myIP requires an HTTP request context")
	}
	ip, err := resolverDeps.ClientIP(r, true)
	if err != nil {
		return nil, err
	}
	resp, err := resolverDeps.LookupIP(ip)
	if err != nil {
		return nil, err
	}
	var uaPtr *useragent.UserAgent
	if raw := r.UserAgent(); raw != "" {
		ua := useragent.Parse(raw)
		uaPtr = &ua
	}
	return ipResponseToMap(resp, uaPtr), nil
}

// resolveLookupIP resolves the lookupIP query — GeoIP/ASN/hostname info for an
// explicit IP argument, matching REST /{ip}.
func resolveLookupIP(p gql.ResolveParams) (interface{}, error) {
	if resolverDeps.LookupIP == nil {
		return nil, errors.New("lookupIP is unavailable: GraphQL server dependencies are not configured")
	}
	ipArg, _ := p.Args["ip"].(string)
	ip := net.ParseIP(ipArg)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %q", ipArg)
	}
	resp, err := resolverDeps.LookupIP(ip)
	if err != nil {
		return nil, err
	}
	return ipResponseToMap(resp, nil), nil
}

// resolveCheckPort resolves the checkPort query — a live TCP reachability check
// against the caller's own IP, matching REST /port/{port}.
func resolveCheckPort(p gql.ResolveParams) (interface{}, error) {
	if resolverDeps.CheckPort == nil || resolverDeps.ClientIP == nil {
		return nil, errors.New("checkPort is unavailable: GraphQL server dependencies are not configured")
	}
	r := requestFromContext(p.Context)
	if r == nil {
		return nil, errors.New("checkPort requires an HTTP request context")
	}
	port, _ := p.Args["port"].(int)
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid port: %d", port)
	}
	ip, err := resolverDeps.ClientIP(r, false)
	if err != nil {
		return nil, err
	}
	reachable, err := resolverDeps.CheckPort(ip, uint64(port))
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"ip":        ip.String(),
		"port":      port,
		"reachable": reachable,
	}, nil
}

// resolveHealth resolves the health query from the same model.HealthResponse
// the REST health endpoints render, so both interfaces report identical state.
func resolveHealth(p gql.ResolveParams) (interface{}, error) {
	if resolverDeps.Health == nil {
		return nil, errors.New("health is unavailable: GraphQL server dependencies are not configured")
	}
	return healthResponseToMap(resolverDeps.Health()), nil
}

// healthResponseToMap converts a model.HealthResponse into the map shape
// expected by the GraphQL HealthResponse type. Field names are the camelCase
// GraphQL spellings of the REST JSON keys; values are copied verbatim so the
// two interfaces can never disagree.
func healthResponseToMap(h model.HealthResponse) map[string]interface{} {
	reasons := make([]interface{}, 0, len(h.RestartReason))
	for _, reason := range h.RestartReason {
		reasons = append(reasons, reason)
	}

	return map[string]interface{}{
		"project": map[string]interface{}{
			"name":        h.Project.Name,
			"tagline":     h.Project.Tagline,
			"description": h.Project.Description,
		},
		"status":         h.Status,
		"pendingRestart": h.PendingRestart,
		"restartReason":  reasons,
		"version":        h.Version,
		"goVersion":      h.GoVersion,
		"build": map[string]interface{}{
			"commit": h.Build.Commit,
			"date":   h.Build.Date,
		},
		"uptime":    h.Uptime,
		"mode":      h.Mode,
		"timestamp": h.Timestamp.Format(time.RFC3339),
		"features": map[string]interface{}{
			"tor": map[string]interface{}{
				"enabled":  h.Features.Tor.Enabled,
				"running":  h.Features.Tor.Running,
				"status":   h.Features.Tor.Status,
				"hostname": h.Features.Tor.Hostname,
			},
			"i2p": map[string]interface{}{
				"enabled":  h.Features.I2P.Enabled,
				"running":  h.Features.I2P.Running,
				"status":   h.Features.I2P.Status,
				"hostname": h.Features.I2P.Hostname,
				"provider": h.Features.I2P.Provider,
			},
			"geoip": h.Features.GeoIP,
		},
		"checks": map[string]interface{}{
			"database":  h.Checks.Database,
			"cache":     h.Checks.Cache,
			"disk":      h.Checks.Disk,
			"scheduler": h.Checks.Scheduler,
			"tor":       h.Checks.Tor,
			"i2p":       h.Checks.I2P,
		},
		"stats": map[string]interface{}{
			"requestsTotal":     h.Stats.RequestsTotal,
			"requests24h":       h.Stats.Requests24h,
			"activeConnections": h.Stats.ActiveConns,
		},
	}
}
