package graphql

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	gql "github.com/graphql-go/graphql"

	"github.com/apimgr/ipgaze/src/server/model"
)

// setResolverDeps installs deps for the duration of the test and restores the
// previous (zero-value) deps on cleanup, so tests don't leak state.
func setResolverDeps(t *testing.T, deps Deps) {
	t.Helper()
	orig := resolverDeps
	resolverDeps = deps
	t.Cleanup(func() {
		resolverDeps = orig
	})
}

// fakeLookupIP returns a canned, realistic-looking response for any IP,
// echoing the requested IP back so tests can assert on it.
func fakeLookupIP(ip net.IP) (model.IPLookupResponse, error) {
	eu := true
	return model.IPLookupResponse{
		IP:         ip,
		IPDecimal:  big.NewInt(16909060),
		Country:    "Testland",
		CountryISO: "TL",
		CountryEU:  &eu,
		RegionName: "Test Region",
		RegionCode: "TR",
		MetroCode:  501,
		PostalCode: "12345",
		City:       "Testville",
		Latitude:   12.34,
		Longitude:  56.78,
		Timezone:   "UTC",
		ASN:        "AS64500",
		ASNOrg:     "Test Org",
		Hostname:   "host.example.test",
	}, nil
}

// resetSchema clears the package-level Schema before tests that need a clean slate.
func resetSchema() {
	Schema = gql.Schema{}
}

// ensureSchema initialises the schema if not already done, fataling on error.
func ensureSchema(t *testing.T) {
	t.Helper()
	resetSchema()
	if err := InitSchema(); err != nil {
		t.Fatalf("InitSchema failed: %v", err)
	}
}

// --- InitSchema ---

func TestInitSchema_Succeeds(t *testing.T) {
	resetSchema()
	if err := InitSchema(); err != nil {
		t.Fatalf("InitSchema() returned unexpected error: %v", err)
	}
	if Schema.QueryType() == nil {
		t.Error("Schema.QueryType() is nil after InitSchema()")
	}
}

func TestInitSchema_Idempotent(t *testing.T) {
	// Calling InitSchema twice should not panic or error
	resetSchema()
	if err := InitSchema(); err != nil {
		t.Fatal(err)
	}
	first := Schema.QueryType().Name()
	if err := InitSchema(); err != nil {
		t.Fatal(err)
	}
	if Schema.QueryType().Name() != first {
		t.Error("schema query type changed between calls")
	}
}

func TestInitSchema_ErrorViaInjection(t *testing.T) {
	// initSchemaFunc is a package-level var that allows injecting a failing implementation
	orig := initSchemaFunc
	t.Cleanup(func() { initSchemaFunc = orig })
	initSchemaFunc = func() error {
		return errors.New("injected test error")
	}
	resetSchema()
	err := InitSchema()
	if err == nil {
		t.Fatal("expected error from injected initSchemaFunc")
	}
}

// --- Schema field existence ---

func TestSchema_HasQueryFields(t *testing.T) {
	ensureSchema(t)
	qt := Schema.QueryType()
	expected := []string{"myIP", "lookupIP", "checkPort", "health"}
	for _, name := range expected {
		if _, ok := qt.Fields()[name]; !ok {
			t.Errorf("schema missing expected field: %q", name)
		}
	}
}

func TestSchema_IPResponseType_HasRequiredFields(t *testing.T) {
	ensureSchema(t)
	qt := Schema.QueryType()
	myIP, ok := qt.Fields()["myIP"]
	if !ok {
		t.Fatal("field 'myIP' not found")
	}
	obj, ok := myIP.Type.(*gql.Object)
	if !ok {
		t.Fatalf("myIP type is not *gql.Object, got %T", myIP.Type)
	}
	requiredFields := []string{
		"ip", "ipDecimal", "country", "countryIso", "countryEu",
		"regionName", "regionCode", "metroCode", "zipCode", "city",
		"latitude", "longitude", "timezone", "asn", "asnOrg",
		"hostname", "userAgent",
	}
	for _, f := range requiredFields {
		if _, ok := obj.Fields()[f]; !ok {
			t.Errorf("IPResponse missing field: %q", f)
		}
	}
}

func TestSchema_PortResponseType_HasRequiredFields(t *testing.T) {
	ensureSchema(t)
	qt := Schema.QueryType()
	cp, ok := qt.Fields()["checkPort"]
	if !ok {
		t.Fatal("field 'checkPort' not found")
	}
	obj, ok := cp.Type.(*gql.Object)
	if !ok {
		t.Fatalf("checkPort type is not *gql.Object, got %T", cp.Type)
	}
	for _, f := range []string{"ip", "port", "reachable"} {
		if _, ok := obj.Fields()[f]; !ok {
			t.Errorf("PortResponse missing field: %q", f)
		}
	}
}

func TestSchema_HealthResponseType_HasRequiredFields(t *testing.T) {
	ensureSchema(t)
	qt := Schema.QueryType()
	h, ok := qt.Fields()["health"]
	if !ok {
		t.Fatal("field 'health' not found")
	}
	obj, ok := h.Type.(*gql.Object)
	if !ok {
		t.Fatalf("health type is not *gql.Object, got %T", h.Type)
	}
	for _, f := range []string{"status", "version"} {
		if _, ok := obj.Fields()[f]; !ok {
			t.Errorf("HealthResponse missing field: %q", f)
		}
	}
}

func TestSchema_LookupIP_RequiresIPArgument(t *testing.T) {
	ensureSchema(t)
	qt := Schema.QueryType()
	lookup, ok := qt.Fields()["lookupIP"]
	if !ok {
		t.Fatal("field 'lookupIP' not found")
	}
	ipArg, ok := lookup.Args[0].PrivateName, true
	_ = ipArg
	_ = ok
	// Verify the argument exists — lookup.Args is a slice
	found := false
	for _, arg := range lookup.Args {
		if arg.PrivateName == "ip" {
			found = true
			// Argument should be NonNull(String)
			nn, isNN := arg.Type.(*gql.NonNull)
			if !isNN {
				t.Errorf("lookupIP 'ip' arg type = %T, want *gql.NonNull", arg.Type)
			} else if nn.OfType != gql.String {
				t.Errorf("lookupIP 'ip' inner type = %v, want String", nn.OfType)
			}
			break
		}
	}
	if !found {
		t.Error("lookupIP missing required 'ip' argument")
	}
}

func TestSchema_CheckPort_RequiresPortArgument(t *testing.T) {
	ensureSchema(t)
	qt := Schema.QueryType()
	cp, ok := qt.Fields()["checkPort"]
	if !ok {
		t.Fatal("field 'checkPort' not found")
	}
	found := false
	for _, arg := range cp.Args {
		if arg.PrivateName == "port" {
			found = true
			nn, isNN := arg.Type.(*gql.NonNull)
			if !isNN {
				t.Errorf("checkPort 'port' arg type = %T, want *gql.NonNull", arg.Type)
			} else if nn.OfType != gql.Int {
				t.Errorf("checkPort 'port' inner type = %v, want Int", nn.OfType)
			}
			break
		}
	}
	if !found {
		t.Error("checkPort missing required 'port' argument")
	}
}

// --- Resolvers ---

func doQuery(t *testing.T, query string, vars map[string]interface{}) *gql.Result {
	t.Helper()
	ensureSchema(t)
	return gql.Do(gql.Params{
		Schema:         Schema,
		RequestString:  query,
		VariableValues: vars,
	})
}

// doQueryWithRequest is like doQuery but threads r through the resolver
// context, the way handleGraphQLQuery does for real requests — needed by
// resolvers (myIP, checkPort) that read the caller's IP off the request.
func doQueryWithRequest(t *testing.T, r *http.Request, query string, vars map[string]interface{}) *gql.Result {
	t.Helper()
	ensureSchema(t)
	return gql.Do(gql.Params{
		Schema:         Schema,
		RequestString:  query,
		VariableValues: vars,
		Context:        withRequest(r.Context(), r),
	})
}

// fakeHealth returns a fully populated health record so tests can assert that
// GraphQL exposes every field REST does.
func fakeHealth() model.HealthResponse {
	return model.HealthResponse{
		Project:        model.ProjectInfo{Name: "IPGaze", Tagline: "See your IP", Description: "IP lookup service"},
		Status:         "healthy",
		PendingRestart: true,
		RestartReason:  []string{"config changed"},
		Version:        "1.2.3",
		GoVersion:      "go1.25.0",
		Build:          model.BuildInfo{Commit: "abc1234", Date: "2026-01-15T10:30:00Z"},
		Uptime:         "72h13m5s",
		Mode:           "production",
		Timestamp:      time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC),
		Features: model.FeaturesInfo{
			Tor:   model.TorInfo{Enabled: true, Running: true, Status: "running", Hostname: "abc.onion"},
			I2P:   model.I2PInfo{Enabled: false, Running: false, Status: "disabled", Hostname: "", Provider: "none"},
			GeoIP: true,
		},
		Checks: model.ChecksInfo{Database: "ok", Cache: "ok", Disk: "ok", Scheduler: "ok", Tor: "ok", I2P: "skipped"},
		Stats:  model.StatsInfo{RequestsTotal: 128401, Requests24h: 4210, ActiveConns: 7},
	}
}

func TestResolveHealth_MirrorsRESTHealthRecord(t *testing.T) {
	setResolverDeps(t, Deps{Health: fakeHealth})
	result := doQuery(t, `{ health {
		project { name tagline description }
		status pendingRestart restartReason version goVersion
		build { commit date }
		uptime mode timestamp
		features { tor { enabled running status hostname } i2p { enabled running status hostname provider } geoip }
		checks { database cache disk scheduler tor i2p }
		stats { requestsTotal requests24h activeConnections }
	} }`, nil)
	if len(result.Errors) > 0 {
		t.Fatalf("query errors: %v", result.Errors)
	}
	data, ok := result.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("result.Data is %T, want map", result.Data)
	}
	health, ok := data["health"].(map[string]interface{})
	if !ok {
		t.Fatalf("health is %T, want map", data["health"])
	}
	if health["status"] != "healthy" {
		t.Errorf("health.status = %v, want healthy", health["status"])
	}
	if health["version"] != "1.2.3" {
		t.Errorf("health.version = %v, want 1.2.3", health["version"])
	}
	if health["goVersion"] != "go1.25.0" {
		t.Errorf("health.goVersion = %v, want go1.25.0", health["goVersion"])
	}
	if health["pendingRestart"] != true {
		t.Errorf("health.pendingRestart = %v, want true", health["pendingRestart"])
	}
	if health["timestamp"] != "2026-01-15T10:30:00Z" {
		t.Errorf("health.timestamp = %v, want 2026-01-15T10:30:00Z", health["timestamp"])
	}
	project, ok := health["project"].(map[string]interface{})
	if !ok || project["name"] != "IPGaze" {
		t.Errorf("health.project = %v, want name IPGaze", health["project"])
	}
	features, ok := health["features"].(map[string]interface{})
	if !ok {
		t.Fatalf("health.features is %T, want map", health["features"])
	}
	i2p, ok := features["i2p"].(map[string]interface{})
	if !ok || i2p["provider"] != "none" {
		t.Errorf("health.features.i2p = %v, want provider none", features["i2p"])
	}
	stats, ok := health["stats"].(map[string]interface{})
	if !ok || stats["requestsTotal"] != 128401 {
		t.Errorf("health.stats = %v, want requestsTotal 128401", health["stats"])
	}
}

// TestGraphQLHealthMirrorsRESTFieldCount pins the GraphQL health type to the
// REST model.HealthResponse field set, so adding a REST field without adding
// the GraphQL one is a test failure rather than a silent divergence.
func TestGraphQLHealthMirrorsRESTFieldCount(t *testing.T) {
	ensureSchema(t)
	healthType, ok := Schema.TypeMap()["HealthResponse"].(*gql.Object)
	if !ok {
		t.Fatal("HealthResponse type is missing from the schema")
	}
	restFields := reflect.TypeOf(model.HealthResponse{}).NumField()
	if got := len(healthType.Fields()); got != restFields {
		t.Errorf("GraphQL HealthResponse has %d fields, REST model.HealthResponse has %d", got, restFields)
	}
}

func TestResolveHealth_ErrorsWithoutDeps(t *testing.T) {
	setResolverDeps(t, Deps{})
	result := doQuery(t, `{ health { status } }`, nil)
	if len(result.Errors) == 0 {
		t.Fatal("expected an error when the health dependency is not configured")
	}
}

func TestResolveMyIP_WithDepsAndRequest_ReturnsRealData(t *testing.T) {
	setResolverDeps(t, Deps{
		ClientIP: func(r *http.Request, allowOverride bool) (net.IP, error) {
			return net.ParseIP("203.0.113.7"), nil
		},
		LookupIP: fakeLookupIP,
	})
	r := httptest.NewRequest(http.MethodGet, "/graphql", nil)
	r.Header.Set("User-Agent", "curl/8.0")
	result := doQueryWithRequest(t, r, `{ myIP { ip ipDecimal country countryIso countryEu city userAgent { product rawValue } } }`, nil)
	if len(result.Errors) > 0 {
		t.Fatalf("query errors: %v", result.Errors)
	}
	data := result.Data.(map[string]interface{})
	myIP, ok := data["myIP"].(map[string]interface{})
	if !ok {
		t.Fatalf("myIP is %T, want map", data["myIP"])
	}
	if myIP["ip"] != "203.0.113.7" {
		t.Errorf("myIP.ip = %v, want 203.0.113.7", myIP["ip"])
	}
	if myIP["country"] != "Testland" {
		t.Errorf("myIP.country = %v, want Testland", myIP["country"])
	}
	if myIP["countryEu"] != true {
		t.Errorf("myIP.countryEu = %v, want true", myIP["countryEu"])
	}
	ua, ok := myIP["userAgent"].(map[string]interface{})
	if !ok {
		t.Fatalf("myIP.userAgent is %T, want map", myIP["userAgent"])
	}
	if ua["rawValue"] != "curl/8.0" {
		t.Errorf("userAgent.rawValue = %v, want curl/8.0", ua["rawValue"])
	}
}

func TestResolveMyIP_NoDeps_ReturnsError(t *testing.T) {
	setResolverDeps(t, Deps{})
	r := httptest.NewRequest(http.MethodGet, "/graphql", nil)
	result := doQueryWithRequest(t, r, `{ myIP { ip } }`, nil)
	if len(result.Errors) == 0 {
		t.Error("expected error when resolver deps are not configured")
	}
}

func TestResolveMyIP_NoRequestContext_ReturnsError(t *testing.T) {
	setResolverDeps(t, Deps{
		ClientIP: func(r *http.Request, allowOverride bool) (net.IP, error) {
			return net.ParseIP("203.0.113.7"), nil
		},
		LookupIP: fakeLookupIP,
	})
	result := doQuery(t, `{ myIP { ip } }`, nil)
	if len(result.Errors) == 0 {
		t.Error("expected error when no *http.Request is in context")
	}
}

func TestResolveLookupIP_EchosIPAndGeoData(t *testing.T) {
	setResolverDeps(t, Deps{LookupIP: fakeLookupIP})
	result := doQuery(t, `{ lookupIP(ip: "1.2.3.4") { ip country city asn } }`, nil)
	if len(result.Errors) > 0 {
		t.Fatalf("query errors: %v", result.Errors)
	}
	data := result.Data.(map[string]interface{})
	ip, ok := data["lookupIP"].(map[string]interface{})
	if !ok {
		t.Fatalf("lookupIP is %T, want map", data["lookupIP"])
	}
	if ip["ip"] != "1.2.3.4" {
		t.Errorf("lookupIP.ip = %v, want 1.2.3.4", ip["ip"])
	}
	if ip["country"] != "Testland" {
		t.Errorf("lookupIP.country = %v, want Testland", ip["country"])
	}
	if ip["asn"] != "AS64500" {
		t.Errorf("lookupIP.asn = %v, want AS64500", ip["asn"])
	}
}

func TestResolveLookupIP_IPv6(t *testing.T) {
	setResolverDeps(t, Deps{LookupIP: fakeLookupIP})
	result := doQuery(t, `{ lookupIP(ip: "2001:db8::1") { ip } }`, nil)
	if len(result.Errors) > 0 {
		t.Fatalf("query errors: %v", result.Errors)
	}
	data := result.Data.(map[string]interface{})
	ip := data["lookupIP"].(map[string]interface{})
	if ip["ip"] != "2001:db8::1" {
		t.Errorf("lookupIP.ip = %v, want 2001:db8::1", ip["ip"])
	}
}

func TestResolveLookupIP_InvalidIPErrors(t *testing.T) {
	setResolverDeps(t, Deps{LookupIP: fakeLookupIP})
	result := doQuery(t, `{ lookupIP(ip: "not-an-ip") { ip } }`, nil)
	if len(result.Errors) == 0 {
		t.Error("expected error for an invalid IP address")
	}
}

func TestResolveLookupIP_NoDeps_ReturnsError(t *testing.T) {
	setResolverDeps(t, Deps{})
	result := doQuery(t, `{ lookupIP(ip: "1.2.3.4") { ip } }`, nil)
	if len(result.Errors) == 0 {
		t.Error("expected error when resolver deps are not configured")
	}
}

func TestResolveLookupIP_MissingArgErrors(t *testing.T) {
	// Omitting the required 'ip' argument should produce a GraphQL error
	ensureSchema(t)
	result := gql.Do(gql.Params{
		Schema:        Schema,
		RequestString: `{ lookupIP { ip } }`,
	})
	if len(result.Errors) == 0 {
		t.Error("expected error when 'ip' argument is missing")
	}
}

// newLocalListener opens a real TCP listener on an ephemeral port so tests
// can exercise a genuinely reachable port without depending on the network.
func newLocalListener(t *testing.T) (net.Listener, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to open local listener: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	port := ln.Addr().(*net.TCPAddr).Port
	return ln, port
}

func TestResolveCheckPort_OpenPort_Reachable(t *testing.T) {
	ln, port := newLocalListener(t)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	setResolverDeps(t, Deps{
		ClientIP: func(r *http.Request, allowOverride bool) (net.IP, error) {
			return net.ParseIP("127.0.0.1"), nil
		},
		CheckPort: func(ip net.IP, p uint64) (bool, error) {
			conn, err := net.Dial("tcp", net.JoinHostPort(ip.String(), fmt.Sprintf("%d", p)))
			if err != nil {
				return false, nil
			}
			conn.Close()
			return true, nil
		},
	})
	r := httptest.NewRequest(http.MethodGet, "/graphql", nil)
	result := doQueryWithRequest(t, r, fmt.Sprintf(`{ checkPort(port: %d) { ip port reachable } }`, port), nil)
	if len(result.Errors) > 0 {
		t.Fatalf("query errors: %v", result.Errors)
	}
	data := result.Data.(map[string]interface{})
	cp := data["checkPort"].(map[string]interface{})
	if cp["reachable"] != true {
		t.Errorf("checkPort.reachable = %v, want true for an open local port", cp["reachable"])
	}
	if cp["ip"] != "127.0.0.1" {
		t.Errorf("checkPort.ip = %v, want 127.0.0.1", cp["ip"])
	}
}

func TestResolveCheckPort_ClosedPort_NotReachable(t *testing.T) {
	// Open and immediately close a listener to get a port that is very
	// likely to refuse new connections for the duration of the test.
	ln, port := newLocalListener(t)
	ln.Close()

	setResolverDeps(t, Deps{
		ClientIP: func(r *http.Request, allowOverride bool) (net.IP, error) {
			return net.ParseIP("127.0.0.1"), nil
		},
		CheckPort: func(ip net.IP, p uint64) (bool, error) {
			conn, err := net.Dial("tcp", net.JoinHostPort(ip.String(), fmt.Sprintf("%d", p)))
			if err != nil {
				return false, nil
			}
			conn.Close()
			return true, nil
		},
	})
	r := httptest.NewRequest(http.MethodGet, "/graphql", nil)
	result := doQueryWithRequest(t, r, fmt.Sprintf(`{ checkPort(port: %d) { ip port reachable } }`, port), nil)
	if len(result.Errors) > 0 {
		t.Fatalf("query errors: %v", result.Errors)
	}
	data := result.Data.(map[string]interface{})
	cp := data["checkPort"].(map[string]interface{})
	if cp["reachable"] != false {
		t.Errorf("checkPort.reachable = %v, want false for a closed local port", cp["reachable"])
	}
}

func TestResolveCheckPort_NoDeps_ReturnsError(t *testing.T) {
	setResolverDeps(t, Deps{})
	r := httptest.NewRequest(http.MethodGet, "/graphql", nil)
	result := doQueryWithRequest(t, r, `{ checkPort(port: 443) { reachable } }`, nil)
	if len(result.Errors) == 0 {
		t.Error("expected error when resolver deps are not configured")
	}
}

func TestResolveCheckPort_NoRequestContext_ReturnsError(t *testing.T) {
	setResolverDeps(t, Deps{
		ClientIP: func(r *http.Request, allowOverride bool) (net.IP, error) {
			return net.ParseIP("127.0.0.1"), nil
		},
		CheckPort: func(ip net.IP, p uint64) (bool, error) { return true, nil },
	})
	result := doQuery(t, `{ checkPort(port: 443) { reachable } }`, nil)
	if len(result.Errors) == 0 {
		t.Error("expected error when no *http.Request is in context")
	}
}

func TestResolveCheckPort_InvalidPortErrors(t *testing.T) {
	setResolverDeps(t, Deps{
		ClientIP: func(r *http.Request, allowOverride bool) (net.IP, error) {
			return net.ParseIP("127.0.0.1"), nil
		},
		CheckPort: func(ip net.IP, p uint64) (bool, error) { return true, nil },
	})
	r := httptest.NewRequest(http.MethodGet, "/graphql", nil)
	result := doQueryWithRequest(t, r, `{ checkPort(port: 0) { reachable } }`, nil)
	if len(result.Errors) == 0 {
		t.Error("expected error for an out-of-range port")
	}
}

func TestResolveCheckPort_MissingPortErrors(t *testing.T) {
	ensureSchema(t)
	result := gql.Do(gql.Params{
		Schema:        Schema,
		RequestString: `{ checkPort { port } }`,
	})
	if len(result.Errors) == 0 {
		t.Error("expected error when 'port' argument is missing")
	}
}

// --- getTheme ---

func TestGetTheme_DefaultDark(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if got := getTheme(r); got != "dark" {
		t.Errorf("getTheme (no cookie) = %q, want dark", got)
	}
}

func TestGetTheme_LightCookie(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "theme", Value: "light"})
	if got := getTheme(r); got != "light" {
		t.Errorf("getTheme (light cookie) = %q, want light", got)
	}
}

func TestGetTheme_DarkCookie(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "theme", Value: "dark"})
	if got := getTheme(r); got != "dark" {
		t.Errorf("getTheme (dark cookie) = %q, want dark", got)
	}
}

func TestGetTheme_AutoCookie(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "theme", Value: "auto"})
	if got := getTheme(r); got != "auto" {
		t.Errorf("getTheme (auto cookie) = %q, want auto", got)
	}
}

func TestGetTheme_InvalidCookieDefaultsDark(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "theme", Value: "hacker"})
	if got := getTheme(r); got != "dark" {
		t.Errorf("getTheme (invalid cookie) = %q, want dark", got)
	}
}

// --- getGraphiQLThemeCSS ---

func TestGetGraphiQLThemeCSS_Dark(t *testing.T) {
	css := getGraphiQLThemeCSS("dark")
	if css != graphiqlDarkTheme {
		t.Error("dark theme CSS does not match graphiqlDarkTheme constant")
	}
	if !strings.Contains(css, "#282a36") {
		t.Error("dark CSS should reference the dark background colour")
	}
}

func TestGetGraphiQLThemeCSS_Light(t *testing.T) {
	css := getGraphiQLThemeCSS("light")
	if css != graphiqlLightTheme {
		t.Error("light theme CSS does not match graphiqlLightTheme constant")
	}
	if !strings.Contains(css, "#ffffff") {
		t.Error("light CSS should reference white background")
	}
}

func TestGetGraphiQLThemeCSS_Auto_FallsThroughToDark(t *testing.T) {
	// "auto" is not "light", so the function returns the dark theme
	css := getGraphiQLThemeCSS("auto")
	if css != graphiqlDarkTheme {
		t.Error("auto theme should fall through to dark CSS")
	}
}

func TestGetGraphiQLThemeCSS_EmptyString_FallsThroughToDark(t *testing.T) {
	css := getGraphiQLThemeCSS("")
	if css != graphiqlDarkTheme {
		t.Error("empty theme string should fall through to dark CSS")
	}
}

// --- Handler ---

func TestHandler_GET_ServesGraphiQL(t *testing.T) {
	resetSchema()
	h := Handler(GraphQLHandlerConfig{Version: "1.0.0", CommitID: "abc123"})
	req := httptest.NewRequest(http.MethodGet, "/graphql", nil)
	rec := httptest.NewRecorder()
	h(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("GET /graphql status = %d, want 200", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html prefix", ct)
	}
	body := rec.Body.String()
	// The HTML includes "GraphQL" in the title and explorer UI.
	if !strings.Contains(body, "GraphQL") {
		t.Error("GraphQL HTML missing 'GraphQL' string")
	}
	if !strings.Contains(body, "<!DOCTYPE html>") {
		t.Error("response missing DOCTYPE")
	}
}

func TestHandler_GET_DarkThemeByDefault(t *testing.T) {
	resetSchema()
	h := Handler(GraphQLHandlerConfig{Version: "v0.1", CommitID: "x"})
	req := httptest.NewRequest(http.MethodGet, "/graphql", nil)
	rec := httptest.NewRecorder()
	h(rec, req)
	body := rec.Body.String()
	// Dark theme uses the Dracula-based palette (AI.md PART 16 "Themes
	// (NON-NEGOTIABLE)"), same as the web UI and Swagger UI.
	if !strings.Contains(body, "#282a36") {
		t.Error("default dark theme CSS (#282a36) not found in HTML output")
	}
}

func TestHandler_GET_LightThemeViaCookie(t *testing.T) {
	resetSchema()
	h := Handler(GraphQLHandlerConfig{Version: "v0.1", CommitID: "x"})
	req := httptest.NewRequest(http.MethodGet, "/graphql", nil)
	req.AddCookie(&http.Cookie{Name: "theme", Value: "light"})
	rec := httptest.NewRecorder()
	h(rec, req)
	body := rec.Body.String()
	// Light theme uses the GitHub-Light-based palette (AI.md PART 16 "Themes
	// (NON-NEGOTIABLE)"), same as the web UI and Swagger UI.
	if !strings.Contains(body, "#ffffff") {
		t.Error("light theme CSS (#ffffff) not found when light cookie is set")
	}
}

func TestHandler_POST_ExecutesQuery(t *testing.T) {
	resetSchema()
	h := Handler(GraphQLHandlerConfig{Version: "v1", CommitID: "deadbeef", Health: fakeHealth})
	body := `{"query":"{ health { status } }"}`
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("POST /graphql status = %d, want 200", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	data, ok := resp["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("response.data is %T", resp["data"])
	}
	health, ok := data["health"].(map[string]interface{})
	if !ok {
		t.Fatalf("response.data.health is %T", data["health"])
	}
	if health["status"] != "healthy" {
		t.Errorf("health.status = %v, want healthy", health["status"])
	}
}

func TestHandler_POST_InvalidJSON(t *testing.T) {
	resetSchema()
	h := Handler(GraphQLHandlerConfig{})
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for invalid JSON body", rec.Code)
	}
}

func TestHandler_POST_EmptyBody(t *testing.T) {
	resetSchema()
	h := Handler(GraphQLHandlerConfig{})
	req := httptest.NewRequest(http.MethodPost, "/graphql", bytes.NewReader([]byte{}))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h(rec, req)
	// Empty body is invalid JSON — expect 400
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for empty body", rec.Code)
	}
}

func TestHandler_PUT_MethodNotAllowed(t *testing.T) {
	resetSchema()
	h := Handler(GraphQLHandlerConfig{})
	req := httptest.NewRequest(http.MethodPut, "/graphql", nil)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405 for PUT", rec.Code)
	}
}

func TestHandler_DELETE_MethodNotAllowed(t *testing.T) {
	resetSchema()
	h := Handler(GraphQLHandlerConfig{})
	req := httptest.NewRequest(http.MethodDelete, "/graphql", nil)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405 for DELETE", rec.Code)
	}
}

func TestHandler_SchemaInitFailure_Returns500(t *testing.T) {
	// Inject a failing initSchemaFunc so Handler cannot build the schema
	orig := initSchemaFunc
	t.Cleanup(func() {
		initSchemaFunc = orig
		resetSchema()
	})
	initSchemaFunc = func() error {
		return errors.New("test schema init failure")
	}
	resetSchema()
	h := Handler(GraphQLHandlerConfig{})
	req := httptest.NewRequest(http.MethodGet, "/graphql", nil)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 when schema init fails", rec.Code)
	}
}

func TestHandler_POST_WithVariables(t *testing.T) {
	resetSchema()
	h := Handler(GraphQLHandlerConfig{Version: "v1", CommitID: "x", LookupIP: fakeLookupIP})
	body := `{"query":"query LookupIP($ip: String!) { lookupIP(ip: $ip) { ip } }","variables":{"ip":"10.0.0.1"}}`
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	data, ok := resp["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("data is %T", resp["data"])
	}
	lookup, ok := data["lookupIP"].(map[string]interface{})
	if !ok {
		t.Fatalf("lookupIP is %T", data["lookupIP"])
	}
	if lookup["ip"] != "10.0.0.1" {
		t.Errorf("ip = %v, want 10.0.0.1", lookup["ip"])
	}
}

func TestHandler_POST_UnknownField_ReturnsGraphQLError(t *testing.T) {
	resetSchema()
	h := Handler(GraphQLHandlerConfig{})
	body := `{"query":"{ nonexistentField { foo } }"}`
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h(rec, req)
	// Status is 200 — GraphQL errors are embedded in the response body
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (GraphQL errors in body)", rec.Code)
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp["errors"] == nil {
		t.Error("expected 'errors' key in response for unknown field query")
	}
}

// --- serveGraphiQL HTML content ---

func TestServeGraphiQL_ContainsScriptTags(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/graphql", nil)
	serveGraphiQL(w, r, GraphQLHandlerConfig{Version: "1.2.3", CommitID: "abc"})
	body := w.Body.String()
	if !strings.Contains(body, "<script") {
		t.Error("GraphQL Explorer HTML missing <script> tags")
	}
	// The UI title is "IPGaze GraphQL Explorer".
	if !strings.Contains(body, "GraphQL") {
		t.Error("GraphQL Explorer HTML missing 'GraphQL' string")
	}
}

func TestServeGraphiQL_ContentTypeHTML(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/graphql", nil)
	serveGraphiQL(w, r, GraphQLHandlerConfig{})
	ct := w.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html prefix", ct)
	}
}

func TestServeGraphiQL_LangAttribute(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/graphql", nil)
	r.Header.Set("Accept-Language", "en")
	serveGraphiQL(w, r, GraphQLHandlerConfig{})
	body := w.Body.String()
	if !strings.Contains(body, `lang="`) {
		t.Error("GraphiQL HTML missing lang attribute on html element")
	}
}
