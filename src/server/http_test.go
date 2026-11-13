package server

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/apimgr/ipgaze/src/config"
	"github.com/apimgr/ipgaze/src/iputil/geo"
	"github.com/apimgr/ipgaze/src/netutil"
	serverhandler "github.com/apimgr/ipgaze/src/server/handler"
	"github.com/apimgr/ipgaze/src/server/model"
)

func lookupAddr(net.IP) (string, error) { return "localhost", nil }
func lookupPort(net.IP, uint64) error   { return nil }

func TestApplyVersionPurgeNavigationGate(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		dest       string
		mode       string
		wantPurge  bool
		wantCookie bool
	}{
		{name: "old browser navigation", method: http.MethodGet, wantPurge: true, wantCookie: true},
		{name: "modern document navigation", method: http.MethodGet, dest: "document", mode: "navigate", wantPurge: true, wantCookie: true},
		{name: "iframe", method: http.MethodGet, dest: "iframe", mode: "navigate"},
		{name: "fetch", method: http.MethodGet, dest: "empty", mode: "cors"},
		{name: "head", method: http.MethodHead, dest: "document", mode: "navigate"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/", nil)
			if tt.dest != "" {
				req.Header.Set("Sec-Fetch-Dest", tt.dest)
			}
			if tt.mode != "" {
				req.Header.Set("Sec-Fetch-Mode", tt.mode)
			}
			req.AddCookie(&http.Cookie{Name: versionCookieName, Value: "old-build"})
			rec := httptest.NewRecorder()
			applyVersionPurge(rec, req, "new-build")
			if got := rec.Header().Get("Clear-Site-Data") != ""; got != tt.wantPurge {
				t.Errorf("Clear-Site-Data present = %v, want %v", got, tt.wantPurge)
			}
			if got := len(rec.Result().Cookies()) > 0; got != tt.wantCookie {
				t.Errorf("build cookie present = %v, want %v", got, tt.wantCookie)
			}
		})
	}
}

type testDb struct{}

func (t *testDb) Country(net.IP) (geo.Country, error) {
	return geo.Country{Name: "Elbonia", ISO: "EB", IsEU: new(bool)}, nil
}

func (t *testDb) City(net.IP) (geo.City, error) {
	return geo.City{Name: "Bornyasherk", RegionName: "North Elbonia", RegionCode: "1234", MetroCode: 1234, PostalCode: "1234", Latitude: 63.416667, Longitude: 10.416667, Timezone: "Europe/Bornyasherk"}, nil
}

func (t *testDb) ASN(net.IP) (geo.ASN, error) {
	return geo.ASN{AutonomousSystemNumber: 59795, AutonomousSystemOrganization: "Hosting4Real"}, nil
}

func (t *testDb) IsEmpty() bool { return false }

func testServer() *Server {
	return &Server{
		HealthHandler: serverhandler.NewHealthHandler("test", "", "", "development", time.Now()),
		cache:         NewCache(100),
		gr:            &testDb{},
		LookupAddr:    lookupAddr,
		LookupPort:    lookupPort,
		StartTime:     time.Now(),
		Version:       "test",
		Mode:          "development",
		// Enable root /healthz alias (default config has this enabled).
		HealthzRootEnabled: true,
	}
}

func httpGet(url string, acceptMediaType string, userAgent string) (string, int, error) {
	r, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", 0, err
	}
	if acceptMediaType != "" {
		r.Header.Set("Accept", acceptMediaType)
	}
	r.Header.Set("User-Agent", userAgent)
	res, err := http.DefaultClient.Do(r)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = res.Body.Close() }()
	data, err := io.ReadAll(res.Body)
	if err != nil {
		return "", 0, err
	}
	return string(data), res.StatusCode, nil
}

func httpGetBearer(url, acceptMediaType, userAgent, token string) (string, int, error) {
	r, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", 0, err
	}
	if acceptMediaType != "" {
		r.Header.Set("Accept", acceptMediaType)
	}
	r.Header.Set("User-Agent", userAgent)
	r.Header.Set("Authorization", "Bearer "+token)
	res, err := http.DefaultClient.Do(r)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = res.Body.Close() }()
	data, err := io.ReadAll(res.Body)
	if err != nil {
		return "", 0, err
	}
	return string(data), res.StatusCode, nil
}

func httpPostBearer(url, body, token string) (*http.Response, string, error) {
	r, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return nil, "", err
	}
	r.Header.Set("Authorization", "Bearer "+token)
	res, err := http.DefaultClient.Do(r)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = res.Body.Close() }()
	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, "", err
	}
	return res, string(data), nil
}

func httpPost(url, body string) (*http.Response, string, error) {
	r, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return nil, "", err
	}
	res, err := http.DefaultClient.Do(r)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = res.Body.Close() }()
	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, "", err
	}
	return res, string(data), nil
}

func TestCLIHandlers(t *testing.T) {
	log.SetOutput(io.Discard)
	s := httptest.NewServer(testServer().Handler())

	var tests = []struct {
		url             string
		out             string
		status          int
		userAgent       string
		acceptMediaType string
	}{
		{s.URL, "127.0.0.1\n", 200, "curl/7.43.0", ""},
		{s.URL, "127.0.0.1\n", 200, "foo/bar", textMediaType},
		{s.URL + "/ip", "127.0.0.1\n", 200, "", ""},
		{s.URL + "/country", "Elbonia\n", 200, "", ""},
		{s.URL + "/country-iso", "EB\n", 200, "", ""},
		{s.URL + "/coordinates", "63.416667,10.416667\n", 200, "", ""},
		{s.URL + "/city", "Bornyasherk\n", 200, "", ""},
		{s.URL + "/foo", "Not found", 404, "", ""},
		{s.URL + "/asn", "AS59795\n", 200, "", ""},
		{s.URL + "/asn-org", "Hosting4Real\n", 200, "", ""},
	}

	for _, tt := range tests {
		out, status, err := httpGet(tt.url, tt.acceptMediaType, tt.userAgent)
		if err != nil {
			t.Fatal(err)
		}
		if status != tt.status {
			t.Errorf("Expected %d, got %d", tt.status, status)
		}
		if out != tt.out {
			t.Errorf("Expected %q, got %q", tt.out, out)
		}
	}
}

func TestDisabledHandlers(t *testing.T) {
	log.SetOutput(io.Discard)
	server := testServer()
	server.LookupPort = nil
	server.LookupAddr = nil
	server.gr, _ = geo.Open("", "", "", "")
	s := httptest.NewServer(server.Handler())

	var tests = []struct {
		url    string
		out    string
		status int
	}{
		{s.URL + "/port/1337", "Not found", 404},
		{s.URL + "/country", "Not found", 404},
		{s.URL + "/country-iso", "Not found", 404},
		{s.URL + "/city", "Not found", 404},
		{s.URL + "/json", "{\n  \"ip\": \"127.0.0.1\",\n  \"ip_decimal\": 2130706433\n}\n", 200},
	}

	for _, tt := range tests {
		out, status, err := httpGet(tt.url, "", "")
		if err != nil {
			t.Fatal(err)
		}
		if status != tt.status {
			t.Errorf("Expected %d, got %d", tt.status, status)
		}
		if out != tt.out {
			t.Errorf("Expected %q, got %q", tt.out, out)
		}
	}
}

func TestJSONHandlers(t *testing.T) {
	log.SetOutput(io.Discard)
	s := httptest.NewServer(testServer().Handler())

	var tests = []struct {
		url    string
		out    string
		status int
	}{
		{s.URL, "{\n  \"ip\": \"127.0.0.1\",\n  \"ip_decimal\": 2130706433,\n  \"country\": \"Elbonia\",\n  \"country_iso\": \"EB\",\n  \"country_eu\": false,\n  \"region_name\": \"North Elbonia\",\n  \"region_code\": \"1234\",\n  \"metro_code\": 1234,\n  \"zip_code\": \"1234\",\n  \"city\": \"Bornyasherk\",\n  \"latitude\": 63.416667,\n  \"longitude\": 10.416667,\n  \"time_zone\": \"Europe/Bornyasherk\",\n  \"asn\": \"AS59795\",\n  \"asn_org\": \"Hosting4Real\",\n  \"hostname\": \"localhost\",\n  \"user_agent\": {\n    \"product\": \"curl\",\n    \"version\": \"7.2.6.0\",\n    \"raw_value\": \"curl/7.2.6.0\"\n  }\n}\n", 200},
		{s.URL + "/port/foo", "{\n  \"ok\": false,\n  \"error\": \"BAD_REQUEST\",\n  \"message\": \"Invalid request format\"\n}\n", 400},
		{s.URL + "/port/0", "{\n  \"ok\": false,\n  \"error\": \"BAD_REQUEST\",\n  \"message\": \"Invalid request format\"\n}\n", 400},
		{s.URL + "/port/65537", "{\n  \"ok\": false,\n  \"error\": \"BAD_REQUEST\",\n  \"message\": \"Invalid request format\"\n}\n", 400},
		{s.URL + "/port/31337", "{\n  \"ip\": \"127.0.0.1\",\n  \"port\": 31337,\n  \"reachable\": true\n}\n", 200},
		{s.URL + "/port/80", "{\n  \"ip\": \"127.0.0.1\",\n  \"port\": 80,\n  \"reachable\": true\n}\n", 200},            // checking that our test server is reachable on port 80
		{s.URL + "/port/80?ip=1.3.3.7", "{\n  \"ip\": \"127.0.0.1\",\n  \"port\": 80,\n  \"reachable\": true\n}\n", 200}, // ensuring that the "ip" parameter is not usable to check remote host ports
		{s.URL + "/foo", "{\n  \"ok\": false,\n  \"error\": \"NOT_FOUND\",\n  \"message\": \"Not found\"\n}\n", 404},
	}

	for _, tt := range tests {
		out, status, err := httpGet(tt.url, jsonMediaType, "curl/7.2.6.0")
		if err != nil {
			t.Fatal(err)
		}
		if status != tt.status {
			t.Errorf("Expected %d for %s, got %d", tt.status, tt.url, status)
		}
		if out != tt.out {
			t.Errorf("Expected %q for %s, got %q", tt.out, tt.url, out)
		}
	}
}

// TestHealthzHandler tests the /healthz endpoint per PART 16
func TestHealthzHandler(t *testing.T) {
	log.SetOutput(io.Discard)
	s := httptest.NewServer(testServer().Handler())

	// Test JSON response
	out, status, err := httpGet(s.URL+"/healthz", jsonMediaType, "curl/7.2.6.0")
	if err != nil {
		t.Fatal(err)
	}
	if status != 200 {
		t.Errorf("Expected 200 for /healthz, got %d", status)
	}

	// Verify response is valid JSON with required fields
	var health model.HealthResponse
	if err := json.Unmarshal([]byte(out), &health); err != nil {
		t.Fatalf("Failed to parse healthz response: %v", err)
	}
	if health.Status != "healthy" {
		t.Errorf("Expected status 'healthy', got %q", health.Status)
	}
	if health.Version != "test" {
		t.Errorf("Expected version 'test', got %q", health.Version)
	}
	if health.Mode != "development" {
		t.Errorf("Expected mode 'development', got %q", health.Mode)
	}

	// Test /api/v1/server/healthz (JSON by default per PART 14 with a non-tool UA;
	// AI.md's isHttpTool() treats an empty User-Agent as a non-interactive tool,
	// so a real client UA is used here to hit the JSON default branch)
	out, status, err = httpGet(s.URL+"/api/v1/server/healthz", "", "ipgaze-cli/1.0")
	if err != nil {
		t.Fatal(err)
	}
	if status != 200 {
		t.Errorf("Expected 200 for /api/v1/server/healthz, got %d", status)
	}
	if err := json.Unmarshal([]byte(out), &health); err != nil {
		t.Fatalf("Failed to parse api/v1/server/healthz response: %v", err)
	}
	if health.Status != "healthy" {
		t.Errorf("Expected status 'healthy', got %q", health.Status)
	}

	// Test /api/v1/server/healthz.txt (PART 14 priority 1: .txt extension always text)
	out, status, err = httpGet(s.URL+"/api/v1/server/healthz.txt", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if status != 200 {
		t.Errorf("Expected 200 for /api/v1/server/healthz.txt, got %d", status)
	}
	if !strings.Contains(out, "status: healthy") {
		t.Errorf("Expected plain-text healthz body to contain %q, got %q", "status: healthy", out)
	}
}

func TestCacheHandler(t *testing.T) {
	t.Setenv("DEBUG", "true")
	log.SetOutput(io.Discard)
	srv := testServer()
	// debug mode is now via s.config.IsDebug() — no profile field
	srv.SetConfig(&config.AppConfig{Server: config.ServerConfig{Debug: config.DebugConfig{RuntimeEndpoints: true}}})
	srv.SetOperatorToken("debug-token")
	s := httptest.NewServer(srv.Handler())
	got, _, err := httpGetBearer(s.URL+"/debug/cache", jsonMediaType, "", "debug-token")
	if err != nil {
		t.Fatal(err)
	}
	want := "{\n  \"size\": 0,\n  \"capacity\": 100,\n  \"evictions\": 0\n}\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCacheResizeHandler(t *testing.T) {
	t.Setenv("DEBUG", "true")
	log.SetOutput(io.Discard)
	srv := testServer()
	// debug mode is now via s.config.IsDebug() — no profile field
	srv.SetConfig(&config.AppConfig{Server: config.ServerConfig{Debug: config.DebugConfig{RuntimeEndpoints: true}}})
	srv.SetOperatorToken("debug-token")
	s := httptest.NewServer(srv.Handler())
	_, got, err := httpPostBearer(s.URL+"/debug/cache/resize", "10", "debug-token")
	if err != nil {
		t.Fatal(err)
	}
	want := "{\n  \"message\": \"Cache capacity updated\",\n  \"capacity\": 10\n}\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestDebugEndpointsRequireOperatorBearer(t *testing.T) {
	t.Setenv("DEBUG", "true")
	srv := testServer()
	srv.SetConfig(&config.AppConfig{Server: config.ServerConfig{Debug: config.DebugConfig{Pprof: true, RuntimeEndpoints: true}}})
	srv.SetOperatorToken("debug-token")
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	for _, endpoint := range []string{"/debug/vars", "/debug/pprof/cmdline"} {
		_, status, err := httpGet(ts.URL+endpoint, "application/json", "")
		if err != nil {
			t.Fatal(err)
		}
		if status != http.StatusUnauthorized {
			t.Errorf("unauthorized GET %s status = %d, want %d", endpoint, status, http.StatusUnauthorized)
		}
		_, status, err = httpGetBearer(ts.URL+endpoint, "application/json", "", "debug-token")
		if err != nil {
			t.Fatal(err)
		}
		if status != http.StatusOK {
			t.Errorf("authorized GET %s status = %d, want %d", endpoint, status, http.StatusOK)
		}
	}
}

func TestIPFromRequestUsesConfiguredProxyResolver(t *testing.T) {
	tests := []struct {
		name         string
		header       http.Header
		clientHeader string
		want         string
	}{
		{
			name:   "walks the forwarded chain from the trusted peer",
			header: http.Header{"X-Forwarded-For": {"8.8.8.8, 10.0.0.2"}},
			want:   "8.8.8.8",
		},
		{
			name:         "pinned header overrides automatic order",
			header:       http.Header{"X-Forwarded-For": {"8.8.8.8"}, "X-Real-Ip": {"9.9.9.9"}},
			clientHeader: "X-Real-IP",
			want:         "9.9.9.9",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = "10.0.0.1:1234"
			req.Header = tt.header
			resolver := netutil.NewTrustResolver(config.TrustedProxiesConfig{ClientIPHeader: tt.clientHeader}, "")
			got, err := ipFromRequestWithResolver(req, false, resolver)
			if err != nil {
				t.Fatalf("ipFromRequestWithResolver() error = %v", err)
			}
			if got.String() != tt.want {
				t.Fatalf("ipFromRequestWithResolver() = %s, want %s", got, tt.want)
			}
		})
	}
}

// TestDetectClientType covers the AI.md PART 14 frontend dispatch: our CLI gets
// JSON, text browsers and regular browsers get HTML, HTTP tools get text.
func TestDetectClientType(t *testing.T) {
	browserUserAgent := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_4) " +
		"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.28 " +
		"Safari/537.36"
	var tests = []struct {
		in  string
		out string
	}{
		{"curl/7.26.0", "text"},
		{"Wget/1.13.4 (linux-gnu)", "text"},
		{"Wget", "html"},
		{"fetch libfetch/2.0", "text"},
		{"HTTPie/0.9.3", "text"},
		{"httpie-go/0.6.0", "text"},
		{"Go 1.1 package server", "text"},
		{"Go-http-client/1.1", "text"},
		{"Go-http-client/2.0", "text"},
		{"ddclient/3.8.3", "text"},
		{"Mikrotik/6.x Fetch", "text"},
		{"", "text"},
		{"ipgaze-cli/1.2.3", "json"},
		{"Lynx/2.9.0dev.10 libwww-FM/2.14", "html"},
		{"w3m/0.5.3+git20230121", "html"},
		{browserUserAgent, "html"},
	}
	for _, tt := range tests {
		r := &http.Request{Header: http.Header{"User-Agent": []string{tt.in}}}
		if got := detectClientType(r); got != tt.out {
			t.Errorf("Expected %q, got %q for %q", tt.out, got, tt.in)
		}
	}
}

func TestDetectClientTypeAcceptPriority(t *testing.T) {
	tests := []struct{ accept, ua, want string }{
		{"application/json", "curl/8.5.0", "json"},
		{"text/html", "ipgaze-cli/1.0", "html"},
		{"text/plain", "ipgaze-cli/1.0", "text"},
		{"*/*", "curl/8.5.0", "text"},
	}
	for _, tt := range tests {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Accept", tt.accept)
		r.Header.Set("User-Agent", tt.ua)
		if got := detectClientType(r); got != tt.want {
			t.Errorf("detectClientType(%q, %q) = %q, want %q", tt.accept, tt.ua, got, tt.want)
		}
	}
}

func TestAPIResponseFormatAcceptPriority(t *testing.T) {
	tests := []struct{ path, accept, ua, want string }{
		{"/api/v1/ip", "", "curl/8.5.0", "text"},
		{"/api/v1/ip", "application/json", "curl/8.5.0", "json"},
		{"/api/v1/ip", "*/*", "curl/8.5.0", "json"},
		{"/api/v1/ip", "text/plain", "Mozilla/5.0", "text"},
		{"/api/v1/ip.txt", "application/json", "curl/8.5.0", "text"},
		{"/api/v1/ip", "", "ipgaze-cli/1.0", "json"},
	}
	for _, tt := range tests {
		r := httptest.NewRequest(http.MethodGet, tt.path, nil)
		r.Header.Set("Accept", tt.accept)
		r.Header.Set("User-Agent", tt.ua)
		if got := apiResponseFormat(r); got != tt.want {
			t.Errorf("apiResponseFormat(%q, %q) = %q, want %q", tt.path, tt.accept, got, tt.want)
		}
	}
}

func TestCsrfConfigFrom_SecureTrue(t *testing.T) {
	got := csrfConfigFrom(config.CSRFConfig{Secure: "true"})
	if got.Secure == nil || !*got.Secure {
		t.Errorf("csrfConfigFrom(Secure=true).Secure = %v, want pointer to true", got.Secure)
	}
}

func TestCsrfConfigFrom_SecureFalse(t *testing.T) {
	got := csrfConfigFrom(config.CSRFConfig{Secure: "false"})
	if got.Secure == nil || *got.Secure {
		t.Errorf("csrfConfigFrom(Secure=false).Secure = %v, want pointer to false", got.Secure)
	}
}

func TestCsrfConfigFrom_SecureAuto_NilMeansAutoDetect(t *testing.T) {
	got := csrfConfigFrom(config.CSRFConfig{Secure: "auto"})
	if got.Secure != nil {
		t.Errorf("csrfConfigFrom(Secure=auto).Secure = %v, want nil", got.Secure)
	}
}

func TestCsrfConfigFrom_SecureEmpty_NilMeansAutoDetect(t *testing.T) {
	got := csrfConfigFrom(config.CSRFConfig{Secure: ""})
	if got.Secure != nil {
		t.Errorf("csrfConfigFrom(Secure=\"\").Secure = %v, want nil", got.Secure)
	}
}

func TestCsrfConfigFrom_FieldsCopiedThrough(t *testing.T) {
	c := config.CSRFConfig{
		Enabled:     true,
		TokenLength: 64,
		CookieName:  "my_csrf",
		HeaderName:  "X-My-CSRF",
		ExemptPaths: []string{"/api/v1/webhooks/*"},
	}
	got := csrfConfigFrom(c)
	if got.Enabled != true || got.TokenLength != 64 || got.CookieName != "my_csrf" || got.HeaderName != "X-My-CSRF" {
		t.Errorf("csrfConfigFrom did not copy fields through: %+v", got)
	}
	found := false
	for _, p := range got.ExemptPaths {
		if p == "/api/v1/webhooks/*" {
			found = true
		}
	}
	if !found {
		t.Errorf("csrfConfigFrom(ExemptPaths) = %v, want to contain /api/v1/webhooks/*", got.ExemptPaths)
	}
}

func TestIPLookupOrNotFoundUncoveredBranches(t *testing.T) {
	log.SetOutput(io.Discard)
	s := httptest.NewServer(testServer().Handler())
	defer s.Close()

	// Path segment with "." but not a valid IP.
	if _, status, err := httpGet(s.URL+"/1.2.3.999", "", ""); err != nil {
		t.Fatal(err)
	} else if status != http.StatusNotFound {
		t.Errorf("GET /1.2.3.999: got status %d, want 404", status)
	}

	// Bracketed IPv6 address is trimmed and parsed.
	if _, status, err := httpGet(s.URL+"/[::1]", "", ""); err != nil {
		t.Fatal(err)
	} else if status != http.StatusOK {
		t.Errorf("GET /[::1]: got status %d, want 200", status)
	}
}

func TestServerLogManagerAndPublicIPSetters(t *testing.T) {
	s := testServer()

	// SetLogManager stores the manager (nil is a valid, no-op value).
	s.SetLogManager(nil)

	// PublicIP is empty until SetPublicIP is called.
	if got := s.PublicIP(); got != "" {
		t.Errorf("PublicIP() before SetPublicIP = %q, want empty", got)
	}
	s.SetPublicIP("203.0.113.5")
	if got := s.PublicIP(); got != "203.0.113.5" {
		t.Errorf("PublicIP() = %q, want %q", got, "203.0.113.5")
	}
}

func TestServerOperatorTokenSetAndValidate(t *testing.T) {
	s := testServer()

	// No token configured: validation always fails.
	if s.ValidateOperatorToken("anything") {
		t.Error("ValidateOperatorToken() with no token configured = true, want false")
	}

	s.SetOperatorToken("s3cr3t-token")
	if !s.ValidateOperatorToken("s3cr3t-token") {
		t.Error("ValidateOperatorToken() with matching token = false, want true")
	}
	if s.ValidateOperatorToken("wrong-token") {
		t.Error("ValidateOperatorToken() with mismatched token = true, want false")
	}

	// Clearing the token (empty string) disables validation again.
	s.SetOperatorToken("")
	if s.ValidateOperatorToken("s3cr3t-token") {
		t.Error("ValidateOperatorToken() after clearing token = true, want false")
	}
}

func TestAPIV1AuthCheckEndpoint(t *testing.T) {
	srv := testServer()
	srv.SetOperatorToken("test-operator-token")
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	for _, token := range []string{"", "wrong-token"} {
		req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/server/auth/check", nil)
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("invalid token status = %d, want 401", resp.StatusCode)
		}
	}

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/server/auth/check", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer test-operator-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("valid token status = %d, want 200", resp.StatusCode)
	}
	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["ok"] != true {
		t.Errorf("valid-token response = %#v, want standard success envelope", body)
	}
	data, ok := body["data"].(map[string]interface{})
	if !ok || data["kind"] != "operator" {
		t.Errorf("valid-token data = %#v, want kind operator", body["data"])
	}
	encoded, _ := json.Marshal(body)
	if strings.Contains(string(encoded), "test-operator-token") {
		t.Fatal("auth check echoed the bearer token")
	}
}

func TestServerSetThreatLookupAndSetHostIPs(t *testing.T) {
	s := testServer()

	// SetThreatLookup with a nil ipService must not panic.
	s.SetThreatLookup(nil)

	// SetHostIPs accepts valid IPv4/IPv6 and ignores invalid values.
	s.SetHostIPs("198.51.100.7", "2001:db8::1")
	if s.HostIPv4 != "198.51.100.7" {
		t.Errorf("HostIPv4 = %q, want %q", s.HostIPv4, "198.51.100.7")
	}
	if s.HostIPv6 != "2001:db8::1" {
		t.Errorf("HostIPv6 = %q, want %q", s.HostIPv6, "2001:db8::1")
	}

	s2 := testServer()
	// Invalid IPv4 (an IPv6 address) and invalid IPv6 (an IPv4 address) are both ignored.
	s2.SetHostIPs("2001:db8::1", "198.51.100.7")
	if s2.HostIPv4 != "" {
		t.Errorf("HostIPv4 with invalid input = %q, want empty", s2.HostIPv4)
	}
	if s2.HostIPv6 != "" {
		t.Errorf("HostIPv6 with invalid input = %q, want empty", s2.HostIPv6)
	}
}

func TestServerSetTrust(t *testing.T) {
	s := testServer()
	tr := netutil.NewTrustResolver(config.TrustedProxiesConfig{}, "")
	s.SetTrust(tr)
	if s.trust != tr {
		t.Error("SetTrust did not store the given TrustResolver")
	}
}

type fakeCacheBackendPinger struct{ err error }

func (f *fakeCacheBackendPinger) Ping(_ context.Context) error { return f.err }

func TestServerSetCacheBackend(t *testing.T) {
	s := testServer()
	if s.cacheBackend != nil {
		t.Fatal("cacheBackend before SetCacheBackend = non-nil, want nil")
	}
	backend := &fakeCacheBackendPinger{}
	s.SetCacheBackend(backend)
	if s.cacheBackend != backend {
		t.Error("SetCacheBackend did not store the given backend")
	}
}

func TestServerSetDiskUsageFunc(t *testing.T) {
	s := testServer()
	if s.diskUsageFunc != nil {
		t.Fatal("diskUsageFunc before SetDiskUsageFunc = non-nil, want nil")
	}
	fn := func(_ string) (uint64, int, error) { return 1024, 50, nil }
	s.SetDiskUsageFunc(fn)
	if s.diskUsageFunc == nil {
		t.Fatal("SetDiskUsageFunc did not store the given function")
	}
	bytesFree, pctUsed, err := s.diskUsageFunc("/tmp")
	if err != nil || bytesFree != 1024 || pctUsed != 50 {
		t.Errorf("diskUsageFunc(\"/tmp\") = (%d, %d, %v), want (1024, 50, nil)", bytesFree, pctUsed, err)
	}
}

type fakeOverlayStatusProvider struct {
	available bool
	running   bool
	status    string
	hostname  string
}

func (f *fakeOverlayStatusProvider) IsAvailable() bool   { return f.available }
func (f *fakeOverlayStatusProvider) IsRunning() bool     { return f.running }
func (f *fakeOverlayStatusProvider) Status() string      { return f.status }
func (f *fakeOverlayStatusProvider) GetHostname() string { return f.hostname }

func TestServerSetTorStatus(t *testing.T) {
	s := testServer()
	if s.TorStatus != nil {
		t.Fatal("TorStatus before SetTorStatus = non-nil, want nil")
	}
	ts := &fakeOverlayStatusProvider{available: true, running: true, status: "running", hostname: "abc.onion"}
	s.SetTorStatus(ts)
	if s.TorStatus != ts {
		t.Error("SetTorStatus did not store the given provider")
	}
	if s.TorStatus.GetHostname() != "abc.onion" {
		t.Errorf("TorStatus.GetHostname() = %q, want %q", s.TorStatus.GetHostname(), "abc.onion")
	}
}

func TestServerSetI2PStatus(t *testing.T) {
	s := testServer()
	if s.I2PStatus != nil {
		t.Fatal("I2PStatus before SetI2PStatus = non-nil, want nil")
	}
	is := &fakeOverlayStatusProvider{available: true, running: true, status: "running", hostname: "abc.b32.i2p"}
	s.SetI2PStatus(is)
	if s.I2PStatus != is {
		t.Error("SetI2PStatus did not store the given provider")
	}
	if s.I2PStatus.GetHostname() != "abc.b32.i2p" {
		t.Errorf("I2PStatus.GetHostname() = %q, want %q", s.I2PStatus.GetHostname(), "abc.b32.i2p")
	}
}
