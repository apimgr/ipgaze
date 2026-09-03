package server

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/apimgr/ipgaze/src/config"
	"github.com/apimgr/ipgaze/src/iputil/geo"
	"github.com/apimgr/ipgaze/src/netutil"
	"github.com/apimgr/ipgaze/src/server/model"
)

func lookupAddr(net.IP) (string, error) { return "localhost", nil }
func lookupPort(net.IP, uint64) error   { return nil }

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
		cache:      NewCache(100),
		gr:         &testDb{},
		LookupAddr: lookupAddr,
		LookupPort: lookupPort,
		StartTime:  time.Now(),
		Version:    "test",
		Mode:       "development",
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
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	if err != nil {
		return "", 0, err
	}
	return string(data), res.StatusCode, nil
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
	defer res.Body.Close()
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

	// Test /api/v1/server/healthz (JSON by default per PART 14: empty UA + empty Accept
	// is not a detected HTTP tool, so the canonical versioned path returns JSON)
	out, status, err = httpGet(s.URL+"/api/v1/server/healthz", "", "")
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
	s := httptest.NewServer(srv.Handler())
	got, _, err := httpGet(s.URL+"/debug/cache", jsonMediaType, "")
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
	s := httptest.NewServer(srv.Handler())
	_, got, err := httpPost(s.URL+"/debug/cache/resize", "10")
	if err != nil {
		t.Fatal(err)
	}
	want := "{\n  \"message\": \"Cache capacity updated\",\n  \"capacity\": 10\n}\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestIPFromRequest(t *testing.T) {
	var tests = []struct {
		remoteAddr     string
		headerKey      string
		headerValue    string
		trustedHeaders []string
		trustedPeer    bool
		out            string
	}{
		{"127.0.0.1:9999", "", "", nil, true, "127.0.0.1"},                                                                // No header given
		{"127.0.0.1:9999", "X-Real-IP", "1.3.3.7", nil, true, "127.0.0.1"},                                                // Trusted header is empty
		{"127.0.0.1:9999", "X-Real-IP", "1.3.3.7", []string{"X-Foo-Bar"}, true, "127.0.0.1"},                              // Trusted header does not match
		{"127.0.0.1:9999", "X-Real-IP", "1.3.3.7", []string{"X-Real-IP", "X-Forwarded-For"}, true, "1.3.3.7"},             // Trusted header matches
		{"127.0.0.1:9999", "X-Forwarded-For", "1.3.3.7", []string{"X-Real-IP", "X-Forwarded-For"}, true, "1.3.3.7"},       // Second trusted header matches
		{"127.0.0.1:9999", "X-Forwarded-For", "1.3.3.7,4.2.4.2", []string{"X-Forwarded-For"}, true, "1.3.3.7"},            // X-Forwarded-For with multiple entries (commas separator)
		{"127.0.0.1:9999", "X-Forwarded-For", "1.3.3.7, 4.2.4.2", []string{"X-Forwarded-For"}, true, "1.3.3.7"},           // X-Forwarded-For with multiple entries (space+comma separator)
		{"127.0.0.1:9999", "X-Forwarded-For", "", []string{"X-Forwarded-For"}, true, "127.0.0.1"},                         // Empty header
		{"127.0.0.1:9999?ip=1.2.3.4", "", "", nil, true, "1.2.3.4"},                                                       // passed in "ip" parameter
		{"127.0.0.1:9999?ip=1.2.3.4", "X-Forwarded-For", "1.3.3.7,4.2.4.2", []string{"X-Forwarded-For"}, true, "1.2.3.4"}, // ip parameter wins over X-Forwarded-For with multiple entries
		{"127.0.0.1:9999", "X-Forwarded-For", "1.3.3.7,4.2.4.2", []string{"X-Forwarded-For"}, false, "127.0.0.1"},         // Untrusted peer: header ignored even though it matches
		{"127.0.0.1:9999", "X-Real-IP", "1.3.3.7", []string{"X-Real-IP"}, false, "127.0.0.1"},                             // Untrusted peer: X-Real-IP ignored
	}
	for _, tt := range tests {
		u, err := url.Parse("http://" + tt.remoteAddr)
		if err != nil {
			t.Fatal(err)
		}
		r := &http.Request{
			RemoteAddr: u.Host,
			Header:     http.Header{},
			URL:        u,
		}
		r.Header.Add(tt.headerKey, tt.headerValue)
		ip, err := ipFromRequest(tt.trustedHeaders, r, true, tt.trustedPeer)
		if err != nil {
			t.Fatal(err)
		}
		out := net.ParseIP(tt.out)
		if !ip.Equal(out) {
			t.Errorf("Expected %s, got %s", out, ip)
		}
	}
}

func TestCLIMatcher(t *testing.T) {
	browserUserAgent := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_4) " +
		"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.28 " +
		"Safari/537.36"
	var tests = []struct {
		in  string
		out bool
	}{
		{"curl/7.26.0", true},
		{"Wget/1.13.4 (linux-gnu)", true},
		{"Wget", true},
		{"fetch libfetch/2.0", true},
		{"HTTPie/0.9.3", true},
		{"httpie-go/0.6.0", true},
		{"Go 1.1 package server", true},
		{"Go-http-client/1.1", true},
		{"Go-http-client/2.0", true},
		{"ddclient/3.8.3", true},
		{"Mikrotik/6.x Fetch", true},
		{browserUserAgent, false},
	}
	for _, tt := range tests {
		r := &http.Request{Header: http.Header{"User-Agent": []string{tt.in}}}
		if got := cliMatcher(r); got != tt.out {
			t.Errorf("Expected %t, got %t for %q", tt.out, got, tt.in)
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
