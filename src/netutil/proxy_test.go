package netutil

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/apimgr/ipgaze/src/config"
)

// --- getProto ---

func TestGetProto_Default(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if got := getProto(r, false); got != "http" {
		t.Errorf("getProto default = %q; want %q", got, "http")
	}
}

func TestGetProto_HTTPSScheme_ReturnsTLS(t *testing.T) {
	// httptest.NewRequest with an https URL automatically sets r.TLS to a non-nil
	// tls.ConnectionState, so getProto must return "https".
	r := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	got := getProto(r, false)
	if got != "https" {
		t.Errorf("getProto https URL = %q; want https", got)
	}
}

func TestGetProto_XForwardedProto_Trusted(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-Proto", "HTTPS")
	if got := getProto(r, true); got != "https" {
		t.Errorf("getProto X-Forwarded-Proto trusted = %q; want https", got)
	}
}

func TestGetProto_XForwardedProto_Untrusted(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	if got := getProto(r, false); got != "http" {
		t.Errorf("getProto X-Forwarded-Proto untrusted = %q; want http (header ignored)", got)
	}
}

func TestGetProto_XForwardedSSL_On(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-Ssl", "on")
	if got := getProto(r, true); got != "https" {
		t.Errorf("getProto X-Forwarded-Ssl trusted = %q; want https", got)
	}
}

func TestGetProto_XUrlScheme(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Url-Scheme", "HTTPS")
	if got := getProto(r, true); got != "https" {
		t.Errorf("getProto X-Url-Scheme = %q; want https", got)
	}
}

// --- getPort ---

func TestGetPort_NoPort(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "example.com"
	if got := getPort(r, false); got != "" {
		t.Errorf("getPort no port = %q; want empty", got)
	}
}

func TestGetPort_Port8080(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "example.com:8080"
	if got := getPort(r, false); got != "8080" {
		t.Errorf("getPort :8080 = %q; want 8080", got)
	}
}

func TestGetPort_Port80_Omitted(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "example.com:80"
	if got := getPort(r, false); got != "" {
		t.Errorf("getPort :80 = %q; want empty (default port suppressed)", got)
	}
}

func TestGetPort_Port443_Omitted(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "example.com:443"
	if got := getPort(r, false); got != "" {
		t.Errorf("getPort :443 = %q; want empty (default port suppressed)", got)
	}
}

func TestGetPort_XForwardedPort_Trusted(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-Port", "9090")
	if got := getPort(r, true); got != "9090" {
		t.Errorf("getPort X-Forwarded-Port trusted = %q; want 9090", got)
	}
}

func TestGetPort_XForwardedPort_80_Omitted(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-Port", "80")
	if got := getPort(r, true); got != "" {
		t.Errorf("getPort X-Forwarded-Port=80 = %q; want empty", got)
	}
}

func TestGetPort_XForwardedPort_Untrusted_Ignored(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-Port", "9090")
	r.Host = "example.com:8080"
	if got := getPort(r, false); got != "8080" {
		t.Errorf("getPort X-Forwarded-Port untrusted = %q; want 8080 from Host", got)
	}
}

// --- getBaseURLPath ---

func TestGetBaseURLPath_Default(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if got := getBaseURLPath(r, false); got != "/" {
		t.Errorf("getBaseURLPath default = %q; want /", got)
	}
}

func TestGetBaseURLPath_XForwardedPrefix_Trusted(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-Prefix", "/app")
	if got := getBaseURLPath(r, true); got != "/app" {
		t.Errorf("getBaseURLPath X-Forwarded-Prefix = %q; want /app", got)
	}
}

func TestGetBaseURLPath_XForwardedPath_Trusted(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-Path", "/base")
	if got := getBaseURLPath(r, true); got != "/base" {
		t.Errorf("getBaseURLPath X-Forwarded-Path = %q; want /base", got)
	}
}

func TestGetBaseURLPath_XScriptName_Trusted(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Script-Name", "/prefix")
	if got := getBaseURLPath(r, true); got != "/prefix" {
		t.Errorf("getBaseURLPath X-Script-Name = %q; want /prefix", got)
	}
}

func TestGetBaseURLPath_Untrusted_HeaderIgnored(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-Prefix", "/ignored")
	if got := getBaseURLPath(r, false); got != "/" {
		t.Errorf("getBaseURLPath untrusted = %q; want / (header ignored)", got)
	}
}

// --- GetClientIP ---

func TestGetClientIP_RemoteAddr(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.1:51234"
	if got := GetClientIP(r, false); got != "203.0.113.1" {
		t.Errorf("GetClientIP RemoteAddr = %q; want 203.0.113.1", got)
	}
}

func TestGetClientIP_XForwardedFor_Single_Trusted(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:9999"
	r.Header.Set("X-Forwarded-For", "203.0.113.5")
	if got := GetClientIP(r, true); got != "203.0.113.5" {
		t.Errorf("GetClientIP XFF single = %q; want 203.0.113.5", got)
	}
}

func TestGetClientIP_XForwardedFor_Chain_Trusted(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:9999"
	r.Header.Set("X-Forwarded-For", "203.0.113.5, 10.0.0.2, 10.0.0.3")
	if got := GetClientIP(r, true); got != "203.0.113.5" {
		t.Errorf("GetClientIP XFF chain = %q; want leftmost 203.0.113.5", got)
	}
}

func TestGetClientIP_XForwardedFor_Untrusted_Ignored(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.1:51234"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := GetClientIP(r, false); got != "203.0.113.1" {
		t.Errorf("GetClientIP XFF untrusted = %q; want RemoteAddr", got)
	}
}

func TestGetClientIP_CFConnectingIP_Trusted(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:9999"
	r.Header.Set("CF-Connecting-IP", "198.51.100.7")
	if got := GetClientIP(r, true); got != "198.51.100.7" {
		t.Errorf("GetClientIP CF-Connecting-IP = %q; want 198.51.100.7", got)
	}
}

func TestGetClientIP_XRealIP_Trusted(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:9999"
	r.Header.Set("X-Real-IP", "198.51.100.9")
	if got := GetClientIP(r, true); got != "198.51.100.9" {
		t.Errorf("GetClientIP X-Real-IP = %q; want 198.51.100.9", got)
	}
}

// --- TrustResolver / IsTrustedPeer ---

func TestNewTrustResolver_NoListenAddr(t *testing.T) {
	tr := NewTrustResolver(testTrustCfg(), "")
	if tr == nil {
		t.Fatal("NewTrustResolver returned nil")
	}
}

func TestNewTrustResolver_IPv4ListenAddr(t *testing.T) {
	tr := NewTrustResolver(testTrustCfg(), "10.0.0.5")
	if tr == nil {
		t.Fatal("NewTrustResolver returned nil")
	}
	if tr.listenCIDR == nil {
		t.Error("expected listenCIDR to be set for 10.0.0.5")
	}
}

func TestNewTrustResolver_Loopback_Excluded(t *testing.T) {
	tr := NewTrustResolver(testTrustCfg(), "0.0.0.0")
	if tr == nil {
		t.Fatal("NewTrustResolver returned nil")
	}
}

func TestIsTrustedPeer_Loopback_AlwaysTrusted(t *testing.T) {
	tr := NewTrustResolver(testTrustCfg(), "")
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "127.0.0.1:12345"
	if !tr.IsTrustedPeer(r) {
		t.Error("127.0.0.1 must always be trusted")
	}
}

func TestIsTrustedPeer_RFC1918_AlwaysTrusted(t *testing.T) {
	tr := NewTrustResolver(testTrustCfg(), "")
	for _, ip := range []string{"10.1.2.3", "172.16.0.1", "192.168.1.100"} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = ip + ":9999"
		if !tr.IsTrustedPeer(r) {
			t.Errorf("RFC 1918 %s must always be trusted", ip)
		}
	}
}

func TestIsTrustedPeer_PublicIP_NotTrusted(t *testing.T) {
	tr := NewTrustResolver(testTrustCfg(), "")
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.50:9999"
	if tr.IsTrustedPeer(r) {
		t.Error("public IP 203.0.113.50 must not be trusted by default")
	}
}

func TestIsTrustedPeer_NilResolver_LoopbackStillTrusted(t *testing.T) {
	var tr *TrustResolver
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	if !tr.IsTrustedPeer(r) {
		t.Error("nil TrustResolver: loopback must still be trusted via alwaysTrustedCIDRs")
	}
}

func TestIsTrustedPeer_NilResolver_PublicNotTrusted(t *testing.T) {
	var tr *TrustResolver
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "8.8.8.8:53"
	if tr.IsTrustedPeer(r) {
		t.Error("nil TrustResolver: public IP must not be trusted")
	}
}

// testTrustCfg returns an empty TrustedProxiesConfig for use in tests.
func testTrustCfg() testCfg { return testCfg{} }

// testCfg satisfies the config.TrustedProxiesConfig shape used by NewTrustResolver.
type testCfg = config.TrustedProxiesConfig

// --- isTorRequest ---

func TestIsTorRequest_EmptyOnionAddress_ReturnsFalse(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "abc123.onion"
	if isTorRequest(r, "") {
		t.Error("isTorRequest with empty onionAddress must return false")
	}
}

func TestIsTorRequest_MatchingHost_ReturnsTrue(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "abc123def456abc123def456abc123def456abc123def456abc123de.onion"
	if !isTorRequest(r, "abc123def456abc123def456abc123def456abc123def456abc123de.onion") {
		t.Error("isTorRequest must return true when Host matches onionAddress")
	}
}

func TestIsTorRequest_CaseInsensitive_ReturnsTrue(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "ABC123.ONION"
	if !isTorRequest(r, "abc123.onion") {
		t.Error("isTorRequest must be case-insensitive")
	}
}

func TestIsTorRequest_WithPort_StripsPortAndMatches(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "abc123.onion:80"
	if !isTorRequest(r, "abc123.onion") {
		t.Error("isTorRequest must strip port from Host before comparing")
	}
}

func TestIsTorRequest_DifferentHost_ReturnsFalse(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "example.com"
	if isTorRequest(r, "abc123.onion") {
		t.Error("isTorRequest must return false when Host does not match onionAddress")
	}
}

// --- IsTorRequest / IsI2PRequest (exported TrustResolver wrappers) ---

func TestIsTorRequest_NilResolver_ReturnsFalse(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "abc123.onion"
	if IsTorRequest(r, nil) {
		t.Error("IsTorRequest with nil resolver must return false")
	}
}

func TestIsTorRequest_MatchingResolver_ReturnsTrue(t *testing.T) {
	tr := NewTrustResolver(testTrustCfg(), "")
	tr.OnionAddress = "abc123.onion"
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "abc123.onion"
	if !IsTorRequest(r, tr) {
		t.Error("IsTorRequest must return true when Host matches tr.OnionAddress")
	}
}

func TestIsTorRequest_NonMatchingResolver_ReturnsFalse(t *testing.T) {
	tr := NewTrustResolver(testTrustCfg(), "")
	tr.OnionAddress = "abc123.onion"
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "example.com"
	if IsTorRequest(r, tr) {
		t.Error("IsTorRequest must return false when Host does not match tr.OnionAddress")
	}
}

func TestIsI2PRequest_NilResolver_ReturnsFalse(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "abc123.b32.i2p"
	if IsI2PRequest(r, nil) {
		t.Error("IsI2PRequest with nil resolver must return false")
	}
}

func TestIsI2PRequest_MatchingResolver_ReturnsTrue(t *testing.T) {
	tr := NewTrustResolver(testTrustCfg(), "")
	tr.I2PAddress = "abc123.b32.i2p"
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "abc123.b32.i2p"
	if !IsI2PRequest(r, tr) {
		t.Error("IsI2PRequest must return true when Host matches tr.I2PAddress")
	}
}

func TestIsI2PRequest_NonMatchingResolver_ReturnsFalse(t *testing.T) {
	tr := NewTrustResolver(testTrustCfg(), "")
	tr.I2PAddress = "abc123.b32.i2p"
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "example.com"
	if IsI2PRequest(r, tr) {
		t.Error("IsI2PRequest must return false when Host does not match tr.I2PAddress")
	}
}

// --- getURLVars priority 0 Tor detection ---

func TestGetURLVars_TorPriority0_ReturnsOnionProtoAndNoPort(t *testing.T) {
	onion := "abc123def456.onion"
	tr := NewTrustResolver(testTrustCfg(), "")
	tr.OnionAddress = onion

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	// Public peer — would not be trusted for proxy headers.
	r.RemoteAddr = "203.0.113.1:12345"
	r.Host = onion
	// Inject forged proxy headers to confirm they are bypassed.
	r.Header.Set("X-Forwarded-Host", "evil.example.com")
	r.Header.Set("X-Forwarded-Proto", "https")

	proto, fqdn, port := getURLVars(r, tr)
	if proto != "http" {
		t.Errorf("Tor priority 0: proto = %q; want %q", proto, "http")
	}
	if fqdn != onion {
		t.Errorf("Tor priority 0: fqdn = %q; want %q", fqdn, onion)
	}
	if port != "" {
		t.Errorf("Tor priority 0: port = %q; want empty (Tor never appends port)", port)
	}
}

func TestGetURLVars_NoOnionAddress_FallsThrough(t *testing.T) {
	tr := NewTrustResolver(testTrustCfg(), "")
	// OnionAddress is empty — normal resolution applies.

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "127.0.0.1:12345"
	r.Host = "example.com"

	proto, fqdn, port := getURLVars(r, tr)
	if proto != "http" {
		t.Errorf("non-Tor: proto = %q; want http", proto)
	}
	if fqdn != "example.com" {
		t.Errorf("non-Tor: fqdn = %q; want example.com", fqdn)
	}
	_ = port
}

// --- BuildURL ---

func TestBuildURL_NoPort_OmittedFromOutput(t *testing.T) {
	tr := NewTrustResolver(testTrustCfg(), "")
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "127.0.0.1:12345"
	r.Host = "example.com"

	got := BuildURL(r, tr, "/ip")
	want := "http://example.com/ip"
	if got != want {
		t.Errorf("BuildURL() = %q, want %q", got, want)
	}
}

func TestBuildURL_WithPort_IncludedInOutput(t *testing.T) {
	tr := NewTrustResolver(testTrustCfg(), "")
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "127.0.0.1:12345"
	r.Host = "example.com:8080"

	got := BuildURL(r, tr, "/ip")
	want := "http://example.com:8080/ip"
	if got != want {
		t.Errorf("BuildURL() = %q, want %q", got, want)
	}
}

// --- GetClientIP: full six-tier priority (AI.md PART 15) ---

// clientIPHeaders holds one candidate value for each of the five proxy headers
// GetClientIP consults, in the spec's priority order.
var clientIPHeaders = []struct {
	name  string
	value string
}{
	{"CF-Connecting-IP", "198.51.100.1"},
	{"True-Client-IP", "198.51.100.2"},
	{"X-Real-IP", "198.51.100.3"},
	{"X-Forwarded-For", "198.51.100.4, 10.0.0.1"},
	{"X-Client-IP", "198.51.100.5"},
}

// clientIPWinners lists the value GetClientIP must return when the header at
// the matching index of clientIPHeaders is the highest-priority one present.
var clientIPWinners = []string{
	"198.51.100.1",
	"198.51.100.2",
	"198.51.100.3",
	"198.51.100.4",
	"198.51.100.5",
}

func TestGetClientIP_PriorityOrder_Trusted(t *testing.T) {
	for i := range clientIPHeaders {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "203.0.113.1:1234"
		// Set the winning header plus every lower-priority header, so a wrong
		// order picks one of the losers instead.
		for j := i; j < len(clientIPHeaders); j++ {
			r.Header.Set(clientIPHeaders[j].name, clientIPHeaders[j].value)
		}
		if got := GetClientIP(r, true); got != clientIPWinners[i] {
			t.Errorf("GetClientIP with %s highest = %q; want %q",
				clientIPHeaders[i].name, got, clientIPWinners[i])
		}
	}
}

func TestGetClientIP_AllHeadersUntrusted_UsesRemoteAddr(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.1:1234"
	for _, h := range clientIPHeaders {
		r.Header.Set(h.name, h.value)
	}
	if got := GetClientIP(r, false); got != "203.0.113.1" {
		t.Errorf("GetClientIP untrusted = %q; want 203.0.113.1", got)
	}
}

func TestGetClientIP_TrueClientIP_Trusted(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.1:1234"
	r.Header.Set("True-Client-IP", "198.51.100.2")
	if got := GetClientIP(r, true); got != "198.51.100.2" {
		t.Errorf("GetClientIP True-Client-IP = %q; want 198.51.100.2", got)
	}
}

func TestGetClientIP_XClientIP_Trusted(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.1:1234"
	r.Header.Set("X-Client-IP", "198.51.100.5")
	if got := GetClientIP(r, true); got != "198.51.100.5" {
		t.Errorf("GetClientIP X-Client-IP = %q; want 198.51.100.5", got)
	}
}

func TestGetClientIP_BlankXFF_FallsThroughToXClientIP(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.1:1234"
	r.Header.Set("X-Forwarded-For", "   ")
	r.Header.Set("X-Client-IP", "198.51.100.5")
	if got := GetClientIP(r, true); got != "198.51.100.5" {
		t.Errorf("GetClientIP blank XFF = %q; want 198.51.100.5", got)
	}
}

func TestGetClientIdentifier_TorRequestNeverReportsLoopback(t *testing.T) {
	tr := &TrustResolver{OnionAddress: "exampleonionaddress.onion"}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "exampleonionaddress.onion"
	r.RemoteAddr = "127.0.0.1:41234"
	if got := GetClientIdentifier(r, tr); got != TorClientSentinel {
		t.Errorf("GetClientIdentifier for a Tor request = %q; want %q", got, TorClientSentinel)
	}
}

func TestGetClientIdentifier_TorCircuitIDExported(t *testing.T) {
	tr := &TrustResolver{OnionAddress: "exampleonionaddress.onion"}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "exampleonionaddress.onion"
	r.RemoteAddr = "[fc00:dead:beef:4dad::1:2a]:41234"
	if got := GetClientIdentifier(r, tr); got != "tor:65578" {
		t.Errorf("GetClientIdentifier with exported circuit ID = %q; want tor:65578", got)
	}
}

func TestGetClientIP_CircuitIDAddressIsNeverReportedAsAnIP(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "[fc00:dead:beef:4dad::1]:41234"
	got := GetClientIP(r, false)
	if !strings.HasPrefix(got, TorClientSentinel+":") {
		t.Errorf("GetClientIP for an exported-circuit address = %q; want a tor:{circuit_id} identifier", got)
	}
}

func TestGetClientIdentifier_ClearnetUsesGetClientIP(t *testing.T) {
	tr := &TrustResolver{OnionAddress: "exampleonionaddress.onion"}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "example.com"
	r.RemoteAddr = "203.0.113.7:1234"
	if got := GetClientIdentifier(r, tr); got != "203.0.113.7" {
		t.Errorf("GetClientIdentifier for a clearnet request = %q; want 203.0.113.7", got)
	}
}
