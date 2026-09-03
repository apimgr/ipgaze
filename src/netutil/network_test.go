package netutil

import (
	"net"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// parseIP
// ---------------------------------------------------------------------------

func TestParseIP_ValidIPv4(t *testing.T) {
	cases := []string{"1.2.3.4", "192.168.0.1", "0.0.0.0", "255.255.255.255"}
	for _, s := range cases {
		ip, err := parseIP(s)
		if err != nil {
			t.Errorf("parseIP(%q) error: %v", s, err)
			continue
		}
		if ip == nil {
			t.Errorf("parseIP(%q) = nil, want non-nil", s)
		}
	}
}

func TestParseIP_ValidIPv6(t *testing.T) {
	cases := []string{
		"::1",
		"2001:db8::1",
		"fe80::1",
		"2001:4860:4860::8888",
	}
	for _, s := range cases {
		ip, err := parseIP(s)
		if err != nil {
			t.Errorf("parseIP(%q) error: %v", s, err)
			continue
		}
		if ip == nil {
			t.Errorf("parseIP(%q) = nil, want non-nil", s)
		}
	}
}

// parseIP must strip brackets that appear in URL form.
func TestParseIP_BracketedIPv6(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"[::1]", "::1"},
		{"[2001:db8::1]", "2001:db8::1"},
	}
	for _, tc := range cases {
		ip, err := parseIP(tc.input)
		if err != nil {
			t.Errorf("parseIP(%q) error: %v", tc.input, err)
			continue
		}
		want := net.ParseIP(tc.want)
		if !ip.Equal(want) {
			t.Errorf("parseIP(%q) = %v, want %v", tc.input, ip, want)
		}
	}
}

func TestParseIP_Invalid(t *testing.T) {
	cases := []string{"", "not-an-ip", "256.0.0.1", ":::", "localhost", "example.com"}
	for _, s := range cases {
		ip, err := parseIP(s)
		if err == nil {
			t.Errorf("parseIP(%q): expected error, got nil (ip=%v)", s, ip)
		}
	}
}

// ---------------------------------------------------------------------------
// isIPv6
// ---------------------------------------------------------------------------

func TestIsIPv6_IPv4_ReturnsFalse(t *testing.T) {
	cases := []string{"1.2.3.4", "192.168.1.100", "10.0.0.1"}
	for _, s := range cases {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("net.ParseIP(%q) = nil", s)
		}
		if isIPv6(ip) {
			t.Errorf("isIPv6(%q) = true, want false", s)
		}
	}
}

func TestIsIPv6_IPv6_ReturnsTrue(t *testing.T) {
	cases := []string{"::1", "2001:db8::1", "fe80::1", "2001:4860:4860::8888"}
	for _, s := range cases {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("net.ParseIP(%q) = nil", s)
		}
		if !isIPv6(ip) {
			t.Errorf("isIPv6(%q) = false, want true", s)
		}
	}
}

// An IPv4-mapped IPv6 address is still addressable as IPv4 via To4().
func TestIsIPv6_IPv4MappedIPv6(t *testing.T) {
	ip := net.ParseIP("::ffff:192.0.2.1")
	if ip == nil {
		t.Fatal("net.ParseIP(::ffff:192.0.2.1) = nil")
	}
	// ::ffff:x.x.x.x has a valid To4(), so isIPv6 should return false.
	if isIPv6(ip) {
		t.Error("isIPv6(::ffff:192.0.2.1) = true, want false (has IPv4 mapping)")
	}
}

// ---------------------------------------------------------------------------
// formatURLWithIP (internal — accessible within the package)
// ---------------------------------------------------------------------------

func TestFormatURLWithIP_IPv4(t *testing.T) {
	got := formatURLWithIP("192.168.1.1", "8080")
	want := "http://192.168.1.1:8080"
	if got != want {
		t.Errorf("formatURLWithIP(IPv4) = %q, want %q", got, want)
	}
}

func TestFormatURLWithIP_IPv6_WrapsInBrackets(t *testing.T) {
	got := formatURLWithIP("::1", "9000")
	want := "http://[::1]:9000"
	if got != want {
		t.Errorf("formatURLWithIP(IPv6) = %q, want %q", got, want)
	}
}

func TestFormatURLWithIP_IPv6_Full(t *testing.T) {
	got := formatURLWithIP("2001:db8::1", "443")
	want := "http://[2001:db8::1]:443"
	if got != want {
		t.Errorf("formatURLWithIP(IPv6 full) = %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// formatURLWithHost (internal)
// ---------------------------------------------------------------------------

func TestFormatURLWithHost(t *testing.T) {
	cases := []struct {
		host string
		port string
		want string
	}{
		{"example.com", "8080", "http://example.com:8080"},
		{"myserver", "3000", "http://myserver:3000"},
		{"192.168.1.1", "80", "http://192.168.1.1:80"},
	}
	for _, tc := range cases {
		got := formatURLWithHost(tc.host, tc.port)
		if got != tc.want {
			t.Errorf("formatURLWithHost(%q,%q) = %q, want %q", tc.host, tc.port, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// getAccessibleURL
// ---------------------------------------------------------------------------

// getAccessibleURL must never return localhost or 0.0.0.0 in the result.
func TestGetAccessibleURL_NeverReturnsLocalhost(t *testing.T) {
	got := getAccessibleURL("8080")
	for _, bad := range []string{"localhost", "127.0.0.1", "0.0.0.0"} {
		if strings.Contains(got, bad) {
			t.Errorf("getAccessibleURL returned %q which contains forbidden value %q", got, bad)
		}
	}
}

// getAccessibleURL must always embed the port.
func TestGetAccessibleURL_ContainsPort(t *testing.T) {
	port := "12345"
	got := getAccessibleURL(port)
	if !strings.Contains(got, port) {
		t.Errorf("getAccessibleURL(%q) = %q, does not contain port", port, got)
	}
}

// getAccessibleURL must return an http:// URL or a fallback with the port.
func TestGetAccessibleURL_StartsWithHTTPOrFallback(t *testing.T) {
	got := getAccessibleURL("8080")
	if !strings.HasPrefix(got, "http://") && !strings.Contains(got, "8080") {
		t.Errorf("getAccessibleURL() = %q — unexpected format", got)
	}
}

// ---------------------------------------------------------------------------
// getOutboundIP — best-effort; result must be a parseable IP or empty
// ---------------------------------------------------------------------------

func TestGetOutboundIP_ValidIPOrEmpty(t *testing.T) {
	ip := getOutboundIP()
	if ip == "" {
		// Acceptable in a network-restricted environment.
		t.Log("getOutboundIP() returned empty string (network may be restricted)")
		return
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		t.Errorf("getOutboundIP() = %q — not a valid IP address", ip)
	}
}

// getOutboundIP must not return a loopback address.
func TestGetOutboundIP_NotLoopback(t *testing.T) {
	ip := getOutboundIP()
	if ip == "" {
		return
	}
	parsed := net.ParseIP(ip)
	if parsed != nil && parsed.IsLoopback() {
		t.Errorf("getOutboundIP() = %q — must not return loopback", ip)
	}
}

// ---------------------------------------------------------------------------
// FetchPublicIP — best-effort; network may be blocked in test environment
// ---------------------------------------------------------------------------

func TestFetchPublicIP_ReturnsValidIPOrError(t *testing.T) {
	ip, err := FetchPublicIP()
	// In CI or network-restricted environments, this may fail — that's OK.
	if err != nil {
		t.Logf("FetchPublicIP() error (may be network-restricted): %v", err)
		return
	}
	if ip == "" {
		t.Error("FetchPublicIP() returned empty string with no error")
		return
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		t.Errorf("FetchPublicIP() = %q — not a valid IP address", ip)
	}
}

func TestFetchPublicIP_NotLoopback(t *testing.T) {
	ip, err := FetchPublicIP()
	if err != nil {
		t.Skip("FetchPublicIP() failed (network may be restricted)")
	}
	parsed := net.ParseIP(ip)
	if parsed != nil && parsed.IsLoopback() {
		t.Errorf("FetchPublicIP() = %q — must not return loopback", ip)
	}
}
