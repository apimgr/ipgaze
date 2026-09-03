package netutil

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestGetHostFromRequest(t *testing.T) {
	tests := []struct {
		name      string
		host      string
		xfwdHost  string
		xRealHost string
		xOrigHost string
		want      string
	}{
		{"plain host", "example.com", "", "", "", "example.com"},
		{"host with port", "example.com:8080", "", "", "", "example.com"},
		{"x-forwarded-host single", "backend", "frontend.com", "", "", "frontend.com"},
		{"x-forwarded-host chain", "backend", "a.com, b.com, c.com", "", "", "a.com"},
		{"x-forwarded-host with spaces", "backend", "  frontend.com  ", "", "", "frontend.com"},
		{"x-real-host beats host", "backend.internal", "", "real.example.com", "", "real.example.com"},
		{"x-original-host beats host", "backend.internal", "", "", "orig.example.com", "orig.example.com"},
		{"x-forwarded-host beats x-real-host", "backend", "fwd.com", "real.com", "", "fwd.com"},
		{"x-forwarded-host with port stripped", "backend", "proxy.example.com:8443", "", "", "proxy.example.com"},
		{"x-real-host with port stripped", "backend", "", "real.example.com:9000", "", "real.example.com"},
		{"empty host uses URL", "", "", "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Host = tt.host
			if tt.xfwdHost != "" {
				req.Header.Set("X-Forwarded-Host", tt.xfwdHost)
			}
			if tt.xRealHost != "" {
				req.Header.Set("X-Real-Host", tt.xRealHost)
			}
			if tt.xOrigHost != "" {
				req.Header.Set("X-Original-Host", tt.xOrigHost)
			}
			got := getHostFromRequest(req)
			if got != tt.want {
				t.Errorf("getHostFromRequest() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetWildcardDomainFromEnv(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		want   string
	}{
		{"single domain no wildcard", "example.com", ""},
		{"two same-base domains", "api.example.com,www.example.com", "*.example.com"},
		{"different bases no wildcard", "api.example.com,other.org", ""},
		{"empty env", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("DOMAIN", tt.domain)
			got := getWildcardDomainFromEnv()
			if got != tt.want {
				t.Errorf("getWildcardDomainFromEnv() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetFQDNUsesEnv(t *testing.T) {
	t.Setenv("DOMAIN", "custom.example.com")
	got := getFQDN()
	if got != "custom.example.com" {
		t.Errorf("getFQDN() with DOMAIN env = %q, want %q", got, "custom.example.com")
	}
}

func TestGetFQDNCommaList(t *testing.T) {
	t.Setenv("DOMAIN", "first.example.com,second.example.com")
	got := getFQDN()
	if got != "first.example.com" {
		t.Errorf("getFQDN() with comma list = %q, want first entry", got)
	}
}

func TestGetAllDomainsFromEnv(t *testing.T) {
	t.Setenv("DOMAIN", "api.example.com, www.example.com , cdn.example.com")
	got := getAllDomains()
	want := []string{"api.example.com", "www.example.com", "cdn.example.com"}
	if len(got) != len(want) {
		t.Fatalf("getAllDomains() = %v (len %d), want %v (len %d)", got, len(got), want, len(want))
	}
	for i, d := range got {
		if d != want[i] {
			t.Errorf("getAllDomains()[%d] = %q, want %q", i, d, want[i])
		}
	}
}

func TestGetAllDomainsFallback(t *testing.T) {
	os.Unsetenv("DOMAIN")
	got := getAllDomains()
	if len(got) == 0 {
		t.Error("getAllDomains() fallback returned empty slice")
	}
}

func TestIsLoopback(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"localhost", true},
		{"LOCALHOST", true},
		{"127.0.0.1", true},
		{"::1", true},
		{"example.com", false},
		{"8.8.8.8", false},
		{"192.168.1.1", false},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			got := isLoopback(tt.host)
			if got != tt.want {
				t.Errorf("isLoopback(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

func TestGetWildcardDomain(t *testing.T) {
	tests := []struct {
		fqdn string
		want string
	}{
		{"api.example.com", "*.example.com"},
		{"www.sub.example.co.uk", "*.example.co.uk"}, // eTLD+1 via publicsuffix (co.uk is the public suffix)
		{"localhost", ""},
		{"", ""},
		{"singleword", ""},
	}
	for _, tt := range tests {
		t.Run(tt.fqdn, func(t *testing.T) {
			got := getWildcardDomain(tt.fqdn)
			if got != tt.want {
				t.Errorf("getWildcardDomain(%q) = %q, want %q", tt.fqdn, got, tt.want)
			}
		})
	}
}

func TestIsDevTLD(t *testing.T) {
	tests := []struct {
		host        string
		projectName string
		want        bool
	}{
		{"example.com", "ipgaze", false},
		{"api.example.com", "ipgaze", false},
		{"ipgaze", "ipgaze", true},
		{"app.ipgaze", "ipgaze", true},
		{"app.ipgaze.local", "ipgaze", true},
		{"server.lan", "ipgaze", true},
		{"box.home.arpa", "ipgaze", true},
		{"localhost", "ipgaze", true},
		{"corp", "ipgaze", true},
		{"", "ipgaze", false},
		{"example.com", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.host+"|"+tt.projectName, func(t *testing.T) {
			if got := IsDevTLD(tt.host, tt.projectName); got != tt.want {
				t.Errorf("IsDevTLD(%q, %q) = %v, want %v", tt.host, tt.projectName, got, tt.want)
			}
		})
	}
}

func TestGetDisplayURL_NeverEmptyAndSchemeCorrect(t *testing.T) {
	t.Setenv("DOMAIN", "display.example.com")

	got := GetDisplayURL("ipgaze", "8080", false)
	if got != "http://display.example.com:8080" {
		t.Errorf("GetDisplayURL with production FQDN = %q, want %q", got, "http://display.example.com:8080")
	}

	if got := GetDisplayURL("ipgaze", "443", true); got != "https://display.example.com" {
		t.Errorf("GetDisplayURL default https port = %q, want %q", got, "https://display.example.com")
	}
}

func TestGetDisplayURL_DevTLDFallsBackToGlobalIP(t *testing.T) {
	t.Setenv("DOMAIN", "box.ipgaze.local")

	got := GetDisplayURL("ipgaze", "8080", false)
	if strings.Contains(got, "box.ipgaze.local") {
		if getGlobalIPv6() != "" || getGlobalIPv4() != "" {
			t.Errorf("GetDisplayURL = %q, want a global IP fallback for a dev TLD", got)
		}
	}
	if !strings.HasPrefix(got, "http://") {
		t.Errorf("GetDisplayURL = %q, want an http:// URL", got)
	}
}

func TestFormatURL(t *testing.T) {
	tests := []struct {
		scheme string
		host   string
		port   string
		want   string
	}{
		{"http", "example.com", "80", "http://example.com"},
		{"https", "example.com", "443", "https://example.com"},
		{"http", "example.com", "8080", "http://example.com:8080"},
		{"https", "example.com", "8443", "https://example.com:8443"},
		{"http", "example.com", "", "http://example.com"},
		{"http", "example.com", "0", "http://example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.scheme+"://"+tt.host+":"+tt.port, func(t *testing.T) {
			got := formatURL(tt.scheme, tt.host, tt.port)
			if got != tt.want {
				t.Errorf("formatURL(%q, %q, %q) = %q, want %q",
					tt.scheme, tt.host, tt.port, got, tt.want)
			}
		})
	}
}

func TestGetFQDN(t *testing.T) {
	// getFQDN depends on the OS hostname and DNS, so we just verify it returns something non-empty.
	fqdn := getFQDN()
	if fqdn == "" {
		t.Error("getFQDN() returned empty string")
	}
}

func TestGetAllDomains(t *testing.T) {
	// getAllDomains depends on OS/network state; verify it returns a non-nil slice.
	domains := getAllDomains()
	if domains == nil {
		t.Error("getAllDomains() returned nil")
	}
	// Should contain at least the FQDN or hostname.
}

func TestExtractBaseDomain(t *testing.T) {
	tests := []struct {
		fqdn string
		want string
	}{
		{"sub.example.com", "example.com"},
		{"api.service.example.com", "example.com"},
		{"example.com", "example.com"},
		{"localhost", ""},
		{"192.168.1.1", ""},
		{"::1", ""},
		{"", ""},
		{"a.b.c.d.e", "d.e"},
		{"trailing.dot.", "trailing.dot"},
	}
	for _, tt := range tests {
		t.Run(tt.fqdn, func(t *testing.T) {
			got := extractBaseDomain(tt.fqdn)
			if got != tt.want {
				t.Errorf("extractBaseDomain(%q) = %q, want %q", tt.fqdn, got, tt.want)
			}
		})
	}
}

func TestIsPublicIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		// Private ranges — must return false
		{"10.0.0.1", false},
		{"10.255.255.255", false},
		{"172.16.0.1", false},
		{"172.31.255.255", false},
		{"192.168.0.1", false},
		{"192.168.255.255", false},
		{"100.64.0.1", false},  // CGNAT
		{"169.254.1.1", false}, // link-local
		{"127.0.0.1", false},   // loopback
		{"fc00::1", false},     // IPv6 ULA
		{"fe80::1", false},     // IPv6 link-local
		{"::1", false},         // IPv6 loopback
		// Public IPs — must return true
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"93.184.216.34", true}, // example.com
		{"2606:4700::1", true},  // Cloudflare IPv6
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP %q", tt.ip)
			}
			got := isPublicIP(ip)
			if got != tt.want {
				t.Errorf("isPublicIP(%q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}
