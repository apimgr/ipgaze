package urlutil

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestValidateRemoteURL_SchemeRejected(t *testing.T) {
	cfg := DefaultFetchRemoteImageConfig()
	if err := ValidateRemoteURL("http://example.com/logo.png", cfg); err == nil {
		t.Fatal("expected http scheme to be rejected when only https is allowed")
	}
}

func TestValidateRemoteURL_InvalidURL(t *testing.T) {
	cfg := DefaultFetchRemoteImageConfig()
	if err := ValidateRemoteURL("://not a url", cfg); err == nil {
		t.Fatal("expected invalid URL to error")
	}
}

func TestValidateRemoteURL_LocalhostRejected(t *testing.T) {
	cfg := DefaultFetchRemoteImageConfig()
	for _, host := range []string{"https://localhost/logo.png", "https://127.0.0.1/logo.png", "https://[::1]/logo.png"} {
		if err := ValidateRemoteURL(host, cfg); err == nil {
			t.Errorf("expected %q to be rejected as localhost", host)
		}
	}
}

func TestValidateRemoteURL_InternalHostnameRejected(t *testing.T) {
	cfg := DefaultFetchRemoteImageConfig()
	for _, host := range []string{"https://myhost.local/logo.png", "https://myhost.internal/logo.png"} {
		if err := ValidateRemoteURL(host, cfg); err == nil {
			t.Errorf("expected %q to be rejected as internal hostname", host)
		}
	}
}

func TestValidateRemoteURL_PrivateIPRejected(t *testing.T) {
	cfg := DefaultFetchRemoteImageConfig()
	for _, host := range []string{
		"https://10.0.0.1/logo.png",
		"https://192.168.1.1/logo.png",
		"https://172.16.0.1/logo.png",
		"https://169.254.169.254/logo.png",
	} {
		if err := ValidateRemoteURL(host, cfg); err == nil {
			t.Errorf("expected %q to be rejected as private/link-local IP", host)
		}
	}
}

func TestValidateRemoteURL_AllowsPublicHTTPS(t *testing.T) {
	cfg := DefaultFetchRemoteImageConfig()
	// A public IP literal avoids a real DNS lookup flake, since
	// ValidateRemoteURL resolves hostnames via net.LookupIP.
	if err := ValidateRemoteURL("https://8.8.8.8/logo.png", cfg); err != nil {
		t.Errorf("expected public IP to be allowed, got: %v", err)
	}
}

func TestValidateRemoteURL_UnspecifiedHostnameRejected(t *testing.T) {
	cfg := DefaultFetchRemoteImageConfig()
	for _, host := range []string{"https://0.0.0.0/logo.png", "https://[::]/logo.png"} {
		if err := ValidateRemoteURL(host, cfg); err == nil {
			t.Errorf("expected %q to be rejected as unspecified", host)
		}
	}
}

func TestIsBlockedFetchIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "::1", // loopback
		"10.0.0.1", "192.168.1.1", "172.16.0.1", // private
		"169.254.1.1",   // link-local unicast
		"0.0.0.0", "::", // unspecified
		"224.0.0.1",   // multicast
		"239.255.0.1", // link-local multicast (also multicast)
	}
	for _, s := range blocked {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("test bug: %q did not parse as an IP", s)
		}
		if !isBlockedFetchIP(ip) {
			t.Errorf("expected %s to be blocked", s)
		}
	}

	allowed := []string{"8.8.8.8", "1.1.1.1"}
	for _, s := range allowed {
		ip := net.ParseIP(s)
		if isBlockedFetchIP(ip) {
			t.Errorf("expected %s to be allowed", s)
		}
	}
}

func TestValidateNotPrivateIP_DNSFailure(t *testing.T) {
	if err := validateNotPrivateIP("this-host-does-not-exist.invalid"); err == nil {
		t.Fatal("expected DNS lookup failure to error")
	}
}

func TestFetchRemoteImage_LoopbackRejectedEvenWithSchemeAllowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write([]byte("fake-png-bytes"))
	}))
	defer srv.Close()

	cfg := DefaultFetchRemoteImageConfig()
	// httptest servers run on 127.0.0.1 over http — allow the scheme to
	// isolate the loopback-IP check from the scheme check.
	cfg.AllowedSchemes = []string{"http"}
	data, contentType, err := FetchRemoteImage(context.Background(), srv.URL, cfg)
	if err == nil {
		t.Fatalf("expected loopback rejection, got data=%q contentType=%q", data, contentType)
	}
	if !strings.Contains(err.Error(), "localhost") {
		t.Errorf("expected localhost rejection error, got: %v", err)
	}
}

func TestFetchRemoteImage_ValidationFailureShortCircuits(t *testing.T) {
	cfg := DefaultFetchRemoteImageConfig()
	_, _, err := FetchRemoteImage(context.Background(), "http://evil.example.com/logo.png", cfg)
	if err == nil {
		t.Fatal("expected non-https URL to fail validation before any fetch")
	}
	if !strings.Contains(err.Error(), "URL validation failed") {
		t.Errorf("expected validation-failure wrapping, got: %v", err)
	}
}

func TestDefaultFetchRemoteImageConfig(t *testing.T) {
	cfg := DefaultFetchRemoteImageConfig()
	if cfg.MaxSize != 10*1024*1024 {
		t.Errorf("unexpected default MaxSize: %d", cfg.MaxSize)
	}
	if cfg.Timeout != 30*time.Second {
		t.Errorf("unexpected default Timeout: %v", cfg.Timeout)
	}
	if len(cfg.AllowedSchemes) != 1 || cfg.AllowedSchemes[0] != "https" {
		t.Errorf("unexpected default AllowedSchemes: %v", cfg.AllowedSchemes)
	}
	found := false
	for _, ty := range cfg.AllowedTypes {
		if ty == "image/png" {
			found = true
		}
	}
	if !found {
		t.Error("expected image/png in default AllowedTypes")
	}
}
