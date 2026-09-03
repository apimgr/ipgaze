// Package urlutil provides SSRF-safe helpers for fetching remote content
// (AI.md "Branding & SEO" → "Remote URL Fetching").
package urlutil

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// FetchRemoteImageConfig configures remote image fetching.
type FetchRemoteImageConfig struct {
	// MaxSize is the max file size in bytes (default: 10MB).
	MaxSize int64
	// Timeout is the request timeout (default: 30s).
	Timeout time.Duration
	// AllowedTypes lists allowed MIME types.
	AllowedTypes []string
	// AllowedSchemes lists allowed URL schemes (default: https only).
	AllowedSchemes []string
}

// DefaultFetchRemoteImageConfig returns safe defaults.
func DefaultFetchRemoteImageConfig() FetchRemoteImageConfig {
	return FetchRemoteImageConfig{
		// 10MB
		MaxSize:      10 * 1024 * 1024,
		Timeout:      30 * time.Second,
		AllowedTypes: []string{"image/png", "image/jpeg", "image/gif", "image/webp", "image/x-icon"},
		// NEVER allow http in production
		AllowedSchemes: []string{"https"},
	}
}

// ValidateRemoteURL validates a URL before fetching.
func ValidateRemoteURL(rawURL string, cfg FetchRemoteImageConfig) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	// Check scheme
	schemeAllowed := false
	for _, s := range cfg.AllowedSchemes {
		if strings.EqualFold(u.Scheme, s) {
			schemeAllowed = true
			break
		}
	}
	if !schemeAllowed {
		return fmt.Errorf("scheme not allowed: %s (allowed: %v)", u.Scheme, cfg.AllowedSchemes)
	}

	// Check for localhost/loopback/unspecified
	hostname := strings.ToLower(u.Hostname())
	if hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1" ||
		hostname == "0.0.0.0" || hostname == "::" {
		return fmt.Errorf("localhost URLs not allowed")
	}

	// Check for internal hostnames
	if strings.HasSuffix(hostname, ".local") || strings.HasSuffix(hostname, ".internal") {
		return fmt.Errorf("internal hostnames not allowed")
	}

	// Check for private/internal IPs (SSRF prevention)
	if err := validateNotPrivateIP(hostname); err != nil {
		return err
	}

	return nil
}

// validateNotPrivateIP checks if hostname resolves to a private IP.
func validateNotPrivateIP(hostname string) error {
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return fmt.Errorf("DNS lookup failed: %w", err)
	}

	for _, ip := range ips {
		if isBlockedFetchIP(ip) {
			return fmt.Errorf("private/local IP not allowed: %s resolves to %s", hostname, ip)
		}
	}
	return nil
}

// isBlockedFetchIP reports whether ip must never be fetched from: any
// private, loopback, unspecified (0.0.0.0/::), or multicast/link-local
// address. Checked both at ValidateRemoteURL time and again at connect
// time (via the dialer in FetchRemoteImage) to close the DNS-rebinding
// TOCTOU window between validation and the actual TCP connection.
func isBlockedFetchIP(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() ||
		ip.IsInterfaceLocalMulticast()
}

// FetchRemoteImage safely fetches an image from a remote URL.
func FetchRemoteImage(ctx context.Context, rawURL string, cfg FetchRemoteImageConfig) ([]byte, string, error) {
	// Validate URL first
	if err := ValidateRemoteURL(rawURL, cfg); err != nil {
		return nil, "", fmt.Errorf("URL validation failed: %w", err)
	}

	// Create HTTP client with timeout. The dialer re-validates the actual
	// IP being connected to (not just the hostname resolved during
	// ValidateRemoteURL above) so a DNS answer that changes between
	// validation and connection (DNS rebinding) can never reach a
	// private/loopback/unspecified/multicast address.
	dialer := &net.Dialer{Timeout: cfg.Timeout}
	client := &http.Client{
		Timeout: cfg.Timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, _, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, fmt.Errorf("invalid dial address: %w", err)
				}
				if ip := net.ParseIP(host); ip != nil && isBlockedFetchIP(ip) {
					return nil, fmt.Errorf("connection blocked: %s is a private/local IP", ip)
				}
				conn, err := dialer.DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				remoteIP, _, splitErr := net.SplitHostPort(conn.RemoteAddr().String())
				if splitErr == nil {
					if ip := net.ParseIP(remoteIP); ip != nil && isBlockedFetchIP(ip) {
						_ = conn.Close()
						return nil, fmt.Errorf("connection blocked: %s is a private/local IP", ip)
					}
				}
				return conn, nil
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Validate each redirect URL
			if err := ValidateRemoteURL(req.URL.String(), cfg); err != nil {
				return fmt.Errorf("redirect blocked: %w", err)
			}
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("creating request: %w", err)
	}

	// Set safe headers
	req.Header.Set("User-Agent", "ipgaze/1.0")
	req.Header.Set("Accept", strings.Join(cfg.AllowedTypes, ", "))

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("fetching URL: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	// Validate content type
	contentType := resp.Header.Get("Content-Type")
	typeAllowed := false
	for _, t := range cfg.AllowedTypes {
		if strings.HasPrefix(contentType, t) {
			typeAllowed = true
			break
		}
	}
	if !typeAllowed {
		return nil, "", fmt.Errorf("content type not allowed: %s", contentType)
	}

	// Read with size limit
	limitedReader := io.LimitReader(resp.Body, cfg.MaxSize+1)
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, "", fmt.Errorf("reading response: %w", err)
	}
	if int64(len(data)) > cfg.MaxSize {
		return nil, "", fmt.Errorf("file too large (max: %d bytes)", cfg.MaxSize)
	}

	return data, contentType, nil
}
