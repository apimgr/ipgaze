// Package api provides the HTTP client for the ipgaze API.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/apimgr/ipgaze/src/common/urlutil"
)

// ErrTokenRevoked is returned by doAPIRequest when the server responds with
// 401 and a TOKEN_REVOKED body. Callers should clear stored credentials and
// log the cli.token_revoked_detected audit event (AI.md PART 32).
var ErrTokenRevoked = errors.New("token revoked by server")

const defaultTimeout = 10 * time.Second

// ConnectionError reports a transport-level failure: the server could not be
// reached at all (DNS, TCP, TLS or timeout). Callers map it to exit code 3.
type ConnectionError struct {
	URL string
	Err error
}

// Error implements the error interface.
func (e *ConnectionError) Error() string {
	return fmt.Sprintf("cannot connect to server at %s: %v", e.URL, e.Err)
}

// Unwrap exposes the underlying transport error.
func (e *ConnectionError) Unwrap() error { return e.Err }

// APIError reports a non-2xx HTTP response and carries the status code so the
// caller can map it to the right exit code (401 authentication, 404 not found).
type APIError struct {
	StatusCode int
	URL        string
	Body       string
}

// Error implements the error interface.
func (e *APIError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("server error %d", e.StatusCode)
	}
	return fmt.Sprintf("server error %d: %s", e.StatusCode, e.Body)
}

// IsUnauthorized reports whether err is an APIError with a 401 or 403 status.
func IsUnauthorized(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.StatusCode == http.StatusUnauthorized || apiErr.StatusCode == http.StatusForbidden
}

// IsNotFound reports whether err is an APIError with a 404 status.
func IsNotFound(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.StatusCode == http.StatusNotFound
}

// IsConnectionError reports whether err is a transport-level failure.
func IsConnectionError(err error) bool {
	var connErr *ConnectionError
	return errors.As(err, &connErr)
}

// FieldNames lists every field the server exposes at /{ip}/{field} and at the
// caller's own /{field} routes, in the hyphenated spelling the --field flag
// accepts.
var FieldNames = []string{
	"ip", "ip-decimal", "country", "country-iso", "region-name", "region-code",
	"city", "zip-code", "time-zone", "asn", "asn-org", "hostname",
	"latitude", "longitude",
}

// normalizeFieldName converts the hyphenated --field spelling to the
// underscore spelling the server's /{ip}/{field} route expects.
func normalizeFieldName(field string) string {
	return strings.ReplaceAll(field, "-", "_")
}

// APIClient is an HTTP client for the ipgaze API.
type APIClient struct {
	baseURL    string
	token      string
	userAgent  string
	lang       string
	httpClient *http.Client
}

// NewAPIClient creates a new APIClient for the given base URL. lang is the
// client's resolved output language (AI.md PART 30 priority chain) and is
// sent as the Accept-Language header so server-rendered (JSON/HTML) error
// and response text comes back in the user's chosen locale.
func NewAPIClient(baseURL, token, userAgent, lang string) *APIClient {
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "https://" + baseURL
	}
	baseURL = strings.TrimSuffix(baseURL, "/")
	return &APIClient{
		baseURL:   baseURL,
		token:     token,
		userAgent: userAgent,
		lang:      lang,
		httpClient: &http.Client{
			Timeout: defaultTimeout,
		},
	}
}

// SetTimeout overrides the HTTP request timeout with the resolved
// server.timeout config value (AI.md PART 32 cli.yml server section).
func (c *APIClient) SetTimeout(d time.Duration) {
	if d <= 0 {
		return
	}
	c.httpClient.Timeout = d
}

// IPResponse represents the server's IP lookup response.
type IPResponse struct {
	IP         string  `json:"ip"`
	IPDecimal  uint64  `json:"ip_decimal,omitempty"`
	Country    string  `json:"country,omitempty"`
	CountryISO string  `json:"country_iso,omitempty"`
	CountryEU  bool    `json:"country_eu,omitempty"`
	City       string  `json:"city,omitempty"`
	RegionName string  `json:"region_name,omitempty"`
	RegionCode string  `json:"region_code,omitempty"`
	PostalCode string  `json:"zip_code,omitempty"`
	Latitude   float64 `json:"latitude,omitempty"`
	Longitude  float64 `json:"longitude,omitempty"`
	Timezone   string  `json:"time_zone,omitempty"`
	ASN        string  `json:"asn,omitempty"`
	ASNOrg     string  `json:"asn_org,omitempty"`
	Hostname   string  `json:"hostname,omitempty"`
}

// GetMyIP returns the caller's IP address as a plain string.
func (c *APIClient) GetMyIP(ctx context.Context) (string, error) {
	body, err := c.doAPIRequest(ctx, "/ip", "text/plain")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

// GetMyIPJSON returns the full IP lookup response for the caller's IP.
func (c *APIClient) GetMyIPJSON(ctx context.Context) (*IPResponse, error) {
	body, err := c.doAPIRequest(ctx, "/json", "application/json")
	if err != nil {
		return nil, err
	}
	var resp IPResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &resp, nil
}

// GetIPJSON returns the full IP lookup response for the given IP address.
func (c *APIClient) GetIPJSON(ctx context.Context, ip string) (*IPResponse, error) {
	path := "/" + urlutil.EncodePathSegment(ip) + "/json"
	body, err := c.doAPIRequest(ctx, path, "application/json")
	if err != nil {
		return nil, err
	}
	var resp IPResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &resp, nil
}

// GetField returns a single field for the caller's own IP (e.g., "country",
// "city") from the server's /{field} routes.
func (c *APIClient) GetField(ctx context.Context, field string) (string, error) {
	body, err := c.doAPIRequest(ctx, "/"+urlutil.EncodePathSegment(field), "text/plain")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

// GetIPField returns a single field for an explicitly supplied IP address via
// the server's /{ip}/{field} route. The field name is normalized to the
// underscore spelling that route expects.
func (c *APIClient) GetIPField(ctx context.Context, ip, field string) (string, error) {
	path := "/" + urlutil.EncodePathSegment(ip) + "/" + urlutil.EncodePathSegment(normalizeFieldName(field))
	body, err := c.doAPIRequest(ctx, path, "text/plain")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

// AutodiscoverResponse is the response from /api/autodiscover (AI.md PART 32).
type AutodiscoverResponse struct {
	ServerName    string                     `json:"server_name"`
	Version       string                     `json:"version"`
	APIVersion    string                     `json:"api_version"`
	BaseURL       string                     `json:"base_url"`
	CLIVersions   map[string]CLIVersionEntry `json:"cli_versions"`
	CLIMinVersion string                     `json:"cli_min_version"`
}

// CLIVersionEntry holds a platform-specific CLI version and its SHA-256 checksum.
type CLIVersionEntry struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

// Autodiscover fetches /api/autodiscover and returns the response.
func (c *APIClient) Autodiscover(ctx context.Context) (*AutodiscoverResponse, error) {
	body, err := c.doAPIRequest(ctx, "/api/autodiscover", "application/json")
	if err != nil {
		return nil, err
	}
	var resp AutodiscoverResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode autodiscover: %w", err)
	}
	return &resp, nil
}

// DownloadBinary fetches /cli/binaries/{filename} and writes it to dst.
// Returns the number of bytes written.
func (c *APIClient) DownloadBinary(ctx context.Context, filename, dst string) (int64, error) {
	url := c.baseURL + "/cli/binaries/" + urlutil.EncodePathSegment(filename)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, fmt.Errorf("create request: %w", err)
	}
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	if c.lang != "" {
		req.Header.Set("Accept-Language", c.lang)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, &ConnectionError{URL: url, Err: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, &APIError{
			StatusCode: resp.StatusCode,
			URL:        url,
			Body:       fmt.Sprintf("downloading %s", filename),
		}
	}
	f, err := os.Create(dst)
	if err != nil {
		return 0, fmt.Errorf("create temp file: %w", err)
	}
	defer f.Close()
	n, err := io.Copy(f, resp.Body)
	if err != nil {
		return 0, fmt.Errorf("write download: %w", err)
	}
	return n, nil
}

// doAPIRequest performs an HTTP GET request and returns the response body.
func (c *APIClient) doAPIRequest(ctx context.Context, path, accept string) ([]byte, error) {
	requestURL := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", accept)
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	if c.lang != "" {
		req.Header.Set("Accept-Language", c.lang)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, &ConnectionError{URL: requestURL, Err: err}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// Detect TOKEN_REVOKED before returning a generic error (AI.md PART 32).
		if resp.StatusCode == http.StatusUnauthorized && isTokenRevoked(body) {
			return nil, ErrTokenRevoked
		}
		return nil, &APIError{
			StatusCode: resp.StatusCode,
			URL:        requestURL,
			Body:       strings.TrimSpace(string(body)),
		}
	}
	return body, nil
}

// isTokenRevoked returns true when the response body signals a revoked token.
// Handles plain-text "TOKEN_REVOKED" and JSON {"error":"TOKEN_REVOKED"}.
func isTokenRevoked(body []byte) bool {
	if strings.TrimSpace(string(body)) == "TOKEN_REVOKED" {
		return true
	}
	var errResp struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &errResp); err == nil {
		return errResp.Error == "TOKEN_REVOKED"
	}
	return false
}
