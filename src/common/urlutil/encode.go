// Package urlutil provides URL construction and encoding helpers.
package urlutil

import (
	"fmt"
	"net/url"
	"strings"
)

// BuildAPIURL builds a versioned API URL from a base URL, version, and path.
// Example: BuildAPIURL("https://ifcfg.us", "v1", "/server/healthz")
// Returns: "https://ifcfg.us/api/v1/server/healthz"
func BuildAPIURL(baseURL, version, path string) string {
	base := strings.TrimRight(baseURL, "/")
	path = "/" + strings.TrimLeft(path, "/")
	return fmt.Sprintf("%s/api/%s%s", base, version, path)
}

// EncodePathSegment URL-encodes a single path segment (encodes slashes too).
func EncodePathSegment(s string) string {
	return url.PathEscape(s)
}

// EncodeQueryValue URL-encodes a query parameter value.
func EncodeQueryValue(s string) string {
	return url.QueryEscape(s)
}

// BuildQueryString builds a URL query string from a map of key-value pairs.
// Keys are sorted for determinism.
func BuildQueryString(params map[string]string) string {
	if len(params) == 0 {
		return ""
	}
	vals := url.Values{}
	for k, v := range params {
		vals.Set(k, v)
	}
	return "?" + vals.Encode()
}
