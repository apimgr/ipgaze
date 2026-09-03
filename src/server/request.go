package server

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/apimgr/ipgaze/src/useragent"
)

// ipFromForwardedForHeader extracts the first IP from X-Forwarded-For header
func ipFromForwardedForHeader(v string) string {
	sep := strings.Index(v, ",")
	if sep == -1 {
		return strings.TrimSpace(v)
	}
	return strings.TrimSpace(v[:sep])
}

// ipFromRequest detects the IP address for this transaction.
//
//   - `headers` - the specific HTTP headers to trust
//   - `r` - the incoming HTTP request
//   - `customIP` - whether to allow the IP to be pulled from query parameters
//   - `trusted` - whether the immediate peer passes the trusted_proxies gate
//     (AI.md PART 8 "Client IP Detection" / PART 12 "Trusted Proxies"); when
//     false, `headers` are ignored and resolution falls straight through to
//     `r.RemoteAddr`
func ipFromRequest(headers []string, r *http.Request, customIP bool, trusted bool) (net.IP, error) {
	remoteIP := ""
	if customIP && r.URL != nil {
		if v, ok := r.URL.Query()["ip"]; ok {
			remoteIP = v[0]
		}
	}
	if remoteIP == "" && trusted {
		for _, header := range headers {
			v := r.Header.Get(header)
			if http.CanonicalHeaderKey(header) == "X-Forwarded-For" {
				v = ipFromForwardedForHeader(v)
			} else {
				v = strings.TrimSpace(v)
			}
			if v != "" {
				remoteIP = v
				break
			}
		}
	}
	if remoteIP == "" {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			return nil, err
		}
		remoteIP = host
	}
	ip := net.ParseIP(remoteIP)
	if ip == nil {
		return nil, fmt.Errorf("could not parse IP: %s", remoteIP)
	}
	return ip, nil
}

// userAgentFromRequest parses the User-Agent header from the request
func userAgentFromRequest(r *http.Request) *useragent.UserAgent {
	var userAgent *useragent.UserAgent
	userAgentRaw := r.UserAgent()
	if userAgentRaw != "" {
		parsed := useragent.Parse(userAgentRaw)
		userAgent = &parsed
	}
	return userAgent
}

// cliMatcher returns true if the request appears to be from a CLI tool.
// Used for backward compatibility; prefer detectClientType for new code.
func cliMatcher(r *http.Request) bool {
	ua := useragent.Parse(r.UserAgent())
	switch ua.Product {
	case "curl", "HTTPie", "httpie-go", "Wget", "fetch libfetch", "Go", "Go-http-client", "ddclient", "Mikrotik", "xh":
		return true
	}
	return false
}

// detectClientType returns the preferred response format for the request per AI.md PART 16.
// Returns "html", "text", or "json".
// Priority: Accept header → User-Agent browser/CLI detection → default "html".
func detectClientType(r *http.Request) string {
	// 1. Check Accept header first (explicit preference)
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "text/html") {
		return "html"
	}
	if strings.Contains(accept, "text/plain") {
		return "text"
	}
	if strings.Contains(accept, "application/json") {
		return "json"
	}

	// 2. Check User-Agent for browser detection
	ua := r.Header.Get("User-Agent")

	browsers := []string{
		"Mozilla/", "Chrome/", "Safari/", "Edge/", "Firefox/",
		"Opera/", "MSIE", "Trident/",
	}
	for _, b := range browsers {
		if strings.Contains(ua, b) {
			return "html"
		}
	}

	// 3. CLI tools (curl, wget, HTTPie, etc.)
	cliTools := []string{
		"curl/", "Wget/", "HTTPie/", "python-requests/",
		"Go-http-client/", "node-fetch/",
	}
	for _, t := range cliTools {
		if strings.Contains(ua, t) {
			return "text"
		}
	}

	// 4. Empty User-Agent → programmatic/CLI access
	if ua == "" {
		return "text"
	}

	// 5. Default: HTML (safest fallback for unknown UAs)
	return "html"
}

// formatCoordinate formats a coordinate value with 6 decimal places
func formatCoordinate(c float64) string {
	return strconv.FormatFloat(c, 'f', 6, 64)
}
