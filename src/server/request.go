package server

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/apimgr/ipgaze/src/common/httputil"
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

// detectClientType returns the preferred response format for a frontend (`/**`)
// route per AI.md PART 14 "Smart Content Negotiation". Returns "html", "text",
// or "json".
//
// Priority, matching AI.md's handleFrontendRequest reference implementation and
// its Accept-header table:
//
//  1. Our CLI client is INTERACTIVE and always receives JSON so it can render
//     its own TUI/GUI — it is never given HTML or pre-formatted text.
//  2. An explicit Accept header wins over User-Agent heuristics.
//  3. Text browsers (lynx, w3m, links) are INTERACTIVE without JavaScript and
//     receive server-rendered HTML, never converted text.
//  4. HTTP tools (curl, wget, httpie) are NON-INTERACTIVE and receive text.
//  5. Everything else (regular browsers, unknown agents) receives HTML.
//
// Client classification is delegated to the canonical detectors in
// src/common/httputil/detect.go — this package keeps no second User-Agent list.
func detectClientType(r *http.Request) string {
	ua := r.Header.Get("User-Agent")

	// Our CLI client always gets JSON, regardless of Accept.
	if httputil.IsOurCliClient(ua) {
		return "json"
	}

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

	if httputil.IsTextBrowser(ua) {
		return "html"
	}
	if httputil.IsHttpTool(ua) {
		return "text"
	}

	// Regular browsers and unknown agents get HTML.
	return "html"
}

// apiResponseFormat returns the response format for a backend (`/api/**`) route
// per AI.md PART 14 "Backend API Content Negotiation". Returns "text" or "json".
//
// API routes emit raw data as plain text — never HTML2TextConverter output —
// because there is no HTML to convert. Priority matches AI.md's
// getAPIResponseFormat reference: `.txt` suffix, then Accept: text/plain, then
// non-interactive client detection, then JSON.
func apiResponseFormat(r *http.Request) string {
	if r.URL != nil && strings.HasSuffix(r.URL.Path, ".txt") {
		return "text"
	}
	if strings.Contains(r.Header.Get("Accept"), "text/plain") {
		return "text"
	}
	if httputil.IsNonInteractiveClient(r.Header.Get("User-Agent")) {
		return "text"
	}
	return "json"
}

// formatCoordinate formats a coordinate value with 6 decimal places
func formatCoordinate(c float64) string {
	return strconv.FormatFloat(c, 'f', 6, 64)
}

// formatCoordinatePair renders "{latitude},{longitude}" for the plain-text and
// scalar coordinate endpoints, returning an empty string when the location is
// unknown. The model marks both fields `omitempty`, so a zero pair means "no
// GeoIP data" rather than the literal point 0,0 — the other GeoIP text routes
// return an empty body in that case and coordinates must not claim a position
// the lookup never produced.
func formatCoordinatePair(lat, lon float64) string {
	if lat == 0 && lon == 0 {
		return ""
	}
	return formatCoordinate(lat) + "," + formatCoordinate(lon)
}
