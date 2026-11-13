package server

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/apimgr/ipgaze/src/common/httputil"
	"github.com/apimgr/ipgaze/src/netutil"
	"github.com/apimgr/ipgaze/src/useragent"
)

// ipFromRequestWithResolver applies the configured peer and forwarding-chain
// trust policy used by production request handlers.
func ipFromRequestWithResolver(r *http.Request, customIP bool, resolver *netutil.TrustResolver) (net.IP, error) {
	if customIP && r.URL != nil {
		if values, ok := r.URL.Query()["ip"]; ok && len(values) > 0 {
			addr, valid := netutil.ParseClientIP(values[0])
			if !valid {
				return nil, fmt.Errorf("could not parse IP")
			}
			return net.IP(addr.AsSlice()), nil
		}
	}
	addr, valid := netutil.ParseClientIP(netutil.GetClientIPWithResolver(r, resolver))
	if !valid {
		return nil, fmt.Errorf("could not parse client IP")
	}
	return net.IP(addr.AsSlice()), nil
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
// Priority matches AI.md's frontend Accept table:
//
//  1. Explicit Accept: application/json.
//  2. Explicit Accept: text/html.
//  3. Explicit Accept: text/plain.
//  4. Text browsers (lynx, w3m, links) are INTERACTIVE without JavaScript and
//     receive server-rendered HTML, never converted text.
//  5. Our CLI client receives JSON, HTTP tools receive text, and other
//     clients (including unknown agents) receive HTML.
//
// Client classification is delegated to the canonical detectors in
// src/common/httputil/detect.go — this package keeps no second User-Agent list.
func detectClientType(r *http.Request) string {
	ua := r.Header.Get("User-Agent")

	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		return "json"
	}
	if strings.Contains(accept, "text/html") {
		return "html"
	}
	if strings.Contains(accept, "text/plain") {
		return "text"
	}
	if httputil.IsOurCliClient(ua) {
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
// explicit Accept preference, non-interactive detection only when Accept is absent,
// then JSON.
func apiResponseFormat(r *http.Request) string {
	if r.URL != nil && strings.HasSuffix(r.URL.Path, ".txt") {
		return "text"
	}
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		return "json"
	}
	if strings.Contains(accept, "text/plain") {
		return "text"
	}
	if strings.TrimSpace(accept) != "" {
		return "json"
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
