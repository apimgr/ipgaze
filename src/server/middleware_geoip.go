package server

import (
	"log"
	"net"
	"net/http"
	"strings"

	i18n "github.com/apimgr/ipgaze/src/common/i18n"
	"github.com/apimgr/ipgaze/src/iputil/geo"
)

// isPrivateIP returns true for RFC 1918, loopback, and link-local addresses.
// Private/internal IPs are never country-blocked per spec.
func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fc00::/7",
		"::1/128",
	}
	for _, cidr := range privateRanges {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err == nil && ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

// GeoIPMiddleware performs country-level blocking using the GeoIP database.
//
// Blocking modes (per AI.md PART 19):
//   - Both lists empty  → no blocking (allow all)
//   - denyCountries set → block listed country codes, allow all others
//   - allowCountries set → allow ONLY listed codes, block all others
//   - Both set          → allowCountries wins (allowlist mode)
//
// Allowlisted IPs (set by AllowlistMiddleware) always bypass country blocking.
// Private/internal IPs are never blocked regardless of configuration.
// If gr is nil or country DB is unavailable, the middleware is a no-op.
func GeoIPMiddleware(gr geo.Reader, denyCountries, allowCountries []string) func(http.Handler) http.Handler {
	// Normalise to uppercase sets for O(1) lookup.
	deny := make(map[string]struct{}, len(denyCountries))
	for _, c := range denyCountries {
		deny[strings.ToUpper(strings.TrimSpace(c))] = struct{}{}
	}
	allow := make(map[string]struct{}, len(allowCountries))
	for _, c := range allowCountries {
		allow[strings.ToUpper(strings.TrimSpace(c))] = struct{}{}
	}

	noop := gr == nil || gr.IsEmpty() || (len(deny) == 0 && len(allow) == 0)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if noop || IsAllowlisted(r.Context()) {
				next.ServeHTTP(w, r)
				return
			}

			ip := extractIP(r)
			if ip == nil || isPrivateIP(ip) {
				next.ServeHTTP(w, r)
				return
			}

			country, err := gr.Country(ip)
			if err != nil || country.ISO == "" {
				// Cannot determine country — allow through (fail open for geo).
				next.ServeHTTP(w, r)
				return
			}

			code := strings.ToUpper(country.ISO)

			blocked := false
			if len(allow) > 0 {
				// Allowlist mode: block everything not explicitly allowed.
				if _, ok := allow[code]; !ok {
					blocked = true
				}
			} else if len(deny) > 0 {
				// Denylist mode: block only listed countries.
				if _, ok := deny[code]; ok {
					blocked = true
				}
			}

			if blocked {
				log.Printf("geoip: blocked request from %s (country %s) %s", ip, code, sanitizeLogValue(r.URL.Path))
				lang := i18n.DetectLocale(r)
				http.Error(w, i18n.T(i18n.WithLang(r.Context(), lang), "errors.blocked_by_country"), http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
