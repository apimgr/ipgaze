package server

import (
	"log"
	"net/http"

	"github.com/apimgr/ipgaze/src/blocklist"
	i18n "github.com/apimgr/ipgaze/src/common/i18n"
	applog "github.com/apimgr/ipgaze/src/log"
)

// BlocklistMiddleware checks the client IP against downloaded blocklists.
// If the IP is found in any blocklist it returns 403 Forbidden.
// Allowlisted IPs (set by AllowlistMiddleware) bypass this check.
// Private/internal IPs (loopback, RFC 1918, link-local) are never blocked:
// public threat blocklists such as firehol_level1 intentionally include
// bogon ranges (127.0.0.0/8, 10.0.0.0/8, 192.168.0.0/16, ...) for perimeter
// filtering of spoofed WAN traffic, and applying that data to a server's own
// loopback/private-network traffic would lock out legitimate local/admin
// access. This mirrors GeoIPMiddleware's isPrivateIP exemption.
// If lookup is nil the middleware is a no-op passthrough.
// lm receives a security.log entry for every block so Fail2ban can escalate a
// repeat offender (AI.md PART 11); a nil manager silently skips the file write.
func BlocklistMiddleware(lookup *blocklist.Lookup, lm *applog.Manager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Allowlisted IPs bypass blocklist checks.
			if IsAllowlisted(r.Context()) {
				next.ServeHTTP(w, r)
				return
			}
			// Clearnet IP lists never apply to hidden-service requests
			// (AI.md PART 31 "Tor Privacy Rules").
			if lookup != nil && !IsTorRequestContext(r.Context()) {
				ip := extractIP(r)
				if ip != nil && !isPrivateIP(ip) && lookup.Contains(ip) {
					log.Printf("blocklist: blocked request from %s %s", ip, sanitizeLogValue(r.URL.Path))
					lm.WriteSecurity("Blocked request from blocklisted IP", sanitizeLogValue(ip.String()))
					lang := i18n.DetectLocale(r)
					http.Error(w, i18n.T(i18n.WithLang(r.Context(), lang), "errors.blocked_by_blocklist"), http.StatusForbidden)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
