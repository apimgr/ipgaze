package server

import (
	"context"
	"net"
	"net/http"
	"strings"

	"github.com/apimgr/ipgaze/src/netutil"
)

// ctxKeyAllowlisted is the context key that marks a request as coming from an
// allowlisted IP. Downstream middleware checks this flag to skip enforcement.
type ctxKeyAllowlistedType struct{}

var ctxKeyAllowlisted = ctxKeyAllowlistedType{}

// ctxKeyClientIP is the context key that carries the trust-resolved client IP.
// It is set once by ClientIPMiddleware and read by extractIP so that allowlist,
// blocklist, and GeoIP enforcement all key on the real client IP behind a
// trusted reverse proxy, matching the rate-limit and logging paths.
type ctxKeyClientIPType struct{}

var ctxKeyClientIP = ctxKeyClientIPType{}

// ctxKeyTorRequest marks a request that arrived over the hidden service. It is
// set once by ClientIPMiddleware so that clearnet IP allow/deny lists and GeoIP
// enforcement can skip themselves entirely — a Tor request has no meaningful
// client IP, and matching one against a CIDR list would silently key on the
// loopback peer instead (AI.md PART 31 "Tor Privacy Rules").
type ctxKeyTorRequestType struct{}

var ctxKeyTorRequest = ctxKeyTorRequestType{}

// IsTorRequestContext reports whether ClientIPMiddleware flagged this request
// as arriving over the hidden service.
func IsTorRequestContext(ctx context.Context) bool {
	v, _ := ctx.Value(ctxKeyTorRequest).(bool)
	return v
}

// AllowlistEntry is a trusted IP/CIDR range with an optional description.
type AllowlistEntry struct {
	CIDR        string
	Description string
}

// AllowlistLookup holds the compiled allowlist and provides fast IP lookup.
type AllowlistLookup struct {
	nets    []*net.IPNet
	singles []net.IP
}

// NewAllowlistLookup compiles a set of AllowlistEntry values into a fast lookup.
// Invalid CIDRs are silently skipped.
func NewAllowlistLookup(entries []AllowlistEntry) *AllowlistLookup {
	al := &AllowlistLookup{}
	for _, e := range entries {
		cidr := strings.TrimSpace(e.CIDR)
		if cidr == "" {
			continue
		}
		// Normalise bare IPs to /32 or /128 so ParseCIDR accepts them.
		if !strings.Contains(cidr, "/") {
			if strings.Contains(cidr, ":") {
				cidr += "/128"
			} else {
				cidr += "/32"
			}
		}
		_, ipnet, err := net.ParseCIDR(cidr)
		if err == nil {
			al.nets = append(al.nets, ipnet)
		}
	}
	return al
}

// Contains returns true if ip is covered by any entry in the allowlist.
func (al *AllowlistLookup) Contains(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, ipnet := range al.nets {
		if ipnet.Contains(ip) {
			return true
		}
	}
	for _, s := range al.singles {
		if s.Equal(ip) {
			return true
		}
	}
	return false
}

// AllowlistMiddleware sets a context flag when the client IP is allowlisted.
// Downstream middleware (blocklist, rate limit, geoip) checks this flag and
// skips enforcement. Auth middleware always runs regardless of allowlist status.
// If al is nil the middleware is a no-op passthrough.
func AllowlistMiddleware(al *AllowlistLookup) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Clearnet IP lists never apply to hidden-service requests
			// (AI.md PART 31 "Tor Privacy Rules").
			if al != nil && !IsTorRequestContext(r.Context()) {
				ip := extractIP(r)
				if ip != nil && al.Contains(ip) {
					ctx := context.WithValue(r.Context(), ctxKeyAllowlisted, true)
					r = r.WithContext(ctx)
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// IsAllowlisted returns true when AllowlistMiddleware set the allowlisted flag
// for this request.
func IsAllowlisted(ctx context.Context) bool {
	v, _ := ctx.Value(ctxKeyAllowlisted).(bool)
	return v
}

// ClientIPMiddleware resolves the real client IP once per request — honoring
// proxy headers only when the immediate peer passes the trusted_proxies gate —
// and stores it in the request context. Downstream allowlist, blocklist, and
// GeoIP enforcement read this value via extractIP. It uses the same resolution
// path as the rate-limit and logging middleware so all four agree on the client
// IP behind a trusted reverse proxy (AI.md PART 12 → "Trusted Proxies"). It must
// be registered before AllowlistMiddleware. If tr is nil it is a no-op.
func ClientIPMiddleware(tr *netutil.TrustResolver) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if tr != nil {
				if netutil.IsTorRequest(r, tr) {
					r = r.WithContext(context.WithValue(r.Context(), ctxKeyTorRequest, true))
				} else if ip := net.ParseIP(netutil.GetClientIdentifier(r, tr)); ip != nil {
					r = r.WithContext(context.WithValue(r.Context(), ctxKeyClientIP, ip))
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// extractIP returns the client IP for access-control decisions. It prefers the
// trust-resolved IP stashed by ClientIPMiddleware and falls back to the raw
// connection peer (r.RemoteAddr) when no resolved value is present.
func extractIP(r *http.Request) net.IP {
	if ip, ok := r.Context().Value(ctxKeyClientIP).(net.IP); ok && ip != nil {
		return ip
	}
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return net.ParseIP(host)
}
