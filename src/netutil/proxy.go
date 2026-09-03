package netutil

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
)

// alwaysTrustedCIDRs lists CIDR ranges that are unconditionally trusted as reverse-proxy peers
// per AI.md PART 12. These cover loopback, RFC 1918 private, IPv6 ULA, and link-local ranges.
var alwaysTrustedCIDRs = func() []*net.IPNet {
	raw := []string{
		"127.0.0.0/8",
		"::1/128",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fc00::/7",
		"169.254.0.0/16",
		"fe80::/10",
	}
	nets := make([]*net.IPNet, 0, len(raw))
	for _, cidr := range raw {
		_, n, err := net.ParseCIDR(cidr)
		if err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}()

// getProto returns the request protocol, honoring proxy headers only when trusted.
// Resolution order per AI.md PART 15:
//  1. X-Forwarded-Proto (trusted only)
//  2. X-Forwarded-Ssl "on" → https (trusted only)
//  3. X-Url-Scheme (trusted only)
//  4. TLS on connection
//  5. "http" default
func getProto(r *http.Request, trusted bool) string {
	if trusted {
		if v := r.Header.Get("X-Forwarded-Proto"); v != "" {
			return strings.ToLower(v)
		}
		if v := r.Header.Get("X-Forwarded-Ssl"); strings.ToLower(v) == "on" {
			return "https"
		}
		if v := r.Header.Get("X-Url-Scheme"); v != "" {
			return strings.ToLower(v)
		}
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

// getPort returns the non-default port for the request.
// Returns "" when the port matches the scheme default (80 for http, 443 for https),
// so callers never emit :80 or :443 in URLs.
// Resolution order per AI.md PART 15:
//  1. X-Forwarded-Port (trusted only)
//  2. Port in Host header
//  3. "" (fall through to proto default)
func getPort(r *http.Request, trusted bool) string {
	if trusted {
		if v := strings.TrimSpace(r.Header.Get("X-Forwarded-Port")); v != "" {
			if v != "80" && v != "443" {
				return v
			}
			return ""
		}
	}
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	if _, port, err := net.SplitHostPort(host); err == nil {
		if port != "80" && port != "443" {
			return port
		}
	}
	return ""
}

// getBaseURLPath returns the path prefix set by a reverse proxy.
// Returns "/" when no prefix header is present.
// Resolution order per AI.md PART 15:
//  1. X-Forwarded-Prefix (trusted only)
//  2. X-Forwarded-Path (trusted only)
//  3. X-Script-Name (trusted only)
//  4. "/"
func getBaseURLPath(r *http.Request, trusted bool) string {
	if trusted {
		for _, h := range []string{"X-Forwarded-Prefix", "X-Forwarded-Path", "X-Script-Name"} {
			if v := strings.TrimSpace(r.Header.Get(h)); v != "" {
				return v
			}
		}
	}
	return "/"
}

// GetClientIP returns the real client IP, honoring proxy headers only when trusted.
// Resolution order per AI.md PART 15 "Client IP Detection":
//  1. CF-Connecting-IP — Cloudflare, single IP (trusted only)
//  2. True-Client-IP — Akamai / Cloudflare Enterprise, single IP (trusted only)
//  3. X-Real-IP — nginx, single IP (trusted only)
//  4. X-Forwarded-For — chain "client, proxy1, proxy2", leftmost entry (trusted only)
//  5. X-Client-IP — alternative, single IP (trusted only)
//  6. r.RemoteAddr host part — always used when the peer is not trusted
func GetClientIP(r *http.Request, trusted bool) string {
	if trusted {
		for _, h := range []string{"CF-Connecting-IP", "True-Client-IP", "X-Real-IP"} {
			if v := strings.TrimSpace(r.Header.Get(h)); v != "" {
				return v
			}
		}
		if xff := r.Header.Get("X-Forwarded-For"); strings.TrimSpace(xff) != "" {
			// XFF is a comma-separated chain; the leftmost entry is the original client.
			if idx := strings.IndexByte(xff, ','); idx > 0 {
				return strings.TrimSpace(xff[:idx])
			}
			return strings.TrimSpace(xff)
		}
		if v := strings.TrimSpace(r.Header.Get("X-Client-IP")); v != "" {
			return v
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if id, ok := torCircuitIdentifier(host); ok {
		return id
	}
	return host
}

// torCircuitPrefix is the range Tor uses to carry the per-rendezvous-circuit
// ID in the PROXY-protocol source address when the hidden service is
// configured with `HiddenServiceExportCircuitID haproxy`. The address is not
// routable and is never a real client address.
var torCircuitPrefix = netip.MustParsePrefix("fc00:dead:beef:4dad::/64")

// torCircuitIdentifier renders a Tor circuit-ID source address as the
// `tor:{circuit_id}` identifier required by AI.md PART 12 "Tor Request Logging
// & Identity". It reports false for any address outside the exported-circuit
// range.
func torCircuitIdentifier(host string) (string, bool) {
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return "", false
	}
	if !torCircuitPrefix.Contains(addr) {
		return "", false
	}
	raw := addr.As16()
	return fmt.Sprintf("%s:%d", TorClientSentinel, binary.BigEndian.Uint64(raw[8:])), true
}

// TorClientSentinel is the literal client identifier recorded for a Tor
// request when circuit-ID export is not enabled. AI.md PART 12 forbids ever
// logging or displaying 127.0.0.1 for a Tor request, and the local Tor
// daemon's loopback address identifies nothing.
const TorClientSentinel = "tor"

// GetClientIdentifier returns the value to record wherever a client IP would
// normally be logged, displayed, or used as a rate-limit key. For a Tor
// request that is `tor:{circuit_id}` when Tor exports the circuit ID, and the
// bare `tor` sentinel otherwise — never the loopback address of the local Tor
// daemon. Every other request resolves through GetClientIP.
func GetClientIdentifier(r *http.Request, tr *TrustResolver) string {
	if IsTorRequest(r, tr) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if id, ok := torCircuitIdentifier(host); ok {
			return id
		}
		return TorClientSentinel
	}
	return GetClientIP(r, tr != nil && tr.IsTrustedPeer(r))
}

// hostMatchesOverlayAddress reports whether r's Host header (port stripped,
// case-insensitive) matches the given overlay-network address (.onion or
// .b32.i2p). Shared by isTorRequest and isI2PRequest.
func hostMatchesOverlayAddress(r *http.Request, address string) bool {
	if address == "" {
		return false
	}
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	// Strip port if present.
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.EqualFold(strings.TrimSpace(host), strings.TrimSpace(address))
}

// isTorRequest reports whether r is a Tor hidden service request per AI.md PART 12.
// A request is a Tor request when onionAddress is non-empty and the request's Host
// header matches it (case-insensitive, port stripped). This is priority 0 — evaluated
// before all proxy header checks, always trusted, no IP check required.
func isTorRequest(r *http.Request, onionAddress string) bool {
	return hostMatchesOverlayAddress(r, onionAddress)
}

// IsTorRequest reports whether r is a Tor hidden service request per AI.md
// PART 12 — the Host header matches tr.OnionAddress. Safe to call with a nil
// resolver (returns false, matching isTorRequest's own nil-OnionAddress path).
func IsTorRequest(r *http.Request, tr *TrustResolver) bool {
	if tr == nil {
		return false
	}
	return isTorRequest(r, tr.OnionAddress)
}

// isI2PRequest reports whether r is an I2P eepsite request per AI.md PART
// 31.2 — the Host header matches i2pAddress (case-insensitive, port
// stripped). Priority 0, exactly like Tor: no reverse-proxy header or IP
// check applies, always trusted.
func isI2PRequest(r *http.Request, i2pAddress string) bool {
	return hostMatchesOverlayAddress(r, i2pAddress)
}

// IsI2PRequest reports whether r is an I2P eepsite request per AI.md PART
// 31.2 — the Host header matches tr.I2PAddress. Safe to call with a nil
// resolver.
func IsI2PRequest(r *http.Request, tr *TrustResolver) bool {
	if tr == nil {
		return false
	}
	return isI2PRequest(r, tr.I2PAddress)
}

// getURLVars returns the resolved proto, fqdn, and port for the request.
// Resolution order per AI.md PART 12:
//
//  0. Tor hidden service: Host matches tr.OnionAddress → proto=http, fqdn=onionAddress, port=""
//  0. I2P eepsite: Host matches tr.I2PAddress → proto=http, fqdn=i2pAddress, port="" (PART 31.2)
//  1. Trusted proxy headers (when IsTrustedPeer)
//  2. r.Host
//  3. DOMAIN env var
//  4. getFQDN() fallback
//
// port is "" when it matches the scheme default (80/443) per AI.md PART 15.
func getURLVars(r *http.Request, tr *TrustResolver) (proto, fqdn, port string) {
	// Priority 0: Tor hidden service / I2P eepsite — bypass all proxy header
	// inspection. Neither ever gets HTTPS upgrade, HSTS, or a cert.
	if tr != nil && isTorRequest(r, tr.OnionAddress) {
		return "http", tr.OnionAddress, ""
	}
	if tr != nil && isI2PRequest(r, tr.I2PAddress) {
		return "http", tr.I2PAddress, ""
	}

	trusted := tr.IsTrustedPeer(r)

	proto = getProto(r, trusted)

	if trusted {
		// When peer is trusted, proxy FQDN headers take highest priority.
		// getHostFromRequest checks X-Forwarded-Host → X-Real-Host → X-Original-Host → r.Host.
		fqdn = getHostFromRequest(r)
	} else {
		// When peer is not trusted, use r.Host directly — what the client sent.
		host := r.Host
		if host == "" {
			host = r.URL.Host
		}
		if h, _, err := net.SplitHostPort(host); err == nil {
			fqdn = h
		} else {
			fqdn = host
		}
	}

	if fqdn == "" {
		// Fall back to DOMAIN env var, then server-level host discovery.
		if domain := os.Getenv("DOMAIN"); domain != "" {
			if idx := strings.IndexByte(domain, ','); idx > 0 {
				fqdn = strings.TrimSpace(domain[:idx])
			} else {
				fqdn = strings.TrimSpace(domain)
			}
		}
	}
	if fqdn == "" {
		fqdn = getFQDN()
	}

	port = getPort(r, trusted)

	return proto, fqdn, port
}

// BuildURL constructs the full canonical URL for the given path.
// :80 and :443 are never included in the output per AI.md PART 15.
func BuildURL(r *http.Request, tr *TrustResolver, path string) string {
	proto, fqdn, port := getURLVars(r, tr)
	if port == "" {
		return fmt.Sprintf("%s://%s%s", proto, fqdn, path)
	}
	return fmt.Sprintf("%s://%s:%s%s", proto, fqdn, port, path)
}
