package netutil

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// getFQDN returns the best domain name for this server per AI.md PART 15 resolution order:
//  1. DOMAIN env var (first entry when comma-separated)
//  2. os.Hostname() — skip loopback/localhost
//  3. HOSTNAME env var — skip loopback/localhost
//  4. First global unicast IPv6 address
//  5. First global unicast IPv4 address
//  6. "localhost" as last resort
func getFQDN() string {
	// 1. DOMAIN env var — explicit user override, comma-separated list
	if domain := os.Getenv("DOMAIN"); domain != "" {
		if idx := strings.Index(domain, ","); idx > 0 {
			return strings.TrimSpace(domain[:idx])
		}
		return strings.TrimSpace(domain)
	}

	// 2. os.Hostname()
	if hostname, err := os.Hostname(); err == nil && hostname != "" && !isLoopback(hostname) {
		return hostname
	}

	// 3. $HOSTNAME env var
	if hostname := os.Getenv("HOSTNAME"); hostname != "" && !isLoopback(hostname) {
		return hostname
	}

	// 4. Global IPv6 (preferred for modern dual-stack networks)
	if ipv6 := getGlobalIPv6(); ipv6 != "" {
		return ipv6
	}

	// 5. Global IPv4
	if ipv4 := getGlobalIPv4(); ipv4 != "" {
		return ipv4
	}

	return "localhost"
}

// isLoopback returns true when host is a loopback address or "localhost".
func isLoopback(host string) bool {
	if strings.ToLower(host) == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// getHostFromRequest extracts the canonical host name from the request.
// Proxy headers are checked in priority order per AI.md PART 15:
// X-Forwarded-Host → X-Real-Host → X-Original-Host → r.Host.
func getHostFromRequest(r *http.Request) string {
	// Check reverse-proxy host headers in priority order.
	for _, header := range []string{"X-Forwarded-Host", "X-Real-Host", "X-Original-Host"} {
		if val := r.Header.Get(header); val != "" {
			// X-Forwarded-Host may be a comma-separated chain; take the first.
			host := strings.TrimSpace(strings.Split(val, ",")[0])
			if host != "" {
				if h, _, err := net.SplitHostPort(host); err == nil {
					return h
				}
				return host
			}
		}
	}

	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	// Strip port if present.
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

// getAllDomains returns the list of domains configured via the DOMAIN env var
// (comma-separated). Used for CORS configuration and SSL certificate provisioning
// per AI.md PART 15. Falls back to [getFQDN()] when DOMAIN is not set.
func getAllDomains() []string {
	if domain := os.Getenv("DOMAIN"); domain != "" {
		parts := strings.Split(domain, ",")
		domains := make([]string, 0, len(parts))
		for _, p := range parts {
			if d := strings.TrimSpace(p); d != "" {
				domains = append(domains, d)
			}
		}
		if len(domains) > 0 {
			return domains
		}
	}
	// Fallback: build list from discoverable host names / IPs.
	return getServerDomains()
}

// getServerDomains returns all addressable domain names for this server:
// FQDN, hostname, and public IP addresses.
func getServerDomains() []string {
	seen := map[string]struct{}{}
	var domains []string

	add := func(d string) {
		if d == "" || d == "localhost" {
			return
		}
		if _, ok := seen[d]; !ok {
			seen[d] = struct{}{}
			domains = append(domains, d)
		}
	}

	add(getFQDN())
	if h, err := os.Hostname(); err == nil {
		add(h)
	}
	if ip := getGlobalIPv4(); ip != "" {
		add(ip)
		if names, err := net.LookupAddr(ip); err == nil {
			for _, n := range names {
				add(strings.TrimSuffix(n, "."))
			}
		}
	}
	if ip := getGlobalIPv6(); ip != "" {
		add(ip)
	}

	if len(domains) == 0 {
		domains = append(domains, "localhost")
	}
	return domains
}

// getWildcardDomain returns the wildcard form of the base domain (e.g. "*.example.com").
// Returns an empty string when no suitable base domain can be determined.
func getWildcardDomain(fqdn string) string {
	base := extractBaseDomain(fqdn)
	if base == "" {
		return ""
	}
	return "*." + base
}

// getWildcardDomainFromEnv infers the wildcard domain from the DOMAIN env var list.
// Returns "*.example.com" when all listed domains share the same base, else "".
// Used for SSL certificate wildcard requests per AI.md PART 15.
func getWildcardDomainFromEnv() string {
	domains := getAllDomains()
	if len(domains) < 2 {
		return ""
	}
	base := extractBaseDomain(domains[0])
	for _, d := range domains[1:] {
		if extractBaseDomain(d) != base {
			return ""
		}
	}
	return "*." + base
}

// GetFQDN returns the best host/domain name for this server when no request
// context is available (startup banners, background tasks, scheduler jobs)
// per AI.md PART 8 → "URL & FQDN Detection" resolution order: DOMAIN env var,
// os.Hostname(), $HOSTNAME env var, first global-unicast IPv6, first
// global-unicast IPv4, then "localhost" as the last resort. Never returns
// a wildcard bind address such as "0.0.0.0" or "[::]" — those are explicitly
// listed as WRONG in AI.md's URL Display Rules.
func GetFQDN() string {
	return getFQDN()
}

// devOnlyTLDs are the static development-only suffixes from AI.md PART 12
// "Dev TLD Handling". A host under any of them never resolves for a remote
// client, so a display URL falls back to a global IP instead.
var devOnlyTLDs = []string{
	"local",
	"test",
	"example",
	"invalid",
	"localhost",
	"lan",
	"internal",
	"home",
	"localdomain",
	"home.arpa",
	"intranet",
	"corp",
	"private",
}

// IsDevTLD reports whether host uses a development-only TLD: the dynamic
// project-name TLD (`{project_name}` itself, or any `*.{project_name}`) or one
// of the static suffixes in devOnlyTLDs.
func IsDevTLD(host, projectName string) bool {
	lower := strings.ToLower(strings.TrimSpace(host))
	if lower == "" {
		return false
	}
	if projectName != "" {
		pn := strings.ToLower(projectName)
		if lower == pn || strings.HasSuffix(lower, "."+pn) {
			return true
		}
	}
	for _, tld := range devOnlyTLDs {
		if lower == tld || strings.HasSuffix(lower, "."+tld) {
			return true
		}
	}
	return false
}

// GetDisplayURL returns the single URL to show in banners, logs, and status
// output per AI.md PART 12 "Dev TLD Handling". A real production FQDN is used
// as-is; a dev TLD or localhost falls back to this host's global IPv6
// (bracketed) then global IPv4, so the printed URL is reachable from another
// machine. The detected FQDN is the last resort when the host has no global
// address at all.
func GetDisplayURL(projectName, port string, sslEnabled bool) string {
	scheme := "http"
	if sslEnabled {
		scheme = "https"
	}
	fqdn := getFQDN()
	if !IsDevTLD(fqdn, projectName) && !isLoopback(fqdn) {
		return formatURL(scheme, fqdn, port)
	}
	if ipv6 := getGlobalIPv6(); ipv6 != "" {
		return formatURL(scheme, "["+ipv6+"]", port)
	}
	if ipv4 := getGlobalIPv4(); ipv4 != "" {
		return formatURL(scheme, ipv4, port)
	}
	return formatURL(scheme, fqdn, port)
}

// formatURL builds a URL string from scheme, host, and port.
// Omits the port for the scheme's default (80 for http, 443 for https).
func formatURL(scheme, host, port string) string {
	if port == "" || port == "0" {
		return fmt.Sprintf("%s://%s", scheme, host)
	}
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		return fmt.Sprintf("%s://%s", scheme, host)
	}
	return fmt.Sprintf("%s://%s:%s", scheme, host, port)
}

// getGlobalIPv6 returns the first global unicast IPv6 address of this host, or empty string.
func getGlobalIPv6() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.To4() != nil {
				continue
			}
			if ip.IsGlobalUnicast() && isPublicIP(ip) {
				return ip.String()
			}
		}
	}
	return ""
}

// getGlobalIPv4 returns the first global unicast IPv4 address of this host, or empty string.
func getGlobalIPv4() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.To4() == nil {
				continue
			}
			if ip.IsGlobalUnicast() && isPublicIP(ip) {
				return ip.String()
			}
		}
	}
	return ""
}

// isPublicIP returns true when ip is a routable public address.
// RFC 1918, RFC 4193, loopback, link-local, and documentation ranges are excluded.
func isPublicIP(ip net.IP) bool {
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"100.64.0.0/10",
		"169.254.0.0/16",
		"fc00::/7",
		"fe80::/10",
		"::1/128",
		"127.0.0.0/8",
	}
	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return false
		}
	}
	return true
}

// extractBaseDomain returns the registrable domain (eTLD+1) portion of a FQDN
// using golang.org/x/net/publicsuffix per AI.md PART 15, so multi-label public
// suffixes resolve correctly: "www.google.co.uk" returns "google.co.uk", not "co.uk".
// Single-label hosts (e.g. "myhost") or IP addresses return an empty string.
func extractBaseDomain(fqdn string) string {
	fqdn = strings.TrimSuffix(fqdn, ".")
	if net.ParseIP(fqdn) != nil {
		return ""
	}
	base, err := publicsuffix.EffectiveTLDPlusOne(fqdn)
	if err != nil {
		return ""
	}
	return base
}
