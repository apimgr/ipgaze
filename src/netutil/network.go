package netutil

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// getAccessibleURL returns the most relevant URL for accessing the server
// Priority: FQDN > hostname > public IP > fallback
// NEVER shows localhost, 127.0.0.1, or 0.0.0.0
func getAccessibleURL(port string) string {
	// Try to get hostname
	hostname, err := os.Hostname()
	if err == nil && hostname != "" && hostname != "localhost" {
		// Try to resolve hostname to see if it's a valid FQDN
		if addrs, err := net.LookupHost(hostname); err == nil && len(addrs) > 0 {
			return formatURLWithHost(hostname, port)
		}
	}

	// Try to get outbound IP (most likely accessible IP)
	if ip := getOutboundIP(); ip != "" {
		return formatURLWithIP(ip, port)
	}

	// Fallback to hostname if we have one
	if hostname != "" && hostname != "localhost" {
		return formatURLWithHost(hostname, port)
	}

	// Last resort: use a generic message
	return fmt.Sprintf("http://<your-host>:%s", port)
}

// getOutboundIP gets the preferred outbound IP of this machine
func getOutboundIP() string {
	// Try IPv4 first
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err == nil {
		defer conn.Close()
		localAddr := conn.LocalAddr().(*net.UDPAddr)
		return localAddr.IP.String()
	}

	// Try IPv6
	conn, err = net.Dial("udp", "[2001:4860:4860::8888]:80")
	if err == nil {
		defer conn.Close()
		localAddr := conn.LocalAddr().(*net.UDPAddr)
		return localAddr.IP.String()
	}

	return ""
}

// formatURLWithIP formats a URL with IP address (handles IPv6 brackets)
func formatURLWithIP(ip, port string) string {
	// IPv6 addresses need brackets
	if strings.Contains(ip, ":") {
		return fmt.Sprintf("http://[%s]:%s", ip, port)
	}
	return fmt.Sprintf("http://%s:%s", ip, port)
}

// formatURLWithHost formats a URL with hostname
func formatURLWithHost(hostname, port string) string {
	return fmt.Sprintf("http://%s:%s", hostname, port)
}

// publicIPSources is the ordered list of external services used by FetchPublicIP.
// Each endpoint returns the public IP as plain text (no JSON parsing required).
var publicIPSources = []string{
	"https://api4.ipify.org",
	"https://api.ipify.org",
	"https://ifconfig.me/ip",
	"https://checkip.amazonaws.com",
}

// FetchPublicIP fetches the server's own external public IP by querying
// public IP echo services in priority order. Returns the first valid IPv4
// response or an error if all sources fail. Used by the public_ip_refresh
// scheduler task (AI.md PART 18).
func FetchPublicIP() (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	var lastErr error
	for _, src := range publicIPSources {
		resp, err := client.Get(src)
		if err != nil {
			lastErr = err
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
		resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("source %s: status %d", src, resp.StatusCode)
			continue
		}
		ip := strings.TrimSpace(string(body))
		if parsed := net.ParseIP(ip); parsed != nil {
			return ip, nil
		}
		lastErr = fmt.Errorf("source %s: invalid IP %q", src, ip)
	}
	return "", fmt.Errorf("FetchPublicIP: all sources failed: %w", lastErr)
}

// isIPv6 checks if the given IP is IPv6
func isIPv6(ip net.IP) bool {
	return ip.To4() == nil
}

// parseIP parses an IP address string, removing brackets if present
func parseIP(ipStr string) (net.IP, error) {
	// Remove brackets if present (from URL)
	ipStr = strings.Trim(ipStr, "[]")

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipStr)
	}

	return ip, nil
}
