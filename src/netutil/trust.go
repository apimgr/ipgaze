package netutil

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/apimgr/ipgaze/src/config"
)

// TrustResolver caches DNS resolutions for additional trusted proxy entries and
// auto-trusts the /24 (IPv4) or /64 (IPv6) subnet containing the server's listen
// address, covering the containerised sidecar reverse-proxy pattern per AI.md PART 12.
// DNS names in cfg.Additional are resolved at construction and refreshed every 5 minutes.
type TrustResolver struct {
	clientIPHeader string
	// listenCIDR is the /24 (IPv4) or /64 (IPv6) derived from the server's bind address.
	listenCIDR netip.Prefix
	// additional holds the raw config entries: IPs, CIDRs, and DNS names.
	additional []string
	mu         sync.RWMutex
	// dnsCache maps DNS names to their last-resolved IPs.
	dnsCache map[string][]net.IP
	// OnionAddress is the .onion hostname configured via tor.onion_address (AI.md PART 12).
	// When non-empty, requests whose Host header matches this value are Tor requests (priority 0).
	OnionAddress string
	// I2PAddress is the .b32.i2p hostname derived from the I2P eepsite destination
	// (AI.md PART 31.2). When non-empty, requests whose Host header matches this
	// value are I2P requests, trusted for FQDN resolution exactly like Tor (priority 0).
	I2PAddress string
}

// NewTrustResolver creates a resolver from TrustedProxiesConfig and the server's listen address.
// listenAddr must be a bare IP (not host:port). Pass "" or "0.0.0.0" or "::" to skip /24 auto-trust.
// DNS names in cfg.Additional are resolved immediately. Call Start(ctx) to keep them fresh.
func NewTrustResolver(cfg config.TrustedProxiesConfig, listenAddr string) *TrustResolver {
	tr := &TrustResolver{
		additional:     cfg.Additional,
		clientIPHeader: cfg.ClientIPHeader,
		dnsCache:       make(map[string][]net.IP),
	}
	if tr.clientIPHeader == "" {
		tr.clientIPHeader = "auto"
	}
	// Derive a subnet from the listen address so a sidecar proxy on the same Docker network
	// is automatically trusted without manual config.
	if listenAddr != "" && listenAddr != "0.0.0.0" && listenAddr != "::" && listenAddr != "[::]" {
		if addr, ok := ParseClientIP(listenAddr); ok {
			var cidrStr string
			if addr.Is4() {
				prefix, _ := addr.Prefix(24)
				cidrStr = prefix.Masked().String()
			} else {
				prefix, _ := addr.Prefix(64)
				cidrStr = prefix.Masked().String()
			}
			tr.listenCIDR, _ = netip.ParsePrefix(cidrStr)
		}
	}
	tr.refreshDNS()
	return tr
}

// Start begins the 5-minute DNS refresh goroutine per AI.md PART 12.
// Returns when ctx is cancelled.
func (tr *TrustResolver) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				tr.refreshDNS()
			}
		}
	}()
}

// IsTrustedPeer reports whether r's immediate peer is a trusted reverse proxy.
// Always-trusted: loopback, RFC 1918 private, RFC 4193 ULA, link-local, and the
// /24 subnet of the server's listen address (sidecar pattern).
// Additional trust entries from config are also honoured.
// Safe to call on a nil receiver — only alwaysTrustedCIDRs apply in that case.
func (tr *TrustResolver) IsTrustedPeer(r *http.Request) bool {
	ipAddr, ok := ParseClientIP(r.RemoteAddr)
	if !ok {
		return false
	}
	return tr.isTrustedIP(ipAddr)
}

func isAlwaysTrustedIP(ipAddr netip.Addr) bool {
	ip := net.IP(ipAddr.AsSlice())

	// Always-trusted ranges — checked even with nil resolver.
	for _, n := range alwaysTrustedCIDRs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (tr *TrustResolver) isTrustedIP(ipAddr netip.Addr) bool {
	if !ipAddr.IsValid() {
		return false
	}
	if isAlwaysTrustedIP(ipAddr) {
		return true
	}
	if tr == nil {
		return false
	}

	// Same /24 as configured listen address (containerised sidecar proxy pattern).
	if tr.listenCIDR.IsValid() && tr.listenCIDR.Contains(ipAddr) {
		return true
	}

	tr.mu.RLock()
	defer tr.mu.RUnlock()

	for _, entry := range tr.additional {
		// Try CIDR.
		if network, err := normalizedPrefix(entry); err == nil {
			if network.Contains(ipAddr) {
				return true
			}
			continue
		}
		// Try exact IP.
		if entryIP, ok := ParseClientIP(entry); ok {
			if entryIP == ipAddr {
				return true
			}
			continue
		}
		// Use cached DNS results.
		if resolved, ok := tr.dnsCache[entry]; ok {
			for _, a := range resolved {
				resolvedAddr, ok := ParseClientIP(a.String())
				if ok && resolvedAddr == ipAddr {
					return true
				}
			}
		}
	}
	return false
}

func normalizedPrefix(value string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
		return netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96).Masked(), nil
	}
	return prefix.Masked(), nil
}

// refreshDNS resolves all DNS-name entries in additional and updates dnsCache.
// IPs and CIDRs are skipped — they are evaluated directly in IsTrustedPeer.
func (tr *TrustResolver) refreshDNS() {
	fresh := make(map[string][]net.IP)
	for _, entry := range tr.additional {
		// Skip entries that are already bare IPs.
		if net.ParseIP(entry) != nil {
			continue
		}
		// Skip CIDR entries.
		if _, _, err := net.ParseCIDR(entry); err == nil {
			continue
		}
		// Resolve DNS name.
		if addrs, err := net.LookupHost(entry); err == nil {
			ips := make([]net.IP, 0, len(addrs))
			for _, a := range addrs {
				if ip := net.ParseIP(a); ip != nil {
					ips = append(ips, ip)
				}
			}
			if len(ips) > 0 {
				fresh[entry] = ips
			}
		}
	}
	tr.mu.Lock()
	tr.dnsCache = fresh
	tr.mu.Unlock()
}
