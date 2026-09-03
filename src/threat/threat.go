// Package threat downloads and manages VPN, proxy, and Tor exit-node IP lists.
// Lists are stored in {dataDir}/security/threat/ and updated daily via the scheduler.
// Detection is purely local — no external API calls at request time.
package threat

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const downloadTimeout = 2 * time.Minute

// Source describes one threat intelligence data source.
type Source struct {
	// Name is a short identifier used in log messages.
	Name string
	// URL is the plain-text CIDR/IP list to download.
	URL string
	// File is the local filename within the data directory.
	File string
	// Kind classifies the source (tor, vpn, proxy) for Lookup routing.
	Kind string
}

// DefaultSources are the built-in threat intelligence sources.
// All are freely available without an API key.
var DefaultSources = []Source{
	{
		Name: "tor_exit",
		URL:  "https://check.torproject.org/torbulkexitlist",
		File: "tor_exit.txt",
		Kind: "tor",
	},
	{
		Name: "vpn_ipv4",
		URL:  "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt",
		File: "vpn_ipv4.txt",
		Kind: "vpn",
	},
	{
		Name: "vpn_ipv6",
		URL:  "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv6.txt",
		File: "vpn_ipv6.txt",
		Kind: "vpn",
	},
	{
		Name: "proxy_socks",
		URL:  "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/socks_proxy_7d.ipset",
		File: "proxy_socks.txt",
		Kind: "proxy",
	},
	{
		Name: "proxy_http",
		URL:  "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/http_proxy_7d.ipset",
		File: "proxy_http.txt",
		Kind: "proxy",
	},
}

// Manager handles downloading and storing threat intelligence lists.
type Manager struct {
	dataDir string
	sources []Source
}

// NewManager creates a new threat intelligence manager.
// dataDir should be {data_dir}/security/threat/.
func NewManager(dataDir string, sources []Source) *Manager {
	if len(sources) == 0 {
		sources = DefaultSources
	}
	return &Manager{dataDir: dataDir, sources: sources}
}

// Initialize downloads any missing lists and returns a populated Lookup.
// Missing files are downloaded; existing files are not re-downloaded at startup
// (the scheduler handles daily refreshes).
func (m *Manager) Initialize() (*Lookup, error) {
	if err := os.MkdirAll(m.dataDir, 0o755); err != nil {
		return nil, fmt.Errorf("threat: create dir: %w", err)
	}

	client := &http.Client{Timeout: downloadTimeout}

	for _, src := range m.sources {
		dest := filepath.Join(m.dataDir, src.File)
		if _, err := os.Stat(dest); os.IsNotExist(err) {
			log.Printf("threat: %s not found, downloading...", src.Name)
			if err := download(client, src.URL, dest); err != nil {
				log.Printf("threat: warning: failed to download %s: %v", src.Name, err)
			} else {
				log.Printf("threat: downloaded %s", src.Name)
			}
		}
	}

	lk := &Lookup{}
	if err := lk.LoadDir(m.dataDir, m.sources); err != nil {
		return lk, fmt.Errorf("threat: load: %w", err)
	}
	return lk, nil
}

// Update downloads all configured sources unconditionally and reloads the given Lookup.
// Called by the scheduler task (threat_update).
func (m *Manager) Update(lk *Lookup) error {
	if err := os.MkdirAll(m.dataDir, 0o755); err != nil {
		return fmt.Errorf("threat: create dir: %w", err)
	}

	client := &http.Client{Timeout: downloadTimeout}
	var lastErr error
	for _, src := range m.sources {
		dest := filepath.Join(m.dataDir, src.File)
		if err := download(client, src.URL, dest); err != nil {
			log.Printf("threat: failed to download %s: %v", src.Name, err)
			lastErr = err
		} else {
			log.Printf("threat: updated %s", src.Name)
		}
	}

	tsPath := filepath.Join(m.dataDir, ".last_updated")
	_ = os.WriteFile(tsPath, []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o644)

	if err := lk.LoadDir(m.dataDir, m.sources); err != nil {
		return fmt.Errorf("threat: reload after update: %w", err)
	}
	return lastErr
}

// download fetches url and writes it atomically to dest (write to temp then rename).
func download(client *http.Client, url, dest string) error {
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d for %s", resp.StatusCode, url)
	}
	// Cap at 50 MB to prevent unbounded reads.
	limited := io.LimitReader(resp.Body, 50*1024*1024)
	data, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	// Write atomically via a temp file in the same directory.
	tmp := dest + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, dest)
}

// kindSet holds the parsed entries for one threat kind (tor/vpn/proxy).
type kindSet struct {
	nets    []*net.IPNet
	singles []net.IP
}

// contains returns true if ip is covered by any entry in the set.
func (ks *kindSet) contains(ip net.IP) bool {
	for _, n := range ks.nets {
		if n.Contains(ip) {
			return true
		}
	}
	for _, s := range ks.singles {
		if s.Equal(ip) {
			return true
		}
	}
	return false
}

// Lookup holds in-memory threat data loaded from disk.
// Call LoadDir to populate; call IsTor/IsVPN/IsProxy to query.
type Lookup struct {
	mu    sync.RWMutex
	tor   kindSet
	vpn   kindSet
	proxy kindSet
}

// LoadDir reads all source files from dir and rebuilds the in-memory tables.
// sources controls which file maps to which kind; the map is replaced atomically.
func (l *Lookup) LoadDir(dir string, sources []Source) error {
	var tor, vpn, proxy kindSet

	for _, src := range sources {
		path := filepath.Join(dir, src.File)
		if err := parseFile(path, src.Kind, &tor, &vpn, &proxy); err != nil {
			// Non-fatal: log and continue — partial data beats no data.
			log.Printf("threat: load %s: %v", src.File, err)
		}
	}

	l.mu.Lock()
	l.tor = tor
	l.vpn = vpn
	l.proxy = proxy
	l.mu.Unlock()
	return nil
}

// parseFile reads one IP list file and appends entries to the appropriate kindSet.
func parseFile(path, kind string, tor, vpn, proxy *kindSet) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	var target *kindSet
	switch kind {
	case "tor":
		target = tor
	case "vpn":
		target = vpn
	case "proxy":
		target = proxy
	default:
		return fmt.Errorf("unknown kind %q", kind)
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		// Strip inline comments.
		if idx := strings.IndexAny(line, " \t"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}
		if strings.Contains(line, "/") {
			_, ipnet, err := net.ParseCIDR(line)
			if err == nil {
				target.nets = append(target.nets, ipnet)
			}
		} else {
			ip := net.ParseIP(line)
			if ip != nil {
				target.singles = append(target.singles, ip)
			}
		}
	}
	return scanner.Err()
}

// IsTor returns true when ip is a known Tor exit node.
func (l *Lookup) IsTor(ip net.IP) bool {
	if ip == nil {
		return false
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.tor.contains(ip)
}

// IsVPN returns true when ip belongs to a known VPN provider address range.
func (l *Lookup) IsVPN(ip net.IP) bool {
	if ip == nil {
		return false
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.vpn.contains(ip)
}

// IsProxy returns true when ip is a known open or data-centre proxy.
func (l *Lookup) IsProxy(ip net.IP) bool {
	if ip == nil {
		return false
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.proxy.contains(ip)
}
