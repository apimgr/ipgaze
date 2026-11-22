// Package blocklist downloads and manages IP/domain blocklists for ipgaze.
// Blocklists are stored in {dataDir}/security/blocklists/ and updated daily.
package blocklist

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"

	"github.com/apimgr/ipgaze/src/tor"
)

// DefaultSources are the built-in blocklist sources.
var DefaultSources = []Source{
	{
		Name: "firehol_level1",
		Type: "ip",
		URL:  "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
		File: "firehol_level1.txt",
	},
}

const maxBlocklistAge = 72 * time.Hour

// Source describes one blocklist data source.
type Source struct {
	Name string
	Type string
	URL  string
	File string
}

// Manager manages blocklist downloads and storage.
type BlocklistManager struct {
	dataDir string
	sources []Source
}

// NewBlocklistManager creates a new blocklist manager. dataDir should be {data_dir}/security/blocklists/.
func NewBlocklistManager(dataDir string, sources []Source) *BlocklistManager {
	if len(sources) == 0 {
		sources = DefaultSources
	}
	return &BlocklistManager{dataDir: dataDir, sources: sources}
}

// Update downloads all configured blocklist sources. Errors are logged but not fatal.
func (m *BlocklistManager) Update() error {
	if err := os.MkdirAll(m.dataDir, 0o755); err != nil {
		return fmt.Errorf("blocklist: create dir: %w", err)
	}
	client := tor.NewHTTPClient(2 * time.Minute)
	var lastErr error
	for _, src := range m.sources {
		if err := m.download(client, src); err != nil {
			log.Printf("blocklist: failed to download %s: %v", src.Name, err)
			lastErr = err
		} else {
			log.Printf("blocklist: updated %s", src.Name)
		}
	}
	if lastErr == nil {
		tsPath := filepath.Join(m.dataDir, ".last_updated")
		if err := os.WriteFile(tsPath, []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o644); err != nil {
			lastErr = fmt.Errorf("blocklist: write update timestamp: %w", err)
		}
	}
	return lastErr
}

// Lookup holds a loaded in-memory copy of all blocklist CIDRs/IPs.
// Call LoadDir to populate from disk; call Contains to check an IP.
type Lookup struct {
	mu            sync.RWMutex
	nets          []*net.IPNet
	singles       []net.IP
	domains       []string
	domainSources map[string][]string
	health        map[string]string
	healthUpdated map[string]time.Time
	skipped       map[string]int
}

// LoadDir reads all .txt files in dir and parses each non-comment line as an
// IP address or CIDR block. Existing data is replaced atomically.
func (l *Lookup) LoadDir(dir string) error {
	return l.LoadDirWithTypes(dir, nil)
}

func (l *Lookup) LoadDirWithTypes(dir string, sourceTypes map[string]string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			// nothing to load yet
			return nil
		}
		return err
	}

	var nets []*net.IPNet
	var singles []net.IP
	var domains []string
	domainSources := make(map[string][]string)
	health := make(map[string]string)
	healthUpdated := make(map[string]time.Time)
	skipped := make(map[string]int)

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".txt") {
			continue
		}
		key := strings.TrimSuffix(e.Name(), filepath.Ext(e.Name()))
		if sourceTypes != nil {
			if _, enabled := sourceTypes[key]; !enabled {
				continue
			}
		}
		f, err := os.Open(filepath.Join(dir, e.Name()))
		if err != nil {
			log.Printf("blocklist: open %s: %v", e.Name(), err)
			continue
		}
		scanner := bufio.NewScanner(f)
		entries := 0
		domainSource := sourceTypes != nil && sourceTypes[key] == "domain"
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
				continue
			}
			// Drop inline annotations after the first whitespace or semicolon.
			commentIndex := len(line)
			for _, marker := range []byte{' ', '\t', ';'} {
				if idx := strings.IndexByte(line, marker); idx >= 0 && idx < commentIndex {
					commentIndex = idx
				}
			}
			line = strings.TrimSpace(line[:commentIndex])
			if domainSource {
				domain := strings.TrimSpace(line)
				wildcard := strings.HasPrefix(domain, "*.")
				if wildcard {
					domain = strings.TrimPrefix(domain, "*.")
				}
				domain, ok := NormalizeDomain(domain)
				if ok && validBlocklistDomain(domain) && (!wildcard || !isPublicSuffix(domain)) {
					if wildcard {
						domain = "*." + domain
					}
					domains = append(domains, domain)
					domainSources[domain] = append(domainSources[domain], key)
					entries++
				} else {
					skipped[key]++
				}
			} else if strings.Contains(line, "/") {
				_, ipnet, err := net.ParseCIDR(line)
				if err == nil {
					nets = append(nets, ipnet)
					entries++
				} else {
					skipped[key]++
				}
			} else {
				ip := net.ParseIP(line)
				if ip != nil {
					singles = append(singles, ip)
					entries++
				} else {
					skipped[key]++
				}
			}
		}
		if err := scanner.Err(); err != nil {
			_ = f.Close()
			return fmt.Errorf("scan %s: %w", e.Name(), err)
		}
		info, statErr := e.Info()
		if statErr == nil {
			healthUpdated[key] = info.ModTime()
		}
		switch {
		case entries == 0 || statErr != nil:
			health[key] = "error"
		case time.Since(info.ModTime()) > maxBlocklistAge:
			health[key] = "degraded"
		default:
			health[key] = "ok"
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("close %s: %w", e.Name(), err)
		}
		if skipped[key] > 0 {
			log.Printf("blocklist: skipped %d invalid entries from %s", skipped[key], key)
		}
	}

	l.mu.Lock()
	l.nets = nets
	l.singles = singles
	l.domains = domains
	l.domainSources = domainSources
	l.health = health
	l.healthUpdated = healthUpdated
	l.skipped = skipped
	l.mu.Unlock()
	return nil
}

func validBlocklistDomain(domain string) bool {
	if domain == "" || strings.Contains(domain, "..") || strings.ContainsAny(domain, "/:@") || net.ParseIP(domain) != nil {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		if strings.Trim(label, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" {
			return false
		}
	}
	return true
}

// NormalizeDomain extracts a hostname from a host, URL, or email domain and
// converts it to the ASCII form used by blocklist entries. IP literals are
// deliberately ignored because they are handled by IP blocklists.
func NormalizeDomain(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", false
	}
	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err != nil {
			return "", false
		}
		value = parsed.Hostname()
	} else if at := strings.LastIndex(value, "@"); at >= 0 {
		value = value[at+1:]
	} else if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	} else if strings.ContainsAny(value, "/?#") {
		return "", false
	}
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	value = strings.Trim(value, "[]")
	if value == "" || net.ParseIP(value) != nil {
		return "", false
	}
	ascii, err := idna.Lookup.ToASCII(value)
	if err != nil {
		return "", false
	}
	ascii = strings.ToLower(strings.TrimSuffix(ascii, "."))
	if !validBlocklistDomain(ascii) {
		return "", false
	}
	return ascii, true
}

func isPublicSuffix(domain string) bool {
	suffix, _ := publicsuffix.PublicSuffix(domain)
	return suffix == domain
}

// SkippedCount reports malformed or unsafe entries ignored while loading a
// source. A missing source has a skipped count of zero.
func (l *Lookup) SkippedCount(id string) int {
	if l == nil {
		return 0
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.skipped[id]
}

// HealthStatus reports the cached health of one parsed list by stable source ID.
func (l *Lookup) HealthStatus(id string) string {
	if l == nil {
		return "error"
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	if status := l.health[id]; status != "" {
		if status == "ok" && time.Since(l.healthUpdated[id]) > maxBlocklistAge {
			return "degraded"
		}
		return status
	}
	return "error"
}

// Contains returns true if ip is covered by any entry in the loaded blocklist.
func (l *Lookup) Contains(ip net.IP) bool {
	if ip == nil {
		return false
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	for _, ipnet := range l.nets {
		if ipnet.Contains(ip) {
			return true
		}
	}
	for _, s := range l.singles {
		if s.Equal(ip) {
			return true
		}
	}
	return false
}

func (l *Lookup) ContainsDomain(host string) bool {
	return len(l.MatchingDomainSources(host)) > 0
}

// MatchingDomainSources returns IDs of loaded domain sources matching host.
func (l *Lookup) MatchingDomainSources(host string) []string {
	host, ok := NormalizeDomain(host)
	if !ok {
		return nil
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	matched := make(map[string]struct{})
	for _, domain := range l.domains {
		match := false
		if strings.HasPrefix(domain, "*.") {
			base := strings.TrimPrefix(domain, "*.")
			if strings.HasSuffix(host, "."+base) {
				match = true
			}
		} else if host == domain {
			match = true
		}
		if match {
			for _, source := range l.domainSources[domain] {
				matched[source] = struct{}{}
			}
		}
	}
	sources := make([]string, 0, len(matched))
	for source := range matched {
		sources = append(sources, source)
	}
	sort.Strings(sources)
	return sources
}

// HasData reports whether at least one parsed blocklist entry is loaded.
func (l *Lookup) HasData() bool {
	if l == nil {
		return false
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.nets) > 0 || len(l.singles) > 0 || len(l.domains) > 0
}

func (m *BlocklistManager) download(client *http.Client, src Source) error {
	resp, err := client.Get(src.URL)
	if err != nil {
		return err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("blocklist: close response body for %s: %v", src.URL, err)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d for %s", resp.StatusCode, src.URL)
	}
	// cap response body at 50 MB to prevent unbounded reads
	limited := io.LimitReader(resp.Body, 50*1024*1024)
	data, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	valid, skipped, err := countValidEntries(data, src.Type)
	if err != nil {
		return fmt.Errorf("blocklist %s is malformed: %w", src.Name, err)
	}
	if valid == 0 {
		return fmt.Errorf("blocklist %s contains no valid entries", src.Name)
	}
	if skipped > 0 {
		log.Printf("blocklist: skipped %d invalid entries from %s", skipped, src.Name)
	}
	dest := filepath.Join(m.dataDir, src.File)
	return writeFileAtomic(dest, data, 0o644)
}

func countValidEntries(data []byte, sourceType string) (int, int, error) {
	valid, skipped := 0, 0
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if index := strings.IndexAny(line, " \t;"); index >= 0 {
			line = strings.TrimSpace(line[:index])
		}
		if sourceType == "domain" {
			wildcard := strings.HasPrefix(line, "*.")
			if wildcard {
				line = strings.TrimPrefix(line, "*.")
			}
			domain, ok := NormalizeDomain(line)
			if ok && (!wildcard || !isPublicSuffix(domain)) {
				valid++
			} else {
				skipped++
			}
			continue
		}
		if strings.Contains(line, "/") {
			if _, _, err := net.ParseCIDR(line); err == nil {
				valid++
			} else {
				skipped++
			}
		} else if net.ParseIP(line) != nil {
			valid++
		} else {
			skipped++
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, skipped, err
	}
	return valid, skipped, nil
}

// writeFileAtomic writes data to a temp file in the same directory as path,
// then renames it into place, so a concurrent Load() or a crash mid-write
// never observes a partially written blocklist file.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		if err := os.Remove(tmpPath); err != nil && !os.IsNotExist(err) {
			log.Printf("blocklist: remove temporary file %s: %v", tmpPath, err)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		if closeErr := tmp.Close(); closeErr != nil {
			return errors.Join(err, closeErr)
		}
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, perm); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
