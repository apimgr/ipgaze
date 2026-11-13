// Package blocklist downloads and manages IP/domain blocklists for ipgaze.
// Blocklists are stored in {dataDir}/security/blocklists/ and updated daily.
package blocklist

import (
	"bufio"
	"errors"
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

	"github.com/apimgr/ipgaze/src/tor"
)

// DefaultSources are the built-in blocklist sources.
var DefaultSources = []Source{
	{
		Name: "firehol_level1",
		URL:  "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
		File: "firehol_level1.txt",
	},
	{
		Name: "spamhaus_drop",
		URL:  "https://www.spamhaus.org/drop/drop.txt",
		File: "spamhaus_drop.txt",
	},
}

// Source describes one blocklist data source.
type Source struct {
	Name string
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
	tsPath := filepath.Join(m.dataDir, ".last_updated")
	_ = os.WriteFile(tsPath, []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o644)
	return lastErr
}

// Lookup holds a loaded in-memory copy of all blocklist CIDRs/IPs.
// Call LoadDir to populate from disk; call Contains to check an IP.
type Lookup struct {
	mu            sync.RWMutex
	nets          []*net.IPNet
	singles       []net.IP
	health        map[string]string
	healthUpdated map[string]time.Time
}

// LoadDir reads all .txt files in dir and parses each non-comment line as an
// IP address or CIDR block. Existing data is replaced atomically.
func (l *Lookup) LoadDir(dir string) error {
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
	health := make(map[string]string)
	healthUpdated := make(map[string]time.Time)

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".txt") {
			continue
		}
		f, err := os.Open(filepath.Join(dir, e.Name()))
		if err != nil {
			log.Printf("blocklist: open %s: %v", e.Name(), err)
			continue
		}
		scanner := bufio.NewScanner(f)
		entries := 0
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
				continue
			}
			// Strip inline comments
			if idx := strings.IndexByte(line, ' '); idx != -1 {
				line = strings.TrimSpace(line[:idx])
			}
			if strings.Contains(line, "/") {
				_, ipnet, err := net.ParseCIDR(line)
				if err == nil {
					nets = append(nets, ipnet)
					entries++
				}
			} else {
				ip := net.ParseIP(line)
				if ip != nil {
					singles = append(singles, ip)
					entries++
				}
			}
		}
		if err := scanner.Err(); err != nil {
			_ = f.Close()
			return fmt.Errorf("scan %s: %w", e.Name(), err)
		}
		info, statErr := e.Info()
		key := strings.TrimSuffix(e.Name(), filepath.Ext(e.Name()))
		if statErr == nil {
			healthUpdated[key] = info.ModTime()
		}
		switch {
		case entries == 0 || statErr != nil:
			health[key] = "error"
		case time.Since(info.ModTime()) > 7*24*time.Hour:
			health[key] = "degraded"
		default:
			health[key] = "ok"
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("close %s: %w", e.Name(), err)
		}
	}

	l.mu.Lock()
	l.nets = nets
	l.singles = singles
	l.health = health
	l.healthUpdated = healthUpdated
	l.mu.Unlock()
	return nil
}

// HealthStatus reports the cached health of one parsed list by stable source ID.
func (l *Lookup) HealthStatus(id string) string {
	if l == nil {
		return "error"
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	if status := l.health[id]; status != "" {
		if status == "ok" && time.Since(l.healthUpdated[id]) > 7*24*time.Hour {
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

// HasData reports whether at least one parsed blocklist entry is loaded.
func (l *Lookup) HasData() bool {
	if l == nil {
		return false
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.nets) > 0 || len(l.singles) > 0
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
	dest := filepath.Join(m.dataDir, src.File)
	return writeFileAtomic(dest, data, 0o644)
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
