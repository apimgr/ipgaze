package geoip

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/apimgr/ipgaze/src/iputil/geo"
	maxminddb "github.com/oschwald/maxminddb-golang"
)

const (
	// ip-location-db databases refresh frequently upstream; 72 h keeps the
	// local copy fresh between the scheduler's weekly geoip_update runs.
	updateInterval = 72 * time.Hour
)

// Download sources per AI.md PART 19 "Database Sources (ip-location-db)".
// ASN and Country come from the jsDelivr npm distribution of
// sapics/ip-location-db; City comes from the project's GitHub Releases,
// because jsDelivr's npm CDN caps files at 50 MB and the city databases
// exceed that.
//
// All three are licensed CC BY 4.0 (ASN and Country via the NRO, City via
// DB-IP), so both attribution notices are mandatory wherever GeoIP-derived
// data is displayed — see index.geoip_attribution_* in the locale files and
// the third-party section of LICENSE.md.
const (
	jsdelivrBaseURL    = "https://cdn.jsdelivr.net/npm/@ip-location-db/"
	geoReleaseBaseURL  = "https://github.com/sapics/ip-location-db/releases/download/latest/"
	asnDownloadURL     = jsdelivrBaseURL + "asn-mmdb/asn.mmdb"
	countryDownloadURL = jsdelivrBaseURL + "geo-whois-asn-country-mmdb/geo-whois-asn-country.mmdb"
	cityV4DownloadURL  = geoReleaseBaseURL + "dbip-city-ipv4.mmdb"
	cityV6DownloadURL  = geoReleaseBaseURL + "dbip-city-ipv6.mmdb"
)

// GeoIPManager handles GeoIP database download, refresh, and lookup delegation.
// Per AI.md PART 19: asn, country, city (IPv4 + IPv6) databases from
// sapics/ip-location-db. WHOIS is not a separate download (per AI.md PART 19,
// "no whois.mmdb file exists") — it is a join of the ASN + Country readers
// at query time, so no whoisFile/whoisDB exist here.
type GeoIPManager struct {
	dataDir        string
	asnFile        string
	countryFile    string
	cityV4File     string
	cityV6File     string
	asnDB          *maxminddb.Reader
	countryDB      *maxminddb.Reader
	cityV4DB       *maxminddb.Reader
	cityV6DB       *maxminddb.Reader
	lastUpdate     time.Time
	updateInterval time.Duration
	// liveReader is the single geo.Reader instance handed out by Reader().
	// It is a thin wrapper that atomically swaps to a freshly opened
	// reader every time loadDatabases() runs, so a caller that stashes
	// the value returned by Reader() once (main.go passes it into
	// server.NewHTTPServer at startup) still sees the weekly-refreshed
	// databases instead of the mmdb file handles that were open at
	// startup.
	liveReader *liveReader
}

// NewGeoIPManager creates a new GeoIP manager.
// Per AI.md PART 19: databases stored at {data_dir}/security/geoip/ as
// asn.mmdb, country.mmdb, dbip-city-ipv4.mmdb, dbip-city-ipv6.mmdb
// (download sources — see the const block doc comment above).
// No whois.mmdb file is downloaded; whois is computed from the ASN +
// Country readers per AI.md PART 19's own text.
func NewGeoIPManager(dataDir string) *GeoIPManager {
	geoipDir := filepath.Join(dataDir, "security", "geoip")
	m := &GeoIPManager{
		dataDir:        geoipDir,
		asnFile:        filepath.Join(geoipDir, "asn.mmdb"),
		countryFile:    filepath.Join(geoipDir, "country.mmdb"),
		cityV4File:     filepath.Join(geoipDir, "dbip-city-ipv4.mmdb"),
		cityV6File:     filepath.Join(geoipDir, "dbip-city-ipv6.mmdb"),
		updateInterval: updateInterval,
	}
	empty, _ := geo.Open("", "", "", "")
	m.liveReader = newLiveReader(empty)
	return m
}

// liveReader implements geo.Reader by delegating to whichever reader is
// currently installed via set(). It exists so the single geo.Reader value
// handed out by GeoIPManager.Reader() keeps working across background
// refreshes: refreshLiveReader() swaps the delegate atomically after every
// successful loadDatabases(), so in-flight lookups always see either the
// old or the new database, never a torn/partial one, and never stale data
// after a refresh has completed.
type liveReader struct {
	current atomic.Pointer[geo.Reader]
}

func newLiveReader(r geo.Reader) *liveReader {
	lr := &liveReader{}
	lr.set(r)
	return lr
}

func (l *liveReader) set(r geo.Reader) {
	l.current.Store(&r)
}

func (l *liveReader) Country(ip net.IP) (geo.Country, error) {
	return (*l.current.Load()).Country(ip)
}

func (l *liveReader) City(ip net.IP) (geo.City, error) {
	return (*l.current.Load()).City(ip)
}

func (l *liveReader) ASN(ip net.IP) (geo.ASN, error) {
	return (*l.current.Load()).ASN(ip)
}

func (l *liveReader) IsEmpty() bool {
	return (*l.current.Load()).IsEmpty()
}

// Initialize downloads databases if needed and loads them
func (m *GeoIPManager) Initialize() error {
	// Create data directory
	if err := os.MkdirAll(m.dataDir, 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	// Check if databases exist
	needsDownload := !m.databasesExist()

	if needsDownload {
		log.Println("GeoIP databases not found, downloading...")
		if err := m.DownloadDatabases(); err != nil {
			return fmt.Errorf("failed to download GeoIP databases: %w", err)
		}
	}

	// Load databases
	if err := m.loadDatabases(); err != nil {
		return fmt.Errorf("failed to load GeoIP databases: %w", err)
	}

	m.lastUpdate = time.Now()
	log.Println("GeoIP databases loaded successfully")
	return nil
}

// databasesExist checks if all required databases exist.
func (m *GeoIPManager) databasesExist() bool {
	files := []string{m.asnFile, m.countryFile, m.cityV4File, m.cityV6File}
	for _, file := range files {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// loadDatabases loads all GeoIP databases into memory.
// Uses maxminddb directly — sapics/ip-location-db uses non-MaxMind database_type
// strings ("asn ipv4", "country ipvAll", etc.) that geoip2-golang rejects.
// Per AI.md PART 19 fail-open behavior, each database is loaded
// independently — a missing/corrupt file for one database leaves the
// others working rather than disabling GeoIP entirely. Any previously
// open readers are closed once the new ones are confirmed open, so a
// weekly refresh never leaks the old mmap'd file descriptors.
func (m *GeoIPManager) loadDatabases() error {
	oldASN, oldCountry, oldCityV4, oldCityV6 := m.asnDB, m.countryDB, m.cityV4DB, m.cityV6DB

	var loadErrs []error

	newASN, err := maxminddb.Open(m.asnFile)
	if err != nil {
		loadErrs = append(loadErrs, fmt.Errorf("load ASN database: %w", err))
		newASN = nil
	}

	newCountry, err := maxminddb.Open(m.countryFile)
	if err != nil {
		loadErrs = append(loadErrs, fmt.Errorf("load country database: %w", err))
		newCountry = nil
	}

	newCityV4, err := maxminddb.Open(m.cityV4File)
	if err != nil {
		loadErrs = append(loadErrs, fmt.Errorf("load city (IPv4) database: %w", err))
		newCityV4 = nil
	}

	newCityV6, err := maxminddb.Open(m.cityV6File)
	if err != nil {
		loadErrs = append(loadErrs, fmt.Errorf("load city (IPv6) database: %w", err))
		newCityV6 = nil
	}

	if newASN == nil && newCountry == nil && newCityV4 == nil && newCityV6 == nil {
		return fmt.Errorf("no GeoIP databases could be loaded: %w", loadErrs[0])
	}

	// Only swap in a newly opened reader if it actually opened; otherwise
	// keep serving whatever was previously loaded for that database.
	if newASN != nil {
		m.asnDB = newASN
	}
	if newCountry != nil {
		m.countryDB = newCountry
	}
	if newCityV4 != nil {
		m.cityV4DB = newCityV4
	}
	if newCityV6 != nil {
		m.cityV6DB = newCityV6
	}

	if newASN != nil && oldASN != nil {
		oldASN.Close()
	}
	if newCountry != nil && oldCountry != nil {
		oldCountry.Close()
	}
	if newCityV4 != nil && oldCityV4 != nil {
		oldCityV4.Close()
	}
	if newCityV6 != nil && oldCityV6 != nil {
		oldCityV6.Close()
	}

	m.refreshLiveReader()

	for _, e := range loadErrs {
		log.Printf("geoip: %v (continuing with remaining databases)", e)
	}
	return nil
}

// refreshLiveReader opens a fresh geo.Reader from the current database
// files and installs it into m.liveReader, so every holder of the value
// previously returned by Reader() immediately sees the refreshed data.
func (m *GeoIPManager) refreshLiveReader() {
	r, err := geo.Open(m.countryFile, m.cityV4File, m.cityV6File, m.asnFile)
	if err != nil {
		// Best-effort: keep serving whatever was previously loaded rather
		// than falling back to an empty reader on a transient error.
		log.Printf("geoip: refresh live reader: %v", err)
		return
	}
	m.liveReader.set(r)
}

// DownloadDatabases downloads the 4 GeoIP databases (asn, country, city
// IPv4, city IPv6) from the sources named in the const block above. Per
// AI.md PART 19's fail-open mandate, each file is downloaded independently
// — one failing download (e.g. a transient CDN outage) does not prevent the
// others from being fetched and used. WHOIS has no separate download (see
// the const block doc comment above).
func (m *GeoIPManager) DownloadDatabases() error {
	type dbSpec struct {
		url      string
		filepath string
	}
	specs := []struct {
		name string
		dbSpec
	}{
		{"asn", dbSpec{asnDownloadURL, m.asnFile}},
		{"country", dbSpec{countryDownloadURL, m.countryFile}},
		{"city-ipv4", dbSpec{cityV4DownloadURL, m.cityV4File}},
		{"city-ipv6", dbSpec{cityV6DownloadURL, m.cityV6File}},
	}

	var errs []error
	for _, s := range specs {
		log.Printf("  Downloading %s.mmdb...", s.name)
		if err := m.downloadFile(s.url, s.filepath); err != nil {
			log.Printf("  Download %s.mmdb failed: %v (continuing with remaining databases)", s.name, err)
			errs = append(errs, fmt.Errorf("download %s: %w", s.name, err))
			continue
		}
	}

	if len(errs) == len(specs) {
		return fmt.Errorf("all GeoIP database downloads failed: %w", errs[0])
	}
	return nil
}

// downloadFile downloads a file from URL to local path
func (m *GeoIPManager) downloadFile(url, localPath string) error {
	// 5-minute timeout for large GeoIP database downloads (~50 MB each)
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	// Download to a temp file in the same directory, then atomically rename
	// into place so an interrupted download never leaves a corrupt DB live.
	tmpPath := localPath + ".tmp"
	out, err := os.Create(tmpPath)
	if err != nil {
		return err
	}

	if _, err := io.Copy(out, resp.Body); err != nil {
		out.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}

	if err := os.Rename(tmpPath, localPath); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return nil
}

// ShouldUpdate checks if databases need updating
func (m *GeoIPManager) ShouldUpdate() bool {
	return time.Since(m.lastUpdate) > m.updateInterval
}

// LastUpdate returns the last update time
func (m *GeoIPManager) LastUpdate() time.Time {
	return m.lastUpdate
}

// ForceUpdate forces immediate database update (bypasses ShouldUpdate check)
// Per AI.md PART 20: Admin Panel "Update now" button
func (m *GeoIPManager) ForceUpdate() error {
	log.Println("Force updating GeoIP databases...")
	if err := m.DownloadDatabases(); err != nil {
		return err
	}

	// Reload databases
	if err := m.loadDatabases(); err != nil {
		return err
	}

	m.lastUpdate = time.Now()
	log.Println("GeoIP databases force updated successfully")
	return nil
}

// GeoIPStatus holds the current GeoIP manager status for the admin UI
// Per AI.md PART 20: Admin Panel elements
type GeoIPStatus struct {
	Enabled        bool      `json:"enabled"`
	ASNEnabled     bool      `json:"asn_enabled"`
	CountryEnabled bool      `json:"country_enabled"`
	CityEnabled    bool      `json:"city_enabled"`
	LastUpdate     time.Time `json:"last_update"`
	DatabasesExist bool      `json:"databases_exist"`
}

// GetStatus returns the current GeoIP status.
func (m *GeoIPManager) GetStatus() GeoIPStatus {
	return GeoIPStatus{
		Enabled:        true,
		ASNEnabled:     m.asnDB != nil,
		CountryEnabled: m.countryDB != nil,
		CityEnabled:    m.cityV4DB != nil || m.cityV6DB != nil,
		LastUpdate:     m.lastUpdate,
		DatabasesExist: m.databasesExist(),
	}
}

// Update updates the databases if needed
func (m *GeoIPManager) Update() error {
	if !m.ShouldUpdate() {
		return nil
	}

	log.Println("Updating GeoIP databases...")
	if err := m.DownloadDatabases(); err != nil {
		return err
	}

	// Reload databases
	if err := m.loadDatabases(); err != nil {
		return err
	}

	m.lastUpdate = time.Now()
	log.Println("GeoIP databases updated successfully")
	return nil
}

// Reader returns a geo.Reader backed by the loaded databases. The returned
// value is stable across the manager's lifetime and safe to store — it
// transparently picks up newly downloaded databases after every
// Initialize/Update/ForceUpdate call, so callers never need to re-fetch it.
func (m *GeoIPManager) Reader() geo.Reader {
	return m.liveReader
}
