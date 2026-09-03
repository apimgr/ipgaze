// Package cve downloads and stores CVE vulnerability databases for ipgaze.
// CVE data is stored in {dataDir}/security/cve/ and updated daily.
package cve

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// NVDAPIURL is the NVD (NIST National Vulnerability Database) CVE API 2.0
// endpoint, per AI.md PART 10 "Default Data Sources (Non-GeoIP)".
// The legacy JSON 1.1 data feeds (nvd.nist.gov/feeds/json/cve/1.1) were
// retired by NIST and now answer HTTP 403, so this is a REST API returning
// paginated JSON rather than a single gzipped dump.
const NVDAPIURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

const (
	// maxResultsPerPage is the largest page size the NVD CVE API 2.0 accepts.
	maxResultsPerPage = 2000
	// requestDelay spaces out page requests. NVD's public (no API key) rate
	// limit is 5 requests per rolling 30 second window; NIST recommends
	// sleeping several seconds between requests to stay under it.
	requestDelay = 6 * time.Second
	// lookbackWindow mirrors the coverage of the retired "recent" feed:
	// every CVE created or modified in the last week. The API caps a single
	// lastModStartDate/lastModEndDate range at 120 days.
	lookbackWindow = 7 * 24 * time.Hour
	// maxResponseBytes caps a single page response to prevent memory exhaustion.
	maxResponseBytes = 32 * 1024 * 1024
	// maxPages bounds the pagination loop so a misbehaving upstream can never
	// spin it forever.
	maxPages = 200
	// nvdTimeLayout is the extended ISO-8601 layout the API expects for the
	// lastModStartDate / lastModEndDate parameters.
	nvdTimeLayout = "2006-01-02T15:04:05.000"
)

// CVEManager manages CVE database downloads and storage.
type CVEManager struct {
	dataDir string
	apiURL  string
	client  *http.Client
	// requestDelay is the pause between paginated API requests. It is a
	// field rather than a constant so tests can drive the pagination loop
	// against a local server without waiting on the public rate limit.
	requestDelay time.Duration
}

// NewCVEManager creates a new CVE manager. dataDir should be {data_dir}/security/cve/.
// Pass an empty apiURL to use the default NVD CVE API 2.0 endpoint.
func NewCVEManager(dataDir, apiURL string) *CVEManager {
	if apiURL == "" {
		apiURL = NVDAPIURL
	}
	return &CVEManager{
		dataDir:      dataDir,
		apiURL:       apiURL,
		client:       &http.Client{Timeout: 5 * time.Minute},
		requestDelay: requestDelay,
	}
}

// nvdResponse is the NVD CVE API 2.0 response envelope.
type nvdResponse struct {
	ResultsPerPage  int                `json:"resultsPerPage"`
	StartIndex      int                `json:"startIndex"`
	TotalResults    int                `json:"totalResults"`
	Format          string             `json:"format"`
	Version         string             `json:"version"`
	Timestamp       string             `json:"timestamp"`
	Vulnerabilities []nvdVulnerability `json:"vulnerabilities"`
}

// nvdVulnerability wraps a single CVE item in the vulnerabilities array.
type nvdVulnerability struct {
	CVE nvdCVE `json:"cve"`
}

// nvdCVE is one CVE record as returned by the API 2.0 schema.
type nvdCVE struct {
	ID           string           `json:"id"`
	Published    string           `json:"published"`
	LastModified string           `json:"lastModified"`
	VulnStatus   string           `json:"vulnStatus"`
	Descriptions []nvdDescription `json:"descriptions"`
	Metrics      nvdMetrics       `json:"metrics"`
	References   []nvdReference   `json:"references"`
}

// nvdDescription is one localized description of a CVE.
type nvdDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// nvdMetrics holds the CVSS scoring blocks. Every field is optional; a CVE
// may carry any combination of scoring versions, or none at all.
type nvdMetrics struct {
	CVSSMetricV40 []nvdCVSSMetric `json:"cvssMetricV40"`
	CVSSMetricV31 []nvdCVSSMetric `json:"cvssMetricV31"`
	CVSSMetricV30 []nvdCVSSMetric `json:"cvssMetricV30"`
	CVSSMetricV2  []nvdCVSSMetric `json:"cvssMetricV2"`
}

// nvdCVSSMetric is one scoring entry. BaseSeverity sits beside cvssData for
// CVSS v2 records and inside cvssData for v3.x and v4.0 records, so both
// positions are decoded and metricSeverity picks whichever is populated.
type nvdCVSSMetric struct {
	Source       string      `json:"source"`
	Type         string      `json:"type"`
	CVSSData     nvdCVSSData `json:"cvssData"`
	BaseSeverity string      `json:"baseSeverity"`
}

// nvdCVSSData is the CVSS vector and score for one scoring entry.
type nvdCVSSData struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

// nvdReference is one external reference URL for a CVE.
type nvdReference struct {
	URL    string `json:"url"`
	Source string `json:"source"`
}

// CVERecord is the normalized form of a CVE stored in nvd.json.
type CVERecord struct {
	ID           string   `json:"id"`
	Published    string   `json:"published"`
	LastModified string   `json:"last_modified"`
	VulnStatus   string   `json:"vuln_status,omitempty"`
	Description  string   `json:"description,omitempty"`
	Severity     string   `json:"severity,omitempty"`
	BaseScore    float64  `json:"base_score,omitempty"`
	VectorString string   `json:"vector_string,omitempty"`
	References   []string `json:"references,omitempty"`
}

// CVEDatabase is the on-disk shape of {dataDir}/nvd.json.
type CVEDatabase struct {
	Source     string      `json:"source"`
	UpdatedAt  string      `json:"updated_at"`
	RangeStart string      `json:"range_start"`
	RangeEnd   string      `json:"range_end"`
	Count      int         `json:"count"`
	CVEs       []CVERecord `json:"cves"`
}

// Update walks the NVD CVE API 2.0 pagination for every CVE created or
// modified within the lookback window, then stores the normalized result
// as nvd.json.
func (m *CVEManager) Update() error {
	if err := os.MkdirAll(m.dataDir, 0o755); err != nil {
		return fmt.Errorf("cve: create dir: %w", err)
	}

	end := time.Now().UTC()
	start := end.Add(-lookbackWindow)

	records := make([]CVERecord, 0, maxResultsPerPage)
	startIndex := 0
	for page := 0; page < maxPages; page++ {
		if page > 0 && m.requestDelay > 0 {
			time.Sleep(m.requestDelay)
		}
		resp, err := m.fetchPage(start, end, startIndex)
		if err != nil {
			return err
		}
		for _, v := range resp.Vulnerabilities {
			if v.CVE.ID == "" {
				continue
			}
			records = append(records, newCVERecord(v.CVE))
		}
		startIndex += len(resp.Vulnerabilities)
		if len(resp.Vulnerabilities) == 0 || startIndex >= resp.TotalResults {
			break
		}
	}

	db := CVEDatabase{
		Source:     m.apiURL,
		UpdatedAt:  end.Format(time.RFC3339),
		RangeStart: start.Format(time.RFC3339),
		RangeEnd:   end.Format(time.RFC3339),
		Count:      len(records),
		CVEs:       records,
	}
	data, err := json.Marshal(db)
	if err != nil {
		return fmt.Errorf("cve: encode database: %w", err)
	}
	dest := filepath.Join(m.dataDir, "nvd.json")
	if err := writeFileAtomic(dest, data, 0o644); err != nil {
		return fmt.Errorf("cve: write file: %w", err)
	}
	log.Printf("cve: updated database (%d CVEs, %d bytes)", len(records), len(data))
	tsPath := filepath.Join(m.dataDir, ".last_updated")
	_ = writeFileAtomic(tsPath, []byte(end.Format(time.RFC3339)+"\n"), 0o644)
	return nil
}

// fetchPage requests a single page of results from the CVE API 2.0.
func (m *CVEManager) fetchPage(start, end time.Time, startIndex int) (*nvdResponse, error) {
	pageURL, err := m.pageURL(start, end, startIndex)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodGet, pageURL, nil)
	if err != nil {
		return nil, fmt.Errorf("cve: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cve: download feed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cve: HTTP %d from %s", resp.StatusCode, m.apiURL)
	}
	limited := io.LimitReader(resp.Body, maxResponseBytes)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("cve: read response: %w", err)
	}
	var parsed nvdResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("cve: decode response: %w", err)
	}
	return &parsed, nil
}

// pageURL builds the request URL for one page, carrying the modification
// window and pagination cursor as query parameters. Any query parameters
// already present on the configured endpoint are preserved.
func (m *CVEManager) pageURL(start, end time.Time, startIndex int) (string, error) {
	u, err := url.Parse(m.apiURL)
	if err != nil {
		return "", fmt.Errorf("cve: parse source URL: %w", err)
	}
	q := u.Query()
	q.Set("resultsPerPage", strconv.Itoa(maxResultsPerPage))
	q.Set("startIndex", strconv.Itoa(startIndex))
	q.Set("lastModStartDate", start.UTC().Format(nvdTimeLayout)+"Z")
	q.Set("lastModEndDate", end.UTC().Format(nvdTimeLayout)+"Z")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// newCVERecord normalizes one API 2.0 CVE item into its stored form.
func newCVERecord(c nvdCVE) CVERecord {
	rec := CVERecord{
		ID:           c.ID,
		Published:    c.Published,
		LastModified: c.LastModified,
		VulnStatus:   c.VulnStatus,
		Description:  englishDescription(c.Descriptions),
	}
	if metric, ok := primaryMetric(c.Metrics); ok {
		rec.Severity = metricSeverity(metric)
		rec.BaseScore = metric.CVSSData.BaseScore
		rec.VectorString = metric.CVSSData.VectorString
	}
	for _, ref := range c.References {
		if ref.URL != "" {
			rec.References = append(rec.References, ref.URL)
		}
	}
	return rec
}

// englishDescription returns the English description, falling back to the
// first available one when NVD has not published an English text.
func englishDescription(descriptions []nvdDescription) string {
	for _, d := range descriptions {
		if d.Lang == "en" {
			return d.Value
		}
	}
	if len(descriptions) > 0 {
		return descriptions[0].Value
	}
	return ""
}

// primaryMetric returns the highest-precedence CVSS entry available for a
// CVE: v4.0, then v3.1, v3.0, then the legacy v2 score.
func primaryMetric(m nvdMetrics) (nvdCVSSMetric, bool) {
	for _, group := range [][]nvdCVSSMetric{m.CVSSMetricV40, m.CVSSMetricV31, m.CVSSMetricV30, m.CVSSMetricV2} {
		if len(group) > 0 {
			return group[0], true
		}
	}
	return nvdCVSSMetric{}, false
}

// metricSeverity reads baseSeverity from wherever the scoring version puts it.
func metricSeverity(metric nvdCVSSMetric) string {
	if metric.CVSSData.BaseSeverity != "" {
		return metric.CVSSData.BaseSeverity
	}
	return metric.BaseSeverity
}

// writeFileAtomic writes data to a temp file in the same directory as path,
// then renames it into place, so a concurrent reader or a crash mid-write
// never observes a partially written CVE database file.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
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
