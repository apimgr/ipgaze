package cve

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// nvdPage renders one NVD CVE API 2.0 response envelope for tests.
func nvdPage(startIndex, total int, ids ...string) string {
	items := make([]string, 0, len(ids))
	for _, id := range ids {
		items = append(items, fmt.Sprintf(`{"cve":{"id":%q,"published":"2026-08-01T00:00:00.000",`+
			`"lastModified":"2026-08-20T00:00:00.000","vulnStatus":"Analyzed",`+
			`"descriptions":[{"lang":"es","value":"descripcion"},{"lang":"en","value":"english text"}],`+
			`"metrics":{"cvssMetricV31":[{"source":"nvd@nist.gov","type":"Primary",`+
			`"cvssData":{"version":"3.1","vectorString":"CVSS:3.1/AV:N","baseScore":9.8,"baseSeverity":"CRITICAL"}}]},`+
			`"references":[{"url":"https://example.com/adv","source":"nvd@nist.gov"}]}}`, id))
	}
	return fmt.Sprintf(`{"resultsPerPage":%d,"startIndex":%d,"totalResults":%d,"format":"NVD_CVE",`+
		`"version":"2.0","timestamp":"2026-08-31T00:00:00.000","vulnerabilities":[%s]}`,
		len(ids), startIndex, total, strings.Join(items, ","))
}

// newTestManager builds a manager pointed at a test server with the inter-page
// rate-limit pause disabled.
func newTestManager(dir, apiURL string) *CVEManager {
	m := NewCVEManager(dir, apiURL)
	m.requestDelay = 0
	return m
}

// mustTime parses an RFC3339 timestamp or fails the test.
func mustTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatalf("parse %q: %v", value, err)
	}
	return parsed
}

// loadDatabase reads and decodes the nvd.json written by Update.
func loadDatabase(t *testing.T, dir string) CVEDatabase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "nvd.json"))
	if err != nil {
		t.Fatalf("ReadFile nvd.json: %v", err)
	}
	var db CVEDatabase
	if err := json.Unmarshal(raw, &db); err != nil {
		t.Fatalf("decode nvd.json: %v", err)
	}
	return db
}

// ---------------------------------------------------------------------------
// NewCVEManager
// ---------------------------------------------------------------------------

func TestNewCVEManager_DefaultAPIURL(t *testing.T) {
	m := NewCVEManager("/tmp/testdir", "")
	if m.apiURL != NVDAPIURL {
		t.Errorf("default apiURL = %q, want %q", m.apiURL, NVDAPIURL)
	}
	if m.dataDir != "/tmp/testdir" {
		t.Errorf("dataDir = %q, want /tmp/testdir", m.dataDir)
	}
}

func TestNewCVEManager_CustomAPIURL(t *testing.T) {
	custom := "https://example.com/rest/json/cves/2.0"
	m := NewCVEManager("/tmp/testdir", custom)
	if m.apiURL != custom {
		t.Errorf("apiURL = %q, want %q", m.apiURL, custom)
	}
}

func TestNewCVEManager_EmptyDataDir(t *testing.T) {
	m := NewCVEManager("", "")
	if m == nil {
		t.Fatal("NewCVEManager returned nil")
	}
}

// NVDAPIURL must point at the REST API 2.0 endpoint, not the retired 1.1 feeds.
func TestNVDAPIURL_IsRESTAPIv2(t *testing.T) {
	if !strings.HasPrefix(NVDAPIURL, "https://") {
		t.Errorf("NVDAPIURL = %q, must start with https://", NVDAPIURL)
	}
	if !strings.Contains(NVDAPIURL, "/rest/json/cves/2.0") {
		t.Errorf("NVDAPIURL = %q, must use the CVE API 2.0 path", NVDAPIURL)
	}
	if strings.Contains(NVDAPIURL, "/feeds/json/cve/1.1") {
		t.Errorf("NVDAPIURL = %q still uses the retired 1.1 data feeds", NVDAPIURL)
	}
}

// ---------------------------------------------------------------------------
// pageURL — query parameter construction
// ---------------------------------------------------------------------------

func TestPageURL_SetsPaginationAndWindow(t *testing.T) {
	m := NewCVEManager("/tmp/testdir", "")
	raw, err := m.pageURL(mustTime(t, "2026-08-24T00:00:00Z"), mustTime(t, "2026-08-31T00:00:00Z"), 4000)
	if err != nil {
		t.Fatalf("pageURL: %v", err)
	}
	for _, want := range []string{
		"resultsPerPage=2000",
		"startIndex=4000",
		"lastModStartDate=2026-08-24T00%3A00%3A00.000Z",
		"lastModEndDate=2026-08-31T00%3A00%3A00.000Z",
	} {
		if !strings.Contains(raw, want) {
			t.Errorf("pageURL = %q, missing %q", raw, want)
		}
	}
}

// ---------------------------------------------------------------------------
// Update — success path using a local httptest server
// ---------------------------------------------------------------------------

func TestUpdate_DownloadsAndWritesDatabase(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, nvdPage(0, 1, "CVE-2026-0001")) //nolint:errcheck
	}))
	defer srv.Close()

	dir := t.TempDir()
	m := newTestManager(dir, srv.URL)

	if err := m.Update(); err != nil {
		t.Fatalf("Update() error: %v", err)
	}

	db := loadDatabase(t, dir)
	if db.Count != 1 || len(db.CVEs) != 1 {
		t.Fatalf("Count = %d, len(CVEs) = %d, want 1 and 1", db.Count, len(db.CVEs))
	}
	rec := db.CVEs[0]
	if rec.ID != "CVE-2026-0001" {
		t.Errorf("ID = %q, want CVE-2026-0001", rec.ID)
	}
	if rec.Description != "english text" {
		t.Errorf("Description = %q, want the English description", rec.Description)
	}
	if rec.Severity != "CRITICAL" || rec.BaseScore != 9.8 {
		t.Errorf("Severity/BaseScore = %q/%v, want CRITICAL/9.8", rec.Severity, rec.BaseScore)
	}
	if rec.VectorString != "CVSS:3.1/AV:N" {
		t.Errorf("VectorString = %q, want CVSS:3.1/AV:N", rec.VectorString)
	}
	if len(rec.References) != 1 || rec.References[0] != "https://example.com/adv" {
		t.Errorf("References = %v, want one advisory URL", rec.References)
	}
	if db.Source != srv.URL {
		t.Errorf("Source = %q, want %q", db.Source, srv.URL)
	}
}

// Update must follow the API's pagination until every result is collected.
func TestUpdate_FollowsPagination(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if r.URL.Query().Get("resultsPerPage") != "2000" {
			t.Errorf("resultsPerPage = %q, want 2000", r.URL.Query().Get("resultsPerPage"))
		}
		switch n {
		case 1:
			if got := r.URL.Query().Get("startIndex"); got != "0" {
				t.Errorf("first startIndex = %q, want 0", got)
			}
			fmt.Fprint(w, nvdPage(0, 3, "CVE-2026-0001", "CVE-2026-0002")) //nolint:errcheck
		default:
			if got := r.URL.Query().Get("startIndex"); got != "2" {
				t.Errorf("second startIndex = %q, want 2", got)
			}
			fmt.Fprint(w, nvdPage(2, 3, "CVE-2026-0003")) //nolint:errcheck
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	m := newTestManager(dir, srv.URL)

	if err := m.Update(); err != nil {
		t.Fatalf("Update() error: %v", err)
	}
	if atomic.LoadInt32(&calls) != 2 {
		t.Errorf("request count = %d, want 2", calls)
	}
	db := loadDatabase(t, dir)
	if db.Count != 3 {
		t.Errorf("Count = %d, want 3", db.Count)
	}
}

// Update must stop when a page comes back empty even if totalResults is larger.
func TestUpdate_StopsOnEmptyPage(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		fmt.Fprint(w, nvdPage(0, 99)) //nolint:errcheck
	}))
	defer srv.Close()

	dir := t.TempDir()
	m := newTestManager(dir, srv.URL)

	if err := m.Update(); err != nil {
		t.Fatalf("Update() error: %v", err)
	}
	if atomic.LoadInt32(&calls) != 1 {
		t.Errorf("request count = %d, want 1", calls)
	}
	if db := loadDatabase(t, dir); db.Count != 0 {
		t.Errorf("Count = %d, want 0", db.Count)
	}
}

// Update must write a .last_updated timestamp file on success.
func TestUpdate_WritesTimestampFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, nvdPage(0, 1, "CVE-2026-0001")) //nolint:errcheck
	}))
	defer srv.Close()

	dir := t.TempDir()
	m := newTestManager(dir, srv.URL)

	if err := m.Update(); err != nil {
		t.Fatalf("Update() error: %v", err)
	}

	ts, err := os.ReadFile(filepath.Join(dir, ".last_updated"))
	if err != nil {
		t.Fatalf(".last_updated not written: %v", err)
	}
	if strings.TrimSpace(string(ts)) == "" {
		t.Error(".last_updated is empty")
	}
}

// Update must create the dataDir if it does not exist.
func TestUpdate_CreatesDirIfMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, nvdPage(0, 1, "CVE-2026-0001")) //nolint:errcheck
	}))
	defer srv.Close()

	base := t.TempDir()
	dir := filepath.Join(base, "nested", "cve")
	m := newTestManager(dir, srv.URL)

	if err := m.Update(); err != nil {
		t.Fatalf("Update() error: %v", err)
	}

	if _, err := os.Stat(dir); err != nil {
		t.Errorf("dataDir was not created: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Update — error paths
// ---------------------------------------------------------------------------

// Update must return an error when the server responds with a non-200 status.
func TestUpdate_ServerError_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	dir := t.TempDir()
	m := newTestManager(dir, srv.URL)

	if err := m.Update(); err == nil {
		t.Error("Update() with 503 response: expected error, got nil")
	}
}

// A 403 (what the retired 1.1 feed URLs now return) must surface the status.
func TestUpdate_Forbidden_ErrorContainsStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	dir := t.TempDir()
	m := newTestManager(dir, srv.URL)

	err := m.Update()
	if err == nil {
		t.Fatal("expected error for 403, got nil")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error %q does not mention 403", err.Error())
	}
}

// Update must return an error when the API URL is unreachable.
// Port 1 is used because nothing listens there.
func TestUpdate_UnreachableURL_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	m := newTestManager(dir, "http://127.0.0.1:1")

	if err := m.Update(); err == nil {
		t.Error("Update() with unreachable URL: expected error, got nil")
	}
}

// Update must not write the database when the server returns an error status.
func TestUpdate_ServerError_DoesNotWriteFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	dir := t.TempDir()
	m := newTestManager(dir, srv.URL)

	_ = m.Update()

	if _, err := os.Stat(filepath.Join(dir, "nvd.json")); err == nil {
		t.Error("nvd.json should not exist after a server-error response")
	}
}

// A malformed body must be reported as a decode failure, not written to disk.
func TestUpdate_InvalidJSON_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "not json") //nolint:errcheck
	}))
	defer srv.Close()

	dir := t.TempDir()
	m := newTestManager(dir, srv.URL)

	err := m.Update()
	if err == nil {
		t.Fatal("expected decode error, got nil")
	}
	if _, statErr := os.Stat(filepath.Join(dir, "nvd.json")); statErr == nil {
		t.Error("nvd.json should not exist after a decode failure")
	}
}

// ---------------------------------------------------------------------------
// Record normalization
// ---------------------------------------------------------------------------

func TestPrimaryMetric_PrefersNewestCVSSVersion(t *testing.T) {
	metrics := nvdMetrics{
		CVSSMetricV31: []nvdCVSSMetric{{CVSSData: nvdCVSSData{BaseScore: 7.5, BaseSeverity: "HIGH"}}},
		CVSSMetricV2:  []nvdCVSSMetric{{BaseSeverity: "MEDIUM"}},
	}
	metric, ok := primaryMetric(metrics)
	if !ok {
		t.Fatal("primaryMetric returned ok = false")
	}
	if metricSeverity(metric) != "HIGH" {
		t.Errorf("severity = %q, want HIGH", metricSeverity(metric))
	}
}

// CVSS v2 keeps baseSeverity beside cvssData rather than inside it.
func TestMetricSeverity_FallsBackToOuterField(t *testing.T) {
	metric := nvdCVSSMetric{BaseSeverity: "MEDIUM"}
	if got := metricSeverity(metric); got != "MEDIUM" {
		t.Errorf("metricSeverity = %q, want MEDIUM", got)
	}
}

func TestEnglishDescription_FallsBackToFirst(t *testing.T) {
	if got := englishDescription([]nvdDescription{{Lang: "fr", Value: "bonjour"}}); got != "bonjour" {
		t.Errorf("englishDescription = %q, want bonjour", got)
	}
	if got := englishDescription(nil); got != "" {
		t.Errorf("englishDescription(nil) = %q, want empty", got)
	}
}

// A record with no CVSS metrics at all must normalize without a severity.
func TestNewCVERecord_NoMetrics(t *testing.T) {
	rec := newCVERecord(nvdCVE{ID: "CVE-2026-9999"})
	if rec.ID != "CVE-2026-9999" {
		t.Errorf("ID = %q, want CVE-2026-9999", rec.ID)
	}
	if rec.Severity != "" || rec.BaseScore != 0 {
		t.Errorf("Severity/BaseScore = %q/%v, want empty/0", rec.Severity, rec.BaseScore)
	}
}
