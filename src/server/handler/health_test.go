package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/apimgr/ipgaze/src/server/model"
)

// stubTorStatus is a minimal TorStatusProvider for tests.
type stubTorStatus struct {
	available bool
	running   bool
	status    string
	hostname  string
}

func (s *stubTorStatus) IsAvailable() bool   { return s.available }
func (s *stubTorStatus) IsRunning() bool     { return s.running }
func (s *stubTorStatus) Status() string      { return s.status }
func (s *stubTorStatus) GetHostname() string { return s.hostname }

// stubI2PStatus is a minimal I2PStatusProvider (plus I2PProviderNamer) for tests.
type stubI2PStatus struct {
	available bool
	running   bool
	status    string
	hostname  string
	provider  string
}

func (s *stubI2PStatus) IsAvailable() bool    { return s.available }
func (s *stubI2PStatus) IsRunning() bool      { return s.running }
func (s *stubI2PStatus) Status() string       { return s.status }
func (s *stubI2PStatus) GetHostname() string  { return s.hostname }
func (s *stubI2PStatus) ProviderName() string { return s.provider }

func newTestHandler() *HealthHandler {
	return NewHealthHandler("1.2.3", "abc123", "2024-01-01", "production", time.Now().Add(-2*time.Hour))
}

func TestNewHealthHandler_Defaults(t *testing.T) {
	h := NewHealthHandler("", "", "", "", time.Now())
	if h.Version != "dev" {
		t.Errorf("Version = %q, want %q", h.Version, "dev")
	}
	if h.Mode != "production" {
		t.Errorf("Mode = %q, want %q", h.Mode, "production")
	}
}

func TestNewHealthHandler_Values(t *testing.T) {
	start := time.Now()
	h := NewHealthHandler("2.0.0", "deadbeef", "2025-01-01", "development", start)
	if h.Version != "2.0.0" {
		t.Errorf("Version = %q, want %q", h.Version, "2.0.0")
	}
	if h.CommitID != "deadbeef" {
		t.Errorf("CommitID = %q, want %q", h.CommitID, "deadbeef")
	}
	if h.BuildDate != "2025-01-01" {
		t.Errorf("BuildDate = %q, want %q", h.BuildDate, "2025-01-01")
	}
	if h.Mode != "development" {
		t.Errorf("Mode = %q, want %q", h.Mode, "development")
	}
	if !h.StartTime.Equal(start) {
		t.Errorf("StartTime = %v, want %v", h.StartTime, start)
	}
}

func TestFormatUptime(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{30 * time.Second, "0m"},
		{61 * time.Second, "1m"},
		{90 * time.Minute, "1h 30m"},
		{25 * time.Hour, "1d 1h 0m"},
		{48*time.Hour + 15*time.Minute, "2d 0h 15m"},
	}
	for _, tt := range tests {
		got := formatUptime(tt.d)
		if got != tt.want {
			t.Errorf("formatUptime(%v) = %q, want %q", tt.d, got, tt.want)
		}
	}
}

func TestCheckTor_NilProvider(t *testing.T) {
	h := newTestHandler()
	h.TorStatus = nil
	if got := h.checkTor(); got != "" {
		t.Errorf("checkTor() = %q, want empty string", got)
	}
}

func TestCheckTor_NotAvailable(t *testing.T) {
	h := newTestHandler()
	h.TorStatus = &stubTorStatus{available: false}
	if got := h.checkTor(); got != "" {
		t.Errorf("checkTor() = %q, want empty string", got)
	}
}

func TestCheckTor_AvailableRunning(t *testing.T) {
	h := newTestHandler()
	h.TorStatus = &stubTorStatus{available: true, running: true, status: "ok"}
	if got := h.checkTor(); got != "ok" {
		t.Errorf("checkTor() = %q, want %q", got, "ok")
	}
}

func TestCheckTor_AvailableNotRunning(t *testing.T) {
	h := newTestHandler()
	h.TorStatus = &stubTorStatus{available: true, running: false}
	if got := h.checkTor(); got != "error" {
		t.Errorf("checkTor() = %q, want %q", got, "error")
	}
}

func TestGetOverallStatus_Healthy(t *testing.T) {
	checks := model.ChecksInfo{
		Database:  "ok",
		Cache:     "ok",
		Disk:      "ok",
		Scheduler: "ok",
	}
	if got := getOverallStatus(checks, false); got != "healthy" {
		t.Errorf("getOverallStatus() = %q, want %q", got, "healthy")
	}
}

func TestGetOverallStatus_UnhealthyDatabase(t *testing.T) {
	checks := model.ChecksInfo{Database: "error", Cache: "ok", Disk: "ok", Scheduler: "ok"}
	if got := getOverallStatus(checks, false); got != "unhealthy" {
		t.Errorf("getOverallStatus() = %q, want %q", got, "unhealthy")
	}
}

func TestGetOverallStatus_UnhealthyCache(t *testing.T) {
	checks := model.ChecksInfo{Database: "ok", Cache: "error", Disk: "ok", Scheduler: "ok"}
	if got := getOverallStatus(checks, false); got != "unhealthy" {
		t.Errorf("getOverallStatus() = %q, want %q", got, "unhealthy")
	}
}

func TestGetOverallStatus_UnhealthyDisk(t *testing.T) {
	checks := model.ChecksInfo{Database: "ok", Cache: "ok", Disk: "error", Scheduler: "ok"}
	if got := getOverallStatus(checks, false); got != "unhealthy" {
		t.Errorf("getOverallStatus() = %q, want %q", got, "unhealthy")
	}
}

func TestGetOverallStatus_UnhealthyScheduler(t *testing.T) {
	checks := model.ChecksInfo{Database: "ok", Cache: "ok", Disk: "ok", Scheduler: "error"}
	if got := getOverallStatus(checks, false); got != "unhealthy" {
		t.Errorf("getOverallStatus() = %q, want %q", got, "unhealthy")
	}
}

// Tor is an optional feature (AI.md PART 31): a Tor failure degrades status
// but must never make the whole server report "unhealthy".
func TestGetOverallStatus_DegradedTor(t *testing.T) {
	checks := model.ChecksInfo{Database: "ok", Cache: "ok", Disk: "ok", Scheduler: "ok", Tor: "error"}
	if got := getOverallStatus(checks, false); got != "degraded" {
		t.Errorf("getOverallStatus() = %q, want %q", got, "degraded")
	}
}

func TestHealthCheckRegistryCachesAndAggregatesDatasetResults(t *testing.T) {
	h := newTestHandler()
	status := "ok"
	h.RegisterHealthCheck("geoip_country", false, func() string { return status })
	h.RegisterHealthCheck("../../private/path", false, func() string { return "ok" })
	if got := h.HealthSnapshot().Checks.Datasets[0].Status; got != "ok" {
		t.Fatalf("initial dataset status = %q", got)
	}
	if got := humanizeHealthCheckKey("en", "blocklist_ads"); got != "Blocklist: ads" {
		t.Fatalf("humanized dataset label = %q", got)
	}
	status = "degraded"
	if got := h.HealthSnapshot().Checks.Datasets[0].Status; got != "ok" {
		t.Fatalf("dataset check ran during request: %q", got)
	}
	h.RefreshHealthChecks()
	resp := h.HealthSnapshot()
	if got := resp.Checks.Datasets[0].Status; got != "degraded" {
		t.Fatalf("refreshed dataset status = %q", got)
	}
	if resp.Status != statusDegraded {
		t.Fatalf("overall status = %q, want degraded", resp.Status)
	}
	h.RegisterHealthCheck("core_data", true, func() string { return "error" })
	h.RefreshHealthChecks()
	if got := h.HealthSnapshot().Status; got != statusUnhealthy {
		t.Fatalf("critical failure status = %q, want unhealthy", got)
	}
}

func TestHealthChecksJSONKeepsCoreAndDatasetOrder(t *testing.T) {
	checks := model.ChecksInfo{
		Database: "ok", Cache: "ok", Disk: "ok", Scheduler: "ok", Tor: "ok", I2P: "ok",
		Datasets: []model.DatasetCheck{{Key: "geoip_country", Status: "ok"}, {Key: "blocklist_ads", Status: "degraded"}},
	}
	encoded, err := json.Marshal(checks)
	if err != nil {
		t.Fatal(err)
	}
	body := string(encoded)
	keys := []string{`"database"`, `"cache"`, `"disk"`, `"scheduler"`, `"tor"`, `"i2p"`, `"geoip_country"`, `"blocklist_ads"`}
	last := -1
	for _, key := range keys {
		position := strings.Index(body, key)
		if position <= last {
			t.Fatalf("health checks JSON order invalid at %s: %s", key, body)
		}
		last = position
	}
}

func TestRequiredHealthProbesFailWhenUnavailable(t *testing.T) {
	h := newTestHandler()
	h.DBRequired = true
	h.SchedulerRequired = true
	h.DiskRequired = true
	h.DiskPath = "/data"
	h.DiskUsage = func(string) (uint64, int, error) { return 0, 0, errors.New("probe failed") }
	if got := h.checkDatabase(); got != "error" {
		t.Errorf("database status = %q", got)
	}
	if got := h.checkScheduler(); got != "error" {
		t.Errorf("scheduler status = %q", got)
	}
	if got := h.checkDisk(); got != "error" {
		t.Errorf("disk status = %q", got)
	}
}

func TestBuildHealthResponse_Basic(t *testing.T) {
	h := newTestHandler()
	h.ProjectName = "IPGaze"
	h.ProjectTagline = "Fast lookup"
	h.ProjectDescription = "Test desc"
	h.GeoIPEnabled = true

	resp := h.buildHealthResponse()

	if resp.Version != "1.2.3" {
		t.Errorf("Version = %q, want %q", resp.Version, "1.2.3")
	}
	if resp.Build.Commit != "abc123" {
		t.Errorf("Build.Commit = %q, want %q", resp.Build.Commit, "abc123")
	}
	if resp.Mode != "production" {
		t.Errorf("Mode = %q, want %q", resp.Mode, "production")
	}
	if resp.Status != "healthy" {
		t.Errorf("Status = %q, want %q", resp.Status, "healthy")
	}
	if !resp.Features.GeoIP {
		t.Errorf("Features.GeoIP = false, want true")
	}
	if resp.Features.Tor.Enabled {
		t.Errorf("Features.Tor.Enabled = true, want false when TorStatus is nil")
	}
	if resp.Features.Tor.Status != "disabled" {
		t.Errorf("Features.Tor.Status = %q, want %q", resp.Features.Tor.Status, "disabled")
	}
	if resp.Checks.Database != "ok" {
		t.Errorf("Checks.Database = %q, want %q", resp.Checks.Database, "ok")
	}
	if resp.Project.Name != "IPGaze" {
		t.Errorf("Project.Name = %q, want %q", resp.Project.Name, "IPGaze")
	}
}

func TestBuildHealthResponse_WithTor(t *testing.T) {
	h := newTestHandler()
	h.TorStatus = &stubTorStatus{
		available: true,
		running:   true,
		status:    "healthy",
		hostname:  "abc.onion",
	}

	resp := h.buildHealthResponse()

	if !resp.Features.Tor.Enabled {
		t.Errorf("Features.Tor.Enabled = false, want true")
	}
	if !resp.Features.Tor.Running {
		t.Errorf("Features.Tor.Running = false, want true")
	}
	if resp.Features.Tor.Hostname != "abc.onion" {
		t.Errorf("Features.Tor.Hostname = %q, want %q", resp.Features.Tor.Hostname, "abc.onion")
	}
	if resp.Checks.Tor != "ok" {
		t.Errorf("Checks.Tor = %q, want %q", resp.Checks.Tor, "ok")
	}
}

func TestBuildHealthResponse_I2PNoProvider(t *testing.T) {
	h := newTestHandler()
	h.I2PStatus = &stubI2PStatus{status: "no_provider", provider: "none"}

	resp := h.buildHealthResponse()
	if !resp.Features.I2P.Enabled {
		t.Error("I2P must retain its opt-in enabled state when no provider is available")
	}
	if resp.Features.I2P.Status != "disabled" || resp.Features.I2P.State != "no_provider" || resp.Features.I2P.Provider != "none" {
		t.Errorf("I2P no-provider health = %+v", resp.Features.I2P)
	}
	if resp.Checks.I2P != "" || resp.Status != statusHealthy {
		t.Errorf("no-provider I2P should not fail health: checks.i2p=%q status=%q", resp.Checks.I2P, resp.Status)
	}
}

func TestBuildHealthResponse_PendingRestart(t *testing.T) {
	h := newTestHandler()
	h.PendingRestart = func() (bool, []string) {
		return true, []string{"port"}
	}

	resp := h.buildHealthResponse()

	if !resp.PendingRestart {
		t.Errorf("PendingRestart = false, want true")
	}
	if resp.Status != "restart_required" {
		t.Errorf("Status = %q, want %q", resp.Status, "restart_required")
	}
	if len(resp.RestartReason) == 0 || resp.RestartReason[0] != "port" {
		t.Errorf("RestartReason = %v, want [port]", resp.RestartReason)
	}
}

func TestBuildHealthResponse_NoPendingRestart(t *testing.T) {
	h := newTestHandler()
	h.PendingRestart = func() (bool, []string) {
		return false, nil
	}

	resp := h.buildHealthResponse()

	if resp.PendingRestart {
		t.Errorf("PendingRestart = true, want false")
	}
	if resp.Status != "healthy" {
		t.Errorf("Status = %q, want healthy", resp.Status)
	}
}

func TestHealthzHandler_JSON(t *testing.T) {
	h := newTestHandler()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	h.HealthzHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", res.StatusCode, http.StatusOK)
	}
	ct := res.Header.Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}

	var body model.HealthResponse
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}
	if body.Version != "1.2.3" {
		t.Errorf("body.Version = %q, want %q", body.Version, "1.2.3")
	}
	if body.Status != "healthy" {
		t.Errorf("body.Status = %q, want %q", body.Status, "healthy")
	}
}

func TestHealthzHandler_HTML(t *testing.T) {
	h := newTestHandler()
	h.ProjectName = "IPGaze"
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()

	h.HealthzHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", res.StatusCode, http.StatusOK)
	}
	ct := res.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	body := w.Body.String()
	if !strings.Contains(body, "<!DOCTYPE html>") {
		t.Errorf("response body missing DOCTYPE: %q", body[:min(200, len(body))])
	}
	if !strings.Contains(body, `data-health-status="healthy"`) {
		t.Errorf("response body missing machine health state")
	}
}

func TestHealthzHandler_HTMLWithTorRow(t *testing.T) {
	h := newTestHandler()
	h.TorStatus = &stubTorStatus{available: true, running: true, status: "ok"}
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()

	h.HealthzHandler(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "Tor</td><td>ok") {
		t.Errorf("response body missing Tor component row")
	}
}

func TestHealthzHandler_PlainText(t *testing.T) {
	h := newTestHandler()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("Accept", "text/plain")
	w := httptest.NewRecorder()

	h.HealthzHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", res.StatusCode, http.StatusOK)
	}
	ct := res.Header.Get("Content-Type")
	if ct != "text/plain" {
		t.Errorf("Content-Type = %q, want %q", ct, "text/plain")
	}
	body := w.Body.String()
	if !strings.Contains(body, "Status: Healthy") {
		t.Errorf("body missing human-readable healthy status: %q", body)
	}
	if !strings.Contains(body, "Version: 1.2.3") {
		t.Errorf("body missing human-readable version: %q", body)
	}
}

func TestHealthzHandler_PlainTextWithTor(t *testing.T) {
	h := newTestHandler()
	h.TorStatus = &stubTorStatus{available: true, running: true, status: "ok"}
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("Accept", "text/plain")
	w := httptest.NewRecorder()

	h.HealthzHandler(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "Tor:                   ok") {
		t.Errorf("body missing human-readable Tor check: %q", body)
	}
}

// TestHealthzHandler_FrontendNegotiation covers the AI.md PART 14 frontend
// ladder that PART 13 defers to for /server/healthz: HTML is the default,
// plain text is reserved for Accept: text/plain, a .txt path, and
// non-interactive HTTP tools, and our own CLI always gets JSON like every
// other frontend route.
func TestHealthzHandler_FrontendNegotiation(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		accept    string
		userAgent string
		wantType  string
	}{
		{"empty accept and browser UA", "/healthz", "", "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0", "text/html"},
		{"accept text/html", "/healthz", "text/html", "", "text/html"},
		{"accept wildcard from browser", "/healthz", "*/*", "Mozilla/5.0 (Macintosh) Safari/605.1", "text/html"},
		{"text browser gets HTML", "/healthz", "", "Lynx/2.9.0", "text/html"},
		{"accept text/plain", "/healthz", "text/plain", "", "text/plain"},
		{"txt path", "/healthz.txt", "", "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0", "text/plain"},
		{"our cli", "/healthz", "", "ipgaze-cli/1.0", "application/json"},
		{"curl", "/healthz", "", "curl/8.5.0", "text/plain"},
		{"empty UA", "/healthz", "", "", "text/plain"},
		{"accept json", "/healthz", "application/json", "", "application/json"},
		{"explicit html beats CLI detection", "/healthz", "text/html", "ipgaze-cli/1.0", "text/html"},
		{"explicit text beats CLI detection", "/healthz", "text/plain", "ipgaze-cli/1.0", "text/plain"},
		{"explicit JSON beats curl detection", "/healthz", "application/json", "curl/8.5.0", "application/json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newTestHandler()
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			if tt.accept != "" {
				req.Header.Set("Accept", tt.accept)
			}
			req.Header.Set("User-Agent", tt.userAgent)
			w := httptest.NewRecorder()

			h.HealthzHandler(w, req)

			res := w.Result()
			if res.StatusCode != http.StatusOK {
				t.Errorf("StatusCode = %d, want %d", res.StatusCode, http.StatusOK)
			}
			if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, tt.wantType) {
				t.Errorf("Content-Type = %q, want prefix %q", ct, tt.wantType)
			}
		})
	}
}

// TestHealthzHandler_TextIncludesI2P verifies the human-readable frontend
// text format renders I2P as one feature line (AI.md PART 13).
func TestHealthzHandler_TextIncludesI2P(t *testing.T) {
	h := newTestHandler()
	h.I2PStatus = &stubI2PStatus{available: true, running: true, status: "healthy", hostname: "abc.b32.i2p", provider: "i2pd"}
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("Accept", "text/plain")
	w := httptest.NewRecorder()

	h.HealthzHandler(w, req)

	body := w.Body.String()
	for _, want := range []string{
		"I2P: Healthy - abc.b32.i2p (i2pd)",
		"I2P:",
		"ok",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q:\n%s", want, body)
		}
	}
}

// TestHealthzHandler_TextI2PDisabled verifies disabled I2P is one readable
// feature line and has no component check.
func TestHealthzHandler_TextI2PDisabled(t *testing.T) {
	h := newTestHandler()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("Accept", "text/plain")
	w := httptest.NewRecorder()

	h.HealthzHandler(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "I2P: Disabled") {
		t.Errorf("body must show disabled I2P in one feature line:\n%s", body)
	}
	checksText := strings.SplitN(body, "Component Status\n", 2)
	if len(checksText) != 2 || strings.Contains(checksText[1], "I2P") {
		t.Errorf("checks.i2p must be omitted when I2P is disabled:\n%s", body)
	}
}

func TestHealthzFrontendFormatting(t *testing.T) {
	if got := frontendDuration("2d 5h 30m"); got != "2 days 5 hours" {
		t.Errorf("frontendDuration() = %q, want %q", got, "2 days 5 hours")
	}
	if got := frontendDuration("45m"); got != "45 minutes" {
		t.Errorf("frontendDuration() = %q, want %q", got, "45 minutes")
	}
	if got := formatHealthCount(1234567); got != "1,234,567" {
		t.Errorf("formatHealthCount() = %q, want %q", got, "1,234,567")
	}
	page := healthzPageData(PageData{}, model.HealthResponse{
		Status: statusRestartRequired,
		Uptime: "2d 5h 30m",
		Build:  model.BuildInfo{Date: "2024-01-10T10:00:00Z"},
		Stats:  model.StatsInfo{RequestsTotal: 1234567},
	})
	if page.StatusClass != "status-warning" || page.StatusIcon != "🔄" || page.StatusMessageKey != "healthz.restart_required" {
		t.Errorf("restart-required display = (%q, %q, %q)", page.StatusClass, page.StatusIcon, page.StatusMessageKey)
	}
	if page.UptimeText != "2 days 5 hours" || page.BuildDateText != "January 10, 2024 at 10:00:00 UTC" || page.RequestsTotalText != "1,234,567" {
		t.Errorf("human-readable health fields = (%q, %q, %q)", page.UptimeText, page.BuildDateText, page.RequestsTotalText)
	}
}

// TestHealthzHandler_HTMLIncludesI2P verifies the inline HTML fallback renders
// the I2P feature with a copyable address, not machine-only field names.
func TestHealthzHandler_HTMLIncludesI2P(t *testing.T) {
	h := newTestHandler()
	h.I2PStatus = &stubI2PStatus{available: true, running: true, status: "healthy", hostname: "abc.b32.i2p", provider: "sam"}
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()

	h.HealthzHandler(w, req)

	body := w.Body.String()
	for _, want := range []string{
		"I2P: Healthy",
		"abc.b32.i2p",
		"sam",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("HTML body missing %q", want)
		}
	}
}

// TestHealthStatusCodes verifies the AI.md PART 13 status/HTTP-code table on
// every health route and every format: unhealthy, maintenance, and
// shutting_down all answer 503 while the body still renders normally.
func TestHealthStatusCodes(t *testing.T) {
	// failing reports the handler shape that produces the given status.
	failing := map[string]func(h *HealthHandler){
		"unhealthy": func(h *HealthHandler) {
			h.Scheduler = nil
			h.DiskPath = "/data"
			h.DiskUsage = func(string) (uint64, int, error) { return 0, 99, nil }
		},
		"maintenance": func(h *HealthHandler) {
			h.MaintenanceActive = func() bool { return true }
		},
		"shutting_down": func(h *HealthHandler) {
			h.MarkShuttingDown()
		},
	}

	formats := []struct {
		name   string
		path   string
		accept string
		api    bool
	}{
		{"frontend json", "/healthz", "application/json", false},
		{"frontend html", "/healthz", "text/html", false},
		{"frontend text", "/healthz", "text/plain", false},
		{"api json", "/api/v1/server/healthz", "application/json", true},
		{"api text", "/api/v1/server/healthz.txt", "", true},
	}

	for status, apply := range failing {
		for _, f := range formats {
			t.Run(status+"/"+f.name, func(t *testing.T) {
				h := newTestHandler()
				apply(h)
				req := httptest.NewRequest(http.MethodGet, f.path, nil)
				if f.accept != "" {
					req.Header.Set("Accept", f.accept)
				}
				w := httptest.NewRecorder()

				if f.api {
					h.APIV1HealthzHandler(w, req)
				} else {
					h.HealthzHandler(w, req)
				}

				res := w.Result()
				if res.StatusCode != http.StatusServiceUnavailable {
					t.Errorf("StatusCode = %d, want %d", res.StatusCode, http.StatusServiceUnavailable)
				}
				body := w.Body.String()
				if f.api || f.accept == "application/json" || f.accept == "text/html" {
					if !strings.Contains(body, status) {
						t.Errorf("body does not report status %q:\n%s", status, body)
					}
				} else if !strings.Contains(body, "Status:") {
					t.Errorf("human-readable body has no status line:\n%s", body)
				}
			})
		}
	}
}

// TestHealthStatusCodes_OK verifies the 200 half of the PART 13 table.
func TestHealthStatusCodes_OK(t *testing.T) {
	tests := []struct {
		name  string
		apply func(h *HealthHandler)
		want  string
	}{
		{"healthy", func(*HealthHandler) {}, "healthy"},
		{"degraded", func(h *HealthHandler) {
			h.TorStatus = &stubTorStatus{available: true, running: false, status: "error"}
		}, "degraded"},
		{"restart_required", func(h *HealthHandler) {
			h.PendingRestart = func() (bool, []string) { return true, []string{"port"} }
		}, "restart_required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newTestHandler()
			tt.apply(h)
			req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
			req.Header.Set("Accept", "application/json")
			w := httptest.NewRecorder()

			h.HealthzHandler(w, req)

			if w.Result().StatusCode != http.StatusOK {
				t.Errorf("StatusCode = %d, want %d", w.Result().StatusCode, http.StatusOK)
			}
			var body model.HealthResponse
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("failed to decode JSON: %v", err)
			}
			if body.Status != tt.want {
				t.Errorf("status = %q, want %q", body.Status, tt.want)
			}
		})
	}
}

// TestAPIV1HealthzHandler_JSONDefault verifies the /api/{api_version}/server/healthz
// content-negotiation JSON default per AI.md PART 14 priority order: browsers,
// our CLI, and Accept: application/json all receive JSON (priority 4). Only
// .txt, Accept: text/plain, or a detected non-interactive HTTP tool (which
// includes an empty User-Agent per AI.md's isHttpTool()) get plain text —
// covered by TestAPIV1HealthzHandler_TextNegotiation.
// The body is BARE, not enveloped: AI.md PART 13 exempts health from the PART 14
// {"ok":...,"data":...} wrapper on every health route in every state.
func TestAPIV1HealthzHandler_JSONDefault(t *testing.T) {
	h := newTestHandler()

	tests := []struct {
		name      string
		accept    string
		userAgent string
	}{
		{"text/html", "text/html", ""},
		{"application/json", "application/json", ""},
		{"explicit JSON beats curl detection", "application/json", "curl/8.5.0"},
		{"explicit Accept wildcard uses JSON", "*/*", "curl/8.5.0"},
		{"browser UA", "", "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0"},
		{"our client UA gets JSON", "", "ipgaze-cli/1.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/server/healthz", nil)
			if tt.accept != "" {
				req.Header.Set("Accept", tt.accept)
			}
			if tt.userAgent != "" {
				req.Header.Set("User-Agent", tt.userAgent)
			}
			w := httptest.NewRecorder()

			h.APIV1HealthzHandler(w, req)

			res := w.Result()
			if res.StatusCode != http.StatusOK {
				t.Errorf("StatusCode = %d, want %d", res.StatusCode, http.StatusOK)
			}
			ct := res.Header.Get("Content-Type")
			if ct != "application/json" {
				t.Errorf("Content-Type = %q, want %q", ct, "application/json")
			}

			raw := w.Body.Bytes()
			// Envelope exception (AI.md PART 13): no "ok"/"data" wrapper.
			var envelopeProbe map[string]json.RawMessage
			if err := json.Unmarshal(raw, &envelopeProbe); err != nil {
				t.Fatalf("failed to decode JSON: %v", err)
			}
			if _, wrapped := envelopeProbe["data"]; wrapped {
				t.Errorf("health body is enveloped, want bare: %s", raw)
			}
			if _, wrapped := envelopeProbe["ok"]; wrapped {
				t.Errorf("health body carries an \"ok\" key, want bare: %s", raw)
			}

			var body model.HealthResponse
			if err := json.Unmarshal(raw, &body); err != nil {
				t.Fatalf("failed to decode health body: %v", err)
			}
			if body.Status != "healthy" {
				t.Errorf("status = %q, want %q", body.Status, "healthy")
			}
			if body.Version != "1.2.3" {
				t.Errorf("version = %q, want %q", body.Version, "1.2.3")
			}
		})
	}
}

func TestUnversionedAPIHealthzNegotiation(t *testing.T) {
	h := newTestHandler()
	req := httptest.NewRequest(http.MethodGet, "/api/healthz", nil)
	req.Header.Set("Accept", "text/plain")
	req.Header.Set("User-Agent", "curl/8.5.0")
	w := httptest.NewRecorder()

	h.APIV1HealthzHandler(w, req)

	if got := w.Result().Header.Get("Content-Type"); !strings.HasPrefix(got, textMediaType) {
		t.Errorf("unversioned health alias content type = %q, want text/plain", got)
	}
	if !strings.Contains(w.Body.String(), "status: healthy") {
		t.Errorf("unversioned health alias text missing status: %s", w.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/healthz", nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "curl/8.5.0")
	w = httptest.NewRecorder()
	h.APIV1HealthzHandler(w, req)
	if got := w.Result().Header.Get("Content-Type"); !strings.HasPrefix(got, jsonMediaType) {
		t.Errorf("explicit JSON alias content type = %q, want application/json", got)
	}
	var body model.HealthResponse
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.Status != statusHealthy {
		t.Errorf("explicit JSON alias body status = %q, error = %v", body.Status, err)
	}
}

// TestAPIV1HealthzHandler_TextNegotiation verifies the plain-text triggers on the
// API healthz route per the AI.md PART 14 priority order: .txt extension, an
// Accept: text/plain header, or a detected non-interactive HTTP tool — the full
// isHttpTool() list (curl/wget/httpie/libcurl/python-requests/go-http-client/
// axios/node-fetch) plus an empty User-Agent, which AI.md's isHttpTool() also
// treats as a non-interactive tool.
func TestAPIV1HealthzHandler_TextNegotiation(t *testing.T) {
	h := newTestHandler()

	tests := []struct {
		name      string
		path      string
		accept    string
		userAgent string
	}{
		{".txt extension", "/api/v1/server/healthz.txt", "", ""},
		{".txt overrides JSON Accept", "/api/v1/server/healthz.txt", "application/json", "curl/8.5.0"},
		{"accept text/plain", "/api/v1/server/healthz", "text/plain", ""},
		{"curl user-agent", "/api/v1/server/healthz", "", "curl/8.5.0"},
		{"wget user-agent", "/api/v1/server/healthz", "", "Wget/1.21.4"},
		{"httpie user-agent", "/api/v1/server/healthz", "", "HTTPie/3.2.2"},
		{"libcurl user-agent", "/api/v1/server/healthz", "", "libcurl/8.5.0"},
		{"python-requests user-agent", "/api/v1/server/healthz", "", "python-requests/2.31.0"},
		{"go-http-client user-agent", "/api/v1/server/healthz", "", "Go-http-client/1.1"},
		{"axios user-agent", "/api/v1/server/healthz", "", "axios/1.6.0"},
		{"node-fetch user-agent", "/api/v1/server/healthz", "", "node-fetch/3.3.0"},
		{"empty user-agent", "/api/v1/server/healthz", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			if tt.accept != "" {
				req.Header.Set("Accept", tt.accept)
			}
			if tt.userAgent != "" {
				req.Header.Set("User-Agent", tt.userAgent)
			}
			w := httptest.NewRecorder()

			h.APIV1HealthzHandler(w, req)

			res := w.Result()
			if res.StatusCode != http.StatusOK {
				t.Errorf("StatusCode = %d, want %d", res.StatusCode, http.StatusOK)
			}
			ct := res.Header.Get("Content-Type")
			if ct != textMediaType {
				t.Errorf("Content-Type = %q, want %q", ct, textMediaType)
			}
			body := w.Body.String()
			if !strings.Contains(body, "status: healthy") {
				t.Errorf("text body missing %q, got:\n%s", "status: healthy", body)
			}
		})
	}
}

// min returns the smaller of a and b (for safe string slicing in error messages).
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
