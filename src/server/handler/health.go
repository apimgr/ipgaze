// Package handler contains HTTP handlers organized by domain
// Per AI.md: handler/ for HTTP request handlers, route handlers, request/response logic
package handler

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/apimgr/ipgaze/src/common/httputil"
	"github.com/apimgr/ipgaze/src/scheduler"
	"github.com/apimgr/ipgaze/src/server/model"
)

const (
	jsonMediaType = "application/json"
	textMediaType = "text/plain"
)

// Health status values per AI.md PART 13 ("Health Status Values & HTTP Codes").
const (
	statusHealthy         = "healthy"
	statusDegraded        = "degraded"
	statusRestartRequired = "restart_required"
	statusUnhealthy       = "unhealthy"
	statusMaintenance     = "maintenance"
	statusShuttingDown    = "shutting_down"
)

// i2pProviderNone is the AI.md PART 13 value for features.i2p.provider when
// no eepsite backend is active.
const i2pProviderNone = "none"

// healthStatusCode maps a health status value to its HTTP status code per the
// AI.md PART 13 table. Applies to every health route and every format.
func healthStatusCode(status string) int {
	switch status {
	case statusUnhealthy, statusMaintenance, statusShuttingDown:
		return http.StatusServiceUnavailable
	default:
		return http.StatusOK
	}
}

// TorStatusProvider is satisfied by tor.Manager or any test stub.
// It allows the health handler to query Tor status without importing the tor package.
type TorStatusProvider interface {
	IsAvailable() bool
	IsRunning() bool
	Status() string
	GetHostname() string
}

// I2PStatusProvider is satisfied by i2p.I2PManager or any test stub.
// It allows the health handler to query I2P status without importing the i2p package.
type I2PStatusProvider interface {
	IsAvailable() bool
	IsRunning() bool
	Status() string
	GetHostname() string
}

// I2PProviderNamer is optionally implemented by an I2PStatusProvider that can
// name its active backend ("i2pd", "sam", or "none") for features.i2p.provider
// (AI.md PART 13). A provider that does not implement it reports "none".
type I2PProviderNamer interface {
	ProviderName() string
}

// HealthzPageData combines base page data with the health response for healthz.tmpl.
type HealthzPageData struct {
	PageData
	Health model.HealthResponse
}

// HealthHandler handles health check routes
type HealthHandler struct {
	Version   string
	CommitID  string
	BuildDate string
	Mode      string
	StartTime time.Time
	// Project branding
	ProjectName        string
	ProjectTagline     string
	ProjectDescription string
	// Feature flags
	GeoIPEnabled bool
	// TorStatus is optional; nil means Tor not configured or binary not found.
	TorStatus TorStatusProvider
	// I2PStatus is optional; nil means I2P not enabled (opt-in, AI.md PART 31.2).
	I2PStatus I2PStatusProvider
	// PendingRestart returns (pending, restartSettings) from the ConfigManager.
	// May be nil (treated as no pending restart).
	PendingRestart func() (bool, []string)
	// DB is the live database connection, pinged for checks.database.
	// Nil is treated as a missing (required) subsystem -> "error" (AI.md PART 10).
	DB *sql.DB
	// CachePing verifies the configured cache backend (AI.md PART 9).
	// Nil means no cache backend was wired -> reported "ok" (nothing to probe).
	CachePing func(ctx context.Context) error
	// Scheduler exposes Status() for checks.scheduler (AI.md PART 18).
	// Nil is treated as the scheduler not running -> "error".
	Scheduler SchedulerStatusProvider
	// DiskPath is the filesystem path checked by DiskUsage (typically data_dir).
	DiskPath string
	// DiskUsage returns free bytes and used-percent for DiskPath. Wired from
	// main.go using the existing diskFreeAndUsedPercent platform helper
	// (src/disk_space_unix.go / src/disk_space_other.go). Nil -> "ok" (can't probe).
	DiskUsage func(path string) (freeBytes uint64, usedPercent int, err error)
	// Stats returns the lifetime request total, requests in the last 24h, and
	// current in-flight request count for the stats block (AI.md PART 13).
	Stats func() (total int64, last24h int64, active int)
	// Render renders a named page template. When set, HealthzHandler uses it for
	// text/html responses instead of the inline fallback HTML.
	Render func(w http.ResponseWriter, r *http.Request, page string, data interface{}) error
	// PageDataFunc builds base PageData for the current request (shared across handlers).
	// When set, HealthzHandler embeds the result in HealthzPageData.
	PageDataFunc func(r *http.Request) PageData
	// MaintenanceActive reports whether maintenance mode is currently active
	// (AI.md PART 13: status "maintenance", HTTP 503). Nil means never active.
	MaintenanceActive func() bool

	// shuttingDown is raised by MarkShuttingDown once graceful shutdown starts
	// (AI.md PART 13: status "shutting_down", HTTP 503).
	shuttingDown atomic.Bool
}

// MarkShuttingDown records that graceful shutdown has begun, so every health
// route reports "shutting_down" with HTTP 503 while connections drain
// (AI.md PART 13). Safe to call from a signal handler goroutine.
func (h *HealthHandler) MarkShuttingDown() {
	h.shuttingDown.Store(true)
}

// isShuttingDown reports whether MarkShuttingDown has been called.
func (h *HealthHandler) isShuttingDown() bool {
	return h.shuttingDown.Load()
}

// SchedulerStatusProvider is satisfied by *scheduler.Scheduler or any test stub.
// It lets the health handler confirm the scheduler is running without depending
// on scheduler internals beyond the already-required Status() method (PART 18).
type SchedulerStatusProvider interface {
	Status() map[string]scheduler.TaskState
}

// NewHealthHandler creates a new HealthHandler
func NewHealthHandler(version, commitID, buildDate, mode string, startTime time.Time) *HealthHandler {
	if version == "" {
		version = "dev"
	}
	if mode == "" {
		mode = "production"
	}
	return &HealthHandler{
		Version:   version,
		CommitID:  commitID,
		BuildDate: buildDate,
		Mode:      mode,
		StartTime: startTime,
	}
}

// formatUptime formats duration as human-readable string
func formatUptime(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	return fmt.Sprintf("%dm", minutes)
}

// healthCheckTimeout bounds each subsystem probe so a stuck backend never
// hangs the /server/healthz response.
const healthCheckTimeout = 2 * time.Second

// diskFreeErrorPercent and diskFreeDegradedPercent are the free-space
// thresholds (percent free, not used) for the disk check. Below the error
// threshold checks.disk reports "error"; below the degraded threshold the
// per-check value stays "ok" (PART 13's ChecksInfo enum is ok/error only)
// but the overall status is downgraded to "degraded".
const (
	diskFreeErrorPercent    = 10
	diskFreeDegradedPercent = 20
)

// checkDatabase pings the live DB connection and returns "ok" or "error"
// per AI.md PART 10/13. A nil DB (not wired, e.g. in a lightweight test
// handler) is not applicable and reports "ok".
func (h *HealthHandler) checkDatabase() string {
	if h.DB == nil {
		return "ok"
	}
	ctx, cancel := context.WithTimeout(context.Background(), healthCheckTimeout)
	defer cancel()
	if err := h.DB.PingContext(ctx); err != nil {
		return "error"
	}
	return "ok"
}

// checkCache pings the configured cache backend (Valkey/Redis/Memcache) per
// AI.md PART 9/13. When no cache backend is wired (CachePing is nil) the
// subsystem is not applicable and reports "ok".
func (h *HealthHandler) checkCache() string {
	if h.CachePing == nil {
		return "ok"
	}
	ctx, cancel := context.WithTimeout(context.Background(), healthCheckTimeout)
	defer cancel()
	if err := h.CachePing(ctx); err != nil {
		return "error"
	}
	return "ok"
}

// checkScheduler confirms the scheduler (AI.md PART 18) is wired and
// responsive. A nil Scheduler (not wired, e.g. in a lightweight test
// handler) is not applicable and reports "ok".
func (h *HealthHandler) checkScheduler() string {
	if h.Scheduler == nil {
		return "ok"
	}
	// Status() only reads an in-memory map under a lock; calling it confirms
	// the scheduler instance is alive and its task table is reachable.
	_ = h.Scheduler.Status()
	return "ok"
}

// checkDisk reports the disk subsystem status per AI.md PART 13. Returns
// "error" when free space drops below diskFreeErrorPercent; otherwise "ok".
// See diskDegraded for the softer degraded threshold used in overall status.
func (h *HealthHandler) checkDisk() string {
	if h.DiskUsage == nil || h.DiskPath == "" {
		return "ok"
	}
	_, usedPercent, err := h.DiskUsage(h.DiskPath)
	if err != nil {
		return "ok"
	}
	freePercent := 100 - usedPercent
	if freePercent < diskFreeErrorPercent {
		return "error"
	}
	return "ok"
}

// diskDegraded reports whether free disk space is low enough to downgrade
// the overall status to "degraded" without failing the per-check ok/error
// value (see diskFreeDegradedPercent).
func (h *HealthHandler) diskDegraded() bool {
	if h.DiskUsage == nil || h.DiskPath == "" {
		return false
	}
	_, usedPercent, err := h.DiskUsage(h.DiskPath)
	if err != nil {
		return false
	}
	freePercent := 100 - usedPercent
	return freePercent < diskFreeDegradedPercent
}

// checkTor returns the Tor subsystem status per AI.md PART 31.
// Returns "ok" when Tor is running, "error" when the binary was found but
// the hidden service is not running, and "" (empty) when Tor is unavailable
// so the field is omitted from the response.
func (h *HealthHandler) checkTor() string {
	if h.TorStatus == nil || !h.TorStatus.IsAvailable() {
		return ""
	}
	if h.TorStatus.IsRunning() {
		return "ok"
	}
	return "error"
}

// checkI2P returns the I2P subsystem status per AI.md PART 31.2. Returns
// "ok" when the eepsite is running, "error" when enabled but not running,
// and "" (empty) when I2P is disabled/unavailable so the field is omitted.
func (h *HealthHandler) checkI2P() string {
	if h.I2PStatus == nil || !h.I2PStatus.IsAvailable() {
		return ""
	}
	if h.I2PStatus.IsRunning() {
		return "ok"
	}
	return "error"
}

// getOverallStatus derives the overall status string from individual checks
// per AI.md PART 13's enum ("healthy", "unhealthy", "degraded"). A failure of
// a core subsystem (database, cache, disk, scheduler) yields "unhealthy". Tor
// is an OPTIONAL feature (AI.md PART 31: missing/failed Tor is WARN, not an
// error, and the server continues), so a Tor failure only degrades status —
// it must never make the whole server report "unhealthy" and trip container
// restart loops. A low-disk warning with no hard errors also yields "degraded".
func getOverallStatus(checks model.ChecksInfo, degraded bool) string {
	if checks.Database == "error" || checks.Cache == "error" ||
		checks.Disk == "error" || checks.Scheduler == "error" {
		return statusUnhealthy
	}
	if degraded || checks.Tor == "error" || checks.I2P == "error" {
		return statusDegraded
	}
	return statusHealthy
}

// i2pProvider returns the features.i2p.provider value for the wired I2P
// provider ("i2pd", "sam", or "none" — AI.md PART 13).
func (h *HealthHandler) i2pProvider() string {
	namer, ok := h.I2PStatus.(I2PProviderNamer)
	if !ok {
		return i2pProviderNone
	}
	name := namer.ProviderName()
	if name == "" {
		return i2pProviderNone
	}
	return name
}

// HealthSnapshot returns the same health payload the REST endpoints render, so
// non-REST transports (GraphQL) report identical state instead of computing
// their own. Safe on a nil receiver, which reports an unconfigured server.
func (h *HealthHandler) HealthSnapshot() model.HealthResponse {
	if h == nil {
		return model.HealthResponse{Status: statusUnhealthy}
	}
	return h.buildHealthResponse()
}

// buildHealthResponse constructs the full health response per AI.md PART 13.
func (h *HealthHandler) buildHealthResponse() model.HealthResponse {
	torCheck := h.checkTor()
	i2pCheck := h.checkI2P()
	checks := model.ChecksInfo{
		Database:  h.checkDatabase(),
		Cache:     h.checkCache(),
		Disk:      h.checkDisk(),
		Scheduler: h.checkScheduler(),
		Tor:       torCheck,
		I2P:       i2pCheck,
	}

	torInfo := model.TorInfo{Status: "disabled"}
	if h.TorStatus != nil && h.TorStatus.IsAvailable() {
		torInfo = model.TorInfo{
			Enabled:  true,
			Running:  h.TorStatus.IsRunning(),
			Status:   h.TorStatus.Status(),
			Hostname: h.TorStatus.GetHostname(),
		}
	}

	i2pInfo := model.I2PInfo{Status: "disabled", Provider: i2pProviderNone}
	if h.I2PStatus != nil && h.I2PStatus.IsAvailable() {
		i2pInfo = model.I2PInfo{
			Enabled:  true,
			Running:  h.I2PStatus.IsRunning(),
			Status:   h.I2PStatus.Status(),
			Hostname: h.I2PStatus.GetHostname(),
			Provider: h.i2pProvider(),
		}
	}

	resp := model.HealthResponse{
		Project: model.ProjectInfo{
			Name:        h.ProjectName,
			Tagline:     h.ProjectTagline,
			Description: h.ProjectDescription,
		},
		Status:    getOverallStatus(checks, h.diskDegraded()),
		Version:   h.Version,
		GoVersion: runtime.Version(),
		Build: model.BuildInfo{
			Commit: h.CommitID,
			Date:   h.BuildDate,
		},
		Uptime:    formatUptime(time.Since(h.StartTime)),
		Mode:      h.Mode,
		Timestamp: time.Now().UTC(),
		Features: model.FeaturesInfo{
			Tor:   torInfo,
			I2P:   i2pInfo,
			GeoIP: h.GeoIPEnabled,
		},
		Checks: checks,
		Stats:  model.StatsInfo{},
	}

	if h.Stats != nil {
		total, last24h, active := h.Stats()
		resp.Stats = model.StatsInfo{
			RequestsTotal: total,
			Requests24h:   last24h,
			ActiveConns:   active,
		}
	}

	// AI.md PART 13: "restart_required" means healthy but a config change needs
	// a restart, so it only replaces an otherwise-healthy status. A server that
	// is already degraded or unhealthy keeps the worse status; the pending
	// restart stays visible through PendingRestart/RestartReason either way.
	if h.PendingRestart != nil {
		if pending, settings := h.PendingRestart(); pending {
			resp.PendingRestart = true
			resp.RestartReason = settings
			if resp.Status == statusHealthy {
				resp.Status = statusRestartRequired
			}
		}
	}

	// Maintenance mode and graceful shutdown both override the check-derived
	// status (AI.md PART 13, both HTTP 503). Shutdown wins over maintenance:
	// once the process is draining, that is the fact a probe needs.
	if h.MaintenanceActive != nil && h.MaintenanceActive() {
		resp.Status = statusMaintenance
	}
	if h.isShuttingDown() {
		resp.Status = statusShuttingDown
	}

	return resp
}

// HealthzHandler serves health check with content negotiation (JSON/text/HTML)
// Per PART 13: /healthz supports HTML, JSON, and text based on Accept header
func (h *HealthHandler) HealthzHandler(w http.ResponseWriter, r *http.Request) {
	accept := r.Header.Get("Accept")
	health := h.buildHealthResponse()
	code := healthStatusCode(health.Status)

	// JSON response for Accept: application/json
	if strings.Contains(accept, jsonMediaType) {
		writeHealthJSON(w, health, code)
		return
	}

	// Plain text only for the clients that cannot use HTML (see healthWantsText).
	if healthWantsText(r) {
		writeHealthText(w, health, code)
		return
	}

	// HTML response via template when renderer is available (preferred path)
	if h.Render != nil {
		var pd PageData
		if h.PageDataFunc != nil {
			pd = h.PageDataFunc(r)
		}
		data := HealthzPageData{PageData: pd, Health: health}
		// Buffer the render so a template failure cannot leave a half-written
		// body behind, and so the PART 13 status code is applied to a page that
		// actually rendered.
		buf := newBufferedResponse()
		if err := h.Render(buf, r, "healthz.tmpl", data); err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		buf.flushTo(w, code)
		return
	}

	// HTML response for browsers — PART 13 canonical field order with 30s auto-refresh
	// and a visible countdown timer (JS progressive enhancement; meta-refresh as fallback).
	// Fallback path when template renderer is not configured.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	torRow := ""
	if health.Checks.Tor != "" {
		torRow = fmt.Sprintf("<li><strong>checks.tor:</strong> %s</li>", health.Checks.Tor)
	}
	i2pRow := ""
	if health.Checks.I2P != "" {
		i2pRow = fmt.Sprintf("<li><strong>checks.i2p:</strong> %s</li>", health.Checks.I2P)
	}
	w.WriteHeader(code)
	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="refresh" content="30">
    <title>%s - Health Status</title>
  </head>
  <body>
    <header>
      <h1>%s</h1>
      <p class="tagline">%s</p>
      <p>%s</p>
    </header>
    <main>
      <p class="status-banner"><strong>status:</strong> %s</p>
      <ul>
        <li><strong>version:</strong> %s</li>
        <li><strong>go_version:</strong> %s</li>
        <li><strong>build.commit:</strong> %s</li>
        <li><strong>build.date:</strong> %s</li>
        <li><strong>uptime:</strong> %s</li>
        <li><strong>mode:</strong> %s</li>
        <li><strong>timestamp:</strong> <time datetime="%s">%s</time></li>
        <li><strong>features.tor.enabled:</strong> %v</li>
        <li><strong>features.tor.running:</strong> %v</li>
        <li><strong>features.tor.status:</strong> %s</li>
        <li><strong>features.tor.hostname:</strong> %s</li>
        <li><strong>features.i2p.enabled:</strong> %v</li>
        <li><strong>features.i2p.running:</strong> %v</li>
        <li><strong>features.i2p.status:</strong> %s</li>
        <li><strong>features.i2p.hostname:</strong> %s</li>
        <li><strong>features.i2p.provider:</strong> %s</li>
        <li><strong>features.geoip:</strong> %v</li>
        <li><strong>checks.database:</strong> %s</li>
        <li><strong>checks.cache:</strong> %s</li>
        <li><strong>checks.disk:</strong> %s</li>
        <li><strong>checks.scheduler:</strong> %s</li>
        %s
        %s
        <li><strong>stats.requests_total:</strong> %d</li>
        <li><strong>stats.requests_24h:</strong> %d</li>
        <li><strong>stats.active_connections:</strong> %d</li>
      </ul>
      <p>Refreshing every 30s</p>
    </main>
  </body>
</html>
`,
		health.Project.Name,
		health.Project.Name,
		health.Project.Tagline,
		health.Project.Description,
		health.Status,
		health.Version,
		health.GoVersion,
		health.Build.Commit,
		health.Build.Date,
		health.Uptime,
		health.Mode,
		health.Timestamp.Format(time.RFC3339),
		health.Timestamp.Format(time.RFC3339),
		health.Features.Tor.Enabled,
		health.Features.Tor.Running,
		health.Features.Tor.Status,
		health.Features.Tor.Hostname,
		health.Features.I2P.Enabled,
		health.Features.I2P.Running,
		health.Features.I2P.Status,
		health.Features.I2P.Hostname,
		health.Features.I2P.Provider,
		health.Features.GeoIP,
		health.Checks.Database,
		health.Checks.Cache,
		health.Checks.Disk,
		health.Checks.Scheduler,
		torRow,
		i2pRow,
		health.Stats.RequestsTotal,
		health.Stats.Requests24h,
		health.Stats.ActiveConns,
	)
}

// writeHealthText writes the flat dot-notation plain-text health representation
// per AI.md PART 13 canonical field order. Shared by the frontend
// /server/healthz text fallback and the /api/{api_version}/server/healthz
// text negotiation path (PART 14 API response rules). code is the PART 13
// status code for health.Status.
func writeHealthText(w http.ResponseWriter, health model.HealthResponse, code int) {
	w.Header().Set("Content-Type", textMediaType)
	w.WriteHeader(code)
	fmt.Fprintf(w,
		"project.name: %s\nproject.tagline: %s\nproject.description: %s\nstatus: %s\nversion: %s\ngo_version: %s\nbuild.commit: %s\nbuild.date: %s\nuptime: %s\nmode: %s\ntimestamp: %s\nfeatures.tor.enabled: %v\nfeatures.tor.running: %v\nfeatures.tor.status: %s\nfeatures.tor.hostname: %s\nfeatures.i2p.enabled: %v\nfeatures.i2p.running: %v\nfeatures.i2p.status: %s\nfeatures.i2p.hostname: %s\nfeatures.i2p.provider: %s\nfeatures.geoip: %v\nchecks.database: %s\nchecks.cache: %s\nchecks.disk: %s\nchecks.scheduler: %s\n",
		health.Project.Name,
		health.Project.Tagline,
		health.Project.Description,
		health.Status,
		health.Version,
		health.GoVersion,
		health.Build.Commit,
		health.Build.Date,
		health.Uptime,
		health.Mode,
		health.Timestamp.Format(time.RFC3339),
		health.Features.Tor.Enabled,
		health.Features.Tor.Running,
		health.Features.Tor.Status,
		health.Features.Tor.Hostname,
		health.Features.I2P.Enabled,
		health.Features.I2P.Running,
		health.Features.I2P.Status,
		health.Features.I2P.Hostname,
		health.Features.I2P.Provider,
		health.Features.GeoIP,
		health.Checks.Database,
		health.Checks.Cache,
		health.Checks.Disk,
		health.Checks.Scheduler,
	)
	if health.Checks.Tor != "" {
		fmt.Fprintf(w, "checks.tor: %s\n", health.Checks.Tor)
	}
	if health.Checks.I2P != "" {
		fmt.Fprintf(w, "checks.i2p: %s\n", health.Checks.I2P)
	}
	fmt.Fprintf(w,
		"stats.requests_total: %d\nstats.requests_24h: %d\nstats.active_connections: %d\n",
		health.Stats.RequestsTotal,
		health.Stats.Requests24h,
		health.Stats.ActiveConns,
	)
}

// apiHealthWantsText reports whether an /api/{api_version}/server/healthz request
// should receive the plain-text representation instead of the JSON envelope.
// Follows the AI.md PART 14 API content-negotiation priority order exactly:
//  1. `.txt` extension on the path -> text (always wins)
//  2. `Accept: text/plain` header -> text
//  3. Non-interactive HTTP tool detected (curl, wget, httpie) -> text
//  4. Default (browsers, API clients, `Accept: application/json`, empty UA) -> JSON
func apiHealthWantsText(r *http.Request) bool {
	if strings.HasSuffix(r.URL.Path, ".txt") {
		return true
	}
	if strings.Contains(r.Header.Get("Accept"), textMediaType) {
		return true
	}
	return IsNonInteractiveHTTPTool(r.Header.Get("User-Agent"))
}

// IsNonInteractiveHTTPTool reports whether the User-Agent is one of the
// non-interactive HTTP tools (curl, wget, httpie) that AI.md PART 14/16 says
// must receive pre-formatted text. It deliberately excludes our own client
// ({project_name}-cli, which handles JSON itself) and programmatic API clients
// (python-requests, node-fetch, raw Go-http-client), which default to JSON.
// Exported so other packages needing the same content-negotiation rule
// (e.g. server.NotFoundHandler's catch-all) reuse this list instead of
// duplicating it.
func IsNonInteractiveHTTPTool(ua string) bool {
	for _, t := range []string{"curl/", "Wget/", "HTTPie/", "httpie-go/", "xh/"} {
		if strings.Contains(ua, t) {
			return true
		}
	}
	return false
}

// APIV1HealthzHandler serves /api/v1/server/healthz and /api/healthz.
// AI.md PART 13 makes health an explicit exception to the PART 14 envelope:
// the body is BARE on every health route in every state, because probes and
// load balancers expect a flat document. The HTTP status code plus the
// top-level status field carry the health state.
func (h *HealthHandler) APIV1HealthzHandler(w http.ResponseWriter, r *http.Request) {
	health := h.buildHealthResponse()
	code := healthStatusCode(health.Status)
	// PART 14 API response rules: JSON by default, text for text/plain or
	// non-interactive CLI clients (PART 13 references these rules for healthz).
	if apiHealthWantsText(r) {
		writeHealthText(w, health, code)
		return
	}
	writeHealthJSON(w, health, code)
}

// writeHealthJSON writes the bare (unwrapped) health document with the PART 13
// status code. Two-space indent per AI.md PART 14 JSON formatting rules.
func writeHealthJSON(w http.ResponseWriter, health model.HealthResponse, code int) {
	b, err := json.MarshalIndent(health, "", "  ")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", jsonMediaType)
	w.WriteHeader(code)
	// Write errors are unrecoverable once headers are sent; log is not actionable here.
	w.Write(b)            //nolint:errcheck
	w.Write([]byte("\n")) //nolint:errcheck
}

// healthWantsText reports whether a frontend health request should receive the
// plain-text representation. AI.md PART 13 defers to the PART 14 frontend
// negotiation ladder, whose default is HTML:
//  1. Accept: text/html -> HTML
//  2. Accept: text/plain -> text
//  3. Browser User-Agent -> HTML
//  4. CLI/HTTP tool with no browser UA -> text
//  5. Default -> HTML
//
// A `.txt` path is also honoured so the root alias behaves like the API route
// when a probe asks for it explicitly.
func healthWantsText(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "text/html") {
		return false
	}
	if strings.Contains(accept, textMediaType) {
		return true
	}
	if strings.HasSuffix(r.URL.Path, ".txt") {
		return true
	}
	ua := r.Header.Get("User-Agent")
	// Our own CLI renders plain text in a terminal; text browsers render HTML
	// themselves, so only they and graphical browsers fall through to HTML.
	if httputil.IsOurCliClient(ua) {
		return true
	}
	if httputil.IsTextBrowser(ua) {
		return false
	}
	return httputil.IsHttpTool(ua)
}

// bufferedResponse captures a rendered response in memory so the caller can
// decide the status code (and abandon a partial render) before anything
// reaches the client.
type bufferedResponse struct {
	header http.Header
	body   bytes.Buffer
}

// newBufferedResponse returns an empty bufferedResponse ready to be written to.
func newBufferedResponse() *bufferedResponse {
	return &bufferedResponse{header: make(http.Header)}
}

// Header implements http.ResponseWriter.
func (b *bufferedResponse) Header() http.Header { return b.header }

// Write implements http.ResponseWriter.
func (b *bufferedResponse) Write(p []byte) (int, error) { return b.body.Write(p) }

// WriteHeader implements http.ResponseWriter. The captured code is discarded:
// the health status code from AI.md PART 13 is authoritative and is supplied
// to flushTo instead.
func (b *bufferedResponse) WriteHeader(int) {}

// flushTo copies the captured headers and body to w under the given status code.
func (b *bufferedResponse) flushTo(w http.ResponseWriter, code int) {
	for k, v := range b.header {
		w.Header()[k] = v
	}
	w.WriteHeader(code)
	// Write errors are unrecoverable once headers are sent; log is not actionable here.
	w.Write(b.body.Bytes()) //nolint:errcheck
}
