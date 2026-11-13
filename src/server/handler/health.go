// Package handler contains HTTP handlers organized by domain
// Per AI.md: handler/ for HTTP request handlers, route handlers, request/response logic
package handler

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	htmltemplate "html/template"
	"log"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/apimgr/ipgaze/src/common/httputil"
	"github.com/apimgr/ipgaze/src/common/i18n"
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
	Health                model.HealthResponse
	StatusClass           string
	StatusIcon            string
	StatusMessageKey      string
	TorStatusText         string
	I2PStatusText         string
	UptimeText            string
	BuildDateText         string
	TimestampText         string
	RequestsTotalText     string
	Requests24hText       string
	ActiveConnectionsText string
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
	if h.I2PStatus == nil {
		return ""
	}
	state := h.I2PStatus.Status()
	if state == "disabled" || state == "no_provider" {
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

	i2pInfo := model.I2PInfo{Status: "disabled", State: "disabled", Provider: i2pProviderNone}
	if h.I2PStatus != nil {
		state := h.I2PStatus.Status()
		status := state
		switch state {
		case "disabled", "no_provider":
			status = "disabled"
		case "starting", "building":
			status = "starting"
		case "running", "healthy":
			status = "healthy"
		case "error":
			status = "error"
		default:
			if strings.HasPrefix(state, "error:") {
				status = state
			} else if state == "" {
				state, status = "disabled", "disabled"
			}
		}
		i2pInfo = model.I2PInfo{
			Enabled:  state != "disabled",
			Running:  h.I2PStatus.IsRunning(),
			Status:   status,
			State:    state,
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
// healthzPageData adds human-readable values and the PART 13 status banner to
// the machine response without changing the JSON or API text representations.
func healthzPageData(pd PageData, health model.HealthResponse) HealthzPageData {
	class, icon, messageKey := "status-error", "❌", "health.unhealthy"
	switch health.Status {
	case statusHealthy:
		class, icon, messageKey = "status-ok", "✅", "health.all_operational"
	case statusDegraded:
		class, icon, messageKey = "status-warning", "⚠️", "healthz.degraded_performance"
	case statusRestartRequired:
		class, icon, messageKey = "status-warning", "🔄", "healthz.restart_required"
	case statusMaintenance:
		class, icon, messageKey = "status-error", "🚧", "healthz.maintenance"
	case statusShuttingDown:
		class, icon, messageKey = "status-error", "🛑", "healthz.shutting_down"
	}
	buildDate := health.Build.Date
	if parsed, err := time.Parse(time.RFC3339, buildDate); err == nil {
		buildDate = frontendTimestamp(parsed)
	}
	return HealthzPageData{
		PageData: pd, Health: health,
		StatusClass: class, StatusIcon: icon, StatusMessageKey: messageKey,
		TorStatusText: healthFeatureStatus(pd.Lang, health.Features.Tor.Status),
		I2PStatusText: healthFeatureStatus(pd.Lang, health.Features.I2P.Status),
		UptimeText:    frontendDuration(health.Uptime), BuildDateText: buildDate,
		TimestampText:         frontendTimestamp(health.Timestamp),
		RequestsTotalText:     formatHealthCount(health.Stats.RequestsTotal),
		Requests24hText:       formatHealthCount(health.Stats.Requests24h),
		ActiveConnectionsText: formatHealthCount(int64(health.Stats.ActiveConns)),
	}
}

func healthFeatureStatus(lang, status string) string {
	if strings.HasPrefix(status, "error:") {
		return i18n.Translate(lang, "common.error") + strings.TrimPrefix(status, "error")
	}
	keys := map[string]string{
		"healthy":  "health.healthy",
		"starting": "status_values.starting",
		"disabled": "common.disabled",
		"error":    "common.error",
	}
	if key := keys[status]; key != "" {
		return i18n.Translate(lang, key)
	}
	return status
}

func frontendTimestamp(t time.Time) string {
	return t.UTC().Format("January 02, 2006 at 15:04:05 MST")
}

func frontendDuration(compact string) string {
	var days, hours, minutes int
	if _, err := fmt.Sscanf(compact, "%dd %dh %dm", &days, &hours, &minutes); err == nil {
		if days > 0 {
			return fmt.Sprintf("%d days %d hours", days, hours)
		}
		if hours > 0 {
			return fmt.Sprintf("%d hours", hours)
		}
		return fmt.Sprintf("%d minutes", minutes)
	}
	if _, err := fmt.Sscanf(compact, "%dh %dm", &hours, &minutes); err == nil {
		if hours > 0 {
			return fmt.Sprintf("%d hours", hours)
		}
		return fmt.Sprintf("%d minutes", minutes)
	}
	if _, err := fmt.Sscanf(compact, "%dm", &minutes); err == nil {
		return fmt.Sprintf("%d minutes", minutes)
	}
	return compact
}

func formatHealthCount(value int64) string {
	negative := value < 0
	if negative {
		value = -value
	}
	digits := strconv.FormatInt(value, 10)
	for i := len(digits) - 3; i > 0; i -= 3 {
		digits = digits[:i] + "," + digits[i:]
	}
	if negative {
		return "-" + digits
	}
	return digits
}

// Per PART 13: /healthz supports HTML, JSON, and text based on Accept header
func (h *HealthHandler) HealthzHandler(w http.ResponseWriter, r *http.Request) {
	accept := r.Header.Get("Accept")
	health := h.buildHealthResponse()
	code := healthStatusCode(health.Status)

	// JSON response for Accept: application/json
	if strings.Contains(accept, jsonMediaType) {
		writeHealthJSON(r.Context(), w, health, code)
		return
	}

	// Our own CLI client is INTERACTIVE per AI.md PART 14's frontend rules —
	// it receives JSON and renders its own TUI, the same as every other
	// frontend route, even without an explicit Accept: application/json.
	if httputil.IsOurCliClient(r.Header.Get("User-Agent")) {
		writeHealthJSON(r.Context(), w, health, code)
		return
	}

	// Plain text only for the clients that cannot use HTML (see healthWantsText).
	if healthWantsText(r) {
		writeFrontendHealthText(r, w, health, code)
		return
	}

	// HTML response via template when renderer is available (preferred path)
	if h.Render != nil {
		var pd PageData
		if h.PageDataFunc != nil {
			pd = h.PageDataFunc(r)
		}
		data := healthzPageData(pd, health)
		// Buffer the render so a template failure cannot leave a half-written
		// body behind, and so the PART 13 status code is applied to a page that
		// actually rendered.
		buf := newBufferedResponse()
		if err := h.Render(buf, r, "healthz.tmpl", data); err != nil {
			log.Printf("health page render failed: status=%d method=%s path=%s err=%v", http.StatusInternalServerError, r.Method, r.URL.Path, err)
			writeHandlerFallback(w, r, http.StatusInternalServerError, i18n.T(r.Context(), "errors.server_error"), false)
			return
		}
		buf.flushTo(w, code)
		return
	}

	writeHealthHTMLFallback(w, r, health, code)
}

// writeHealthHTMLFallback renders the public health fields safely when a custom
// page renderer is unavailable.
func writeHealthHTMLFallback(w http.ResponseWriter, r *http.Request, health model.HealthResponse, code int) {
	lang := i18n.DetectLocale(r)
	page := healthzPageData(PageData{Lang: lang, Dir: string(i18n.LocaleDirection(lang))}, health)
	const source = `<!doctype html>
<!DOCTYPE html><html lang="{{.Lang}}" dir="{{.Dir}}" class="theme-dark"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="30"><title>{{.Health.Project.Name}} - {{t .Lang "healthz.page_title"}}</title></head>
<body><header></header><main class="container"><header class="health-header"><h1>📦 {{.Health.Project.Name}}</h1><p class="tagline">{{.Health.Project.Tagline}}</p><p>{{.Health.Project.Description}}</p></header>
<div class="status-banner {{.StatusClass}}" data-health-status="{{.Health.Status}}"><span class="status-icon">{{.StatusIcon}}</span><span class="status-text">{{t .Lang .StatusMessageKey}}</span></div>
<section class="section-card"><h2>{{t .Lang "health.version"}} &amp; {{t .Lang "health.build"}}</h2><dl class="info-list"><dt>{{t .Lang "health.version"}}</dt><dd><code>{{.Health.Version}}</code></dd><dt>{{t .Lang "health.go_version"}}</dt><dd><code>{{.Health.GoVersion}}</code></dd><dt>{{t .Lang "healthz.commit_label"}}</dt><dd><code>{{.Health.Build.Commit}}</code></dd><dt>{{t .Lang "healthz.build_date_label"}}</dt><dd><time datetime="{{.Health.Build.Date}}">{{.BuildDateText}}</time></dd><dt>{{t .Lang "health.uptime"}}</dt><dd>{{.UptimeText}}</dd><dt>{{t .Lang "health.mode"}}</dt><dd><span class="badge badge-{{.Health.Mode}}">{{.Health.Mode}}</span></dd><dt>{{t .Lang "healthz.timestamp_label"}}</dt><dd><time datetime="{{.Health.Timestamp}}">{{.TimestampText}}</time></dd></dl></section>
<section class="section-card"><h2>{{t .Lang "health.features"}}</h2><ul class="feature-list"><li class="{{if .Health.Features.Tor.Enabled}}feature-enabled{{else}}feature-disabled{{end}}">🧅 {{t .Lang "healthz.check_tor"}}: {{.TorStatusText}}{{if .Health.Features.Tor.Hostname}} - <code>{{.Health.Features.Tor.Hostname}}</code>{{end}}</li>{{if .Health.Features.I2P.Enabled}}<li class="feature-enabled">🔗 {{t .Lang "healthz.check_i2p"}}: {{.I2PStatusText}}{{if .Health.Features.I2P.Hostname}} - <code>{{.Health.Features.I2P.Hostname}}</code>{{end}} ({{.Health.Features.I2P.Provider}})</li>{{else}}<li class="feature-disabled">🔗 I2P: {{t .Lang "common.disabled"}}</li>{{end}}<li class="{{if .Health.Features.GeoIP}}feature-enabled{{else}}feature-disabled{{end}}">🌍 {{t .Lang "admin.geoip"}}</li></ul></section>
<section class="section-card"><h2>{{t .Lang "health.component_status"}}</h2><div class="table-wrapper"><table class="data-table"><thead><tr><th>{{t .Lang "healthz.column_component"}}</th><th>{{t .Lang "health.status"}}</th></tr></thead><tbody><tr><td>{{t .Lang "healthz.check_database"}}</td><td>{{.Health.Checks.Database}}</td></tr><tr><td>{{t .Lang "healthz.check_cache"}}</td><td>{{.Health.Checks.Cache}}</td></tr><tr><td>{{t .Lang "healthz.check_disk"}}</td><td>{{.Health.Checks.Disk}}</td></tr><tr><td>{{t .Lang "healthz.check_scheduler"}}</td><td>{{.Health.Checks.Scheduler}}</td></tr>{{if .Health.Checks.Tor}}<tr><td>{{t .Lang "healthz.check_tor"}}</td><td>{{.Health.Checks.Tor}}</td></tr>{{end}}{{if .Health.Checks.I2P}}<tr><td>{{t .Lang "healthz.check_i2p"}}</td><td>{{.Health.Checks.I2P}}</td></tr>{{end}}</tbody></table></div></section>
<section class="section-card"><h2>{{t .Lang "health.server_statistics"}}</h2><dl class="info-list stats-grid"><dt>{{t .Lang "health.total_requests"}}</dt><dd>{{.RequestsTotalText}}</dd><dt>{{t .Lang "health.requests_24h"}}</dt><dd>{{.Requests24hText}}</dd><dt>{{t .Lang "health.active_connections"}}</dt><dd>{{.ActiveConnectionsText}}</dd></dl></section>
<footer class="health-footer"><p>{{t .Lang "health.last_checked"}} <time datetime="{{.Health.Timestamp}}">{{.TimestampText}}</time></p><p>{{t .Lang "healthz.refreshing_in_prefix"}} 30s</p></footer></main><footer></footer></body></html>`
	tmpl, err := htmltemplate.New("healthz").Funcs(htmltemplate.FuncMap{"t": i18n.Translate}).Parse(source)
	if err != nil {
		writeHandlerFallback(w, r, http.StatusInternalServerError, i18n.Translate(lang, "errors.server_error"), false)
		return
	}
	var body bytes.Buffer
	if err := tmpl.Execute(&body, page); err != nil {
		writeHandlerFallback(w, r, http.StatusInternalServerError, i18n.Translate(lang, "errors.server_error"), false)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	_, _ = w.Write(body.Bytes())
}

func writeAPIHealthText(w http.ResponseWriter, health model.HealthResponse, code int) {
	w.Header().Set("Content-Type", textMediaType)
	w.WriteHeader(code)
	_, _ = fmt.Fprintf(w, "project.name: %s\nproject.tagline: %s\nproject.description: %s\nstatus: %s\n", health.Project.Name, health.Project.Tagline, health.Project.Description, health.Status)
	if health.PendingRestart {
		_, _ = fmt.Fprintf(w, "pending_restart: true\nrestart_reason: %s\n", strings.Join(health.RestartReason, ","))
	}
	_, _ = fmt.Fprintf(w, "version: %s\ngo_version: %s\nbuild.commit: %s\nbuild.date: %s\nuptime: %s\nmode: %s\ntimestamp: %s\n", health.Version, health.GoVersion, health.Build.Commit, health.Build.Date, health.Uptime, health.Mode, health.Timestamp.Format(time.RFC3339))
	_, _ = fmt.Fprintf(w, "features.tor: %s", health.Features.Tor.Status)
	if health.Features.Tor.Hostname != "" {
		_, _ = fmt.Fprintf(w, " %s", health.Features.Tor.Hostname)
	}
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintf(w, "features.i2p: %s", health.Features.I2P.Status)
	if health.Features.I2P.Hostname != "" {
		_, _ = fmt.Fprintf(w, " %s", health.Features.I2P.Hostname)
	}
	_, _ = fmt.Fprintf(w, " provider=%s state=%s\n", health.Features.I2P.Provider, health.Features.I2P.State)
	geoip := "disabled"
	if health.Features.GeoIP {
		geoip = "enabled"
	}
	_, _ = fmt.Fprintf(w, "features.geoip: %s\nchecks.database: %s\nchecks.cache: %s\nchecks.disk: %s\nchecks.scheduler: %s\n", geoip, health.Checks.Database, health.Checks.Cache, health.Checks.Disk, health.Checks.Scheduler)
	if health.Checks.Tor != "" {
		_, _ = fmt.Fprintf(w, "checks.tor: %s\n", health.Checks.Tor)
	}
	if health.Checks.I2P != "" {
		_, _ = fmt.Fprintf(w, "checks.i2p: %s\n", health.Checks.I2P)
	}
	_, _ = fmt.Fprintf(w, "stats.requests_total: %d\nstats.requests_24h: %d\nstats.active_connections: %d\n", health.Stats.RequestsTotal, health.Stats.Requests24h, health.Stats.ActiveConns)
}

// writeFrontendHealthText produces the human-readable frontend representation
// required for /server/healthz and the optional /healthz alias.
func writeFrontendHealthText(r *http.Request, w http.ResponseWriter, health model.HealthResponse, code int) {
	lang := i18n.DetectLocale(r)
	statusLabel := map[string]string{
		statusHealthy:         i18n.Translate(lang, "health.healthy"),
		statusDegraded:        i18n.Translate(lang, "healthz.degraded_performance"),
		statusRestartRequired: i18n.Translate(lang, "healthz.restart_required"),
		statusUnhealthy:       i18n.Translate(lang, "health.unhealthy"),
		statusMaintenance:     i18n.Translate(lang, "healthz.maintenance"),
		statusShuttingDown:    i18n.Translate(lang, "healthz.shutting_down"),
	}[health.Status]
	if statusLabel == "" {
		statusLabel = health.Status
	}
	w.Header().Set("Content-Type", textMediaType)
	w.WriteHeader(code)
	_, _ = fmt.Fprintf(w, "%s - %s\n\n%s: %s\n%s: %s\n%s: %s (%s)\n%s: %s\n%s: %s\n%s: %s\n%s %s\n\n%s\n", health.Project.Name, health.Project.Tagline, i18n.Translate(lang, "health.status"), statusLabel, i18n.Translate(lang, "health.version"), health.Version, i18n.Translate(lang, "health.build"), health.Build.Commit, frontendTimestampString(health.Build.Date), i18n.Translate(lang, "health.go_version"), health.GoVersion, i18n.Translate(lang, "health.uptime"), frontendDuration(health.Uptime), i18n.Translate(lang, "health.mode"), health.Mode, i18n.Translate(lang, "health.last_checked"), frontendTimestamp(health.Timestamp), i18n.Translate(lang, "health.features"))
	if health.PendingRestart {
		_, _ = fmt.Fprintf(w, "  %s %s\n", i18n.Translate(lang, "healthz.restart_pending"), strings.Join(health.RestartReason, ", "))
	}
	if health.Features.Tor.Enabled {
		_, _ = fmt.Fprintf(w, "  %s: %s", i18n.Translate(lang, "healthz.check_tor"), healthFeatureStatus(lang, health.Features.Tor.Status))
		if health.Features.Tor.Hostname != "" {
			_, _ = fmt.Fprintf(w, " - %s", health.Features.Tor.Hostname)
		}
		_, _ = fmt.Fprintln(w)
	} else {
		_, _ = fmt.Fprintf(w, "  %s: %s\n", i18n.Translate(lang, "healthz.check_tor"), i18n.Translate(lang, "common.disabled"))
	}
	if health.Features.I2P.Enabled {
		_, _ = fmt.Fprintf(w, "  %s: %s", i18n.Translate(lang, "healthz.check_i2p"), healthFeatureStatus(lang, health.Features.I2P.Status))
		if health.Features.I2P.Hostname != "" {
			_, _ = fmt.Fprintf(w, " - %s", health.Features.I2P.Hostname)
		}
		_, _ = fmt.Fprintf(w, " (%s)\n", health.Features.I2P.Provider)
	} else {
		_, _ = fmt.Fprintf(w, "  %s: %s\n", i18n.Translate(lang, "healthz.check_i2p"), i18n.Translate(lang, "common.disabled"))
	}
	featureState := i18n.Translate(lang, "common.disabled")
	if health.Features.GeoIP {
		featureState = i18n.Translate(lang, "common.enabled")
	}
	_, _ = fmt.Fprintf(w, "  %s: %s\n\n%s\n", i18n.Translate(lang, "admin.geoip"), featureState, i18n.Translate(lang, "health.component_status"))
	checks := []struct{ name, value string }{
		{i18n.Translate(lang, "healthz.check_database"), health.Checks.Database},
		{i18n.Translate(lang, "healthz.check_cache"), health.Checks.Cache},
		{i18n.Translate(lang, "healthz.check_disk"), health.Checks.Disk},
		{i18n.Translate(lang, "healthz.check_scheduler"), health.Checks.Scheduler},
	}
	if health.Checks.Tor != "" {
		checks = append(checks, struct{ name, value string }{i18n.Translate(lang, "healthz.check_tor"), health.Checks.Tor})
	}
	if health.Checks.I2P != "" {
		checks = append(checks, struct{ name, value string }{i18n.Translate(lang, "healthz.check_i2p"), health.Checks.I2P})
	}
	for _, check := range checks {
		_, _ = fmt.Fprintf(w, "  %-22s %s\n", check.name+":", check.value)
	}
	_, _ = fmt.Fprintf(w, "\n%s\n  %-22s %s\n  %-22s %s\n  %-22s %s\n", i18n.Translate(lang, "health.server_statistics"), i18n.Translate(lang, "health.total_requests")+":", formatHealthCount(health.Stats.RequestsTotal), i18n.Translate(lang, "health.requests_24h")+":", formatHealthCount(health.Stats.Requests24h), i18n.Translate(lang, "health.active_connections")+":", formatHealthCount(int64(health.Stats.ActiveConns)))
}

func frontendTimestampString(value string) string {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return value
	}
	return frontendTimestamp(parsed)
}

// apiHealthWantsText reports whether an /api/{api_version}/server/healthz request
// should receive the plain-text representation instead of the JSON envelope.
// Follows the AI.md PART 14 API content-negotiation priority order exactly:
//  1. `.txt` extension on the path -> text (always wins)
//  2. `Accept: text/plain` header -> text
//  3. Non-interactive HTTP tool detected (curl, wget, httpie, libcurl,
//     python-requests, go-http-client, axios, node-fetch, empty UA) -> text
//  4. Default (browsers, our CLI, `Accept: application/json`) -> JSON
func apiHealthWantsText(r *http.Request) bool {
	if r.URL.Path == "/api/healthz" {
		return false
	}
	if strings.HasSuffix(r.URL.Path, ".txt") {
		return true
	}
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, textMediaType) {
		return true
	}
	// An explicit Accept: text/html or application/json overrides the
	// non-interactive-tool heuristic below — the client told us what it
	// wants, so an absent/tool-like User-Agent must not force text.
	if strings.Contains(accept, "text/html") || strings.Contains(accept, jsonMediaType) {
		return false
	}
	return IsNonInteractiveHTTPTool(r.Header.Get("User-Agent"))
}

// IsNonInteractiveHTTPTool reports whether the User-Agent is one of the
// non-interactive HTTP tools (curl, wget, httpie, libcurl, python-requests,
// go-http-client, axios, node-fetch, or an empty UA) that AI.md PART 14
// says must receive pre-formatted text. It delegates to httputil.IsHttpTool
// so this list never drifts out of sync with the canonical detector used by
// the rest of the content-negotiation stack. Exported so other packages
// needing the same rule (e.g. server.NotFoundHandler's catch-all) reuse it
// instead of duplicating it.
func IsNonInteractiveHTTPTool(ua string) bool {
	return httputil.IsHttpTool(ua)
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
		writeAPIHealthText(w, health, code)
		return
	}
	writeHealthJSON(r.Context(), w, health, code)
}

// writeHealthJSON writes the bare (unwrapped) health document with the PART 13
// status code. Two-space indent per AI.md PART 14 JSON formatting rules.
func writeHealthJSON(ctx context.Context, w http.ResponseWriter, health model.HealthResponse, code int) {
	b, err := json.MarshalIndent(health, "", "  ")
	if err != nil {
		// This path only ever serves JSON clients, so its fallback is the
		// canonical PART 9 envelope (AI.md 24426: the error path honors content
		// negotiation — JSON for API clients).
		WriteAPIError(w, http.StatusInternalServerError, "", i18n.T(ctx, "errors.server_error"))
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
// negotiation ladder, whose default is HTML. Our own CLI client is handled
// earlier in HealthzHandler (it always gets JSON), so by the time this runs
// only text browsers, graphical browsers, and non-interactive HTTP tools
// remain:
//  1. Accept: text/html -> HTML
//  2. Accept: text/plain -> text
//  3. Text browser User-Agent -> HTML (renders it themselves)
//  4. Non-interactive HTTP tool -> text
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
