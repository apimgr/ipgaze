package handler

import (
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"time"

	i18n "github.com/apimgr/ipgaze/src/common/i18n"
	"github.com/apimgr/ipgaze/src/config"
	"github.com/apimgr/ipgaze/src/server/metrics"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// metricsAPIVersion is the API version segment of the versioned metrics alias.
const metricsAPIVersion = "v1"

// IsLoopbackRequest returns true when the request's immediate TCP peer is a
// loopback address (127.0.0.0/8 or ::1). Proxy headers are deliberately
// ignored — this is the gate for INTERNAL endpoints (AI.md PART 20 /metrics,
// PART 31.1 /server/tor/*), which must never be reachable through a proxy.
func IsLoopbackRequest(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// MetricsRouter is the subset of the router needed to mount metrics routes.
// chi.Router satisfies it, as does any router with the same Get signature.
type MetricsRouter interface {
	Get(pattern string, h http.HandlerFunc)
}

// MetricsAuth wraps a metrics service handler with the mandatory per-service
// bearer-token check from AI.md PART 20.
// An empty token disables that service: 403 with an empty body.
// The token is read from the Authorization header only — query-string tokens
// are forbidden because they leak into access logs and proxy logs.
func MetricsAuth(cfg config.MetricsConfig, token string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		// Escape hatch for firewalled internal networks only; default false.
		if cfg.Auth.AllowUnauthenticated {
			h.ServeHTTP(w, r)
			return
		}
		if token == "" {
			padMetricsAuth(start)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		auth := r.Header.Get("Authorization")
		want := "Bearer " + token
		// Constant-time comparison; never an early exit on the first mismatch.
		if len(auth) != len(want) || subtle.ConstantTimeCompare([]byte(auth), []byte(want)) != 1 {
			padMetricsAuth(start)
			lang := i18n.DetectLocale(r)
			http.Error(w, i18n.T(i18n.WithLang(r.Context(), lang), "errors.unauthorized"), http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// metricsAuthFloor is the minimum wall time a rejected metrics request takes,
// per AI.md PART 11's requirement that failed auth be padded to at least
// 100ms. Duplicated here rather than shared with the server package's
// equivalent because importing src/server from a handler would cycle.
const metricsAuthFloor = 100 * time.Millisecond

// padMetricsAuth sleeps out the remainder of metricsAuthFloor so a missing
// header, a disabled service, and a wrong token are indistinguishable by
// response time.
func padMetricsAuth(start time.Time) {
	if remaining := metricsAuthFloor - time.Since(start); remaining > 0 {
		time.Sleep(remaining)
	}
}

// RegisterMetricsRoutes mounts the canonical metrics endpoint set of AI.md
// PART 20. Every alias invokes the SAME handler — never a redirect, because
// redirects break Prometheus scrapers. appName is both the metric-name prefix
// used in the Grafana queries and the Loki stream's app label.
func RegisterMetricsRoutes(r MetricsRouter, cfg config.MetricsConfig, appName string) {
	logBuffer := metrics.DefaultLogBuffer(cfg.Loki.MaxEntries)
	logDisabledMetricsServices(cfg, logBuffer)

	prom := MetricsAuth(cfg, cfg.Auth.Tokens.Prometheus, promhttp.Handler())
	grafana := MetricsAuth(cfg, cfg.Auth.Tokens.Grafana, GrafanaDashboardHandler(appName))
	loki := MetricsAuth(cfg, cfg.Auth.Tokens.Loki, LokiStreamsHandler(cfg.Loki, logBuffer, appName))

	mount := func(prefix string) {
		// The bare path serves the same handler as the prometheus sub-endpoint.
		r.Get(prefix, prom.ServeHTTP)
		r.Get(prefix+"/prometheus", prom.ServeHTTP)
		r.Get(prefix+"/grafana", grafana.ServeHTTP)
		r.Get(prefix+"/loki", loki.ServeHTTP)
	}

	mount("/server/metrics")
	mount("/api/" + metricsAPIVersion + "/server/metrics")
	mount("/api/metrics")
	if cfg.Root.Enabled {
		mount("/metrics")
	}
}

// logDisabledMetricsServices records, once at startup, which metrics services
// are disabled by an empty token, per AI.md PART 20. The notice goes to the log
// buffer and the structured log, never to the console, and never names a token.
func logDisabledMetricsServices(cfg config.MetricsConfig, buffer *metrics.LogBuffer) {
	if cfg.Auth.AllowUnauthenticated {
		return
	}
	services := map[string]string{
		"prometheus": cfg.Auth.Tokens.Prometheus,
		"grafana":    cfg.Auth.Tokens.Grafana,
		"loki":       cfg.Auth.Tokens.Loki,
	}
	names := make([]string, 0, len(services))
	for name, token := range services {
		if token == "" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		buffer.Record("warn", "metrics service disabled: no bearer token configured",
			slog.String("service", name))
	}
}

// LokiStreamsHandler serves recent structured log entries as Loki push-API
// streams, bounded by loki.max_entries and loki.max_age. Credentials are
// redacted by the buffer before an entry is ever stored.
func LokiStreamsHandler(cfg config.MetricsLokiConfig, buffer *metrics.LogBuffer, appName string) http.Handler {
	maxAge, err := time.ParseDuration(cfg.MaxAge)
	if err != nil || maxAge <= 0 {
		maxAge = time.Hour
	}
	maxEntries := cfg.MaxEntries
	if maxEntries <= 0 {
		maxEntries = 1000
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entries := buffer.Recent(maxEntries, maxAge)
		payload := metrics.LokiPayload{Streams: buffer.Streams(entries, appName)}
		if payload.Streams == nil {
			payload.Streams = []metrics.LokiStream{}
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		// Write errors are unrecoverable once the header has been written.
		json.NewEncoder(w).Encode(payload) //nolint:errcheck
	})
}

// GrafanaDashboardHandler serves a complete, importable Grafana dashboard
// covering every metric category required by AI.md PART 20. The datasource is
// a template variable so the dashboard imports against any Prometheus source.
func GrafanaDashboardHandler(appName string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		// Write errors are unrecoverable once the header has been written.
		json.NewEncoder(w).Encode(grafanaDashboard(appName)) //nolint:errcheck
	})
}

// grafanaDatasource points a panel at the dashboard's datasource variable.
type grafanaDatasource struct {
	Type string `json:"type"`
	UID  string `json:"uid"`
}

// grafanaGridPos is a panel's position on the dashboard grid.
type grafanaGridPos struct {
	H int `json:"h"`
	W int `json:"w"`
	X int `json:"x"`
	Y int `json:"y"`
}

// grafanaTarget is one PromQL query inside a panel.
type grafanaTarget struct {
	Expr         string `json:"expr"`
	LegendFormat string `json:"legendFormat"`
	RefID        string `json:"refId"`
}

// grafanaFieldDefaults holds the default field options for a panel.
type grafanaFieldDefaults struct {
	Unit string `json:"unit"`
}

// grafanaFieldConfig carries the panel's unit so axes render correctly.
type grafanaFieldConfig struct {
	Defaults grafanaFieldDefaults `json:"defaults"`
}

// grafanaPanel describes one Grafana time-series panel.
type grafanaPanel struct {
	Type       string             `json:"type"`
	Title      string             `json:"title"`
	ID         int                `json:"id"`
	Datasource grafanaDatasource  `json:"datasource"`
	GridPos    grafanaGridPos     `json:"gridPos"`
	Targets    []grafanaTarget    `json:"targets"`
	FieldCfg   grafanaFieldConfig `json:"fieldConfig"`
}

// grafanaTemplateVar is a dashboard template variable.
type grafanaTemplateVar struct {
	Name  string `json:"name"`
	Label string `json:"label"`
	Type  string `json:"type"`
	Query string `json:"query"`
}

// grafanaTemplating holds the dashboard's variable list.
type grafanaTemplating struct {
	List []grafanaTemplateVar `json:"list"`
}

// grafanaTimeRange is the dashboard's default time window.
type grafanaTimeRange struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// grafanaDashboardDoc is a complete importable Grafana dashboard definition.
type grafanaDashboardDoc struct {
	Title         string              `json:"title"`
	UID           string              `json:"uid"`
	SchemaVersion int                 `json:"schemaVersion"`
	Version       int                 `json:"version"`
	Editable      bool                `json:"editable"`
	Refresh       string              `json:"refresh"`
	Tags          []string            `json:"tags"`
	Time          grafanaTimeRange    `json:"time"`
	Templating    grafanaTemplating   `json:"templating"`
	Panels        []grafanaPanel      `json:"panels"`
	Annotations   map[string][]any    `json:"annotations"`
	Links         []map[string]string `json:"links"`
}

// grafanaPanelSpec is the compact description each full panel is built from.
type grafanaPanelSpec struct {
	title  string
	expr   string
	legend string
	unit   string
}

// grafanaPanelSpecs lists at least one panel per metric category required by
// PART 20: HTTP, database, cache, scheduler, system, and business.
func grafanaPanelSpecs(prefix string) []grafanaPanelSpec {
	return []grafanaPanelSpec{
		{"HTTP Request Rate", "sum(rate(" + prefix + "_http_requests_total[5m])) by (status)", "{{status}}", "reqps"},
		{"HTTP Request Duration (p95)", "histogram_quantile(0.95, sum(rate(" + prefix + "_http_request_duration_seconds_bucket[5m])) by (le, path))", "{{path}}", "s"},
		{"HTTP Request Size", "sum(rate(" + prefix + "_http_request_size_bytes_sum[5m]))", "request bytes/s", "Bps"},
		{"Database Queries", "sum(rate(" + prefix + "_db_queries_total[5m])) by (operation)", "{{operation}}", "ops"},
		{"Database Connections Open", prefix + "_db_connections_open", "open connections", "short"},
		{"Cache Hit Ratio", "sum(rate(" + prefix + "_cache_hits_total[5m])) / clamp_min(sum(rate(" + prefix + "_cache_hits_total[5m])) + sum(rate(" + prefix + "_cache_misses_total[5m])), 1)", "hit ratio", "percentunit"},
		{"Scheduler Task Runs", "sum(rate(" + prefix + "_scheduler_tasks_total[5m])) by (task)", "{{task}}", "ops"},
		{"Scheduler Task Failures", "sum(rate(" + prefix + "_scheduler_task_failures_total[5m])) by (task)", "{{task}}", "ops"},
		{"System CPU Usage", prefix + "_system_cpu_usage_percent", "cpu", "percent"},
		{"System Memory Used", prefix + "_system_memory_used_bytes", "memory used", "bytes"},
		{"System Disk Usage", prefix + "_system_disk_usage_percent", "{{path}}", "percent"},
		{"Goroutines", prefix + "_go_goroutines", "goroutines", "short"},
		{"Application Uptime", prefix + "_app_uptime_seconds", "uptime", "s"},
		{"API Calls", "sum(rate(" + prefix + "_http_requests_total{path=~\"/api/.*\"}[5m]))", "api calls/s", "reqps"},
	}
}

// grafanaDashboard builds the dashboard document served by the grafana service.
func grafanaDashboard(appName string) grafanaDashboardDoc {
	ds := grafanaDatasource{Type: "prometheus", UID: "${datasource}"}
	specs := grafanaPanelSpecs(appName)
	panels := make([]grafanaPanel, 0, len(specs))
	for i, spec := range specs {
		panels = append(panels, grafanaPanel{
			Type:       "timeseries",
			Title:      spec.title,
			ID:         i + 1,
			Datasource: ds,
			GridPos:    grafanaGridPos{H: 8, W: 12, X: (i % 2) * 12, Y: (i / 2) * 8},
			Targets: []grafanaTarget{{
				Expr:         spec.expr,
				LegendFormat: spec.legend,
				RefID:        "A",
			}},
			FieldCfg: grafanaFieldConfig{Defaults: grafanaFieldDefaults{Unit: spec.unit}},
		})
	}
	return grafanaDashboardDoc{
		Title:         appName + " Overview",
		UID:           appName + "-overview",
		SchemaVersion: 39,
		Version:       1,
		Editable:      true,
		Refresh:       "30s",
		Tags:          []string{appName, "prometheus"},
		Time:          grafanaTimeRange{From: "now-6h", To: "now"},
		Templating: grafanaTemplating{List: []grafanaTemplateVar{{
			Name:  "datasource",
			Label: "Datasource",
			Type:  "datasource",
			Query: "prometheus",
		}}},
		Panels:      panels,
		Annotations: map[string][]any{"list": {}},
		Links:       []map[string]string{},
	}
}
