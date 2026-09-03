package metrics

import (
	"runtime"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// App info
	AppInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ipgaze_app_info",
		Help: "Application information.",
	}, []string{"version", "commit", "build_date", "go_version"})

	AppUptime = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ipgaze_app_uptime_seconds",
		Help: "Application uptime in seconds.",
	})

	AppStartTime = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ipgaze_app_start_timestamp",
		Help: "Unix timestamp when the application started.",
	})

	// HTTP metrics
	HTTPRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ipgaze_http_requests_total",
		Help: "Total number of HTTP requests.",
	}, []string{"method", "path", "status"})

	HTTPRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "ipgaze_http_request_duration_seconds",
		Help:    "HTTP request duration in seconds.",
		Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
	}, []string{"method", "path"})

	HTTPRequestSize = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "ipgaze_http_request_size_bytes",
		Help:    "HTTP request size in bytes.",
		Buckets: []float64{100, 1000, 10000, 100000, 1000000, 10000000},
	}, []string{"method", "path"})

	HTTPResponseSize = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "ipgaze_http_response_size_bytes",
		Help:    "HTTP response size in bytes.",
		Buckets: []float64{100, 1000, 10000, 100000, 1000000, 10000000},
	}, []string{"method", "path"})

	HTTPActiveRequests = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ipgaze_http_active_requests",
		Help: "Number of HTTP requests currently being processed.",
	})

	// Database metrics
	DBQueriesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ipgaze_db_queries_total",
		Help: "Total number of database queries.",
	}, []string{"operation", "table"})

	DBQueryDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "ipgaze_db_query_duration_seconds",
		Help:    "Database query duration in seconds.",
		Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1},
	}, []string{"operation", "table"})

	DBConnectionsOpen = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ipgaze_db_connections_open",
		Help: "Number of open database connections.",
	})

	DBConnectionsInUse = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ipgaze_db_connections_in_use",
		Help: "Number of database connections currently in use.",
	})

	DBErrorsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ipgaze_db_errors_total",
		Help: "Total number of database errors.",
	}, []string{"operation", "error_type"})

	// Cache metrics
	CacheHitsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ipgaze_cache_hits_total",
		Help: "Total number of cache hits.",
	}, []string{"cache"})

	CacheMissesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ipgaze_cache_misses_total",
		Help: "Total number of cache misses.",
	}, []string{"cache"})

	CacheEvictionsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ipgaze_cache_evictions_total",
		Help: "Total number of cache evictions.",
	}, []string{"cache"})

	CacheSize = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ipgaze_cache_size",
		Help: "Current number of items in the cache.",
	}, []string{"cache"})

	CacheBytes = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ipgaze_cache_bytes",
		Help: "Current size of the cache in bytes.",
	}, []string{"cache"})

	// Scheduler metrics
	SchedulerTasksTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ipgaze_scheduler_tasks_total",
		Help: "Total number of scheduler task runs.",
	}, []string{"task", "status"})

	SchedulerTaskDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "ipgaze_scheduler_task_duration_seconds",
		Help:    "Scheduler task duration in seconds.",
		Buckets: []float64{0.1, 0.5, 1, 5, 10, 30, 60, 300, 600},
	}, []string{"task"})

	SchedulerTasksRunning = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ipgaze_scheduler_tasks_running",
		Help: "Number of currently running scheduler tasks.",
	}, []string{"task"})

	SchedulerLastRunTimestamp = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ipgaze_scheduler_last_run_timestamp",
		Help: "Unix timestamp of the last task run.",
	}, []string{"task"})

	// Authentication metrics (REQUIRED per AI.md PART 20)
	AuthAttemptsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ipgaze_auth_attempts_total",
		Help: "Total number of authentication attempts.",
	}, []string{"method", "status"})

	AuthSessionsActive = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ipgaze_auth_sessions_active",
		Help: "Number of active user sessions.",
	})

	// Rate limiting metrics (if rate limiting enabled)
	RateLimitRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ipgaze_ratelimit_requests_total",
		Help: "Total rate-limited requests processed.",
	}, []string{"limit", "status"})

	RateLimitBlockedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ipgaze_ratelimit_blocked_total",
		Help: "Total requests blocked by rate limiter.",
	}, []string{"limit"})

	// Tor metrics (if Tor enabled — registered always so /metrics is always consistent)
	TorEnabled = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ipgaze_tor_enabled",
		Help: "1 if Tor hidden service support is enabled, 0 otherwise.",
	})

	TorRunning = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ipgaze_tor_running",
		Help: "1 if the Tor process is currently running, 0 otherwise.",
	})

	TorCircuitEstablished = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ipgaze_tor_circuit_established",
		Help: "1 if a Tor circuit is established, 0 otherwise.",
	})

	TorRequestsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ipgaze_tor_requests_total",
		Help: "Total requests received via the Tor hidden service.",
	})

	// System metrics (registered only when include_system: true)
	SystemCPUUsagePercent    prometheus.Gauge
	SystemMemoryUsagePercent prometheus.Gauge
	SystemMemoryUsedBytes    prometheus.Gauge
	SystemMemoryTotalBytes   prometheus.Gauge
	SystemDiskUsagePercent   *prometheus.GaugeVec
	SystemDiskUsedBytes      *prometheus.GaugeVec
	SystemDiskTotalBytes     *prometheus.GaugeVec

	// Go runtime metrics (registered only when include_runtime: true)
	GoGoroutines    prometheus.Gauge
	GoMemAllocBytes prometheus.Gauge
	GoMemSysBytes   prometheus.Gauge
	GoGCRunsTotal   prometheus.Counter
	GoGCPauseTotal  prometheus.Counter
)

// InitAppInfo sets the app info gauge and start time. Call once at startup.
func InitAppInfo(version, commit, buildDate string) {
	AppInfo.With(prometheus.Labels{
		"version":    version,
		"commit":     commit,
		"build_date": buildDate,
		"go_version": runtime.Version(),
	}).Set(1)
	AppStartTime.Set(float64(time.Now().Unix()))
}

// RegisterSystemMetrics registers system-level gauges (CPU, memory, disk) into the
// default registry. Only call this when include_system is true — calling it twice panics.
func RegisterSystemMetrics() {
	SystemCPUUsagePercent = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ipgaze_system_cpu_usage_percent",
		Help: "Current CPU usage percentage (0-100).",
	})
	SystemMemoryUsagePercent = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ipgaze_system_memory_usage_percent",
		Help: "Current memory usage percentage (0-100).",
	})
	SystemMemoryUsedBytes = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ipgaze_system_memory_used_bytes",
		Help: "Memory currently in use (bytes).",
	})
	SystemMemoryTotalBytes = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ipgaze_system_memory_total_bytes",
		Help: "Total system memory (bytes).",
	})
	SystemDiskUsagePercent = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ipgaze_system_disk_usage_percent",
		Help: "Disk usage percentage for the data directory.",
	}, []string{"path"})
	SystemDiskUsedBytes = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ipgaze_system_disk_used_bytes",
		Help: "Disk space used (bytes).",
	}, []string{"path"})
	SystemDiskTotalBytes = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ipgaze_system_disk_total_bytes",
		Help: "Total disk space (bytes).",
	}, []string{"path"})
}

// RegisterRuntimeMetrics registers the Go runtime metrics into the default registry.
// Only call this when include_runtime is true — calling it twice will panic.
func RegisterRuntimeMetrics() {
	GoGoroutines = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ipgaze_go_goroutines",
		Help: "Number of goroutines currently running.",
	})
	GoMemAllocBytes = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ipgaze_go_mem_alloc_bytes",
		Help: "Number of bytes allocated and still in use.",
	})
	GoMemSysBytes = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ipgaze_go_mem_sys_bytes",
		Help: "Number of bytes obtained from the OS.",
	})
	GoGCRunsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ipgaze_go_gc_runs_total",
		Help: "Total number of completed GC cycles.",
	})
	GoGCPauseTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ipgaze_go_gc_pause_total_seconds",
		Help: "Total time spent in GC stop-the-world pauses.",
	})
}
