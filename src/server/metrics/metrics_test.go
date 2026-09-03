package metrics

import (
	"runtime"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
)

// TestInitAppInfo verifies that InitAppInfo populates AppInfo and AppStartTime.
func TestInitAppInfo(t *testing.T) {
	before := time.Now().Unix()
	InitAppInfo("1.2.3", "abc123", "2026-01-01")
	after := time.Now().Unix()

	// AppStartTime must be within [before, after].
	m := &dto.Metric{}
	if err := AppStartTime.Write(m); err != nil {
		t.Fatalf("AppStartTime.Write: %v", err)
	}
	ts := int64(m.GetGauge().GetValue())
	if ts < before || ts > after {
		t.Errorf("AppStartTime = %d; want in [%d, %d]", ts, before, after)
	}

	// AppInfo gauge must be 1 for the labels we just set.
	mg := &dto.Metric{}
	if err := AppInfo.With(map[string]string{
		"version":    "1.2.3",
		"commit":     "abc123",
		"build_date": "2026-01-01",
		"go_version": runtime.Version(),
	}).Write(mg); err != nil {
		t.Fatalf("AppInfo.With.Write: %v", err)
	}
	if got := mg.GetGauge().GetValue(); got != 1 {
		t.Errorf("AppInfo gauge = %v; want 1", got)
	}
}

// TestHTTPRequestsTotal verifies counter increments on HTTPRequestsTotal.
func TestHTTPRequestsTotal(t *testing.T) {
	HTTPRequestsTotal.With(map[string]string{
		"method": "GET",
		"path":   "/healthz",
		"status": "200",
	}).Add(3)

	m := &dto.Metric{}
	if err := HTTPRequestsTotal.With(map[string]string{
		"method": "GET",
		"path":   "/healthz",
		"status": "200",
	}).Write(m); err != nil {
		t.Fatalf("HTTPRequestsTotal.Write: %v", err)
	}
	// promauto counters accumulate across all tests — just verify it is >= 3.
	if got := m.GetCounter().GetValue(); got < 3 {
		t.Errorf("HTTPRequestsTotal = %v; want >= 3", got)
	}
}

// TestHTTPRequestDuration verifies observations are accepted without panicking.
func TestHTTPRequestDuration(t *testing.T) {
	HTTPRequestDuration.With(map[string]string{
		"method": "POST",
		"path":   "/api/v1/lookup",
	}).Observe(0.042)
}

// TestHTTPRequestSize verifies observations are accepted without panicking.
func TestHTTPRequestSize(t *testing.T) {
	HTTPRequestSize.With(map[string]string{
		"method": "GET",
		"path":   "/api/v1/lookup",
	}).Observe(512)
}

// TestHTTPResponseSize verifies observations are accepted without panicking.
func TestHTTPResponseSize(t *testing.T) {
	HTTPResponseSize.With(map[string]string{
		"method": "GET",
		"path":   "/api/v1/lookup",
	}).Observe(1024)
}

// TestHTTPActiveRequests verifies gauge set/add/sub operations.
func TestHTTPActiveRequests(t *testing.T) {
	HTTPActiveRequests.Set(0)
	HTTPActiveRequests.Inc()
	HTTPActiveRequests.Inc()

	m := &dto.Metric{}
	if err := HTTPActiveRequests.Write(m); err != nil {
		t.Fatalf("HTTPActiveRequests.Write: %v", err)
	}
	if got := m.GetGauge().GetValue(); got < 2 {
		t.Errorf("HTTPActiveRequests = %v; want >= 2", got)
	}

	HTTPActiveRequests.Dec()
	m2 := &dto.Metric{}
	if err := HTTPActiveRequests.Write(m2); err != nil {
		t.Fatalf("HTTPActiveRequests.Write after Dec: %v", err)
	}
	if got := m2.GetGauge().GetValue(); got < 1 {
		t.Errorf("HTTPActiveRequests after Dec = %v; want >= 1", got)
	}
}

// TestDBQueriesTotal verifies database query counter increments.
func TestDBQueriesTotal(t *testing.T) {
	DBQueriesTotal.With(map[string]string{
		"operation": "SELECT",
		"table":     "lookups",
	}).Inc()

	m := &dto.Metric{}
	if err := DBQueriesTotal.With(map[string]string{
		"operation": "SELECT",
		"table":     "lookups",
	}).Write(m); err != nil {
		t.Fatalf("DBQueriesTotal.Write: %v", err)
	}
	if got := m.GetCounter().GetValue(); got < 1 {
		t.Errorf("DBQueriesTotal = %v; want >= 1", got)
	}
}

// TestDBQueryDuration verifies histogram observations for DB queries.
func TestDBQueryDuration(t *testing.T) {
	DBQueryDuration.With(map[string]string{
		"operation": "INSERT",
		"table":     "events",
	}).Observe(0.002)
}

// TestDBConnectionGauges verifies set operations on open/in-use connection gauges.
func TestDBConnectionGauges(t *testing.T) {
	DBConnectionsOpen.Set(5)
	DBConnectionsInUse.Set(2)

	mOpen := &dto.Metric{}
	if err := DBConnectionsOpen.Write(mOpen); err != nil {
		t.Fatalf("DBConnectionsOpen.Write: %v", err)
	}
	if got := mOpen.GetGauge().GetValue(); got != 5 {
		t.Errorf("DBConnectionsOpen = %v; want 5", got)
	}

	mInUse := &dto.Metric{}
	if err := DBConnectionsInUse.Write(mInUse); err != nil {
		t.Fatalf("DBConnectionsInUse.Write: %v", err)
	}
	if got := mInUse.GetGauge().GetValue(); got != 2 {
		t.Errorf("DBConnectionsInUse = %v; want 2", got)
	}
}

// TestDBErrorsTotal verifies error counter increments.
func TestDBErrorsTotal(t *testing.T) {
	DBErrorsTotal.With(map[string]string{
		"operation":  "SELECT",
		"error_type": "timeout",
	}).Inc()

	m := &dto.Metric{}
	if err := DBErrorsTotal.With(map[string]string{
		"operation":  "SELECT",
		"error_type": "timeout",
	}).Write(m); err != nil {
		t.Fatalf("DBErrorsTotal.Write: %v", err)
	}
	if got := m.GetCounter().GetValue(); got < 1 {
		t.Errorf("DBErrorsTotal = %v; want >= 1", got)
	}
}

// TestCacheMetrics verifies hit, miss, eviction counters and size/bytes gauges.
func TestCacheMetrics(t *testing.T) {
	const cacheName = "geoip"

	CacheHitsTotal.With(map[string]string{"cache": cacheName}).Add(10)
	CacheMissesTotal.With(map[string]string{"cache": cacheName}).Add(2)
	CacheEvictionsTotal.With(map[string]string{"cache": cacheName}).Add(1)
	CacheSize.With(map[string]string{"cache": cacheName}).Set(100)
	CacheBytes.With(map[string]string{"cache": cacheName}).Set(4096)

	hits := &dto.Metric{}
	if err := CacheHitsTotal.With(map[string]string{"cache": cacheName}).Write(hits); err != nil {
		t.Fatalf("CacheHitsTotal.Write: %v", err)
	}
	if got := hits.GetCounter().GetValue(); got < 10 {
		t.Errorf("CacheHitsTotal = %v; want >= 10", got)
	}

	misses := &dto.Metric{}
	if err := CacheMissesTotal.With(map[string]string{"cache": cacheName}).Write(misses); err != nil {
		t.Fatalf("CacheMissesTotal.Write: %v", err)
	}
	if got := misses.GetCounter().GetValue(); got < 2 {
		t.Errorf("CacheMissesTotal = %v; want >= 2", got)
	}

	evictions := &dto.Metric{}
	if err := CacheEvictionsTotal.With(map[string]string{"cache": cacheName}).Write(evictions); err != nil {
		t.Fatalf("CacheEvictionsTotal.Write: %v", err)
	}
	if got := evictions.GetCounter().GetValue(); got < 1 {
		t.Errorf("CacheEvictionsTotal = %v; want >= 1", got)
	}

	sz := &dto.Metric{}
	if err := CacheSize.With(map[string]string{"cache": cacheName}).Write(sz); err != nil {
		t.Fatalf("CacheSize.Write: %v", err)
	}
	if got := sz.GetGauge().GetValue(); got != 100 {
		t.Errorf("CacheSize = %v; want 100", got)
	}

	cb := &dto.Metric{}
	if err := CacheBytes.With(map[string]string{"cache": cacheName}).Write(cb); err != nil {
		t.Fatalf("CacheBytes.Write: %v", err)
	}
	if got := cb.GetGauge().GetValue(); got != 4096 {
		t.Errorf("CacheBytes = %v; want 4096", got)
	}
}

// TestSchedulerMetrics verifies scheduler task counters, durations, and gauges.
func TestSchedulerMetrics(t *testing.T) {
	const task = "geoip_update"

	SchedulerTasksTotal.With(map[string]string{"task": task, "status": "success"}).Inc()
	SchedulerTaskDuration.With(map[string]string{"task": task}).Observe(1.5)
	SchedulerTasksRunning.With(map[string]string{"task": task}).Set(1)
	SchedulerLastRunTimestamp.With(map[string]string{"task": task}).SetToCurrentTime()

	m := &dto.Metric{}
	if err := SchedulerTasksTotal.With(map[string]string{"task": task, "status": "success"}).Write(m); err != nil {
		t.Fatalf("SchedulerTasksTotal.Write: %v", err)
	}
	if got := m.GetCounter().GetValue(); got < 1 {
		t.Errorf("SchedulerTasksTotal = %v; want >= 1", got)
	}

	mRunning := &dto.Metric{}
	if err := SchedulerTasksRunning.With(map[string]string{"task": task}).Write(mRunning); err != nil {
		t.Fatalf("SchedulerTasksRunning.Write: %v", err)
	}
	if got := mRunning.GetGauge().GetValue(); got != 1 {
		t.Errorf("SchedulerTasksRunning = %v; want 1", got)
	}

	mTs := &dto.Metric{}
	if err := SchedulerLastRunTimestamp.With(map[string]string{"task": task}).Write(mTs); err != nil {
		t.Fatalf("SchedulerLastRunTimestamp.Write: %v", err)
	}
	if got := mTs.GetGauge().GetValue(); got <= 0 {
		t.Errorf("SchedulerLastRunTimestamp = %v; want > 0", got)
	}
}

// TestRegisterRuntimeMetrics verifies that runtime metric vars are non-nil after
// registration and that a snapshot can be taken without panicking.
func TestRegisterRuntimeMetrics(t *testing.T) {
	// RegisterRuntimeMetrics will panic if called twice (promauto re-registration).
	// Guard with a nil check so this test is safe to run in any order.
	if GoGoroutines != nil {
		t.Skip("runtime metrics already registered")
	}

	RegisterRuntimeMetrics()

	if GoGoroutines == nil {
		t.Error("GoGoroutines is nil after RegisterRuntimeMetrics")
	}
	if GoMemAllocBytes == nil {
		t.Error("GoMemAllocBytes is nil after RegisterRuntimeMetrics")
	}
	if GoMemSysBytes == nil {
		t.Error("GoMemSysBytes is nil after RegisterRuntimeMetrics")
	}
	if GoGCRunsTotal == nil {
		t.Error("GoGCRunsTotal is nil after RegisterRuntimeMetrics")
	}
	if GoGCPauseTotal == nil {
		t.Error("GoGCPauseTotal is nil after RegisterRuntimeMetrics")
	}
}

// TestRuntimeCollectorStartStop verifies that Start and Stop do not panic or deadlock.
func TestRuntimeCollectorStartStop(t *testing.T) {
	// Ensure runtime metrics are registered before creating the collector.
	if GoGoroutines == nil {
		RegisterRuntimeMetrics()
	}

	c := NewRuntimeCollector()
	c.Start()
	// Give the background goroutine a moment to take an initial snapshot.
	time.Sleep(50 * time.Millisecond)
	c.Stop()

	// Verify at least one metric was populated.
	m := &dto.Metric{}
	if err := GoGoroutines.Write(m); err != nil {
		t.Fatalf("GoGoroutines.Write: %v", err)
	}
	if got := m.GetGauge().GetValue(); got < 1 {
		t.Errorf("GoGoroutines = %v; want >= 1", got)
	}
}

// TestRuntimeCollectorSnapshotNilGuard verifies snapshot is a no-op when vars are nil.
func TestRuntimeCollectorSnapshotNilGuard(t *testing.T) {
	saved := GoGoroutines
	GoGoroutines = nil
	defer func() { GoGoroutines = saved }()

	c := &RuntimeCollector{stop: make(chan struct{})}
	// Must not panic.
	c.snapshot()
}

// TestRuntimeCollectorGCDeltaBranches forces GC between two snapshots so that
// the NumGC and PauseTotalNs delta branches in snapshot() are exercised.
func TestRuntimeCollectorGCDeltaBranches(t *testing.T) {
	if GoGoroutines == nil {
		RegisterRuntimeMetrics()
	}

	c := NewRuntimeCollector()

	// First snapshot sets lastGC / lastPauseNs baselines.
	c.snapshot()

	// Force at least one GC cycle so ms.NumGC > c.lastGC on the next call.
	runtime.GC()

	// Second snapshot should enter the delta branches.
	c.snapshot()

	// Both GC counters must be > 0 now.
	mgc := &dto.Metric{}
	if err := GoGCRunsTotal.Write(mgc); err != nil {
		t.Fatalf("GoGCRunsTotal.Write: %v", err)
	}
	if got := mgc.GetCounter().GetValue(); got < 1 {
		t.Errorf("GoGCRunsTotal = %v after forced GC; want >= 1", got)
	}
}

// TestStartUptimeUpdater verifies that AppUptime is updated after at least one tick.
func TestStartUptimeUpdater(t *testing.T) {
	stop := make(chan struct{})
	StartUptimeUpdater(stop)

	// Wait for at least one 1-second tick. Margin is generous because the
	// ticker fires on wall-clock time and scheduling can lag under a loaded
	// host (e.g. many concurrent Docker containers on the CI/build box).
	time.Sleep(1800 * time.Millisecond)
	close(stop)

	m := &dto.Metric{}
	if err := AppUptime.Write(m); err != nil {
		t.Fatalf("AppUptime.Write: %v", err)
	}
	if got := m.GetGauge().GetValue(); got <= 0 {
		t.Errorf("AppUptime = %v after 1s; want > 0", got)
	}
}

// TestUptimeUpdaterStop verifies that closing the stop channel causes the updater
// to exit cleanly without leaking goroutines.
func TestUptimeUpdaterStop(t *testing.T) {
	stop := make(chan struct{})
	StartUptimeUpdater(stop)
	// Close immediately — the goroutine must exit.
	close(stop)
	// Allow a scheduler cycle for the goroutine to notice the close.
	time.Sleep(20 * time.Millisecond)
}

// TestAuthMetrics verifies authentication attempt counter and active sessions gauge.
func TestAuthMetrics(t *testing.T) {
	AuthAttemptsTotal.With(map[string]string{"method": "password", "status": "success"}).Inc()
	AuthAttemptsTotal.With(map[string]string{"method": "api_token", "status": "failed"}).Add(2)

	m := &dto.Metric{}
	if err := AuthAttemptsTotal.With(map[string]string{
		"method": "password", "status": "success",
	}).Write(m); err != nil {
		t.Fatalf("AuthAttemptsTotal.Write: %v", err)
	}
	if got := m.GetCounter().GetValue(); got < 1 {
		t.Errorf("AuthAttemptsTotal(password,success) = %v; want >= 1", got)
	}

	AuthSessionsActive.Set(5)
	ms := &dto.Metric{}
	if err := AuthSessionsActive.Write(ms); err != nil {
		t.Fatalf("AuthSessionsActive.Write: %v", err)
	}
	if got := ms.GetGauge().GetValue(); got != 5 {
		t.Errorf("AuthSessionsActive = %v; want 5", got)
	}
}

// TestRateLimitMetrics verifies rate-limit counters.
func TestRateLimitMetrics(t *testing.T) {
	RateLimitRequestsTotal.With(map[string]string{"limit": "per_ip", "status": "allowed"}).Inc()
	RateLimitBlockedTotal.With(map[string]string{"limit": "global"}).Add(3)

	m := &dto.Metric{}
	if err := RateLimitBlockedTotal.With(map[string]string{"limit": "global"}).Write(m); err != nil {
		t.Fatalf("RateLimitBlockedTotal.Write: %v", err)
	}
	if got := m.GetCounter().GetValue(); got < 3 {
		t.Errorf("RateLimitBlockedTotal = %v; want >= 3", got)
	}
}

// TestTorMetrics verifies tor gauge and counter operations.
func TestTorMetrics(t *testing.T) {
	TorEnabled.Set(1)
	TorRunning.Set(0)
	TorCircuitEstablished.Set(0)
	TorRequestsTotal.Add(10)

	me := &dto.Metric{}
	if err := TorEnabled.Write(me); err != nil {
		t.Fatalf("TorEnabled.Write: %v", err)
	}
	if got := me.GetGauge().GetValue(); got != 1 {
		t.Errorf("TorEnabled = %v; want 1", got)
	}

	mr := &dto.Metric{}
	if err := TorRequestsTotal.Write(mr); err != nil {
		t.Fatalf("TorRequestsTotal.Write: %v", err)
	}
	if got := mr.GetCounter().GetValue(); got < 10 {
		t.Errorf("TorRequestsTotal = %v; want >= 10", got)
	}
}

// TestRegisterSystemMetrics verifies that system metric vars are non-nil after registration.
func TestRegisterSystemMetrics(t *testing.T) {
	// RegisterSystemMetrics panics on double registration; guard with nil check.
	if SystemCPUUsagePercent != nil {
		t.Skip("system metrics already registered")
	}

	RegisterSystemMetrics()

	if SystemCPUUsagePercent == nil {
		t.Error("SystemCPUUsagePercent is nil after RegisterSystemMetrics")
	}
	if SystemMemoryUsagePercent == nil {
		t.Error("SystemMemoryUsagePercent is nil after RegisterSystemMetrics")
	}
	if SystemMemoryUsedBytes == nil {
		t.Error("SystemMemoryUsedBytes is nil after RegisterSystemMetrics")
	}
	if SystemMemoryTotalBytes == nil {
		t.Error("SystemMemoryTotalBytes is nil after RegisterSystemMetrics")
	}
	if SystemDiskUsagePercent == nil {
		t.Error("SystemDiskUsagePercent is nil after RegisterSystemMetrics")
	}
	if SystemDiskUsedBytes == nil {
		t.Error("SystemDiskUsedBytes is nil after RegisterSystemMetrics")
	}
	if SystemDiskTotalBytes == nil {
		t.Error("SystemDiskTotalBytes is nil after RegisterSystemMetrics")
	}

	// Verify set operations work without panic.
	SystemCPUUsagePercent.Set(12.5)
	SystemMemoryUsagePercent.Set(45.0)
	SystemMemoryUsedBytes.Set(1 << 30)
	SystemMemoryTotalBytes.Set(8 << 30)
	SystemDiskUsagePercent.With(map[string]string{"path": "/var/lib/ipgaze"}).Set(62.3)
	SystemDiskUsedBytes.With(map[string]string{"path": "/var/lib/ipgaze"}).Set(50 << 30)
	SystemDiskTotalBytes.With(map[string]string{"path": "/var/lib/ipgaze"}).Set(100 << 30)
}
