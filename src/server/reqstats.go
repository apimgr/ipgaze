package server

import (
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// requestStats tracks lightweight, always-on request counters used by the
// /server/healthz stats block (AI.md PART 13). Unlike the Prometheus metrics
// in src/server/metrics, these are recorded unconditionally regardless of
// whether the /metrics endpoint is enabled.
type requestStats struct {
	total  int64 // atomic: lifetime request count
	active int64 // atomic: currently in-flight requests

	mu          sync.Mutex
	hourBuckets [24]int64
	hourStamps  [24]int64
}

// newRequestStats constructs a zeroed requestStats tracker.
func newRequestStats() *requestStats {
	return &requestStats{}
}

// recordStart increments the in-flight request gauge. Call recordEnd via defer.
func (rs *requestStats) recordStart() {
	atomic.AddInt64(&rs.active, 1)
}

// recordEnd decrements the in-flight request gauge.
func (rs *requestStats) recordEnd() {
	atomic.AddInt64(&rs.active, -1)
}

// recordRequest increments the lifetime total and the current hour's bucket,
// used to derive the rolling 24h count.
func (rs *requestStats) recordRequest() {
	atomic.AddInt64(&rs.total, 1)

	hour := time.Now().Unix() / 3600
	idx := hour % 24

	rs.mu.Lock()
	if rs.hourStamps[idx] != hour {
		rs.hourStamps[idx] = hour
		rs.hourBuckets[idx] = 0
	}
	rs.hourBuckets[idx]++
	rs.mu.Unlock()
}

// snapshot returns the lifetime total, the rolling 24h count, and the current
// in-flight request count.
func (rs *requestStats) snapshot() (total int64, last24h int64, active int) {
	total = atomic.LoadInt64(&rs.total)
	active = int(atomic.LoadInt64(&rs.active))

	nowHour := time.Now().Unix() / 3600
	rs.mu.Lock()
	for i := 0; i < 24; i++ {
		if nowHour-rs.hourStamps[i] < 24 {
			last24h += rs.hourBuckets[i]
		}
	}
	rs.mu.Unlock()
	return total, last24h, active
}

// statsMiddleware records lightweight request counters for the healthz stats
// block (AI.md PART 13). Always active, independent of the Prometheus
// metricsEnabled gate.
func (s *Server) statsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.reqStats == nil {
			s.reqStats = newRequestStats()
		}
		s.reqStats.recordStart()
		defer s.reqStats.recordEnd()
		s.reqStats.recordRequest()
		next.ServeHTTP(w, r)
	})
}

// HealthStats returns the lifetime request total, requests in the last 24h,
// and current in-flight request count for the /server/healthz stats block
// (AI.md PART 13). Wired into HealthHandler.Stats from Handler().
func (s *Server) HealthStats() (total int64, last24h int64, active int) {
	if s.reqStats == nil {
		s.reqStats = newRequestStats()
	}
	return s.reqStats.snapshot()
}
