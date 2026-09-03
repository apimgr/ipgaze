package server

import (
	"expvar"
	"runtime"
	"time"
)

// Counters published on /debug/vars. expvar.Int and expvar.Float mutate
// atomically, so these are safe to update from concurrent request handlers.
var (
	expvarRequestCount    = expvar.NewInt("requests_total")
	expvarRequestDuration = expvar.NewFloat("requests_duration_seconds")
	expvarErrorCount      = expvar.NewInt("errors_total")
	expvarStartTime       = time.Now()
)

func init() {
	// Seconds elapsed since this process published its expvar counters
	expvar.Publish("uptime_seconds", expvar.Func(func() any {
		return time.Since(expvarStartTime).Seconds()
	}))

	// Live goroutine count
	expvar.Publish("goroutines", expvar.Func(func() any {
		return runtime.NumGoroutine()
	}))

	// Heap and system memory usage snapshot
	expvar.Publish("memory", expvar.Func(func() any {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return map[string]uint64{
			"alloc":       m.Alloc,
			"total_alloc": m.TotalAlloc,
			"sys":         m.Sys,
			"heap_alloc":  m.HeapAlloc,
			"heap_sys":    m.HeapSys,
		}
	}))
}

// recordExpvarRequest records a completed request and its duration for expvar.
// Named distinctly from requestStats.recordRequest, which tracks hourly buckets.
func recordExpvarRequest(duration time.Duration) {
	expvarRequestCount.Add(1)
	expvarRequestDuration.Add(duration.Seconds())
}

// recordExpvarError records a failed request for expvar.
func recordExpvarError() {
	expvarErrorCount.Add(1)
}
