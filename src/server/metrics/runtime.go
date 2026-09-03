package metrics

import (
	"runtime"
	"time"
)

// RuntimeCollector periodically collects Go runtime metrics using only the
// standard library runtime package (CGO_ENABLED=0 compatible — no gopsutil).
type RuntimeCollector struct {
	stop        chan struct{}
	lastGC      uint32
	lastPauseNs uint64
}

// NewRuntimeCollector creates a new RuntimeCollector. Call RegisterRuntimeMetrics
// before creating a collector so the gauge/counter vars are non-nil.
func NewRuntimeCollector() *RuntimeCollector {
	return &RuntimeCollector{
		stop: make(chan struct{}),
	}
}

// Start begins the background collection goroutine (every 15 seconds).
func (c *RuntimeCollector) Start() {
	go c.collect()
}

// Stop signals the background goroutine to exit.
func (c *RuntimeCollector) Stop() {
	close(c.stop)
}

func (c *RuntimeCollector) collect() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	// Collect once immediately so metrics are populated from the start.
	c.snapshot()

	for {
		select {
		case <-c.stop:
			return
		case <-ticker.C:
			c.snapshot()
		}
	}
}

func (c *RuntimeCollector) snapshot() {
	if GoGoroutines == nil {
		return
	}

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	GoGoroutines.Set(float64(runtime.NumGoroutine()))
	GoMemAllocBytes.Set(float64(ms.Alloc))
	GoMemSysBytes.Set(float64(ms.Sys))

	// GC runs: add delta since last snapshot (ms.NumGC is cumulative)
	if ms.NumGC > c.lastGC {
		GoGCRunsTotal.Add(float64(ms.NumGC - c.lastGC))
		c.lastGC = ms.NumGC
	}

	// GC pause total: add delta since last snapshot (ms.PauseTotalNs is cumulative)
	if ms.PauseTotalNs > c.lastPauseNs {
		GoGCPauseTotal.Add(float64(ms.PauseTotalNs-c.lastPauseNs) / 1e9)
		c.lastPauseNs = ms.PauseTotalNs
	}
}
