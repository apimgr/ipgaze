package metrics

import (
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
)

// SystemCollector updates host CPU, memory, and data-directory disk metrics.
// RegisterSystemMetrics must be called first, only when include_system is true.
type SystemCollector struct {
	dataDir  string
	interval time.Duration
	stop     <-chan struct{}
}

// NewSystemCollector creates a collector that exits when stop is closed.
func NewSystemCollector(dataDir string, interval time.Duration, stop <-chan struct{}) *SystemCollector {
	if interval <= 0 {
		interval = 15 * time.Second
	}
	return &SystemCollector{dataDir: dataDir, interval: interval, stop: stop}
}

// Start collects immediately, then refreshes system metrics on the configured interval.
func (c *SystemCollector) Start() {
	go c.collect()
}

func (c *SystemCollector) collect() {
	c.snapshot()
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-ticker.C:
			c.snapshot()
		}
	}
}

func (c *SystemCollector) snapshot() {
	if values, err := cpu.Percent(0, false); err == nil && len(values) > 0 {
		SystemCPUUsagePercent.Set(values[0])
	}
	if memory, err := mem.VirtualMemory(); err == nil {
		SystemMemoryUsagePercent.Set(memory.UsedPercent)
		SystemMemoryUsedBytes.Set(float64(memory.Used))
		SystemMemoryTotalBytes.Set(float64(memory.Total))
	}
	if usage, err := disk.Usage(c.dataDir); err == nil {
		SystemDiskUsagePercent.WithLabelValues(c.dataDir).Set(usage.UsedPercent)
		SystemDiskUsedBytes.WithLabelValues(c.dataDir).Set(float64(usage.Used))
		SystemDiskTotalBytes.WithLabelValues(c.dataDir).Set(float64(usage.Total))
	}
}
