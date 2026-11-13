package metrics

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
)

func TestSystemCollectorIntervalAndShutdown(t *testing.T) {
	if SystemCPUUsagePercent == nil {
		RegisterSystemMetrics()
	}

	defaultCollector := NewSystemCollector(t.TempDir(), 0, nil)
	if defaultCollector.interval != 15*time.Second {
		t.Fatalf("default interval = %s, want 15s", defaultCollector.interval)
	}

	stop := make(chan struct{})
	collector := NewSystemCollector(t.TempDir(), time.Millisecond, stop)
	if collector.interval != time.Millisecond {
		t.Fatalf("configured interval = %s, want 1ms", collector.interval)
	}
	done := make(chan struct{})
	go func() {
		collector.collect()
		close(done)
	}()
	time.Sleep(10 * time.Millisecond)
	close(stop)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("system collector did not stop after its stop channel closed")
	}
}

func TestSystemCollectorSnapshotUpdatesMetrics(t *testing.T) {
	if SystemCPUUsagePercent == nil {
		RegisterSystemMetrics()
	}
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "probe"), []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}

	collector := NewSystemCollector(dataDir, time.Second, nil)
	collector.snapshot()

	metric := &dto.Metric{}
	if err := SystemDiskUsagePercent.With(map[string]string{"path": dataDir}).Write(metric); err != nil {
		t.Fatalf("disk usage metric: %v", err)
	}
	if metric.GetGauge() == nil {
		t.Fatal("disk usage metric was not recorded")
	}
}
