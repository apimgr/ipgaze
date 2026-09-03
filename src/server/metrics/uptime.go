package metrics

import "time"

// StartUptimeUpdater updates the AppUptime gauge every second.
// Call once at startup; pass ctx.Done() as the stop channel for clean shutdown.
func StartUptimeUpdater(stop <-chan struct{}) {
	start := time.Now()
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				AppUptime.Set(time.Since(start).Seconds())
			}
		}
	}()
}
