package scheduler

import (
	"time"

	smetrics "github.com/apimgr/ipgaze/src/server/metrics"
)

// RecordTaskStart marks a task as running in the metrics.
func RecordTaskStart(taskName string) {
	smetrics.SchedulerTasksRunning.WithLabelValues(taskName).Inc()
}

// RecordTaskEnd records the result of a completed task run.
func RecordTaskEnd(taskName string, duration time.Duration, err error) {
	smetrics.SchedulerTasksRunning.WithLabelValues(taskName).Dec()
	smetrics.SchedulerTaskDuration.WithLabelValues(taskName).Observe(duration.Seconds())
	smetrics.SchedulerLastRunTimestamp.WithLabelValues(taskName).SetToCurrentTime()

	status := "success"
	if err != nil {
		status = "failed"
	}
	smetrics.SchedulerTasksTotal.WithLabelValues(taskName, status).Inc()
}
