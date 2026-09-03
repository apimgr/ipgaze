package scheduler

import (
	"errors"
	"testing"
	"time"
)

// RecordTaskStart / RecordTaskEnd delegate to Prometheus counters which are
// registered at package init.  Calling them must not panic.

func TestRecordTaskStart_NoPanic(t *testing.T) {
	RecordTaskStart("test_task")
}

func TestRecordTaskEnd_Success_NoPanic(t *testing.T) {
	RecordTaskStart("task_ok")
	RecordTaskEnd("task_ok", 100*time.Millisecond, nil)
}

func TestRecordTaskEnd_Failure_NoPanic(t *testing.T) {
	RecordTaskStart("task_fail")
	RecordTaskEnd("task_fail", 50*time.Millisecond, errors.New("oops"))
}

func TestRecordTaskEnd_ZeroDuration_NoPanic(t *testing.T) {
	RecordTaskStart("task_zero")
	RecordTaskEnd("task_zero", 0, nil)
}
