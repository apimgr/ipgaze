package scheduler

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// --- helpers ---------------------------------------------------------------

func newTestScheduler(t *testing.T) *Scheduler {
	t.Helper()
	s, err := NewScheduler(nil, SchedulerRunConfig{
		Timezone:      "UTC",
		CatchUpWindow: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}
	t.Cleanup(s.Stop)
	return s
}

func runningTask(id, name, schedule string, fn func() error) *Task {
	return &Task{ID: id, Name: name, Schedule: schedule, Fn: fn, Enabled: true}
}

// --- DefaultConfig ---------------------------------------------------------

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Timezone == "" {
		t.Error("Timezone must not be empty")
	}
	if cfg.CatchUpWindow <= 0 {
		t.Error("CatchUpWindow must be positive")
	}
}

// --- NewScheduler ----------------------------------------------------------

func TestNewScheduler_ValidTimezone(t *testing.T) {
	s, err := NewScheduler(nil, SchedulerRunConfig{Timezone: "America/New_York"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s.Stop()
	if s.timezone == nil {
		t.Error("timezone must not be nil")
	}
}

func TestNewScheduler_InvalidTimezone_FallsBackToUTC(t *testing.T) {
	s, err := NewScheduler(nil, SchedulerRunConfig{Timezone: "Not/AReal/Zone"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s.Stop()
	if s.timezone != time.UTC {
		t.Errorf("expected UTC fallback, got %s", s.timezone)
	}
}

func TestNewScheduler_ZeroCatchUp_DefaultsToHour(t *testing.T) {
	s, err := NewScheduler(nil, SchedulerRunConfig{CatchUpWindow: 0})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s.Stop()
	if s.CatchUpWindow != time.Hour {
		t.Errorf("CatchUpWindow = %v, want 1h", s.CatchUpWindow)
	}
}

func TestNewScheduler_NilDB(t *testing.T) {
	s, err := NewScheduler(nil, DefaultConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s.Stop()
	if s.db != nil {
		t.Error("db must be nil when passed nil")
	}
}

// --- Start / Stop ----------------------------------------------------------

func TestStart_Then_Stop(t *testing.T) {
	s := newTestScheduler(t)

	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	s.mu.RLock()
	running := s.running
	s.mu.RUnlock()
	if !running {
		t.Error("scheduler should be marked running after Start")
	}

	s.Stop()

	s.mu.RLock()
	running = s.running
	s.mu.RUnlock()
	if running {
		t.Error("scheduler should not be marked running after Stop")
	}
}

func TestStart_AlreadyRunning_ReturnsError(t *testing.T) {
	s := newTestScheduler(t)

	if err := s.Start(); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	if err := s.Start(); err == nil {
		t.Error("expected error on second Start, got nil")
	}
}

func TestStop_WhenNotRunning_IsNoop(t *testing.T) {
	s := newTestScheduler(t)
	// Must not panic
	s.Stop()
}

func TestStop_Idempotent(t *testing.T) {
	s := newTestScheduler(t)
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	s.Stop()
	// Second call must not panic or block
	s.Stop()
}

// --- AddTask ---------------------------------------------------------------

func TestAddTask_HappyPath(t *testing.T) {
	s := newTestScheduler(t)

	task := runningTask("t1", "Test Task", "@every 1h", func() error { return nil })
	if err := s.AddTask(task); err != nil {
		t.Fatalf("AddTask: %v", err)
	}

	s.mu.RLock()
	_, ok := s.tasks["t1"]
	s.mu.RUnlock()
	if !ok {
		t.Error("task not stored after AddTask")
	}
}

func TestAddTask_MissingID_ReturnsError(t *testing.T) {
	s := newTestScheduler(t)
	err := s.AddTask(&Task{Schedule: "@hourly", Fn: func() error { return nil }})
	if err == nil {
		t.Error("expected error for missing task ID")
	}
}

func TestAddTask_MissingSchedule_ReturnsError(t *testing.T) {
	s := newTestScheduler(t)
	err := s.AddTask(&Task{ID: "t1", Fn: func() error { return nil }})
	if err == nil {
		t.Error("expected error for missing schedule")
	}
}

func TestAddTask_MissingFn_ReturnsError(t *testing.T) {
	s := newTestScheduler(t)
	err := s.AddTask(&Task{ID: "t1", Schedule: "@hourly"})
	if err == nil {
		t.Error("expected error for missing task function")
	}
}

func TestAddTask_DisabledTask_NotScheduled(t *testing.T) {
	s := newTestScheduler(t)
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	task := &Task{ID: "disabled", Schedule: "@hourly", Fn: func() error { return nil }, Enabled: false}
	if err := s.AddTask(task); err != nil {
		t.Fatalf("AddTask: %v", err)
	}

	s.mu.RLock()
	_, inJobs := s.jobs["disabled"]
	s.mu.RUnlock()
	if inJobs {
		t.Error("disabled task must not be added to gocron jobs")
	}
}

func TestAddTask_EnabledAfterStart_Scheduled(t *testing.T) {
	s := newTestScheduler(t)
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	task := runningTask("enabled-at-start", "Enabled", "@every 1h", func() error { return nil })
	if err := s.AddTask(task); err != nil {
		t.Fatalf("AddTask: %v", err)
	}

	s.mu.RLock()
	_, inJobs := s.jobs["enabled-at-start"]
	s.mu.RUnlock()
	if !inJobs {
		t.Error("enabled task must be added to gocron jobs when scheduler is running")
	}
}

// --- jobDefinition ---------------------------------------------------------

func TestJobDefinition_BuiltinAliases(t *testing.T) {
	aliases := []string{"@hourly", "@daily", "@weekly", "@monthly"}
	for _, a := range aliases {
		_, err := jobDefinition(a)
		if err != nil {
			t.Errorf("jobDefinition(%q): unexpected error %v", a, err)
		}
	}
}

func TestJobDefinition_EveryDuration_Valid(t *testing.T) {
	cases := []string{"@every 5m", "@every 1h", "@every 30s", "@every 24h"}
	for _, c := range cases {
		_, err := jobDefinition(c)
		if err != nil {
			t.Errorf("jobDefinition(%q): unexpected error %v", c, err)
		}
	}
}

func TestJobDefinition_EveryDuration_Invalid(t *testing.T) {
	_, err := jobDefinition("@every notaduration")
	if err == nil {
		t.Error("expected error for invalid @every duration")
	}
}

func TestJobDefinition_CronExpression(t *testing.T) {
	cases := []string{"0 * * * *", "*/5 * * * *", "0 0 * * 0"}
	for _, c := range cases {
		_, err := jobDefinition(c)
		if err != nil {
			t.Errorf("jobDefinition(%q): unexpected error %v", c, err)
		}
	}
}

// --- Status ----------------------------------------------------------------

func TestStatus_EmptyScheduler(t *testing.T) {
	s := newTestScheduler(t)
	st := s.Status()
	if len(st) != 0 {
		t.Errorf("Status: expected empty map, got %d entries", len(st))
	}
}

func TestStatus_ReturnsRegisteredTasks(t *testing.T) {
	s := newTestScheduler(t)

	tasks := []*Task{
		runningTask("a", "Alpha", "@every 1h", func() error { return nil }),
		runningTask("b", "Beta", "@every 2h", func() error { return nil }),
	}
	for _, task := range tasks {
		if err := s.AddTask(task); err != nil {
			t.Fatalf("AddTask(%s): %v", task.ID, err)
		}
	}

	st := s.Status()
	if len(st) != 2 {
		t.Errorf("Status: expected 2 entries, got %d", len(st))
	}
	for _, task := range tasks {
		entry, ok := st[task.ID]
		if !ok {
			t.Errorf("Status: missing entry for task %s", task.ID)
			continue
		}
		if entry.Name != task.Name {
			t.Errorf("Status[%s].Name = %q, want %q", task.ID, entry.Name, task.Name)
		}
		if entry.Schedule != task.Schedule {
			t.Errorf("Status[%s].Schedule = %q, want %q", task.ID, entry.Schedule, task.Schedule)
		}
		if entry.Enabled != task.Enabled {
			t.Errorf("Status[%s].Enabled = %v, want %v", task.ID, entry.Enabled, task.Enabled)
		}
	}
}

// --- GetTaskStates ---------------------------------------------------------

func TestGetTaskStates_NilDB_ReturnsNilNil(t *testing.T) {
	s := newTestScheduler(t)
	states, err := s.GetTaskStates()
	if err != nil {
		t.Errorf("GetTaskStates: unexpected error: %v", err)
	}
	if states != nil {
		t.Errorf("GetTaskStates: expected nil states, got %v", states)
	}
}

// --- EnableTask / DisableTask ----------------------------------------------

func TestEnableTask_UnknownID_ReturnsError(t *testing.T) {
	s := newTestScheduler(t)
	if err := s.EnableTask("nope"); err == nil {
		t.Error("expected error for unknown task ID")
	}
}

func TestDisableTask_UnknownID_ReturnsError(t *testing.T) {
	s := newTestScheduler(t)
	if err := s.DisableTask("nope"); err == nil {
		t.Error("expected error for unknown task ID")
	}
}

func TestEnableDisableTask_ToggleEnabled(t *testing.T) {
	s := newTestScheduler(t)

	task := &Task{ID: "tog", Name: "Toggle", Schedule: "@every 1h", Fn: func() error { return nil }, Enabled: false}
	if err := s.AddTask(task); err != nil {
		t.Fatalf("AddTask: %v", err)
	}

	if err := s.EnableTask("tog"); err != nil {
		t.Fatalf("EnableTask: %v", err)
	}
	s.mu.RLock()
	if !s.tasks["tog"].Enabled {
		t.Error("task should be enabled after EnableTask")
	}
	s.mu.RUnlock()

	if err := s.DisableTask("tog"); err != nil {
		t.Fatalf("DisableTask: %v", err)
	}
	s.mu.RLock()
	if s.tasks["tog"].Enabled {
		t.Error("task should be disabled after DisableTask")
	}
	s.mu.RUnlock()
}

func TestDisableTask_RemovesFromJobs(t *testing.T) {
	s := newTestScheduler(t)
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	task := runningTask("rem", "Remove Me", "@every 1h", func() error { return nil })
	if err := s.AddTask(task); err != nil {
		t.Fatalf("AddTask: %v", err)
	}

	s.mu.RLock()
	_, before := s.jobs["rem"]
	s.mu.RUnlock()
	if !before {
		t.Fatal("job should exist in jobs map after AddTask when scheduler is running")
	}

	if err := s.DisableTask("rem"); err != nil {
		t.Fatalf("DisableTask: %v", err)
	}

	s.mu.RLock()
	_, after := s.jobs["rem"]
	s.mu.RUnlock()
	if after {
		t.Error("job must be removed from jobs map after DisableTask")
	}
}

func TestEnableTask_AlreadyInJobs_DoesNotDuplicate(t *testing.T) {
	s := newTestScheduler(t)
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	task := runningTask("dup", "Dup", "@every 1h", func() error { return nil })
	if err := s.AddTask(task); err != nil {
		t.Fatalf("AddTask: %v", err)
	}

	// EnableTask on an already-enabled, already-scheduled task must not return an error
	if err := s.EnableTask("dup"); err != nil {
		t.Errorf("EnableTask on already-enabled task: %v", err)
	}
}

// --- RunNow ----------------------------------------------------------------

func TestRunNow_UnknownID_ReturnsError(t *testing.T) {
	s := newTestScheduler(t)
	if err := s.RunNow("unknown"); err == nil {
		t.Error("expected error for unknown task ID")
	}
}

func TestRunNow_ExecutesFnAsynchronously(t *testing.T) {
	s := newTestScheduler(t)

	var ran atomic.Bool
	done := make(chan struct{})
	task := runningTask("rn", "RunNow", "@every 1h", func() error {
		ran.Store(true)
		close(done)
		return nil
	})
	if err := s.AddTask(task); err != nil {
		t.Fatalf("AddTask: %v", err)
	}

	if err := s.RunNow("rn"); err != nil {
		t.Fatalf("RunNow: %v", err)
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("RunNow task did not execute within 3 seconds")
	}

	if !ran.Load() {
		t.Error("task function was not called")
	}
}

func TestRunNow_TaskReturnsError_DoesNotPanic(t *testing.T) {
	s := newTestScheduler(t)

	done := make(chan struct{})
	task := runningTask("fail", "Fail", "@every 1h", func() error {
		defer close(done)
		return errors.New("expected task error")
	})
	if err := s.AddTask(task); err != nil {
		t.Fatalf("AddTask: %v", err)
	}

	if err := s.RunNow("fail"); err != nil {
		t.Fatalf("RunNow: %v", err)
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("failing task did not execute within 3 seconds")
	}
}

func TestRunNow_TaskFails_InvokesOnFailure(t *testing.T) {
	s := newTestScheduler(t)

	done := make(chan struct{})
	var gotErr error
	var gotTaskName string
	s.OnFailure = func(task *Task, err error) {
		gotTaskName = task.Name
		gotErr = err
		close(done)
	}

	task := runningTask("fail-hook", "FailHook", "@every 1h", func() error {
		return errors.New("expected task error")
	})
	if err := s.AddTask(task); err != nil {
		t.Fatalf("AddTask: %v", err)
	}

	if err := s.RunNow("fail-hook"); err != nil {
		t.Fatalf("RunNow: %v", err)
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("OnFailure was not invoked within 3 seconds")
	}

	if gotTaskName != "FailHook" {
		t.Errorf("OnFailure task.Name = %q, want %q", gotTaskName, "FailHook")
	}
	if gotErr == nil || gotErr.Error() != "expected task error" {
		t.Errorf("OnFailure err = %v, want %q", gotErr, "expected task error")
	}
}

func TestRunNow_TaskSucceeds_DoesNotInvokeOnFailure(t *testing.T) {
	s := newTestScheduler(t)

	done := make(chan struct{})
	called := false
	s.OnFailure = func(task *Task, err error) {
		called = true
	}

	task := runningTask("ok-hook", "OKHook", "@every 1h", func() error {
		defer close(done)
		return nil
	})
	if err := s.AddTask(task); err != nil {
		t.Fatalf("AddTask: %v", err)
	}

	if err := s.RunNow("ok-hook"); err != nil {
		t.Fatalf("RunNow: %v", err)
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("task did not execute within 3 seconds")
	}
	// Give a brief moment in case OnFailure were (incorrectly) invoked async.
	time.Sleep(50 * time.Millisecond)

	if called {
		t.Error("OnFailure was invoked for a successful task run")
	}
}

// --- Concurrency -----------------------------------------------------------

func TestAddTask_ConcurrentCalls_NoPanic(t *testing.T) {
	s := newTestScheduler(t)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		id := i
		go func() {
			defer wg.Done()
			task := runningTask(
				time.Now().String()+string(rune('A'+id)),
				"concurrent",
				"@every 1h",
				func() error { return nil },
			)
			_ = s.AddTask(task)
		}()
	}
	wg.Wait()
}

func TestStatus_ConcurrentReads_NoPanic(t *testing.T) {
	s := newTestScheduler(t)
	if err := s.AddTask(runningTask("c", "C", "@every 1h", func() error { return nil })); err != nil {
		t.Fatalf("AddTask: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.Status()
		}()
	}
	wg.Wait()
}

// --- TaskState fields ------------------------------------------------------

func TestTaskState_Fields(t *testing.T) {
	now := time.Now()
	state := TaskState{
		ID:         "x",
		Name:       "X Task",
		Schedule:   "0 * * * *",
		LastRun:    &now,
		LastStatus: TaskStatusSuccess,
		LastError:  "",
		NextRun:    &now,
		RunCount:   5,
		FailCount:  1,
		Enabled:    true,
	}

	if state.LastStatus != TaskStatusSuccess {
		t.Errorf("LastStatus = %q, want %q", state.LastStatus, TaskStatusSuccess)
	}
	if state.RunCount != 5 {
		t.Errorf("RunCount = %d, want 5", state.RunCount)
	}
	if state.FailCount != 1 {
		t.Errorf("FailCount = %d, want 1", state.FailCount)
	}
}

// Confirm all TaskStatus constants have distinct non-empty values.
func TestTaskStatusConstants(t *testing.T) {
	statuses := []TaskStatus{TaskStatusSuccess, TaskStatusFailed, TaskStatusSkipped, TaskStatusRunning}
	seen := make(map[TaskStatus]bool)
	for _, st := range statuses {
		if st == "" {
			t.Errorf("TaskStatus constant must not be empty")
		}
		if seen[st] {
			t.Errorf("duplicate TaskStatus value %q", st)
		}
		seen[st] = true
	}
}
