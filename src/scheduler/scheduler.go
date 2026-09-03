package scheduler

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	gocron "github.com/go-co-op/gocron/v2"
)

// TaskStatus represents the status of a task run
type TaskStatus string

const (
	TaskStatusSuccess TaskStatus = "success"
	TaskStatusFailed  TaskStatus = "failed"
	TaskStatusSkipped TaskStatus = "skipped"
	TaskStatusRunning TaskStatus = "running"
)

// TaskState represents the persistent state of a scheduled task.
// Field names match the AI.md PART 10 schema: id / name (not task_id / task_name).
type TaskState struct {
	ID         string
	Name       string
	Schedule   string
	LastRun    *time.Time
	LastStatus TaskStatus
	LastError  string
	NextRun    *time.Time
	RunCount   int64
	FailCount  int64
	Enabled    bool
}

// Task represents a scheduled task
type Task struct {
	ID       string
	Name     string
	Schedule string
	Fn       func() error
	Enabled  bool
	// IsGlobal indicates this task runs on ONE node only (cluster mode)
	IsGlobal bool
}

// Scheduler manages periodic tasks using go-co-op/gocron/v2 per AI.md PART 18.
type Scheduler struct {
	sched gocron.Scheduler
	tasks map[string]*Task
	// jobs stores live gocron job handles for NextRun()/LastRun() access
	jobs          map[string]gocron.Job
	db            *sql.DB
	timezone      *time.Location
	CatchUpWindow time.Duration
	mu            sync.RWMutex
	running       bool
	// OnFailure, if set, is invoked after a task run fails (after the
	// history/state update). Kept as a caller-supplied hook rather than a
	// direct dependency so the scheduler package stays decoupled from the
	// notification subsystem (AI.md PART 17/18).
	OnFailure func(task *Task, err error)
}

// SchedulerRunConfig holds scheduler configuration
type SchedulerRunConfig struct {
	Timezone      string
	CatchUpWindow time.Duration
}

// DefaultConfig returns default scheduler configuration
func DefaultConfig() SchedulerRunConfig {
	return SchedulerRunConfig{
		Timezone:      "America/New_York",
		CatchUpWindow: time.Hour,
	}
}

// NewScheduler creates a new scheduler with the given configuration.
func NewScheduler(db *sql.DB, cfg SchedulerRunConfig) (*Scheduler, error) {
	loc, err := time.LoadLocation(cfg.Timezone)
	if err != nil {
		// Fall back to UTC if timezone not found
		loc = time.UTC
		log.Printf("Scheduler: timezone %q not found, using UTC", cfg.Timezone)
	}

	catchUp := cfg.CatchUpWindow
	if catchUp == 0 {
		catchUp = time.Hour
	}

	sched, err := gocron.NewScheduler(gocron.WithLocation(loc))
	if err != nil {
		return nil, fmt.Errorf("failed to create scheduler: %w", err)
	}

	return &Scheduler{
		sched:         sched,
		tasks:         make(map[string]*Task),
		jobs:          make(map[string]gocron.Job),
		db:            db,
		timezone:      loc,
		CatchUpWindow: catchUp,
	}, nil
}

// jobDefinition converts a schedule string to a gocron.JobDefinition.
// Supports: cron format, @hourly, @daily, @weekly, @monthly, @every Xm/Xh
func jobDefinition(schedule string) (gocron.JobDefinition, error) {
	switch schedule {
	case "@hourly":
		return gocron.CronJob("0 * * * *", false), nil
	case "@daily":
		return gocron.CronJob("0 0 * * *", false), nil
	case "@weekly":
		return gocron.CronJob("0 0 * * 0", false), nil
	case "@monthly":
		return gocron.CronJob("0 0 1 * *", false), nil
	}
	if strings.HasPrefix(schedule, "@every ") {
		dur, err := time.ParseDuration(strings.TrimPrefix(schedule, "@every "))
		if err != nil {
			return nil, fmt.Errorf("invalid @every duration %q: %w", schedule, err)
		}
		return gocron.DurationJob(dur), nil
	}
	return gocron.CronJob(schedule, false), nil
}

// scheduleTask registers a task with the gocron scheduler
func (s *Scheduler) scheduleTask(task *Task) error {
	def, err := jobDefinition(task.Schedule)
	if err != nil {
		return err
	}

	// Capture task pointer to avoid loop-variable capture issues
	t := task
	job, err := s.sched.NewJob(
		def,
		gocron.NewTask(func() { s.runTask(t) }),
		gocron.WithName(task.ID),
	)
	if err != nil {
		return fmt.Errorf("failed to schedule task %q: %w", task.ID, err)
	}

	s.jobs[task.ID] = job
	return nil
}

// AddTask adds a new scheduled task.
// Schedule supports: cron format, @hourly, @daily, @weekly, @monthly, @every Xm/Xh
func (s *Scheduler) AddTask(task *Task) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if task.ID == "" {
		return fmt.Errorf("task ID is required")
	}
	if task.Schedule == "" {
		return fmt.Errorf("task schedule is required")
	}
	if task.Fn == nil {
		return fmt.Errorf("task function is required")
	}

	// Store task
	s.tasks[task.ID] = task

	// If scheduler is running, add to gocron immediately
	if s.running && task.Enabled {
		if err := s.scheduleTask(task); err != nil {
			return err
		}
	}

	// Save state to database
	if s.db != nil {
		if err := s.saveTaskState(task); err != nil {
			log.Printf("Scheduler: failed to save task state: %v", err)
		}
	}

	log.Printf("Scheduler: Added task '%s' (%s) with schedule '%s'", task.Name, task.ID, task.Schedule)
	return nil
}

// saveTaskState saves or updates task state in database
func (s *Scheduler) saveTaskState(task *Task) error {
	if s.db == nil {
		return nil
	}

	query := `
INSERT INTO scheduler_tasks (id, name, schedule, enabled)
VALUES (?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
    name     = excluded.name,
    schedule = excluded.schedule,
    enabled  = excluded.enabled
`
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := s.db.ExecContext(ctx, query, task.ID, task.Name, task.Schedule, task.Enabled)
	return err
}

// Start begins the scheduler
func (s *Scheduler) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("scheduler already running")
	}

	// Load task states from database
	if s.db != nil {
		if err := s.loadTaskStates(); err != nil {
			log.Printf("Scheduler: failed to load task states: %v", err)
		}

		// Check for missed tasks within catch-up window
		s.checkMissedTasks()
	}

	// Schedule all enabled tasks
	for _, task := range s.tasks {
		if task.Enabled {
			if err := s.scheduleTask(task); err != nil {
				log.Printf("Scheduler: failed to schedule task '%s': %v", task.Name, err)
			}
		}
	}

	// gocron.Start() is non-blocking
	s.sched.Start()
	s.running = true

	log.Println("Scheduler: Started")
	return nil
}

// Stop stops the scheduler and waits for running jobs to complete.
func (s *Scheduler) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return
	}

	// gocron Shutdown blocks until all running jobs complete
	if err := s.sched.Shutdown(); err != nil {
		log.Printf("Scheduler: shutdown error: %v", err)
	}

	s.running = false
	log.Println("Scheduler: Stopped")
}

// loadTaskStates loads task states from database
func (s *Scheduler) loadTaskStates() error {
	query := `
SELECT id, last_run, last_status, run_count, fail_count, enabled
FROM scheduler_tasks
`
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var taskID string
		var lastRun sql.NullInt64
		var lastStatus sql.NullString
		var runCount, failCount int64
		var enabled bool

		if err := rows.Scan(&taskID, &lastRun, &lastStatus, &runCount, &failCount, &enabled); err != nil {
			continue
		}

		// Update task if we have it
		if task, ok := s.tasks[taskID]; ok {
			task.Enabled = enabled
		}
	}

	return rows.Err()
}

// checkMissedTasks checks for tasks that should have run while the app was down
func (s *Scheduler) checkMissedTasks() {
	if s.db == nil {
		return
	}

	cutoff := time.Now().Add(-s.CatchUpWindow).Unix()

	query := `
SELECT id, last_run, schedule
FROM scheduler_tasks
WHERE enabled = 1 AND (last_run IS NULL OR last_run < ?)
`
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, query, cutoff)
	if err != nil {
		log.Printf("Scheduler: failed to check missed tasks: %v", err)
		return
	}
	defer rows.Close()

	var missedTasks []string
	for rows.Next() {
		var taskID string
		var lastRun sql.NullInt64
		var schedule string

		if err := rows.Scan(&taskID, &lastRun, &schedule); err != nil {
			continue
		}

		// Check if task should have run within catch-up window
		if task, ok := s.tasks[taskID]; ok {
			missedTasks = append(missedTasks, task.ID)
		}
	}

	// Run missed tasks
	for _, taskID := range missedTasks {
		if task, ok := s.tasks[taskID]; ok {
			log.Printf("Scheduler: Running missed task '%s'", task.Name)
			go s.runTask(task)
		}
	}
}

// runTask executes a task and records the result in scheduler_history per AI.md PART 10.
func (s *Scheduler) runTask(task *Task) {
	startTime := time.Now()
	log.Printf("Scheduler: Running task '%s' (%s)", task.Name, task.ID)

	// Record Prometheus metrics for observability (AI.md PART 18)
	RecordTaskStart(task.ID)

	// Execute the task. A recover here keeps one misbehaving task from
	// crashing the whole process — runTask is invoked both from gocron's
	// own goroutines and directly via `go s.runTask(task)` in
	// checkMissedTasks, and an unrecovered panic on either path is fatal.
	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("panic: %v", r)
				log.Printf("Scheduler: Task '%s' panicked: %v\n%s", task.Name, r, debug.Stack())
			}
		}()
		err = task.Fn()
	}()

	duration := time.Since(startTime)
	durationMs := duration.Milliseconds()
	RecordTaskEnd(task.ID, duration, err)

	// Determine status
	status := TaskStatusSuccess
	errMsg := ""
	if err != nil {
		status = TaskStatusFailed
		errMsg = err.Error()
		log.Printf("Scheduler: Task '%s' failed: %v", task.Name, err)
	} else {
		log.Printf("Scheduler: Task '%s' completed successfully (took %v)", task.Name, time.Since(startTime))
	}

	if s.db != nil {
		// Update the task summary row
		s.updateTaskRun(task.ID, status, errMsg)
		// Append a row to scheduler_history (AI.md PART 10)
		s.appendHistory(task.ID, startTime, status, errMsg, durationMs)
	}

	if status == TaskStatusFailed && s.OnFailure != nil {
		s.OnFailure(task, err)
	}
}

// appendHistory inserts a run record into scheduler_history.
func (s *Scheduler) appendHistory(taskID string, startedAt time.Time, status TaskStatus, errMsg string, durationMs int64) {
	var errArg interface{}
	if errMsg != "" {
		errArg = errMsg
	}
	query := `
INSERT INTO scheduler_history (task_id, started_at, finished_at, status, error, duration_ms)
VALUES (?, ?, strftime('%s', 'now'), ?, ?, ?)
`
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := s.db.ExecContext(ctx, query, taskID, startedAt.Unix(), string(status), errArg, durationMs); err != nil {
		log.Printf("Scheduler: failed to append history for task %s: %v", taskID, err)
	}
}

// updateTaskRun updates the task run status in database
func (s *Scheduler) updateTaskRun(taskID string, status TaskStatus, errMsg string) {
	var query string
	var args []interface{}

	if status == TaskStatusSuccess {
		query = `
UPDATE scheduler_tasks SET
    last_run    = strftime('%s', 'now'),
    last_status = ?,
    last_error  = NULL,
    run_count   = run_count + 1
WHERE id = ?
`
		args = []interface{}{status, taskID}
	} else {
		query = `
UPDATE scheduler_tasks SET
    last_run    = strftime('%s', 'now'),
    last_status = ?,
    last_error  = ?,
    fail_count  = fail_count + 1
WHERE id = ?
`
		args = []interface{}{status, errMsg, taskID}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := s.db.ExecContext(ctx, query, args...); err != nil {
		log.Printf("Scheduler: failed to update task run state: %v", err)
	}
}

// EnableTask enables a task
func (s *Scheduler) EnableTask(taskID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	task, ok := s.tasks[taskID]
	if !ok {
		return fmt.Errorf("task not found: %s", taskID)
	}

	task.Enabled = true

	// Add to gocron if scheduler is running
	if s.running {
		if _, exists := s.jobs[taskID]; !exists {
			if err := s.scheduleTask(task); err != nil {
				return err
			}
		}
	}

	// Update database (best-effort; in-memory task state is authoritative)
	if s.db != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.db.ExecContext(ctx, "UPDATE scheduler_tasks SET enabled = 1 WHERE id = ?", taskID) //nolint:errcheck
	}

	return nil
}

// DisableTask disables a task
func (s *Scheduler) DisableTask(taskID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	task, ok := s.tasks[taskID]
	if !ok {
		return fmt.Errorf("task not found: %s", taskID)
	}

	task.Enabled = false

	// Remove from gocron
	if job, exists := s.jobs[taskID]; exists {
		if err := s.sched.RemoveJob(job.ID()); err != nil {
			log.Printf("Scheduler: failed to remove job %s: %v", taskID, err)
		}
		delete(s.jobs, taskID)
	}

	// Update database (best-effort; in-memory task state is authoritative)
	if s.db != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.db.ExecContext(ctx, "UPDATE scheduler_tasks SET enabled = 0 WHERE id = ?", taskID) //nolint:errcheck
	}

	return nil
}

// RunNow runs a task immediately in a goroutine
func (s *Scheduler) RunNow(taskID string) error {
	s.mu.RLock()
	task, ok := s.tasks[taskID]
	s.mu.RUnlock()

	if !ok {
		return fmt.Errorf("task not found: %s", taskID)
	}

	go s.runTask(task)
	return nil
}

// Status returns a map of task ID to TaskState for all registered tasks.
// Populates NextRun and LastRun from live gocron job handles per AI.md PART 18.
func (s *Scheduler) Status() map[string]TaskState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make(map[string]TaskState, len(s.tasks))
	for id, task := range s.tasks {
		state := TaskState{
			ID:       task.ID,
			Name:     task.Name,
			Schedule: task.Schedule,
			Enabled:  task.Enabled,
		}
		if job, ok := s.jobs[id]; ok {
			if next, err := job.NextRun(); err == nil && !next.IsZero() {
				state.NextRun = &next
			}
			if last, err := job.LastRunStartedAt(); err == nil && !last.IsZero() {
				state.LastRun = &last
			}
		}
		out[id] = state
	}
	return out
}

// GetTaskStates returns the state of all tasks from the database
func (s *Scheduler) GetTaskStates() ([]TaskState, error) {
	if s.db == nil {
		return nil, nil
	}

	query := `
SELECT id, name, schedule, last_run, last_status, last_error,
       next_run, run_count, fail_count, enabled
FROM scheduler_tasks
ORDER BY name
`
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var states []TaskState
	for rows.Next() {
		var state TaskState
		var lastRun, nextRun sql.NullInt64
		var lastStatus, lastError sql.NullString

		err := rows.Scan(
			&state.ID,
			&state.Name,
			&state.Schedule,
			&lastRun,
			&lastStatus,
			&lastError,
			&nextRun,
			&state.RunCount,
			&state.FailCount,
			&state.Enabled,
		)
		if err != nil {
			continue
		}

		if lastRun.Valid {
			t := time.Unix(lastRun.Int64, 0)
			state.LastRun = &t
		}
		if lastStatus.Valid {
			state.LastStatus = TaskStatus(lastStatus.String)
		}
		if lastError.Valid {
			state.LastError = lastError.String
		}
		if nextRun.Valid {
			t := time.Unix(nextRun.Int64, 0)
			state.NextRun = &t
		}

		states = append(states, state)
	}

	return states, rows.Err()
}
