package scheduler

import (
	"database/sql"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// openTestDB opens an in-memory SQLite DB and creates the scheduler schema.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	schema := []string{
		`CREATE TABLE IF NOT EXISTS scheduler_tasks (
			id          TEXT PRIMARY KEY,
			name        TEXT NOT NULL,
			enabled     INTEGER NOT NULL DEFAULT 1,
			schedule    TEXT NOT NULL,
			last_run    INTEGER,
			next_run    INTEGER,
			last_status TEXT,
			last_error  TEXT,
			run_count   INTEGER NOT NULL DEFAULT 0,
			fail_count  INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS scheduler_history (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			task_id     TEXT NOT NULL,
			started_at  INTEGER NOT NULL,
			finished_at INTEGER,
			status      TEXT NOT NULL,
			error       TEXT,
			duration_ms INTEGER
		)`,
	}
	for _, s := range schema {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("schema exec: %v", err)
		}
	}
	return db
}

// newDBScheduler creates a scheduler wired to an in-memory SQLite DB.
func newDBScheduler(t *testing.T) *Scheduler {
	t.Helper()
	db := openTestDB(t)
	s, err := NewScheduler(db, SchedulerRunConfig{
		Timezone:      "UTC",
		CatchUpWindow: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}
	t.Cleanup(s.Stop)
	return s
}

// --- saveTaskState ---

func TestSaveTaskState_InsertsRow(t *testing.T) {
	s := newDBScheduler(t)
	task := &Task{ID: "t1", Name: "Task One", Schedule: "@daily", Enabled: true}

	if err := s.saveTaskState(task); err != nil {
		t.Fatalf("saveTaskState: %v", err)
	}

	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM scheduler_tasks WHERE id = 't1'").Scan(&count); err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 row, got %d", count)
	}
}

func TestSaveTaskState_Upsert(t *testing.T) {
	s := newDBScheduler(t)
	task := &Task{ID: "t2", Name: "Original", Schedule: "@hourly", Enabled: true}

	if err := s.saveTaskState(task); err != nil {
		t.Fatalf("first save: %v", err)
	}

	task.Name = "Updated"
	if err := s.saveTaskState(task); err != nil {
		t.Fatalf("second save: %v", err)
	}

	var name string
	if err := s.db.QueryRow("SELECT name FROM scheduler_tasks WHERE id = 't2'").Scan(&name); err != nil {
		t.Fatalf("query: %v", err)
	}
	if name != "Updated" {
		t.Errorf("name = %q, want %q", name, "Updated")
	}
}

func TestSaveTaskState_NilDB_NoError(t *testing.T) {
	s, err := NewScheduler(nil, DefaultConfig())
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}
	defer s.Stop()
	task := &Task{ID: "t3", Name: "No DB Task", Schedule: "@daily", Enabled: true}
	if err := s.saveTaskState(task); err != nil {
		t.Errorf("saveTaskState with nil db: %v", err)
	}
}

// --- loadTaskStates ---

func TestLoadTaskStates_UpdatesEnabledFlag(t *testing.T) {
	s := newDBScheduler(t)

	task := &Task{ID: "load1", Name: "Load Test", Schedule: "@daily", Fn: func() error { return nil }, Enabled: true}
	s.tasks[task.ID] = task

	if _, err := s.db.Exec(
		`INSERT INTO scheduler_tasks (id, name, schedule, enabled) VALUES (?, ?, ?, ?)`,
		"load1", "Load Test", "@daily", 0,
	); err != nil {
		t.Fatalf("insert: %v", err)
	}

	if err := s.loadTaskStates(); err != nil {
		t.Fatalf("loadTaskStates: %v", err)
	}

	if s.tasks["load1"].Enabled {
		t.Error("expected Enabled=false after load, got true")
	}
}

func TestLoadTaskStates_EmptyTable_NoError(t *testing.T) {
	s := newDBScheduler(t)
	if err := s.loadTaskStates(); err != nil {
		t.Errorf("loadTaskStates on empty table: %v", err)
	}
}

// --- appendHistory ---

func TestAppendHistory_InsertsRecord(t *testing.T) {
	s := newDBScheduler(t)

	task := &Task{ID: "hist1", Name: "History Task", Schedule: "@daily", Enabled: true}
	if err := s.saveTaskState(task); err != nil {
		t.Fatalf("saveTaskState: %v", err)
	}

	s.appendHistory("hist1", time.Now(), TaskStatusSuccess, "", 42)

	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM scheduler_history WHERE task_id = 'hist1'").Scan(&count); err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 history row, got %d", count)
	}
}

func TestAppendHistory_WithError(t *testing.T) {
	s := newDBScheduler(t)

	task := &Task{ID: "hist2", Name: "Failing Task", Schedule: "@daily", Enabled: true}
	if err := s.saveTaskState(task); err != nil {
		t.Fatalf("saveTaskState: %v", err)
	}

	s.appendHistory("hist2", time.Now(), TaskStatusFailed, "something went wrong", 100)

	var errCol string
	if err := s.db.QueryRow("SELECT COALESCE(error,'') FROM scheduler_history WHERE task_id = 'hist2'").Scan(&errCol); err != nil {
		t.Fatalf("query: %v", err)
	}
	if errCol != "something went wrong" {
		t.Errorf("error = %q, want %q", errCol, "something went wrong")
	}
}

// --- updateTaskRun ---

func TestUpdateTaskRun_UpdatesRow(t *testing.T) {
	s := newDBScheduler(t)

	task := &Task{ID: "upd1", Name: "Update Run", Schedule: "@daily", Enabled: true}
	if err := s.saveTaskState(task); err != nil {
		t.Fatalf("saveTaskState: %v", err)
	}

	s.updateTaskRun("upd1", TaskStatusSuccess, "")

	var lastStatus string
	if err := s.db.QueryRow("SELECT COALESCE(last_status,'') FROM scheduler_tasks WHERE id = 'upd1'").Scan(&lastStatus); err != nil {
		t.Fatalf("query: %v", err)
	}
	if lastStatus != string(TaskStatusSuccess) {
		t.Errorf("last_status = %q, want %q", lastStatus, TaskStatusSuccess)
	}
}

func TestUpdateTaskRun_Failed(t *testing.T) {
	s := newDBScheduler(t)

	task := &Task{ID: "upd2", Name: "Fail Run", Schedule: "@daily", Enabled: true}
	if err := s.saveTaskState(task); err != nil {
		t.Fatalf("saveTaskState: %v", err)
	}

	s.updateTaskRun("upd2", TaskStatusFailed, "task error")

	var failCount int64
	if err := s.db.QueryRow("SELECT fail_count FROM scheduler_tasks WHERE id = 'upd2'").Scan(&failCount); err != nil {
		t.Fatalf("query: %v", err)
	}
	if failCount != 1 {
		t.Errorf("fail_count = %d, want 1", failCount)
	}
}

// --- GetTaskStates ---

func TestGetTaskStates_ReturnsInsertedRows(t *testing.T) {
	s := newDBScheduler(t)

	for _, task := range []*Task{
		{ID: "gs1", Name: "GS Task 1", Schedule: "@daily", Enabled: true},
		{ID: "gs2", Name: "GS Task 2", Schedule: "@hourly", Enabled: false},
	} {
		if err := s.saveTaskState(task); err != nil {
			t.Fatalf("saveTaskState %s: %v", task.ID, err)
		}
	}

	states, err := s.GetTaskStates()
	if err != nil {
		t.Fatalf("GetTaskStates: %v", err)
	}
	if len(states) != 2 {
		t.Errorf("len(states) = %d, want 2", len(states))
	}
}

func TestGetTaskStates_NilDB_ReturnsNil(t *testing.T) {
	s, err := NewScheduler(nil, DefaultConfig())
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}
	defer s.Stop()
	states, err := s.GetTaskStates()
	if err != nil {
		t.Errorf("GetTaskStates: %v", err)
	}
	if states != nil {
		t.Errorf("expected nil states, got %v", states)
	}
}

func TestGetTaskStates_PopulatesLastRunAndStatus(t *testing.T) {
	s := newDBScheduler(t)

	task := &Task{ID: "gs3", Name: "Run History", Schedule: "@daily", Enabled: true}
	if err := s.saveTaskState(task); err != nil {
		t.Fatalf("saveTaskState: %v", err)
	}
	s.updateTaskRun("gs3", TaskStatusSuccess, "")

	states, err := s.GetTaskStates()
	if err != nil {
		t.Fatalf("GetTaskStates: %v", err)
	}
	if len(states) != 1 {
		t.Fatalf("len(states) = %d, want 1", len(states))
	}
	if states[0].LastStatus != TaskStatusSuccess {
		t.Errorf("LastStatus = %q, want %q", states[0].LastStatus, TaskStatusSuccess)
	}
}

// --- checkMissedTasks ---

func TestCheckMissedTasks_RunsMissedTask(t *testing.T) {
	s := newDBScheduler(t)

	var ran bool
	task := &Task{
		ID: "missed1", Name: "Missed Task", Schedule: "@daily", Enabled: true,
		Fn: func() error { ran = true; return nil },
	}
	s.tasks[task.ID] = task

	// Insert a row with last_run far in the past (beyond catch-up window).
	past := time.Now().Add(-2 * s.CatchUpWindow).Unix()
	if _, err := s.db.Exec(
		`INSERT INTO scheduler_tasks (id, name, schedule, enabled, last_run) VALUES (?, ?, ?, ?, ?)`,
		"missed1", "Missed Task", "@daily", 1, past,
	); err != nil {
		t.Fatalf("insert: %v", err)
	}

	s.checkMissedTasks()

	// Allow async goroutine to complete.
	deadline := time.Now().Add(2 * time.Second)
	for !ran && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !ran {
		t.Error("expected missed task to run, but it did not")
	}
}

func TestCheckMissedTasks_NilDB_NoOp(t *testing.T) {
	s, err := NewScheduler(nil, DefaultConfig())
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}
	defer s.Stop()
	s.checkMissedTasks()
}

// --- Start with DB ---

func TestStart_LoadsStateFromDB(t *testing.T) {
	s := newDBScheduler(t)

	task := &Task{
		ID: "start1", Name: "Start Task", Schedule: "@daily",
		Fn: func() error { return nil }, Enabled: true,
	}

	// Bypass AddTask (which upserts enabled=true) so the DB row remains disabled.
	s.tasks[task.ID] = task

	if _, err := s.db.Exec(
		`INSERT INTO scheduler_tasks (id, name, schedule, enabled) VALUES (?, ?, ?, ?)`,
		"start1", "Start Task", "@daily", 0,
	); err != nil {
		t.Fatalf("insert: %v", err)
	}

	// Start() calls loadTaskStates() which should set task.Enabled = false.
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if s.tasks["start1"].Enabled {
		t.Error("expected task disabled after loading DB state")
	}
}
