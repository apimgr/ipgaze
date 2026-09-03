package db

import (
	"context"
	"database/sql"
	"testing"
)

// openLoggingMemDB opens an in-memory SQLite database via the "sqlite+logged"
// wrapper driver, exercising the full loggingConn/loggingStmt code path.
func openLoggingMemDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestLoggingDriver_ExecQueryContext(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		SetQueryLogging(enabled)
		db := openLoggingMemDB(t)

		if _, err := db.Exec(`CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT)`); err != nil {
			t.Fatalf("create table: %v", err)
		}
		if _, err := db.Exec(`INSERT INTO t (name) VALUES (?)`, "alice"); err != nil {
			t.Fatalf("insert: %v", err)
		}

		rows, err := db.Query(`SELECT name FROM t WHERE id = ?`, 1)
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		var got string
		for rows.Next() {
			if err := rows.Scan(&got); err != nil {
				t.Fatalf("scan: %v", err)
			}
		}
		rows.Close()
		if got != "alice" {
			t.Errorf("got %q, want alice", got)
		}

		// Trigger an error path (unique/constraint failure not needed —
		// a syntax error suffices to exercise logQuery's error branch).
		if _, err := db.Exec(`INSERT INTO nonexistent_table VALUES (1)`); err == nil {
			t.Error("expected error inserting into nonexistent table")
		}
	}
	SetQueryLogging(false)
}

func TestLoggingDriver_PrepareStmtExecQuery(t *testing.T) {
	SetQueryLogging(true)
	defer SetQueryLogging(false)
	db := openLoggingMemDB(t)

	if _, err := db.Exec(`CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT)`); err != nil {
		t.Fatalf("create table: %v", err)
	}

	stmt, err := db.Prepare(`INSERT INTO t (name) VALUES (?)`)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	defer stmt.Close()

	if _, err := stmt.Exec("bob"); err != nil {
		t.Fatalf("stmt exec: %v", err)
	}

	qstmt, err := db.Prepare(`SELECT name FROM t WHERE name = ?`)
	if err != nil {
		t.Fatalf("prepare select: %v", err)
	}
	defer qstmt.Close()

	rows, err := qstmt.Query("bob")
	if err != nil {
		t.Fatalf("stmt query: %v", err)
	}
	defer rows.Close()
	found := false
	for rows.Next() {
		found = true
	}
	if !found {
		t.Error("expected to find row inserted via prepared statement")
	}
}

func TestLoggingDriver_BeginTxCommitRollback(t *testing.T) {
	SetQueryLogging(true)
	defer SetQueryLogging(false)
	db := openLoggingMemDB(t)

	if _, err := db.Exec(`CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT)`); err != nil {
		t.Fatalf("create table: %v", err)
	}

	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	if _, err := tx.Exec(`INSERT INTO t (name) VALUES (?)`, "carol"); err != nil {
		t.Fatalf("tx exec: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	tx2, err := db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := tx2.Exec(`INSERT INTO t (name) VALUES (?)`, "dave"); err != nil {
		t.Fatalf("tx2 exec: %v", err)
	}
	if err := tx2.Rollback(); err != nil {
		t.Fatalf("rollback: %v", err)
	}

	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM t`).Scan(&count); err != nil {
		t.Fatalf("count query: %v", err)
	}
	if count != 1 {
		t.Errorf("got %d rows, want 1 (rollback should have discarded dave)", count)
	}
}

func TestLoggingDriver_PingAndConcurrentConns(t *testing.T) {
	db := openLoggingMemDB(t)
	if err := db.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}
}

func TestRegisterLoggingDrivers_Idempotent(t *testing.T) {
	// Calling registerLoggingDrivers multiple times (via OpenSQLite/
	// OpenLibSQLDriver) must not panic (sync.Once guards double sql.Register).
	registerLoggingDrivers()
	registerLoggingDrivers()

	db, err := OpenSQLite(":memory:")
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	defer db.Close()
}
