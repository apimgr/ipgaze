package db

import (
	"testing"

	"github.com/apimgr/ipgaze/src/config"
)

// TestNewDB_SQLitePragmaEffect guards against a regression where NewDB's
// sqlite DSN used mattn/go-sqlite3 query-parameter syntax
// ("?_journal=WAL&_busy_timeout=...&_foreign_keys=..."), which
// modernc.org/sqlite silently ignores rather than rejecting — so the
// connection opened successfully but WAL/foreign-key/busy-timeout were
// never actually applied. NewDB now sets them via explicit PRAGMA
// statements after opening; this test asserts the pragmas actually took
// effect, not just that NewDB() returned no error.
func TestNewDB_SQLitePragmaEffect(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := &config.DatabaseConfig{Driver: "sqlite"}

	sqlDB, err := NewDB(cfg, tmpDir)
	if err != nil {
		t.Fatalf("NewDB() error = %v", err)
	}
	defer sqlDB.Close()

	var journalMode string
	if err := sqlDB.QueryRow("PRAGMA journal_mode").Scan(&journalMode); err != nil {
		t.Fatalf("PRAGMA journal_mode: %v", err)
	}
	if journalMode != "wal" {
		t.Errorf("journal_mode = %q, want %q", journalMode, "wal")
	}

	var foreignKeys int
	if err := sqlDB.QueryRow("PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
		t.Fatalf("PRAGMA foreign_keys: %v", err)
	}
	if foreignKeys != 1 {
		t.Errorf("foreign_keys = %d, want 1", foreignKeys)
	}

	var busyTimeout int
	if err := sqlDB.QueryRow("PRAGMA busy_timeout").Scan(&busyTimeout); err != nil {
		t.Fatalf("PRAGMA busy_timeout: %v", err)
	}
	if busyTimeout != 5000 {
		t.Errorf("busy_timeout = %d, want 5000", busyTimeout)
	}
}
