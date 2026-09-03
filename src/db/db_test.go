package db

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/apimgr/ipgaze/src/config"
)

func TestNewDB_SQLite(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &config.DatabaseConfig{
		Driver: "sqlite",
	}

	db, err := NewDB(cfg, tmpDir)
	if err != nil {
		t.Fatalf("NewDB() error = %v", err)
	}
	defer db.Close()

	// Verify the database file was created directly under the passed dbDir
	// (NewDB no longer appends a "db" subdirectory — callers pass the
	// already-resolved sqlite directory, e.g. paths.Directories.DB).
	dbPath := filepath.Join(tmpDir, "server.db")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Errorf("expected database file at %s", dbPath)
	}

	// Verify we can query the database
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").Scan(&count)
	if err != nil {
		t.Errorf("failed to query database: %v", err)
	}
	// Schema should have created at least one table
	if count == 0 {
		t.Error("expected at least one table after schema migration")
	}
}

func TestNewDB_SQLiteAliases(t *testing.T) {
	// Test that sqlite2 and sqlite3 aliases are normalized to sqlite
	for _, alias := range []string{"sqlite2", "sqlite3"} {
		t.Run(alias, func(t *testing.T) {
			tmpDir := t.TempDir()
			cfg := &config.DatabaseConfig{
				Driver: alias,
			}

			db, err := NewDB(cfg, tmpDir)
			if err != nil {
				t.Fatalf("NewDB() with driver %q error = %v", alias, err)
			}
			db.Close()
		})
	}
}

func TestNewDB_UnsupportedDriver(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := &config.DatabaseConfig{
		Driver: "postgres",
	}

	_, err := NewDB(cfg, tmpDir)
	if err == nil {
		t.Error("expected error for unsupported driver")
	}
}

func TestNewDB_LibSQLMissingURL(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := &config.DatabaseConfig{
		Driver: "libsql",
		URL:    "", // missing URL
	}

	_, err := NewDB(cfg, tmpDir)
	if err == nil {
		t.Error("expected error for libsql with missing URL")
	}
}

func TestApplyPool_HonorsConfiguredLimits(t *testing.T) {
	tmpDir := t.TempDir()
	sqlDB, err := OpenSQLite(filepath.Join(tmpDir, "pool.db"))
	if err != nil {
		t.Fatalf("OpenSQLite() error = %v", err)
	}
	defer sqlDB.Close()

	pool := config.DatabasePoolConfig{
		MaxOpen:     25,
		MaxIdle:     5,
		MaxLifetime: "2m",
		MaxIdleTime: "30s",
	}
	applyPool(sqlDB, pool, false)

	stats := sqlDB.Stats()
	if stats.MaxOpenConnections != 25 {
		t.Errorf("MaxOpenConnections = %d, want 25", stats.MaxOpenConnections)
	}
}

func TestApplyPool_SQLiteStaysSingleWriter(t *testing.T) {
	tmpDir := t.TempDir()
	sqlDB, err := OpenSQLite(filepath.Join(tmpDir, "pool.db"))
	if err != nil {
		t.Fatalf("OpenSQLite() error = %v", err)
	}
	defer sqlDB.Close()

	applyPool(sqlDB, config.DatabasePoolConfig{MaxOpen: 25, MaxIdle: 5}, true)

	if got := sqlDB.Stats().MaxOpenConnections; got != 1 {
		t.Errorf("MaxOpenConnections for sqlite = %d, want 1", got)
	}
}

func TestApplyPool_ZeroValuesUseDefaults(t *testing.T) {
	tmpDir := t.TempDir()
	sqlDB, err := OpenSQLite(filepath.Join(tmpDir, "pool.db"))
	if err != nil {
		t.Fatalf("OpenSQLite() error = %v", err)
	}
	defer sqlDB.Close()

	applyPool(sqlDB, config.DatabasePoolConfig{}, false)

	want := config.DefaultDatabasePoolConfig().MaxOpen
	if got := sqlDB.Stats().MaxOpenConnections; got != want {
		t.Errorf("MaxOpenConnections = %d, want the default %d", got, want)
	}
}
