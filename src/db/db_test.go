package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/apimgr/ipgaze/src/config"
)

func TestSQLiteConcurrentReadersAndWriters(t *testing.T) {
	store, err := OpenSQLite(filepath.Join(t.TempDir(), "concurrent.db"))
	if err != nil {
		t.Fatalf("open SQLite store: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("close SQLite store: %v", err)
		}
	})
	if err := store.Write(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.Exec(`CREATE TABLE concurrency_probe (id INTEGER PRIMARY KEY, value INTEGER NOT NULL)`)
		return err
	}); err != nil {
		t.Fatalf("create probe table: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	var wg sync.WaitGroup
	var failures sync.Map
	for writer := 0; writer < 20; writer++ {
		wg.Add(1)
		go func(writer int) {
			defer wg.Done()
			for iteration := 0; time.Now().Before(deadline); iteration++ {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				err := store.Write(ctx, func(tx *sql.Tx) error {
					_, err := tx.ExecContext(ctx, `INSERT INTO concurrency_probe(value) VALUES(?)`, writer+iteration)
					return err
				})
				cancel()
				if err != nil {
					failures.Store(err.Error(), struct{}{})
					return
				}
			}
		}(writer)
	}
	for reader := 0; reader < 20; reader++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				var count int64
				if err := store.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM concurrency_probe`).Scan(&count); err != nil {
					failures.Store(err.Error(), struct{}{})
					return
				}
			}
		}()
	}
	wg.Wait()
	failures.Range(func(key, _ any) bool {
		if strings.Contains(strings.ToLower(fmt.Sprint(key)), "locked") {
			t.Errorf("concurrency operation returned locked error: %s", key)
		} else {
			t.Errorf("concurrency operation failed: %s", key)
		}
		return true
	})
}

func TestNewDB_SQLite(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &config.DatabaseConfig{
		Driver: "sqlite",
	}

	db, err := NewDB(cfg, tmpDir)
	if err != nil {
		t.Fatalf("NewDB() error = %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	})

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

func TestRemoteStoreUsageAndStatsUseSharedHandleOnce(t *testing.T) {
	handle, err := openSQLiteDB(":memory:")
	if err != nil {
		t.Fatalf("open remote test handle: %v", err)
	}
	if _, err := handle.Exec(`CREATE TABLE owners(id TEXT PRIMARY KEY,last_seen_at INTEGER); CREATE TABLE api_tokens(id TEXT PRIMARY KEY,last_used_at INTEGER)`); err != nil {
		t.Fatalf("create usage tables: %v", err)
	}
	if _, err := handle.Exec(`INSERT INTO owners(id,last_seen_at) VALUES('owner',0); INSERT INTO api_tokens(id,last_used_at) VALUES('token',0)`); err != nil {
		t.Fatalf("seed usage tables: %v", err)
	}
	store := newRemoteStore(handle, config.DefaultDatabasePoolConfig())
	t.Cleanup(func() { _ = store.Close() })
	store.MarkOwnerUsage("token", "owner", time.Unix(120, 0))
	if err := store.FlushHotCounters(context.Background()); err != nil {
		t.Fatalf("flush remote usage: %v", err)
	}
	var tokenUsed, ownerSeen int64
	if err := handle.QueryRow(`SELECT last_used_at FROM api_tokens WHERE id='token'`).Scan(&tokenUsed); err != nil {
		t.Fatal(err)
	}
	if err := handle.QueryRow(`SELECT last_seen_at FROM owners WHERE id='owner'`).Scan(&ownerSeen); err != nil {
		t.Fatal(err)
	}
	if tokenUsed != 120 || ownerSeen != 120 {
		t.Fatalf("flushed usage = token %d, owner %d; want 120", tokenUsed, ownerSeen)
	}
	if got, want := store.Stats().MaxOpenConnections, handle.Stats().MaxOpenConnections; got != want {
		t.Fatalf("remote Stats MaxOpenConnections = %d, want %d (shared pool counted once)", got, want)
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
			if err := db.Close(); err != nil {
				t.Errorf("close database: %v", err)
			}
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
	t.Cleanup(func() {
		if err := sqlDB.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	})

	pool := config.DatabasePoolConfig{
		MaxOpen:     25,
		MaxIdle:     5,
		MaxLifetime: "2m",
		MaxIdleTime: "30s",
	}
	applyPool(sqlDB.readDB, pool, false)

	stats := sqlDB.readDB.Stats()
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
	t.Cleanup(func() {
		if err := sqlDB.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	})

	if got := sqlDB.writeDB.Stats().MaxOpenConnections; got != 1 {
		t.Errorf("MaxOpenConnections for sqlite = %d, want 1", got)
	}
	if got := sqlDB.readDB.Stats().MaxOpenConnections; got <= 1 {
		t.Errorf("MaxOpenConnections for sqlite reader = %d, want a reader pool", got)
	}
}

func TestApplyPool_ZeroValuesUseDefaults(t *testing.T) {
	tmpDir := t.TempDir()
	sqlDB, err := OpenSQLite(filepath.Join(tmpDir, "pool.db"))
	if err != nil {
		t.Fatalf("OpenSQLite() error = %v", err)
	}
	t.Cleanup(func() {
		if err := sqlDB.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	})

	applyPool(sqlDB.readDB, config.DatabasePoolConfig{}, false)

	want := config.DefaultDatabasePoolConfig().MaxOpen
	if got := sqlDB.readDB.Stats().MaxOpenConnections; got != want {
		t.Errorf("MaxOpenConnections = %d, want the default %d", got, want)
	}
}
