// Package db provides database initialization and connection management for ipgaze.
// Per AI.md PART 10: default driver is sqlite via modernc.org/sqlite (CGO_ENABLED=0 safe).
// Alternate driver is libsql (Turso/libSQL remote — tursodatabase/libsql-client-go).
package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/apimgr/ipgaze/src/config"
)

// applyPool configures the database/sql connection pool from the AI.md PART 10
// "Connection Pooling" settings. The pool block is documented as applying to
// libsql/remote only — SQLite is single-writer — so a SQLite handle keeps one
// open and one idle connection regardless of the configured counts, while the
// lifetime and idle-time ceilings are honoured for every driver.
func applyPool(db *sql.DB, pool config.DatabasePoolConfig, sqliteConn bool) {
	defaults := config.DefaultDatabasePoolConfig()
	maxOpen := pool.MaxOpen
	if maxOpen <= 0 {
		maxOpen = defaults.MaxOpen
	}
	maxIdle := pool.MaxIdle
	if maxIdle <= 0 {
		maxIdle = defaults.MaxIdle
	}
	if maxIdle > maxOpen {
		maxIdle = maxOpen
	}
	if sqliteConn {
		maxOpen = 1
		maxIdle = 1
	}
	db.SetMaxOpenConns(maxOpen)
	db.SetMaxIdleConns(maxIdle)
	db.SetConnMaxLifetime(pool.ResolvedMaxLifetime())
	db.SetConnMaxIdleTime(pool.ResolvedMaxIdleTime())
}

// NewDB opens (or creates) the database described by cfg and returns a ready *sql.DB.
// The connection pool is configured with conservative defaults safe for SQLite.
// The schema is applied immediately so callers always receive a fully migrated DB.
//
// dbDir is the sqlite database directory as resolved by paths.Directories.DB
// (AI.md PART 4/PART 12: defaults to {data_dir}/db natively or
// /data/db/sqlite in Docker, but is independently relocatable via the
// DATABASE_DIR env var) — callers must pass dirs.DB, not the data directory.
func NewDB(cfg *config.DatabaseConfig, dbDir string) (*sql.DB, error) {
	driver := cfg.NormalizedDriver()

	var dsn string
	var db *sql.DB
	var err error
	sqliteConn := driver == "sqlite"
	switch driver {
	case "sqlite":
		if err := os.MkdirAll(dbDir, 0o700); err != nil {
			return nil, fmt.Errorf("db: create db directory: %w", err)
		}
		// Bare path per AI.md PART 10's canonical sql.Open("sqlite", path)
		// example: modernc.org/sqlite does not recognize the mattn/go-sqlite3
		// "?_journal=...&_busy_timeout=...&_foreign_keys=..." query-parameter
		// syntax — those params are silently ignored rather than erroring, so
		// WAL/busy_timeout/foreign_keys must be applied via explicit PRAGMA
		// statements below instead (matching main.go's OpenSQLite call sites).
		dsn = filepath.Join(dbDir, "server.db")
		db, err = OpenSQLite(dsn)
	case "libsql":
		if verr := cfg.ValidateLibSQL(); verr != nil {
			return nil, fmt.Errorf("db: invalid libsql config: %w", verr)
		}
		dsn = cfg.URL
		db, err = OpenLibSQLDriver(dsn)
	default:
		return nil, fmt.Errorf("db: unsupported driver %q", driver)
	}
	if err != nil {
		return nil, fmt.Errorf("db: open %s: %w", driver, err)
	}

	applyPool(db, cfg.Pool, sqliteConn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("db: ping %s: %w", driver, err)
	}

	if sqliteConn {
		// Unlike main.go's own non-fatal inline PRAGMA calls, NewDB is a
		// full DB-open path whose whole purpose is to guarantee these
		// settings are actually in effect (see the DSN comment above) — so
		// a PRAGMA failure here must surface as an error rather than
		// silently leaving WAL/foreign-keys/busy-timeout unset.
		if _, err := db.ExecContext(ctx, "PRAGMA journal_mode=WAL"); err != nil {
			return nil, fmt.Errorf("db: set journal_mode: %w", err)
		}
		if _, err := db.ExecContext(ctx, "PRAGMA foreign_keys=ON"); err != nil {
			return nil, fmt.Errorf("db: set foreign_keys: %w", err)
		}
		if _, err := db.ExecContext(ctx, "PRAGMA busy_timeout=5000"); err != nil {
			return nil, fmt.Errorf("db: set busy_timeout: %w", err)
		}
	}

	if err := EnsureSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("db: apply schema: %w", err)
	}

	return db, nil
}
