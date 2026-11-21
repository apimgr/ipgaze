// Package db provides database initialization and connection management for ipgaze.
// Per AI.md PART 10: default driver is sqlite via modernc.org/sqlite (CGO_ENABLED=0 safe).
// Alternate driver is libsql (Turso/libSQL remote — tursodatabase/libsql-client-go).
package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
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
		dsn, err = sqliteDataSourceName(cfg.URL, dbDir)
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(sqliteFilePath(dsn)), 0o700); err != nil {
			return nil, fmt.Errorf("db: create SQLite directory: %w", err)
		}
		db, err = OpenSQLite(dsn)
	case "libsql":
		if verr := cfg.ValidateLibSQL(); verr != nil {
			return nil, fmt.Errorf("db: invalid libsql config: %w", verr)
		}
		if cfg.SSLCA != "" || cfg.SSLCert != "" || cfg.SSLKey != "" {
			return nil, fmt.Errorf("server.database.ssl_ca/ssl_cert/ssl_key are unsupported by the active libsql driver")
		}
		dsn = cfg.URL
		if err := validateLibSQLURL(dsn); err != nil {
			return nil, err
		}
		db, err = OpenLibSQL(dsn, cfg.Token)
	default:
		if cfg.URL != "" {
			return nil, fmt.Errorf("server.database.url has an unsupported scheme; use the URL form")
		}
		return nil, fmt.Errorf("db: unsupported driver %q", driver)
	}
	if err != nil {
		if driver == "libsql" {
			return nil, fmt.Errorf("db: open libsql connection failed (URL credentials are omitted)")
		}
		return nil, fmt.Errorf("db: open %s: %w", driver, err)
	}

	applyPool(db, cfg.Pool, sqliteConn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		if driver == "libsql" {
			return nil, errors.Join(fmt.Errorf("db: ping libsql connection failed (URL credentials are omitted)"), db.Close())
		}
		return nil, errors.Join(fmt.Errorf("db: ping %s: %w", driver, err), db.Close())
	}

	if sqliteConn {
		// Unlike main.go's own non-fatal inline PRAGMA calls, NewDB is a
		// full DB-open path whose whole purpose is to guarantee these
		// settings are actually in effect (see the DSN comment above) — so
		// a PRAGMA failure here must surface as an error rather than
		// silently leaving WAL/foreign-keys/busy-timeout unset.
		if _, err := db.ExecContext(ctx, "PRAGMA journal_mode=WAL"); err != nil {
			return nil, errors.Join(fmt.Errorf("db: set journal_mode: %w", err), db.Close())
		}
		if _, err := db.ExecContext(ctx, "PRAGMA foreign_keys=ON"); err != nil {
			return nil, errors.Join(fmt.Errorf("db: set foreign_keys: %w", err), db.Close())
		}
		if _, err := db.ExecContext(ctx, "PRAGMA busy_timeout=5000"); err != nil {
			return nil, errors.Join(fmt.Errorf("db: set busy_timeout: %w", err), db.Close())
		}
	}

	if err := EnsureSchema(db); err != nil {
		return nil, errors.Join(fmt.Errorf("db: apply schema: %w", err), db.Close())
	}

	return db, nil
}

func sqliteDataSourceName(raw, dbDir string) (string, error) {
	if raw == "" {
		return filepath.Join(dbDir, "server.db"), nil
	}
	if strings.Contains(raw, ";") || (strings.Contains(raw, "=") && !strings.HasPrefix(strings.ToLower(raw), "file:")) {
		return "", fmt.Errorf("server.database.url is invalid; use the URL form")
	}
	path := raw
	if strings.HasPrefix(strings.ToLower(raw), "file:") {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Scheme != "file" || (parsed.Host != "" && parsed.Host != "localhost") {
			return "", fmt.Errorf("server.database.url is invalid; use the URL form")
		}
		path = parsed.Path
		if path == "" {
			path = parsed.Opaque
		}
		if path == "" {
			return "", fmt.Errorf("server.database.url is invalid; use the URL form")
		}
		if !filepath.IsAbs(path) {
			path = filepath.Join(dbDir, path)
		}
		if parsed.RawQuery != "" {
			return "file:" + filepath.ToSlash(path) + "?" + parsed.RawQuery, nil
		}
	} else if strings.Contains(raw, "://") {
		return "", fmt.Errorf("server.database.url is invalid; use the URL form")
	} else if !filepath.IsAbs(path) {
		path = filepath.Join(dbDir, path)
	}
	return path, nil
}

func sqliteFilePath(dsn string) string {
	if strings.HasPrefix(dsn, "file:") {
		parsed, err := url.Parse(dsn)
		if err == nil {
			if parsed.Path != "" {
				return parsed.Path
			}
			return parsed.Opaque
		}
	}
	return dsn
}

func validateLibSQLURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" {
		return fmt.Errorf("server.database.url is invalid; use the URL form")
	}
	switch strings.ToLower(parsed.Scheme) {
	case "libsql", "https":
		return nil
	case "http":
		if privateLibSQLHost(parsed.Hostname()) {
			return nil
		}
		return fmt.Errorf("server.database.url must use TLS; use https:// or libsql://")
	default:
		return fmt.Errorf("server.database.url has an unsupported scheme; use the URL form")
	}
}

func privateLibSQLHost(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return isPrivateOrLoopback(ip)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(addresses) == 0 {
		return false
	}
	for _, address := range addresses {
		if !isPrivateOrLoopback(address.IP) {
			return false
		}
	}
	return true
}

func isPrivateOrLoopback(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate()
}
