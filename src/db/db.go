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

// applyPool configures a remote database/sql pool. SQLite pools are configured
// separately because every SQLite file has a one-connection writer and a
// query-only reader pool.
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

// NewDB opens (or creates) the database described by cfg and returns a ready
// Store. SQLite receives separate reader and writer handles; libSQL uses one
// remote handle behind the same store API. The schema is applied immediately.
//
// dbDir is the sqlite database directory as resolved by paths.Directories.DB
// (AI.md PART 4/PART 12: defaults to {data_dir}/db natively or
// /data/db/sqlite in Docker, but is independently relocatable via the
// DATABASE_DIR env var) — callers must pass dirs.DB, not the data directory.
func NewDB(cfg *config.DatabaseConfig, dbDir string) (*Store, error) {
	driver := cfg.NormalizedDriver()

	var dsn string
	var store *Store
	var err error
	switch driver {
	case "sqlite":
		dsn, err = sqliteDataSourceName(cfg.URL, dbDir)
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(sqliteFilePath(dsn)), 0o700); err != nil {
			return nil, fmt.Errorf("db: create SQLite directory: %w", err)
		}
		store, err = openSQLiteStore(dsn, cfg.Pool)
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
		var handle *sql.DB
		handle, err = OpenLibSQL(dsn, cfg.Token)
		if err == nil {
			store = newRemoteStore(handle, cfg.Pool)
		}
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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := store.PingContext(ctx); err != nil {
		if driver == "libsql" {
			return nil, errors.Join(fmt.Errorf("db: ping libsql connection failed (URL credentials are omitted)"), store.Close())
		}
		return nil, errors.Join(fmt.Errorf("db: ping %s: %w", driver, err), store.Close())
	}

	schemaCtx, schemaCancel := context.WithTimeout(context.Background(), migrationTimeout)
	defer schemaCancel()
	if err := EnsureSchemaContext(schemaCtx, store); err != nil {
		return nil, errors.Join(fmt.Errorf("db: apply schema: %w", err), store.Close())
	}

	return store, nil
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
