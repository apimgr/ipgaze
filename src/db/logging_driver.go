// Package db query logging — implements server.debug.log_queries per
// AI.md PART 6. Wraps the sqlite and libsql drivers so every query/exec
// logs its SQL text, args, duration, and error via slog.Debug, gated by
// queryLogEnabled (set once at startup from --debug/DEBUG=true AND
// server.debug.log_queries — never by mode alone).
package db

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tursodatabase/libsql-client-go/libsql"
	"modernc.org/sqlite"
)

var (
	queryLogEnabled atomic.Bool
	registerOnce    sync.Once
)

// SetQueryLogging enables or disables SQL query logging for all connections
// opened via OpenSQLite/OpenLibSQL, including ones already open. Callers
// should set this once at startup based on cfg.IsDebug() &&
// cfg.Server.Debug.LogQueries per AI.md PART 6.
func SetQueryLogging(enabled bool) {
	queryLogEnabled.Store(enabled)
}

// registerLoggingDrivers registers the "sqlite+logged" and "libsql+logged"
// driver names, each wrapping the real driver so every query can be logged.
// Registration always happens (idempotently) regardless of whether logging
// is currently enabled — SetQueryLogging toggles the behavior at call time.
func registerLoggingDrivers() {
	registerOnce.Do(func() {
		sql.Register("sqlite+logged", &loggingDriver{inner: &sqlite.Driver{}})
		sql.Register("libsql+logged", &loggingDriver{inner: libsql.Driver{}})
	})
}

// OpenSQLite opens dsn via the sqlite driver, transparently logging every
// query when SetQueryLogging(true) is active.
func OpenSQLite(dsn string) (*sql.DB, error) {
	registerLoggingDrivers()
	return sql.Open("sqlite+logged", dsn)
}

// OpenLibSQLDriver opens url via the libsql driver, transparently logging
// every query when SetQueryLogging(true) is active.
func OpenLibSQLDriver(url string) (*sql.DB, error) {
	registerLoggingDrivers()
	return sql.Open("libsql+logged", url)
}

// logQuery emits a slog.Debug entry for query with args, duration, and
// error, when queryLogEnabled is true. No-op otherwise (checked first so
// disabled logging costs a single atomic load).
func logQuery(query string, args []driver.NamedValue, start time.Time, err error) {
	if !queryLogEnabled.Load() {
		return
	}
	attrs := []any{
		"query", query,
		"duration_ms", time.Since(start).Milliseconds(),
	}
	if len(args) > 0 {
		vals := make([]any, len(args))
		for i, a := range args {
			vals[i] = a.Value
		}
		attrs = append(attrs, "args", vals)
	}
	if err != nil {
		attrs = append(attrs, "error", err.Error())
		slog.Debug("db query failed", attrs...)
		return
	}
	slog.Debug("db query", attrs...)
}

// loggingDriver wraps a database/sql driver.Driver so every connection it
// opens logs queries via logQuery.
type loggingDriver struct {
	inner driver.Driver
}

func (d *loggingDriver) Open(name string) (driver.Conn, error) {
	conn, err := d.inner.Open(name)
	if err != nil {
		return nil, err
	}
	return &loggingConn{inner: conn}, nil
}

// loggingConn wraps a driver.Conn, forwarding every method to inner and
// logging around the query-executing ones. Optional driver interfaces
// (Pinger, ConnBeginTx, ConnPrepareContext, ExecerContext, QueryerContext,
// SessionResetter, NamedValueChecker, Validator) are always declared on the
// wrapper but delegate to inner only when inner itself implements them,
// falling back to the same defaults database/sql applies for drivers that
// don't implement the optional interface.
type loggingConn struct {
	inner driver.Conn
}

func (c *loggingConn) Prepare(query string) (driver.Stmt, error) {
	stmt, err := c.inner.Prepare(query)
	if err != nil {
		return nil, err
	}
	return &loggingStmt{inner: stmt, query: query}, nil
}

func (c *loggingConn) Close() error { return c.inner.Close() }

// Begin implements the legacy driver.Conn interface. BeginTx below is
// implemented and preferred by database/sql; this remains only as the
// required fallback for callers that bypass context.
func (c *loggingConn) Begin() (driver.Tx, error) {
	//lint:ignore SA1019 required driver.Conn fallback, see doc comment above
	return c.inner.Begin()
}

func (c *loggingConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	if p, ok := c.inner.(driver.ConnPrepareContext); ok {
		stmt, err := p.PrepareContext(ctx, query)
		if err != nil {
			return nil, err
		}
		return &loggingStmt{inner: stmt, query: query}, nil
	}
	return c.Prepare(query)
}

func (c *loggingConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if b, ok := c.inner.(driver.ConnBeginTx); ok {
		return b.BeginTx(ctx, opts)
	}
	//lint:ignore SA1019 fallback when inner lacks ConnBeginTx
	return c.inner.Begin()
}

func (c *loggingConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	execer, ok := c.inner.(driver.ExecerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	start := time.Now()
	res, err := execer.ExecContext(ctx, query, args)
	logQuery(query, args, start, err)
	return res, err
}

func (c *loggingConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	queryer, ok := c.inner.(driver.QueryerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	start := time.Now()
	rows, err := queryer.QueryContext(ctx, query, args)
	logQuery(query, args, start, err)
	return rows, err
}

func (c *loggingConn) Ping(ctx context.Context) error {
	if p, ok := c.inner.(driver.Pinger); ok {
		return p.Ping(ctx)
	}
	return nil
}

func (c *loggingConn) ResetSession(ctx context.Context) error {
	if r, ok := c.inner.(driver.SessionResetter); ok {
		return r.ResetSession(ctx)
	}
	return nil
}

func (c *loggingConn) CheckNamedValue(nv *driver.NamedValue) error {
	if chk, ok := c.inner.(driver.NamedValueChecker); ok {
		return chk.CheckNamedValue(nv)
	}
	return driver.ErrSkip
}

func (c *loggingConn) IsValid() bool {
	if v, ok := c.inner.(driver.Validator); ok {
		return v.IsValid()
	}
	return true
}

// loggingStmt wraps a driver.Stmt, logging around the query-executing
// methods. Defensive completeness for any future direct db.Prepare use —
// current call sites all go through *sql.DB's context-based query/exec,
// which loggingConn already handles directly.
type loggingStmt struct {
	inner driver.Stmt
	query string
}

func (s *loggingStmt) Close() error  { return s.inner.Close() }
func (s *loggingStmt) NumInput() int { return s.inner.NumInput() }

// Exec implements the legacy driver.Stmt interface. StmtExecContext below is
// implemented and preferred by database/sql; this remains only as the
// required fallback for callers that bypass context.
func (s *loggingStmt) Exec(args []driver.Value) (driver.Result, error) {
	start := time.Now()
	//lint:ignore SA1019 required driver.Stmt fallback, see doc comment above
	res, err := s.inner.Exec(args)
	logQuery(s.query, valuesToNamed(args), start, err)
	return res, err
}

// Query implements the legacy driver.Stmt interface. StmtQueryContext below is
// implemented and preferred by database/sql; this remains only as the
// required fallback for callers that bypass context.
func (s *loggingStmt) Query(args []driver.Value) (driver.Rows, error) {
	start := time.Now()
	//lint:ignore SA1019 required driver.Stmt fallback, see doc comment above
	rows, err := s.inner.Query(args)
	logQuery(s.query, valuesToNamed(args), start, err)
	return rows, err
}

func (s *loggingStmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	execer, ok := s.inner.(driver.StmtExecContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	start := time.Now()
	res, err := execer.ExecContext(ctx, args)
	logQuery(s.query, args, start, err)
	return res, err
}

func (s *loggingStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	queryer, ok := s.inner.(driver.StmtQueryContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	start := time.Now()
	rows, err := queryer.QueryContext(ctx, args)
	logQuery(s.query, args, start, err)
	return rows, err
}

func (s *loggingStmt) CheckNamedValue(nv *driver.NamedValue) error {
	if chk, ok := s.inner.(driver.NamedValueChecker); ok {
		return chk.CheckNamedValue(nv)
	}
	return driver.ErrSkip
}

// valuesToNamed converts legacy driver.Value args (from the non-context
// Exec/Query path) into driver.NamedValue for a uniform logQuery signature.
func valuesToNamed(args []driver.Value) []driver.NamedValue {
	out := make([]driver.NamedValue, len(args))
	for i, v := range args {
		out[i] = driver.NamedValue{Ordinal: i + 1, Value: v}
	}
	return out
}
