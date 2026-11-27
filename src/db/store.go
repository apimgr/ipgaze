package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"net/url"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apimgr/ipgaze/src/config"
	smetrics "github.com/apimgr/ipgaze/src/server/metrics"
)

const (
	writeTimeout     = 10 * time.Second
	readTimeout      = 5 * time.Second
	maxWriteAttempts = 5
)

var ErrOfflineReadOnly = errors.New("db: remote database is unavailable; cache mode is read-only")

var memoryDatabaseID atomic.Uint64

// Store owns the database handles. Application code uses its read and write
// methods and never receives either *sql.DB handle.
type Store struct {
	readDB         *sql.DB
	writeDB        *sql.DB
	remoteDB       bool
	memory         bool
	path           string
	tokenIDColumn  string
	usageMu        sync.Mutex
	usageLastToken map[string]time.Time
	usageLastOwner map[string]time.Time
	usageTokens    map[string]int64
	usageOwners    map[string]int64
	closeOnce      sync.Once
	closeErr       error
	replica        *databaseReplica
}

// APITokenIDColumn returns the stable public identifier column for token rows.
// Legacy databases retain their integer primary key and use public_id instead.
func (s *Store) APITokenIDColumn() string {
	if s != nil && s.tokenIDColumn == "public_id" {
		return "public_id"
	}
	return "id"
}

// OpenSQLite opens a SQLite store with the default reader pool configuration.
// The returned store has distinct query-only reader and immediate writer pools.
func OpenSQLite(dsn string) (*Store, error) {
	return openSQLiteStore(dsn, config.DefaultDatabasePoolConfig())
}

func newRemoteStore(handle *sql.DB, pool config.DatabasePoolConfig) *Store {
	applyPool(handle, pool, false)
	return &Store{
		readDB: handle, writeDB: handle, remoteDB: true,
		usageLastToken: make(map[string]time.Time), usageLastOwner: make(map[string]time.Time),
		usageTokens: make(map[string]int64), usageOwners: make(map[string]int64),
	}
}

func openSQLiteStore(dsn string, pool config.DatabasePoolConfig) (*Store, error) {
	memory := dsn == ":memory:" || strings.Contains(dsn, "mode=memory")
	if dsn == ":memory:" {
		dsn = fmt.Sprintf("file:ipgaze-memory-%d?mode=memory&cache=shared", memoryDatabaseID.Add(1))
	}
	writeDSN := withSQLitePragmas(dsn, true)
	readDSN := withSQLitePragmas(dsn, false)
	writer, err := openSQLiteDB(writeDSN)
	if err != nil {
		return nil, err
	}
	reader, err := openSQLiteDB(readDSN)
	if err != nil {
		return nil, errors.Join(err, writer.Close())
	}
	store := &Store{readDB: reader, writeDB: writer, path: sqliteFilePath(dsn), memory: memory, usageLastToken: make(map[string]time.Time), usageLastOwner: make(map[string]time.Time), usageTokens: make(map[string]int64), usageOwners: make(map[string]int64)}
	applySQLitePools(writer, reader, pool)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := writer.PingContext(ctx); err != nil {
		return nil, errors.Join(fmt.Errorf("db: ping SQLite writer %q: %w", store.path, err), store.Close())
	}
	if err := reader.PingContext(ctx); err != nil {
		return nil, errors.Join(fmt.Errorf("db: ping SQLite reader %q: %w", store.path, err), store.Close())
	}
	if err := store.checkSQLitePragmas(ctx); err != nil {
		return nil, errors.Join(err, store.Close())
	}
	return store, nil
}

func withSQLitePragmas(dsn string, writer bool) string {
	parsed, err := parseSQLiteDSN(dsn)
	if err != nil {
		return dsn
	}
	query := parsed.Query()
	query.Add("_pragma", "busy_timeout(10000)")
	if !strings.Contains(dsn, "mode=memory") {
		query.Add("_pragma", "journal_mode(WAL)")
	}
	query.Add("_pragma", "synchronous(NORMAL)")
	query.Add("_pragma", "foreign_keys(1)")
	if writer {
		query.Set("_txlock", "immediate")
	} else {
		query.Add("_pragma", "query_only(1)")
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func parseSQLiteDSN(dsn string) (*url.URL, error) {
	if strings.HasPrefix(strings.ToLower(dsn), "file:") {
		return url.Parse(dsn)
	}
	if dsn == ":memory:" {
		return url.Parse(dsn)
	}
	return &url.URL{Scheme: "file", Path: filepath.ToSlash(dsn)}, nil
}

func applySQLitePools(writer, reader *sql.DB, pool config.DatabasePoolConfig) {
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
	writer.SetMaxOpenConns(1)
	writer.SetMaxIdleConns(1)
	writer.SetConnMaxLifetime(0)
	writer.SetConnMaxIdleTime(0)
	reader.SetMaxOpenConns(maxOpen)
	reader.SetMaxIdleConns(maxIdle)
	reader.SetConnMaxLifetime(pool.ResolvedMaxLifetime())
	reader.SetConnMaxIdleTime(pool.ResolvedMaxIdleTime())
}

func (s *Store) checkSQLitePragmas(ctx context.Context) error {
	var journalMode string
	if err := s.writeDB.QueryRowContext(ctx, "PRAGMA journal_mode=WAL").Scan(&journalMode); err != nil {
		return fmt.Errorf("db: read journal_mode for %q: %w", s.path, err)
	}
	if !s.memory && !strings.EqualFold(journalMode, "wal") {
		return fmt.Errorf("db: journal_mode for %q is %q, want wal", s.path, journalMode)
	}
	for name, handle := range map[string]*sql.DB{"writer": s.writeDB, "reader": s.readDB} {
		var busyTimeout int
		if err := handle.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&busyTimeout); err != nil {
			return fmt.Errorf("db: read %s busy_timeout for %q: %w", name, s.path, err)
		}
		if busyTimeout != 10000 {
			return fmt.Errorf("db: %s busy_timeout for %q is %d, want 10000", name, s.path, busyTimeout)
		}
		var foreignKeys int
		if err := handle.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
			return fmt.Errorf("db: read %s foreign_keys for %q: %w", name, s.path, err)
		}
		if foreignKeys != 1 {
			return fmt.Errorf("db: %s foreign_keys for %q is %d, want 1", name, s.path, foreignKeys)
		}
	}
	var queryOnly int
	if err := s.readDB.QueryRowContext(ctx, "PRAGMA query_only").Scan(&queryOnly); err != nil {
		return fmt.Errorf("db: read query_only for %q: %w", s.path, err)
	}
	if queryOnly != 1 {
		return fmt.Errorf("db: reader for %q is not query-only", s.path)
	}
	for name, handle := range map[string]*sql.DB{"writer": s.writeDB, "reader": s.readDB} {
		var synchronous int
		if err := handle.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&synchronous); err != nil {
			return fmt.Errorf("db: read %s synchronous for %q: %w", name, s.path, err)
		}
		if synchronous != 1 {
			return fmt.Errorf("db: %s synchronous for %q is %d, want NORMAL (1)", name, s.path, synchronous)
		}
	}
	return nil
}

// Read returns a read-only query facade bound to ctx. Each query receives its
// own bounded context; callers cannot select the writer handle.
func (s *Store) Read(ctx context.Context) *Reader {
	if ctx == nil {
		ctx = context.Background()
	}
	return &Reader{store: s, ctx: ctx}
}

// OfflineReadOnly reports whether the remote database is unavailable while a
// valid local replica is serving reads.
func (s *Store) OfflineReadOnly() bool {
	return s != nil && s.replica != nil && s.replica.offlineMode && s.replica.offline.Load() && !s.replica.dirty.Load()
}

// Reader performs only reads against the store's query-only handle.
type Reader struct {
	store *Store
	ctx   context.Context
}

func (r *Reader) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	queryCtx, cancel := context.WithTimeout(nonNilContext(ctx, r.ctx), queryTimeout(query))
	readDB := r.store.readDB
	if r.store.replica != nil && r.store.replica.useCache(query) {
		rows, err := r.store.replica.cache.readDB.QueryContext(queryCtx, query, args...)
		if err == nil {
			time.AfterFunc(queryTimeout(query), cancel)
			return rows, nil
		}
	}
	rows, err := readDB.QueryContext(queryCtx, query, args...)
	if err != nil {
		if r.store.replica != nil {
			r.store.replica.confirmAvailability()
			if r.store.replica.offlineMode && r.store.replica.useCache(query) {
				rows, cacheErr := r.store.replica.cache.readDB.QueryContext(queryCtx, query, args...)
				if cacheErr == nil {
					time.AfterFunc(queryTimeout(query), cancel)
					return rows, nil
				}
				err = errors.Join(err, cacheErr)
			}
		} else {
			cancel()
			return nil, err
		}
		cancel()
		return nil, err
	}
	if r.store.replica != nil {
		r.store.replica.setOffline(false)
	}
	// The timer releases the query context if a caller abandons these rows.
	time.AfterFunc(queryTimeout(query), cancel)
	return rows, nil
}

func (r *Reader) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	queryCtx, cancel := context.WithTimeout(nonNilContext(ctx, r.ctx), queryTimeout(query))
	readDB := r.store.readDB
	if r.store.replica != nil && r.store.replica.useCache(query) {
		readDB = r.store.replica.cache.readDB
	}
	row := readDB.QueryRowContext(queryCtx, query, args...)
	// QueryRow has no Close method. Its context is deliberately deadline-bounded
	// and is canceled by the timer even if Scan is never called.
	time.AfterFunc(queryTimeout(query), cancel)
	return row
}

func nonNilContext(ctx, fallback context.Context) context.Context {
	if ctx != nil {
		return ctx
	}
	if fallback != nil {
		return fallback
	}
	return context.Background()
}

func queryTimeout(query string) time.Duration {
	upper := strings.ToUpper(query)
	if strings.Contains(upper, "SECURITY_REPORTS") || strings.Contains(upper, "GROUP BY") {
		return 2 * time.Minute
	}
	if strings.Contains(upper, " JOIN ") {
		return 15 * time.Second
	}
	return readTimeout
}

// QueryContext routes through Read so no caller can choose a database handle.
func (s *Store) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return s.Read(ctx).QueryContext(ctx, query, args...)
}

// QueryRowContext routes through Read so no caller can choose a database handle.
func (s *Store) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return s.Read(ctx).QueryRowContext(ctx, query, args...)
}

func (s *Store) Query(query string, args ...any) (*sql.Rows, error) {
	return s.QueryContext(context.Background(), query, args...)
}

func (s *Store) QueryRow(query string, args ...any) *sql.Row {
	return s.QueryRowContext(context.Background(), query, args...)
}

// Write executes fn in one immediate write transaction. Busy/locked failures
// are retried with bounded exponential backoff, always within a 10s deadline.
func (s *Store) Write(ctx context.Context, fn func(*sql.Tx) error) error {
	if fn == nil {
		return errors.New("db: nil write callback")
	}
	if s.OfflineReadOnly() {
		return ErrOfflineReadOnly
	}
	var previousDirty bool
	replicaHeld := false
	if ctx == nil {
		ctx = context.Background()
	}
	if s.replica != nil {
		previousDirty = s.replica.beginWrite()
		replicaHeld = true
		defer func() {
			if replicaHeld {
				s.replica.finishWrite(previousDirty, false)
			}
		}()
	}
	writeCtx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	var totalWait time.Duration
	var lastErr error
	for attempt := 0; attempt < maxWriteAttempts; attempt++ {
		waited, err := s.writeOnce(writeCtx, fn)
		totalWait += waited
		if err != nil {
			lastErr = err
			if !isBusyError(err) || attempt+1 == maxWriteAttempts {
				break
			}
			smetrics.RecordDBBusyRetry()
			if err := backoff(writeCtx, attempt); err != nil {
				lastErr = errors.Join(lastErr, err)
				break
			}
			continue
		}
		lastErr = err
		if lastErr == nil {
			s.observeWriteWait(totalWait)
			if s.replica != nil {
				s.replica.finishWrite(previousDirty, true)
				replicaHeld = false
				s.replica.setOffline(false)
				s.replica.afterWrite()
			}
			return nil
		}
		if !isBusyError(lastErr) || attempt+1 == maxWriteAttempts {
			break
		}
		smetrics.RecordDBBusyRetry()
		if err := backoff(writeCtx, attempt); err != nil {
			lastErr = errors.Join(lastErr, err)
			break
		}
	}
	s.observeWriteWait(totalWait)
	if s.replica != nil && lastErr != nil {
		s.replica.finishWrite(previousDirty, false)
		replicaHeld = false
		s.replica.confirmAvailability()
	}
	return lastErr
}

func (s *Store) writeOnce(ctx context.Context, fn func(*sql.Tx) error) (time.Duration, error) {
	waitStart := time.Now()
	tx, err := s.writeDB.BeginTx(ctx, nil)
	waited := time.Since(waitStart)
	if err != nil {
		return waited, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if err := fn(tx); err != nil {
		return waited, err
	}
	if err := tx.Commit(); err != nil {
		return waited, err
	}
	committed = true
	return waited, nil
}

func (s *Store) observeWriteWait(waited time.Duration) {
	smetrics.ObserveDBWriteWait(waited)
	if waited <= time.Second {
		return
	}
	caller := "unknown"
	if pc, _, _, ok := runtime.Caller(2); ok {
		if fn := runtime.FuncForPC(pc); fn != nil {
			caller = fn.Name()
		}
	}
	slog.Warn("db.busy", "wait_ms", waited.Milliseconds(), "caller", caller)
}

func backoff(ctx context.Context, attempt int) error {
	delay := 25*time.Millisecond*(1<<attempt) + time.Duration(rand.Intn(25))*time.Millisecond
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func isBusyError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "sqlite_busy") ||
		strings.Contains(message, "sqlite_locked") ||
		strings.Contains(message, "database is locked") ||
		strings.Contains(message, "database table is locked")
}

// ExecContext is a convenience for one-statement writes. It still delegates
// to Write, so application callers cannot bypass immediate transactions.
func (s *Store) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	var result sql.Result
	err := s.Write(ctx, func(tx *sql.Tx) error {
		var err error
		result, err = tx.ExecContext(ctx, query, args...)
		return err
	})
	return result, err
}

func (s *Store) Exec(query string, args ...any) (sql.Result, error) {
	return s.ExecContext(context.Background(), query, args...)
}

// VacuumInto creates a consistent SQLite snapshot through the private writer
// connection. VACUUM cannot run inside a transaction; callers restrict this to
// offline maintenance and the Store retains sole ownership of the handle.
func (s *Store) VacuumInto(ctx context.Context, destination string) error {
	if s == nil || s.remoteDB {
		return errors.New("db: VACUUM INTO is available only for SQLite maintenance")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if _, err := s.writeDB.ExecContext(ctx, `VACUUM INTO ?`, destination); err != nil {
		return fmt.Errorf("db: vacuum snapshot: %w", err)
	}
	return nil
}

func (s *Store) PingContext(ctx context.Context) error {
	if err := s.readDB.PingContext(ctx); err != nil {
		if s.replica != nil {
			s.replica.setOffline(true)
		}
		return err
	}
	err := s.writeDB.PingContext(ctx)
	if s.replica != nil {
		s.replica.setOffline(err != nil)
	}
	return err
}

// MarkOwnerUsage queues token and owner activity for the next hot-counter
// flush. It performs no database I/O and limits each identity to one queued
// update per minute.
func (s *Store) MarkOwnerUsage(tokenID string, ownerID string, now time.Time) {
	if s == nil || tokenID == "" || ownerID == "" {
		return
	}
	if now.IsZero() {
		now = time.Now()
	}
	s.usageMu.Lock()
	defer s.usageMu.Unlock()
	if previous := s.usageLastToken[tokenID]; now.Sub(previous) >= time.Minute || previous.IsZero() {
		s.usageLastToken[tokenID] = now
		s.usageTokens[tokenID] = now.Unix()
	}
	if previous := s.usageLastOwner[ownerID]; now.Sub(previous) >= time.Minute || previous.IsZero() {
		s.usageLastOwner[ownerID] = now
		s.usageOwners[ownerID] = now.Unix()
	}
}

// FlushHotCounters writes queued token and owner activity in one transaction.
func (s *Store) FlushHotCounters(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	s.usageMu.Lock()
	tokens := make(map[string]int64, len(s.usageTokens))
	owners := make(map[string]int64, len(s.usageOwners))
	for id, timestamp := range s.usageTokens {
		tokens[id] = timestamp
	}
	for id, timestamp := range s.usageOwners {
		owners[id] = timestamp
	}
	s.usageMu.Unlock()
	if len(tokens)+len(owners) == 0 {
		return nil
	}
	if err := s.Write(ctx, func(tx *sql.Tx) error {
		for id, timestamp := range tokens {
			if _, err := tx.ExecContext(ctx, `UPDATE api_tokens SET last_used_at = ? WHERE `+s.APITokenIDColumn()+` = ? AND (last_used_at IS NULL OR last_used_at < ? - 60)`, timestamp, id, timestamp); err != nil {
				return err
			}
		}
		for id, timestamp := range owners {
			if _, err := tx.ExecContext(ctx, `UPDATE owners SET last_seen_at = ? WHERE id = ? AND (last_seen_at IS NULL OR last_seen_at < ? - 60)`, timestamp, id, timestamp); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	s.usageMu.Lock()
	for id, timestamp := range tokens {
		if s.usageTokens[id] == timestamp {
			delete(s.usageTokens, id)
		}
	}
	for id, timestamp := range owners {
		if s.usageOwners[id] == timestamp {
			delete(s.usageOwners, id)
		}
	}
	s.usageMu.Unlock()
	return nil
}

// Stats combines reader and writer pool statistics for the exported metrics.
func (s *Store) Stats() sql.DBStats {
	readStats, writeStats := s.readDB.Stats(), s.writeDB.Stats()
	if s.remoteDB || s.readDB == s.writeDB {
		return readStats
	}
	return sql.DBStats{
		MaxOpenConnections: readStats.MaxOpenConnections + writeStats.MaxOpenConnections,
		OpenConnections:    readStats.OpenConnections + writeStats.OpenConnections,
		InUse:              readStats.InUse + writeStats.InUse,
		Idle:               readStats.Idle + writeStats.Idle,
		WaitCount:          readStats.WaitCount + writeStats.WaitCount,
		WaitDuration:       readStats.WaitDuration + writeStats.WaitDuration,
		MaxIdleClosed:      readStats.MaxIdleClosed + writeStats.MaxIdleClosed,
		MaxIdleTimeClosed:  readStats.MaxIdleTimeClosed + writeStats.MaxIdleTimeClosed,
		MaxLifetimeClosed:  readStats.MaxLifetimeClosed + writeStats.MaxLifetimeClosed,
	}
}

// Close checkpoints the WAL before closing the read handle and then the writer.
func (s *Store) Close() error {
	s.closeOnce.Do(func() {
		var usageErr error
		if s.writeDB != nil {
			ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
			usageErr = s.FlushHotCounters(ctx)
			cancel()
		}
		if s.replica != nil {
			s.replica.close()
		}
		var checkpointErr error
		if !s.remoteDB && s.writeDB != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			var busy, logFrames, checkpointed int
			checkpointErr = s.writeDB.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &logFrames, &checkpointed)
			cancel()
			if checkpointErr == nil && busy != 0 {
				checkpointErr = fmt.Errorf("db: WAL checkpoint for %q remained busy", s.path)
			}
		}
		var readErr, writeErr error
		if s.readDB != nil {
			readErr = s.readDB.Close()
		}
		if s.writeDB != nil && s.writeDB != s.readDB {
			writeErr = s.writeDB.Close()
		}
		if s.writeDB == s.readDB {
			writeErr = readErr
		}
		s.closeErr = errors.Join(usageErr, checkpointErr, readErr, writeErr)
	})
	return s.closeErr
}
