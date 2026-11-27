package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apimgr/ipgaze/src/config"
)

var replicaTablePattern = regexp.MustCompile("(?i)\\b(?:from|join|update|into)\\s+[\"`\\[]?([a-z_][a-z0-9_]*)")
var replicaExcludedTablePattern = regexp.MustCompile(`(?i)\b(?:rate_limits|audit_log|app_secrets)\b`)

var replicaTables = []string{
	"scheduler_tasks", "scheduler_history", "backups", "owners", "api_tokens",
	"pgp_keypairs", "ip_blocks", "security_reports", "captcha_challenges",
}

type databaseReplica struct {
	primary     *Store
	cache       *Store
	interval    time.Duration
	maxAge      time.Duration
	offlineMode bool
	dirty       atomic.Bool
	offline     atomic.Bool
	started     atomic.Bool
	stop        chan struct{}
	done        chan struct{}
	syncMu      sync.Mutex
	closeOnce   sync.Once
}

func newDatabaseReplica(primary *Store, cfg config.DatabaseCacheConfig, dbDir string, pool config.DatabasePoolConfig) (*databaseReplica, error) {
	interval, err := time.ParseDuration(strings.TrimSpace(cfg.SyncInterval))
	if err != nil || interval <= 0 {
		interval = 30 * time.Second
	}
	maxAge, err := time.ParseDuration(strings.TrimSpace(cfg.MaxAge))
	if err != nil || maxAge <= 0 {
		maxAge = time.Hour
	}
	path := strings.TrimSpace(cfg.Path)
	operatorAbsolutePath := path != "" && filepath.IsAbs(path)
	if path == "" {
		path = filepath.Join(dbDir, "cache.db")
	} else if !filepath.IsAbs(path) {
		path = filepath.Join(dbDir, path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create cache directory: %w", err)
	}
	cacheDir := filepath.Dir(path)
	if operatorAbsolutePath {
		info, err := os.Stat(cacheDir)
		if err != nil {
			return nil, fmt.Errorf("inspect configured cache directory: %w", err)
		}
		if !info.IsDir() || info.Mode().Perm() != 0o700 {
			return nil, fmt.Errorf("configured cache directory must be a private directory with mode 0700")
		}
	} else if err := os.Chmod(cacheDir, 0o700); err != nil {
		return nil, fmt.Errorf("secure cache directory: %w", err)
	}
	cache, err := openSQLiteStore(path, pool)
	if err != nil {
		return nil, fmt.Errorf("open SQLite cache: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, errorsJoinClose(fmt.Errorf("secure cache file: %w", err), cache)
	}
	ctx, cancel := context.WithTimeout(context.Background(), migrationTimeout)
	defer cancel()
	if err := EnsureSchemaContext(ctx, cache); err != nil {
		return nil, errorsJoinClose(fmt.Errorf("apply cache schema: %w", err), cache)
	}
	if _, err := cache.writeDB.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS cache_meta (table_name TEXT PRIMARY KEY, synced_at TEXT NOT NULL, watermark TEXT NOT NULL DEFAULT '')`); err != nil {
		return nil, errorsJoinClose(fmt.Errorf("create cache metadata: %w", err), cache)
	}
	if _, err := cache.writeDB.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS cache_state (id INTEGER PRIMARY KEY CHECK(id=1), dirty INTEGER NOT NULL)`); err != nil {
		return nil, errorsJoinClose(fmt.Errorf("create cache state: %w", err), cache)
	}
	if _, err := cache.writeDB.ExecContext(ctx, `INSERT INTO cache_state(id,dirty) VALUES(1,1) ON CONFLICT(id) DO NOTHING`); err != nil {
		return nil, errorsJoinClose(fmt.Errorf("initialize cache state: %w", err), cache)
	}
	replica := &databaseReplica{primary: primary, cache: cache, interval: interval, maxAge: maxAge, offlineMode: cfg.OfflineMode, stop: make(chan struct{}), done: make(chan struct{})}
	replica.dirty.Store(!replica.hasFreshSnapshot())
	return replica, nil
}

func errorsJoinClose(err error, store *Store) error {
	return errors.Join(err, store.Close())
}

func (r *databaseReplica) start() {
	if !r.started.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer close(r.done)
		ticker := time.NewTicker(r.interval)
		defer ticker.Stop()
		for {
			select {
			case <-r.stop:
				return
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				err := r.primary.PingContext(ctx)
				cancel()
				r.setOffline(err != nil)
				if err == nil {
					syncCtx, syncCancel := context.WithTimeout(context.Background(), 2*time.Minute)
					if syncErr := r.sync(syncCtx); syncErr != nil {
						slog.Warn("database cache sync failed", "error", syncErr)
					}
					syncCancel()
				}
			}
		}
	}()
}

func (r *databaseReplica) close() {
	r.closeOnce.Do(func() {
		if r.started.Load() {
			close(r.stop)
			<-r.done
		}
		if err := r.cache.Close(); err != nil {
			slog.Warn("close local database cache", "error", err)
		}
	})
}

func (r *databaseReplica) setOffline(offline bool) { r.offline.Store(offline) }

func (r *databaseReplica) confirmAvailability() {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	err := r.primary.PingContext(ctx)
	cancel()
	r.setOffline(err != nil)
}

func (r *databaseReplica) hasFreshSnapshot() bool {
	var dirty int
	if err := r.cache.readDB.QueryRow(`SELECT dirty FROM cache_state WHERE id=1`).Scan(&dirty); err != nil || dirty != 0 {
		return false
	}
	for _, table := range replicaTables {
		var syncedAt string
		if err := r.cache.readDB.QueryRow(`SELECT synced_at FROM cache_meta WHERE table_name=?`, table).Scan(&syncedAt); err != nil {
			return false
		}
		synced, err := time.Parse(time.RFC3339Nano, syncedAt)
		if err != nil || time.Since(synced) > r.maxAge || synced.After(time.Now().Add(time.Minute)) {
			return false
		}
	}
	return true
}

func (r *databaseReplica) afterWrite() {
	r.syncMu.Lock()
	if err := r.invalidate(); err != nil {
		slog.Warn("database cache invalidation failed after successful remote write", "error", err)
	}
	r.syncMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := r.sync(ctx); err != nil {
		slog.Warn("database cache refresh failed after successful remote write; cache bypassed", "error", err)
	}
}

func (r *databaseReplica) invalidate() error {
	r.dirty.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := r.cache.writeDB.ExecContext(ctx, `UPDATE cache_state SET dirty=1 WHERE id=1`)
	return err
}

// beginWrite blocks background sync and bypasses the cache until the remote
// transaction commits or rolls back. It does not persist dirty state, so a
// rejected write leaves the local replica unchanged.
func (r *databaseReplica) beginWrite() bool {
	r.syncMu.Lock()
	return r.dirty.Swap(true)
}

func (r *databaseReplica) finishWrite(previousDirty, committed bool) {
	if !committed {
		r.dirty.Store(previousDirty)
	}
	r.syncMu.Unlock()
}

func (r *databaseReplica) useCache(query string) bool {
	if r.dirty.Load() || (r.offline.Load() && !r.offlineMode) || replicaExcludedTablePattern.MatchString(query) {
		return false
	}
	matches := replicaTablePattern.FindAllStringSubmatch(query, -1)
	if len(matches) == 0 {
		return false
	}
	allowed := make(map[string]struct{}, len(replicaTables))
	for _, table := range replicaTables {
		allowed[table] = struct{}{}
	}
	for _, match := range matches {
		table := strings.TrimPrefix(strings.ToLower(match[1]), "srv_")
		if _, ok := allowed[table]; !ok {
			return false
		}
		var syncedAt string
		if err := r.cache.readDB.QueryRow(`SELECT synced_at FROM cache_meta WHERE table_name=?`, table).Scan(&syncedAt); err != nil {
			return false
		}
		synced, err := time.Parse(time.RFC3339Nano, syncedAt)
		if err != nil || time.Since(synced) > r.maxAge || synced.After(time.Now().Add(time.Minute)) {
			return false
		}
	}
	return true
}

func (r *databaseReplica) sync(ctx context.Context) error {
	r.syncMu.Lock()
	defer r.syncMu.Unlock()
	previousDirty := r.dirty.Swap(true)
	commitStarted := false
	committed := false
	defer func() {
		if !committed && !commitStarted {
			r.dirty.Store(previousDirty)
		}
	}()
	if ctx == nil {
		ctx = context.Background()
	}
	if err := r.primary.PingContext(ctx); err != nil {
		r.setOffline(true)
		return err
	}
	r.setOffline(false)
	if ctx == nil {
		ctx = context.Background()
	}
	infos := make(map[string]replicaTableInfo, len(replicaTables))
	for _, table := range replicaTables {
		info, err := r.remoteTableInfo(ctx, table)
		if err != nil {
			return fmt.Errorf("inspect remote %s: %w", table, err)
		}
		infos[table] = info
	}
	tx, err := r.cache.writeDB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if _, err := tx.ExecContext(ctx, `UPDATE cache_state SET dirty=1 WHERE id=1`); err != nil {
		return fmt.Errorf("mark cache dirty in sync transaction: %w", err)
	}
	for i := len(replicaTables) - 1; i >= 0; i-- {
		table := replicaTables[i]
		if infos[table].updatedAt >= 0 {
			continue
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM `+table); err != nil {
			return fmt.Errorf("clear cached %s: %w", replicaTables[i], err)
		}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, table := range replicaTables {
		info := infos[table]
		watermark := ""
		if info.updatedAt >= 0 {
			_ = r.cache.readDB.QueryRowContext(ctx, `SELECT watermark FROM cache_meta WHERE table_name=?`, table).Scan(&watermark)
		}
		columns, rows, err := r.readRemoteTable(ctx, table, info, watermark)
		if err != nil {
			return fmt.Errorf("read remote %s: %w", table, err)
		}
		if len(columns) != 0 && len(rows) != 0 {
			placeholders := strings.TrimSuffix(strings.Repeat("?,", len(columns)), ",")
			quotedColumns := make([]string, len(columns))
			for i, column := range columns {
				quotedColumns[i] = `"` + strings.ReplaceAll(column, `"`, `""`) + `"`
			}
			statement := `INSERT INTO ` + table + ` (` + strings.Join(quotedColumns, ",") + `) VALUES (` + placeholders + `)`
			if len(info.primaryKeys) > 0 && info.updatedAt >= 0 {
				quotedKeys := quoteSQLIdentifiers(info.primaryKeys)
				updateColumns := make([]string, 0, len(columns)-len(info.primaryKeys))
				keySet := make(map[string]struct{}, len(info.primaryKeys))
				for _, key := range info.primaryKeys {
					keySet[strings.ToLower(key)] = struct{}{}
				}
				for _, column := range columns {
					if _, isKey := keySet[strings.ToLower(column)]; !isKey {
						quoted := `"` + strings.ReplaceAll(column, `"`, `""`) + `"`
						updateColumns = append(updateColumns, quoted+`=excluded.`+quoted)
					}
				}
				statement += ` ON CONFLICT (` + strings.Join(quotedKeys, ",") + `) `
				if len(updateColumns) == 0 {
					statement += `DO NOTHING`
				} else {
					statement += `DO UPDATE SET ` + strings.Join(updateColumns, ",")
				}
			}
			for _, row := range rows {
				if _, err := tx.ExecContext(ctx, statement, row...); err != nil {
					return fmt.Errorf("write cached %s row: %w", table, err)
				}
				if info.updatedAt >= 0 {
					value := fmt.Sprint(row[info.updatedAt])
					if compareWatermark(value, watermark) > 0 {
						watermark = value
					}
				}
			}
		}
		if info.updatedAt >= 0 && len(info.primaryKeys) > 0 {
			if err := r.removeDeletedRows(ctx, tx, table, info.primaryKeys); err != nil {
				return fmt.Errorf("reconcile cached %s deletions: %w", table, err)
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO cache_meta(table_name,synced_at,watermark) VALUES(?,?,?) ON CONFLICT(table_name) DO UPDATE SET synced_at=excluded.synced_at,watermark=excluded.watermark`, table, now, watermark); err != nil {
			return fmt.Errorf("update cache metadata for %s: %w", table, err)
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE cache_state SET dirty=0 WHERE id=1`); err != nil {
		return fmt.Errorf("mark cache clean: %w", err)
	}
	commitStarted = true
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit cache sync: %w", err)
	}
	committed = true
	r.dirty.Store(false)
	return nil
}

type replicaTableInfo struct {
	columns     []string
	primaryKeys []string
	updatedAt   int
}

func (r *databaseReplica) remoteTableInfo(ctx context.Context, table string) (replicaTableInfo, error) {
	rows, err := r.primary.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
	if err != nil {
		return replicaTableInfo{}, err
	}
	defer rows.Close()
	info := replicaTableInfo{updatedAt: -1}
	var keys []struct {
		order int
		name  string
	}
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, kind string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &primaryKey); err != nil {
			return replicaTableInfo{}, err
		}
		info.columns = append(info.columns, name)
		if strings.EqualFold(name, "updated_at") {
			info.updatedAt = len(info.columns) - 1
		}
		if primaryKey > 0 {
			keys = append(keys, struct {
				order int
				name  string
			}{order: primaryKey, name: name})
		}
	}
	if err := rows.Err(); err != nil {
		return replicaTableInfo{}, err
	}
	for order := 1; order <= len(keys); order++ {
		for _, key := range keys {
			if key.order == order {
				info.primaryKeys = append(info.primaryKeys, key.name)
			}
		}
	}
	return info, nil
}

func (r *databaseReplica) readRemoteTable(ctx context.Context, table string, info replicaTableInfo, watermark string) ([]string, [][]any, error) {
	query := `SELECT * FROM ` + table
	var args []any
	if watermark != "" && info.updatedAt >= 0 {
		query += ` WHERE updated_at >= ?`
		args = append(args, watermark)
	}
	rows, err := r.primary.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return nil, nil, err
	}
	var result [][]any
	for rows.Next() {
		values := make([]any, len(columns))
		dest := make([]any, len(columns))
		for i := range values {
			dest[i] = &values[i]
		}
		if err := rows.Scan(dest...); err != nil {
			return nil, nil, err
		}
		for i, value := range values {
			if raw, ok := value.([]byte); ok {
				values[i] = append([]byte(nil), raw...)
			}
		}
		result = append(result, values)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	return columns, result, nil
}

func (r *databaseReplica) removeDeletedRows(ctx context.Context, tx *sql.Tx, table string, primaryKeys []string) error {
	quotedKeys := quoteSQLIdentifiers(primaryKeys)
	remoteRows, err := r.primary.QueryContext(ctx, `SELECT `+strings.Join(quotedKeys, ",")+` FROM `+table)
	if err != nil {
		return err
	}
	remoteSet := make(map[string]struct{})
	for remoteRows.Next() {
		values := make([]any, len(primaryKeys))
		dest := make([]any, len(primaryKeys))
		for i := range values {
			dest[i] = &values[i]
		}
		if err := remoteRows.Scan(dest...); err != nil {
			_ = remoteRows.Close()
			return err
		}
		remoteSet[replicaKey(values)] = struct{}{}
	}
	if err := remoteRows.Err(); err != nil {
		_ = remoteRows.Close()
		return err
	}
	if err := remoteRows.Close(); err != nil {
		return err
	}
	localRows, err := r.cache.readDB.QueryContext(ctx, `SELECT `+strings.Join(quotedKeys, ",")+` FROM `+table)
	if err != nil {
		return err
	}
	var stale [][]any
	for localRows.Next() {
		values := make([]any, len(primaryKeys))
		dest := make([]any, len(primaryKeys))
		for i := range values {
			dest[i] = &values[i]
		}
		if err := localRows.Scan(dest...); err != nil {
			_ = localRows.Close()
			return err
		}
		if _, exists := remoteSet[replicaKey(values)]; !exists {
			stale = append(stale, values)
		}
	}
	if err := localRows.Err(); err != nil {
		_ = localRows.Close()
		return err
	}
	if err := localRows.Close(); err != nil {
		return err
	}
	conditions := make([]string, len(primaryKeys))
	for i, key := range quotedKeys {
		conditions[i] = key + `=?`
	}
	statement := `DELETE FROM ` + table + ` WHERE ` + strings.Join(conditions, ` AND `)
	for _, values := range stale {
		if _, err := tx.ExecContext(ctx, statement, values...); err != nil {
			return err
		}
	}
	return nil
}

func quoteSQLIdentifiers(names []string) []string {
	quoted := make([]string, len(names))
	for i, name := range names {
		quoted[i] = `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
	}
	return quoted
}

func replicaKey(values []any) string {
	parts := make([]string, len(values))
	for i, value := range values {
		parts[i] = fmt.Sprintf("%T:%v", value, value)
	}
	return strings.Join(parts, "\x00")
}

func compareWatermark(left, right string) int {
	leftTime, leftErr := time.Parse(time.RFC3339Nano, left)
	rightTime, rightErr := time.Parse(time.RFC3339Nano, right)
	if leftErr == nil && rightErr == nil {
		if leftTime.Before(rightTime) {
			return -1
		}
		if leftTime.After(rightTime) {
			return 1
		}
		return 0
	}
	if leftNumber, leftErr := strconv.ParseFloat(left, 64); leftErr == nil {
		if rightNumber, rightErr := strconv.ParseFloat(right, 64); rightErr == nil {
			if leftNumber < rightNumber {
				return -1
			}
			if leftNumber > rightNumber {
				return 1
			}
			return 0
		}
	}
	return strings.Compare(left, right)
}
