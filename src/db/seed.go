package db

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
)

// SeedFromSQLite copies application tables from a verified SQLite backup into
// an already initialized database. It is used only when a remote restore target
// is empty; conflicts are left untouched so the system owner and imported
// app_secrets rows remain authoritative.
func (s *Store) SeedFromSQLite(ctx context.Context, backupPath string) error {
	if s == nil || backupPath == "" {
		return fmt.Errorf("db: seed requires a target and SQLite backup path")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	source, err := OpenSQLite(backupPath)
	if err != nil {
		return fmt.Errorf("open SQLite backup: %w", err)
	}
	defer func() { _ = source.Close() }()

	rows, err := source.readDB.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		return fmt.Errorf("list SQLite backup tables: %w", err)
	}
	tables := make([]string, 0)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			_ = rows.Close()
			return err
		}
		if _, ok := databaseObjectNames[strings.ToLower(name)]; ok {
			tables = append(tables, name)
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	sort.Slice(tables, func(i, j int) bool {
		if tables[i] == "owners" {
			return true
		}
		if tables[j] == "owners" {
			return false
		}
		return tables[i] < tables[j]
	})

	if s.replica != nil {
		if err := s.replica.invalidate(); err != nil {
			return fmt.Errorf("invalidate local cache before seed: %w", err)
		}
	}
	tx, err := s.writeDB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin database seed: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	for _, table := range tables {
		columns, err := sqliteTableColumns(ctx, source.readDB, table)
		if err != nil {
			return fmt.Errorf("read SQLite backup columns for %s: %w", table, err)
		}
		if len(columns) == 0 {
			continue
		}
		quotedColumns := make([]string, len(columns))
		placeholders := make([]string, len(columns))
		for i, column := range columns {
			quotedColumns[i] = quoteIdentifier(column)
			placeholders[i] = "?"
		}
		query := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s) ON CONFLICT DO NOTHING", quoteIdentifier(table), strings.Join(quotedColumns, ","), strings.Join(placeholders, ","))
		backupRows, err := source.readDB.QueryContext(ctx, `SELECT `+strings.Join(quotedColumns, ",")+` FROM `+quoteIdentifier(table))
		if err != nil {
			return fmt.Errorf("read SQLite backup table %s: %w", table, err)
		}
		for backupRows.Next() {
			values := make([]any, len(columns))
			pointers := make([]any, len(columns))
			for i := range values {
				pointers[i] = &values[i]
			}
			if err := backupRows.Scan(pointers...); err != nil {
				_ = backupRows.Close()
				return fmt.Errorf("scan SQLite backup table %s: %w", table, err)
			}
			if _, err := tx.ExecContext(ctx, query, values...); err != nil {
				_ = backupRows.Close()
				return fmt.Errorf("seed database table %s: %w", table, err)
			}
		}
		if err := backupRows.Err(); err != nil {
			_ = backupRows.Close()
			return fmt.Errorf("read SQLite backup table %s: %w", table, err)
		}
		if err := backupRows.Close(); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit database seed: %w", err)
	}
	committed = true
	if s.replica != nil {
		s.replica.setOffline(false)
		s.replica.afterWrite()
	}
	return nil
}

func sqliteTableColumns(ctx context.Context, conn *sql.DB, table string) ([]string, error) {
	rows, err := conn.QueryContext(ctx, `PRAGMA table_info(`+quoteIdentifier(table)+`)`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var columns []string
	for rows.Next() {
		var cid, notNull, primary int
		var name, kind string
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &primary); err != nil {
			return nil, err
		}
		columns = append(columns, name)
	}
	return columns, rows.Err()
}

func quoteIdentifier(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}
