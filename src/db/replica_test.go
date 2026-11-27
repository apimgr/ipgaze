package db

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/apimgr/ipgaze/src/config"
)

func TestDatabaseReplicaSyncReadAndWriteThrough(t *testing.T) {
	primary, err := OpenSQLite(filepath.Join(t.TempDir(), "primary.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = primary.Close() })
	if err := EnsureSchema(primary); err != nil {
		t.Fatal(err)
	}
	if _, err := primary.Exec(`INSERT INTO owners(id) VALUES(?)`, "owner-a"); err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	replica, err := newDatabaseReplica(primary, config.DefaultDatabaseCacheConfig(), root, config.DefaultDatabasePoolConfig())
	if err != nil {
		t.Fatal(err)
	}
	primary.replica = replica
	t.Cleanup(replica.close)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := replica.sync(ctx); err != nil {
		t.Fatalf("sync initial snapshot: %v", err)
	}
	if replica.dirty.Load() {
		t.Fatal("successful sync left cache dirty")
	}
	var owner string
	if err := replica.cache.QueryRow(`SELECT id FROM owners WHERE id=?`, "owner-a").Scan(&owner); err != nil {
		t.Fatalf("read synced owner: %v", err)
	}
	if !replica.useCache(`SELECT id FROM owners WHERE id=?`) {
		t.Fatal("fresh owners table was not cache eligible")
	}
	if err := primary.Write(ctx, func(*sql.Tx) error { return errors.New("rejected remote write") }); err == nil {
		t.Fatal("rejected write unexpectedly succeeded")
	}
	if replica.dirty.Load() || !replica.useCache(`SELECT id FROM owners`) {
		t.Fatal("rejected write changed or invalidated the local cache")
	}
	if replica.useCache(`SELECT key FROM rate_limits`) || replica.useCache(`SELECT value FROM app_secrets`) || replica.useCache(`SELECT * FROM unknown_table`) {
		t.Fatal("excluded or unknown table was cache eligible")
	}

	if _, err := primary.Exec(`UPDATE owners SET last_seen_at=? WHERE id=?`, 123, "owner-a"); err != nil {
		t.Fatalf("write through primary: %v", err)
	}
	var lastSeen int
	if err := replica.cache.QueryRow(`SELECT last_seen_at FROM owners WHERE id=?`, "owner-a").Scan(&lastSeen); err != nil {
		t.Fatalf("read refreshed cache: %v", err)
	}
	if lastSeen != 123 {
		t.Fatalf("cached last_seen_at = %d, want 123", lastSeen)
	}

	replica.maxAge = -time.Second
	if replica.useCache(`SELECT id FROM owners`) {
		t.Fatal("stale table was cache eligible")
	}
	replica.maxAge = time.Hour
	replica.offlineMode = false
	replica.setOffline(true)
	if replica.useCache(`SELECT id FROM owners`) {
		t.Fatal("offline cache was used while offline mode was disabled")
	}
	replica.offlineMode = true
	if !replica.useCache(`SELECT id FROM owners`) {
		t.Fatal("fresh cache was not available in offline mode")
	}
	rows, err := primary.QueryContext(ctx, `SELECT id FROM owners WHERE id=?`, "owner-a")
	if err != nil {
		t.Fatalf("offline read fallback: %v", err)
	}
	if !rows.Next() {
		t.Fatal("offline cache fallback returned no owner")
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(filepath.Join(root, "cache.db"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("cache file permissions = %04o, want 0600", info.Mode().Perm())
	}
	if err := replica.invalidate(); err != nil {
		t.Fatalf("persist dirty state: %v", err)
	}
	replica.close()
	reopened, err := newDatabaseReplica(primary, config.DefaultDatabaseCacheConfig(), root, config.DefaultDatabasePoolConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reopened.close)
	if reopened.hasFreshSnapshot() || reopened.useCache(`SELECT id FROM owners`) {
		t.Fatal("cache with a persisted dirty marker was served after restart")
	}
}

func TestDatabaseReplicaKeepsFreshCacheWhenRemoteSyncFails(t *testing.T) {
	primary, err := OpenSQLite(filepath.Join(t.TempDir(), "primary.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = primary.Close() })
	if err := EnsureSchema(primary); err != nil {
		t.Fatal(err)
	}
	if _, err := primary.Exec(`INSERT INTO owners(id) VALUES(?)`, "owner-a"); err != nil {
		t.Fatal(err)
	}
	replica, err := newDatabaseReplica(primary, config.DefaultDatabaseCacheConfig(), t.TempDir(), config.DefaultDatabasePoolConfig())
	if err != nil {
		t.Fatal(err)
	}
	primary.replica = replica
	t.Cleanup(replica.close)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := replica.sync(ctx); err != nil {
		t.Fatalf("sync initial snapshot: %v", err)
	}
	if err := primary.writeDB.Close(); err != nil {
		t.Fatal(err)
	}
	if err := replica.sync(ctx); err == nil {
		t.Fatal("sync unexpectedly succeeded after the remote writer closed")
	}
	if !replica.offline.Load() || replica.dirty.Load() || !primary.OfflineReadOnly() {
		t.Fatal("remote outage did not preserve a clean offline read-only cache")
	}
	if !replica.useCache(`SELECT id FROM owners`) {
		t.Fatal("fresh cache was bypassed after failed offline sync")
	}
}

func TestDatabaseReplicaRejectsInvalidCachePath(t *testing.T) {
	primary, err := OpenSQLite(filepath.Join(t.TempDir(), "primary.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer primary.Close()
	if err := EnsureSchema(primary); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	path := filepath.Join(root, "not-a-directory")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultDatabaseCacheConfig()
	cfg.Enabled = true
	cfg.Path = filepath.Join(path, "cache.db")
	if _, err := newDatabaseReplica(primary, cfg, root, config.DefaultDatabasePoolConfig()); err == nil {
		t.Fatal("expected invalid cache directory error")
	}
}

func TestDatabaseReplicaDoesNotChangeConfiguredAbsoluteParentPermissions(t *testing.T) {
	primary, err := OpenSQLite(filepath.Join(t.TempDir(), "primary.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer primary.Close()
	if err := EnsureSchema(primary); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultDatabaseCacheConfig()
	cfg.Enabled = true
	cfg.Path = filepath.Join(root, "cache.db")
	if _, err := newDatabaseReplica(primary, cfg, t.TempDir(), config.DefaultDatabasePoolConfig()); err == nil {
		t.Fatal("expected insecure configured cache parent to be rejected")
	}
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("configured cache parent permissions changed to %04o", info.Mode().Perm())
	}
}
