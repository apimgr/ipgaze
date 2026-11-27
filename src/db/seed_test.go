package db

import (
	"context"
	"path/filepath"
	"testing"
)

func TestSeedFromSQLiteCopiesTablesIntoInitializedTarget(t *testing.T) {
	backupPath := filepath.Join(t.TempDir(), "server.db")
	source, err := OpenSQLite(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := EnsureSchema(source); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Exec(`INSERT INTO owners(id) VALUES('restored-owner')`); err != nil {
		t.Fatal(err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}

	target, err := OpenSQLite(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = target.Close() })
	if err := EnsureSchema(target); err != nil {
		t.Fatal(err)
	}
	if err := target.SeedFromSQLite(context.Background(), backupPath); err != nil {
		t.Fatalf("SeedFromSQLite: %v", err)
	}
	var count int
	if err := target.QueryRow(`SELECT COUNT(*) FROM owners WHERE id = 'restored-owner'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("restored owner count = %d, want 1", count)
	}
}
