//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckFilePermissions(t *testing.T) {
	dir := t.TempDir()

	t.Run("missing file returns nil", func(t *testing.T) {
		if err := checkFilePermissions(filepath.Join(dir, "no-such-file")); err != nil {
			t.Errorf("expected nil for missing file, got %v", err)
		}
	})

	t.Run("secure 0600 permissions returns nil", func(t *testing.T) {
		f := filepath.Join(dir, "secure.yml")
		if err := os.WriteFile(f, []byte("token: x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := checkFilePermissions(f); err != nil {
			t.Errorf("expected nil for 0600 file, got %v", err)
		}
	})

	t.Run("insecure permissions returns error", func(t *testing.T) {
		f := filepath.Join(dir, "insecure.yml")
		if err := os.WriteFile(f, []byte("token: x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := checkFilePermissions(f); err == nil {
			t.Error("expected error for 0644 file")
		}
	})
}
