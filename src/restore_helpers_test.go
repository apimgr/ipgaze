package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDirOrFileExists(t *testing.T) {
	dir := t.TempDir()

	t.Run("existing file returns true", func(t *testing.T) {
		f := filepath.Join(dir, "exists.txt")
		if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if !dirOrFileExists(f) {
			t.Error("expected true for existing file")
		}
	})

	t.Run("existing dir returns true", func(t *testing.T) {
		if !dirOrFileExists(dir) {
			t.Error("expected true for existing dir")
		}
	})

	t.Run("missing path returns false", func(t *testing.T) {
		if dirOrFileExists(filepath.Join(dir, "no-such-path")) {
			t.Error("expected false for missing path")
		}
	})
}

func TestRestoreCopyFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.txt")
	dst := filepath.Join(dir, "nested", "dst.txt")

	if err := os.WriteFile(src, []byte("hello world"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := restoreCopyFile(src, dst, 0o640); err != nil {
		t.Fatalf("restoreCopyFile: %v", err)
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read dst: %v", err)
	}
	if string(got) != "hello world" {
		t.Errorf("dst content = %q, want %q", got, "hello world")
	}

	t.Run("missing source returns error", func(t *testing.T) {
		if err := restoreCopyFile(filepath.Join(dir, "missing"), filepath.Join(dir, "out"), 0o600); err == nil {
			t.Error("expected error for missing source file")
		}
	})
}

func TestRestoreCopyDir(t *testing.T) {
	src := t.TempDir()
	dst := filepath.Join(t.TempDir(), "copied")

	if err := os.MkdirAll(filepath.Join(src, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "sub", "b.txt"), []byte("b"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := restoreCopyDir(src, dst); err != nil {
		t.Fatalf("restoreCopyDir: %v", err)
	}

	for _, rel := range []string{"a.txt", filepath.Join("sub", "b.txt")} {
		if _, err := os.Stat(filepath.Join(dst, rel)); err != nil {
			t.Errorf("expected %s to exist in copy: %v", rel, err)
		}
	}
}

func TestRestoreMoveDir(t *testing.T) {
	t.Run("same filesystem rename", func(t *testing.T) {
		root := t.TempDir()
		src := filepath.Join(root, "src")
		dst := filepath.Join(root, "dst", "nested")
		if err := os.MkdirAll(src, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(src, "f.txt"), []byte("f"), 0o644); err != nil {
			t.Fatal(err)
		}

		if err := restoreMoveDir(src, dst); err != nil {
			t.Fatalf("restoreMoveDir: %v", err)
		}
		if _, err := os.Stat(filepath.Join(dst, "f.txt")); err != nil {
			t.Errorf("expected file moved into dst: %v", err)
		}
		if _, err := os.Stat(src); !os.IsNotExist(err) {
			t.Error("expected src to no longer exist after move")
		}
	})
}

func TestRestoreReplaceDir(t *testing.T) {
	t.Run("no existing dst just moves src in", func(t *testing.T) {
		root := t.TempDir()
		src := filepath.Join(root, "src")
		dst := filepath.Join(root, "dst")
		if err := os.MkdirAll(src, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(src, "new.txt"), []byte("new"), 0o644); err != nil {
			t.Fatal(err)
		}

		if err := restoreReplaceDir(src, dst); err != nil {
			t.Fatalf("restoreReplaceDir: %v", err)
		}
		if _, err := os.Stat(filepath.Join(dst, "new.txt")); err != nil {
			t.Errorf("expected new.txt in replaced dst: %v", err)
		}
	})

	t.Run("existing dst is replaced with new content", func(t *testing.T) {
		root := t.TempDir()
		src := filepath.Join(root, "src")
		dst := filepath.Join(root, "dst")
		if err := os.MkdirAll(src, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(dst, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, "old.txt"), []byte("old"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(src, "new.txt"), []byte("new"), 0o644); err != nil {
			t.Fatal(err)
		}

		if err := restoreReplaceDir(src, dst); err != nil {
			t.Fatalf("restoreReplaceDir: %v", err)
		}
		if _, err := os.Stat(filepath.Join(dst, "new.txt")); err != nil {
			t.Errorf("expected new.txt in replaced dst: %v", err)
		}
		if _, err := os.Stat(filepath.Join(dst, "old.txt")); !os.IsNotExist(err) {
			t.Error("expected old.txt to be gone after replace")
		}
		if _, err := os.Stat(dst + ".restore-old"); !os.IsNotExist(err) {
			t.Error("expected .restore-old cleanup after successful replace")
		}
	})
}
