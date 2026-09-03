package path

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func mkTempBase(t *testing.T) string {
	t.Helper()
	os.MkdirAll(filepath.Join(os.TempDir(), "apimgr"), 0755)
	base, err := os.MkdirTemp(filepath.Join(os.TempDir(), "apimgr"), "ipgaze-pid-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	return base
}

func TestWritePIDFile_CreatesFile(t *testing.T) {
	base := mkTempBase(t)
	pidPath := filepath.Join(base, "sub", "test.pid")

	if err := WritePIDFile(pidPath); err != nil {
		t.Fatalf("WritePIDFile() error = %v", err)
	}
	data, err := os.ReadFile(pidPath)
	if err != nil {
		t.Fatalf("pid file not readable: %v", err)
	}
	pid, err := strconv.Atoi(string(data[:len(data)-1]))
	if err != nil {
		t.Fatalf("pid file content not a number: %q", data)
	}
	if pid != os.Getpid() {
		t.Errorf("pid file contains %d, want %d", pid, os.Getpid())
	}
}

func TestCheckPIDFile_NoFile(t *testing.T) {
	base := mkTempBase(t)
	pidPath := filepath.Join(base, "nonexistent.pid")

	running, pid, err := CheckPIDFile(pidPath)
	if err != nil {
		t.Errorf("CheckPIDFile(nonexistent) error = %v, want nil", err)
	}
	if running {
		t.Errorf("CheckPIDFile(nonexistent) running = true, want false")
	}
	if pid != 0 {
		t.Errorf("CheckPIDFile(nonexistent) pid = %d, want 0", pid)
	}
}

func TestCheckPIDFile_StalePID(t *testing.T) {
	base := mkTempBase(t)
	pidPath := filepath.Join(base, "stale.pid")

	// PID 999999999 is virtually guaranteed to not exist
	if err := os.WriteFile(pidPath, []byte("999999999\n"), 0644); err != nil {
		t.Fatal(err)
	}

	running, _, err := CheckPIDFile(pidPath)
	if err != nil {
		t.Errorf("CheckPIDFile(stale) error = %v, want nil", err)
	}
	if running {
		t.Errorf("CheckPIDFile(stale) running = true, want false (stale PID)")
	}

	// Stale PID file should have been removed
	if _, err := os.Stat(pidPath); !os.IsNotExist(err) {
		t.Error("CheckPIDFile should have removed the stale PID file")
	}
}

func TestCheckPIDFile_RunningProcess(t *testing.T) {
	base := mkTempBase(t)
	pidPath := filepath.Join(base, "running.pid")

	// Write the current process PID — it IS running
	if err := os.WriteFile(pidPath, []byte(strconv.Itoa(os.Getpid())+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// isOurProcess checks /proc/{pid}/exe; since we're in test the binary is the test binary.
	// CheckPIDFile returns (true, pid, nil) if running and our process, or (false, 0, nil) if not
	// recognized as our binary. Either way, no error.
	_, _, err := CheckPIDFile(pidPath)
	if err != nil {
		t.Errorf("CheckPIDFile(current PID) unexpected error = %v", err)
	}
}

func TestCheckPIDFile_CorruptContent(t *testing.T) {
	base := mkTempBase(t)
	pidPath := filepath.Join(base, "corrupt.pid")

	if err := os.WriteFile(pidPath, []byte("not-a-number\n"), 0644); err != nil {
		t.Fatal(err)
	}

	running, _, err := CheckPIDFile(pidPath)
	if err != nil {
		t.Errorf("CheckPIDFile(corrupt) error = %v, want nil (corrupt files are removed)", err)
	}
	if running {
		t.Errorf("CheckPIDFile(corrupt) running = true, want false")
	}

	// Corrupt PID file should have been removed
	if _, err := os.Stat(pidPath); !os.IsNotExist(err) {
		t.Error("CheckPIDFile should have removed the corrupt PID file")
	}
}

func TestRemovePIDFile_OwnProcess(t *testing.T) {
	base := mkTempBase(t)
	pidPath := filepath.Join(base, "own.pid")

	if err := WritePIDFile(pidPath); err != nil {
		t.Fatal(err)
	}

	if err := RemovePIDFile(pidPath); err != nil {
		t.Errorf("RemovePIDFile() error = %v", err)
	}

	if _, err := os.Stat(pidPath); !os.IsNotExist(err) {
		t.Error("RemovePIDFile should have deleted the PID file")
	}
}

func TestRemovePIDFile_NoFile(t *testing.T) {
	base := mkTempBase(t)
	pidPath := filepath.Join(base, "nonexistent.pid")

	if err := RemovePIDFile(pidPath); err != nil {
		t.Errorf("RemovePIDFile(nonexistent) = %v, want nil", err)
	}
}

func TestRemovePIDFile_OtherProcess(t *testing.T) {
	base := mkTempBase(t)
	pidPath := filepath.Join(base, "other.pid")

	// Write a different PID
	if err := os.WriteFile(pidPath, []byte("1\n"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := RemovePIDFile(pidPath); err != nil {
		t.Errorf("RemovePIDFile(other process) = %v, want nil", err)
	}

	// File should NOT be removed (it belongs to another process)
	if _, err := os.Stat(pidPath); os.IsNotExist(err) {
		t.Error("RemovePIDFile should NOT remove PID file belonging to another process")
	}
}

func TestDirOf_WithSlash(t *testing.T) {
	got := dirOf("/foo/bar/baz")
	if got != "/foo/bar" {
		t.Errorf("dirOf(/foo/bar/baz) = %q, want %q", got, "/foo/bar")
	}
}

func TestDirOf_NoSlash(t *testing.T) {
	got := dirOf("filename")
	if got != "." {
		t.Errorf("dirOf(filename) = %q, want %q", got, ".")
	}
}

func TestDirOf_TrailingSlash(t *testing.T) {
	got := dirOf("/foo/bar/")
	if got != "/foo/bar" {
		t.Errorf("dirOf(/foo/bar/) = %q, want %q", got, "/foo/bar")
	}
}

func TestIsProcessRunning_NegativePID(t *testing.T) {
	if isProcessRunning(-1) {
		t.Error("isProcessRunning(-1) should return false")
	}
}

func TestIsProcessRunning_ZeroPID(t *testing.T) {
	if isProcessRunning(0) {
		t.Error("isProcessRunning(0) should return false")
	}
}

func TestIsProcessRunning_CurrentProcess(t *testing.T) {
	if !isProcessRunning(os.Getpid()) {
		t.Error("isProcessRunning(current PID) should return true")
	}
}

func TestWritePIDFile_UserModePermissions(t *testing.T) {
	prev := testForceNonRoot
	defer func() { testForceNonRoot = prev }()
	testForceNonRoot = true

	pidPath := filepath.Join(t.TempDir(), "run", "ipgaze.pid")
	if err := WritePIDFile(pidPath); err != nil {
		t.Fatalf("WritePIDFile() error = %v", err)
	}
	defer os.Remove(pidPath)

	fi, err := os.Stat(pidPath)
	if err != nil {
		t.Fatalf("stat pid file: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("pid file mode = %#o, want 0600", got)
	}

	di, err := os.Stat(filepath.Dir(pidPath))
	if err != nil {
		t.Fatalf("stat pid dir: %v", err)
	}
	if got := di.Mode().Perm(); got != 0o700 {
		t.Errorf("pid dir mode = %#o, want 0700", got)
	}
}

func TestWritePIDFile_SystemModePermissions(t *testing.T) {
	prev := testForceNonRoot
	defer func() { testForceNonRoot = prev }()
	testForceNonRoot = false
	if !isElevated() {
		t.Skip("test binary is not running elevated")
	}

	pidPath := filepath.Join(t.TempDir(), "run", "ipgaze.pid")
	if err := WritePIDFile(pidPath); err != nil {
		t.Fatalf("WritePIDFile() error = %v", err)
	}
	defer os.Remove(pidPath)

	fi, err := os.Stat(pidPath)
	if err != nil {
		t.Fatalf("stat pid file: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o644 {
		t.Errorf("pid file mode = %#o, want 0644", got)
	}
}
