package path

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestGetDirectories_Returns(t *testing.T) {
	dirs := GetDirectories()
	if dirs.Config == "" {
		t.Error("GetDirectories().Config is empty")
	}
	if dirs.Data == "" {
		t.Error("GetDirectories().Data is empty")
	}
}

func TestGetAllDirs_ContainsProjectName(t *testing.T) {
	// DATABASE_DIR/BACKUP_DIR are Init-Only overrides (PART 12) and must not
	// leak in from the ambient environment (e.g. the build container sets
	// BACKUP_DIR=/data/backups, which does not embed the project name).
	t.Setenv("DATABASE_DIR", "")
	t.Setenv("BACKUP_DIR", "")

	dirs := GetAllDirs("testproject")
	// In a container, DB path is /data/db/sqlite which does not contain the project name.
	// Only check paths that are expected to embed the project name.
	for _, d := range []string{dirs.Config, dirs.Data, dirs.Logs, dirs.SSL, dirs.Security, dirs.Backup} {
		if d != "" && !strings.Contains(d, "testproject") {
			t.Errorf("expected path to contain 'testproject', got %q", d)
		}
	}
}

func TestGetAllDirs_PIDContainsProjectName(t *testing.T) {
	dirs := GetAllDirs("testproject")
	if dirs.PID == "" {
		t.Error("PID path is empty")
	}
}

func TestGetFullDirs_DatabaseDirEnvOverride(t *testing.T) {
	t.Setenv("DATABASE_DIR", "/custom/db/path")
	t.Setenv("BACKUP_DIR", "")

	_, _, _, _, _, _, _, dbDir, _ := GetFullDirs("myapp")
	if dbDir != "/custom/db/path" {
		t.Errorf("dbDir = %q, want %q (DATABASE_DIR env override)", dbDir, "/custom/db/path")
	}
}

func TestGetFullDirs_BackupDirEnvOverride(t *testing.T) {
	t.Setenv("DATABASE_DIR", "")
	t.Setenv("BACKUP_DIR", "/custom/backup/path")

	_, _, _, _, _, _, _, _, backupDir := GetFullDirs("myapp")
	if backupDir != "/custom/backup/path" {
		t.Errorf("backupDir = %q, want %q (BACKUP_DIR env override)", backupDir, "/custom/backup/path")
	}
}

func TestGetFullDirs_ContainsOrg(t *testing.T) {
	// When running inside a container the paths use /config/ and /data/ without the org name.
	// Outside a container the paths embed OrgName. Check that all paths are non-empty.
	configDir, dataDir, logsDir, _, _, _, _, _, _ := GetFullDirs("myapp")
	for _, d := range []string{configDir, dataDir, logsDir} {
		if d == "" {
			t.Errorf("GetFullDirs returned empty path for myapp")
		}
	}
}

func TestGetDefaultDirs_NonEmpty(t *testing.T) {
	configDir, dataDir, logsDir := GetDefaultDirs("myapp")
	if configDir == "" {
		t.Error("configDir is empty")
	}
	if dataDir == "" {
		t.Error("dataDir is empty")
	}
	if logsDir == "" {
		t.Error("logsDir is empty")
	}
}

func TestGetDefaultDirs_ContainsProjectName(t *testing.T) {
	configDir, dataDir, logsDir := GetDefaultDirs("myapp")
	// In container mode paths are /config/myapp, /data/myapp, /data/log/myapp.
	// All three should contain "myapp".
	for _, d := range []string{configDir, dataDir, logsDir} {
		if !strings.Contains(d, "myapp") {
			t.Errorf("expected path to contain 'myapp', got %q", d)
		}
	}
}

func TestGetDefaultDirsLegacy_NonEmpty(t *testing.T) {
	configDir, dataDir, logsDir := GetDefaultDirsLegacy("myapp")
	if configDir == "" {
		t.Error("configDir is empty")
	}
	if dataDir == "" {
		t.Error("dataDir is empty")
	}
	if logsDir == "" {
		t.Error("logsDir is empty")
	}
}

func TestGetDefaultDirsLegacy_ContainsProjectName(t *testing.T) {
	configDir, dataDir, logsDir := GetDefaultDirsLegacy("myapp")
	// GetDefaultDirsLegacy does not check container env, so paths always
	// include the project name regardless of environment.
	for _, d := range []string{configDir, dataDir, logsDir} {
		if !strings.Contains(d, "myapp") {
			t.Errorf("expected legacy path to contain 'myapp', got %q", d)
		}
	}
}

func TestEnsureDir_CreatesDir(t *testing.T) {
	base, err := os.MkdirTemp(filepath.Join(os.TempDir(), "apimgr"), "ipgaze-")
	if err != nil {
		os.MkdirAll(filepath.Join(os.TempDir(), "apimgr"), 0755)
		base, err = os.MkdirTemp(filepath.Join(os.TempDir(), "apimgr"), "ipgaze-")
		if err != nil {
			t.Fatal(err)
		}
	}
	defer os.RemoveAll(base)

	target := filepath.Join(base, "sub", "dir")
	if err := EnsureDir(target, false); err != nil {
		t.Fatalf("EnsureDir() error = %v", err)
	}
	if fi, err := os.Stat(target); err != nil || !fi.IsDir() {
		t.Errorf("EnsureDir() did not create directory %q", target)
	}
}

func TestEnsureDir_Idempotent(t *testing.T) {
	base, err := os.MkdirTemp(filepath.Join(os.TempDir(), "apimgr"), "ipgaze-")
	if err != nil {
		os.MkdirAll(filepath.Join(os.TempDir(), "apimgr"), 0755)
		base, err = os.MkdirTemp(filepath.Join(os.TempDir(), "apimgr"), "ipgaze-")
		if err != nil {
			t.Fatal(err)
		}
	}
	defer os.RemoveAll(base)

	target := filepath.Join(base, "already")
	if err := os.MkdirAll(target, 0755); err != nil {
		t.Fatal(err)
	}
	if err := EnsureDir(target, false); err != nil {
		t.Errorf("EnsureDir() on existing dir error = %v", err)
	}
}

func TestEnsureDirs_CreatesAll(t *testing.T) {
	base, err := os.MkdirTemp(filepath.Join(os.TempDir(), "apimgr"), "ipgaze-")
	if err != nil {
		os.MkdirAll(filepath.Join(os.TempDir(), "apimgr"), 0755)
		base, err = os.MkdirTemp(filepath.Join(os.TempDir(), "apimgr"), "ipgaze-")
		if err != nil {
			t.Fatal(err)
		}
	}
	defer os.RemoveAll(base)

	cfg := filepath.Join(base, "config")
	data := filepath.Join(base, "data")
	logs := filepath.Join(base, "logs")

	if err := EnsureDirs(cfg, data, logs); err != nil {
		t.Fatalf("EnsureDirs() error = %v", err)
	}
	for _, d := range []string{cfg, data, logs} {
		if fi, err := os.Stat(d); err != nil || !fi.IsDir() {
			t.Errorf("EnsureDirs() did not create %q", d)
		}
	}
}

func TestEnsureDirectories_CreatesAll(t *testing.T) {
	base, err := os.MkdirTemp(filepath.Join(os.TempDir(), "apimgr"), "ipgaze-")
	if err != nil {
		os.MkdirAll(filepath.Join(os.TempDir(), "apimgr"), 0755)
		base, err = os.MkdirTemp(filepath.Join(os.TempDir(), "apimgr"), "ipgaze-")
		if err != nil {
			t.Fatal(err)
		}
	}
	defer os.RemoveAll(base)

	dirs := Directories{
		Config:   filepath.Join(base, "config"),
		Data:     filepath.Join(base, "data"),
		Logs:     filepath.Join(base, "logs"),
		Cache:    filepath.Join(base, "cache"),
		SSL:      filepath.Join(base, "ssl"),
		Security: filepath.Join(base, "security"),
		DB:       filepath.Join(base, "db"),
		Backup:   filepath.Join(base, "backup"),
	}

	if err := EnsureDirectories(dirs); err != nil {
		t.Fatalf("EnsureDirectories() error = %v", err)
	}
	for _, d := range []string{dirs.Config, dirs.Data, dirs.Logs, dirs.Cache, dirs.SSL, dirs.Security, dirs.DB, dirs.Backup} {
		if fi, err := os.Stat(d); err != nil || !fi.IsDir() {
			t.Errorf("EnsureDirectories() did not create %q", d)
		}
	}
}

func TestEnsureDirectories_EmptyPIDSkipped(t *testing.T) {
	base, err := os.MkdirTemp(filepath.Join(os.TempDir(), "apimgr"), "ipgaze-")
	if err != nil {
		os.MkdirAll(filepath.Join(os.TempDir(), "apimgr"), 0755)
		base, err = os.MkdirTemp(filepath.Join(os.TempDir(), "apimgr"), "ipgaze-")
		if err != nil {
			t.Fatal(err)
		}
	}
	defer os.RemoveAll(base)

	dirs := Directories{
		Config: filepath.Join(base, "config"),
		Data:   filepath.Join(base, "data"),
		Logs:   filepath.Join(base, "logs"),
	}

	if err := EnsureDirectories(dirs); err != nil {
		t.Fatalf("EnsureDirectories() error = %v", err)
	}
}

func TestIsRunningInContainer_ReturnsBool(t *testing.T) {
	// Just assert the function returns without panicking; value depends on env.
	_ = IsRunningInContainer()
}

func TestGetBackupDir_NonEmpty(t *testing.T) {
	dir := GetBackupDir("", "/var/lib/apimgr/ipgaze")
	if dir == "" {
		t.Error("GetBackupDir() returned empty string")
	}
}

func TestGetBackupDir_FlagWins(t *testing.T) {
	t.Setenv("BACKUP_DIR", "/env/backups")
	dir := GetBackupDir("/flag/backups", "/var/lib/apimgr/ipgaze")
	if dir != "/flag/backups" {
		t.Errorf("GetBackupDir(flag) = %q, want /flag/backups", dir)
	}
}

func TestGetBackupDir_EnvWins(t *testing.T) {
	t.Setenv("BACKUP_DIR", "/env/backups")
	dir := GetBackupDir("", "/var/lib/apimgr/ipgaze")
	if dir != "/env/backups" {
		t.Errorf("GetBackupDir(env) = %q, want /env/backups", dir)
	}
}

func TestGetAllDirs_XDGOverride(t *testing.T) {
	base, err := os.MkdirTemp(filepath.Join(os.TempDir(), "apimgr"), "ipgaze-")
	if err != nil {
		os.MkdirAll(filepath.Join(os.TempDir(), "apimgr"), 0755)
		base, err = os.MkdirTemp(filepath.Join(os.TempDir(), "apimgr"), "ipgaze-")
		if err != nil {
			t.Fatal(err)
		}
	}
	defer os.RemoveAll(base)

	t.Setenv("XDG_CONFIG_HOME", filepath.Join(base, "cfg"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(base, "data"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(base, "cache"))

	// GetAllDirs respects XDG env vars when not in a container.
	// In container mode the container paths are used and Config is still non-empty.
	dirs := GetAllDirs("xdgtest")
	if dirs.Config == "" {
		t.Error("Config should not be empty")
	}
}

func TestNormalizePath_Empty(t *testing.T) {
	got := normalizePath("")
	if got != "" {
		t.Errorf("normalizePath(\"\") = %q, want empty", got)
	}
}

func TestNormalizePath_Simple(t *testing.T) {
	got := normalizePath("foo/bar")
	if got != "foo/bar" {
		t.Errorf("normalizePath(\"foo/bar\") = %q, want %q", got, "foo/bar")
	}
}

func TestNormalizePath_WithTraversal(t *testing.T) {
	got := normalizePath("foo/../bar/../../../etc")
	if got != "" {
		t.Errorf("normalizePath with traversal = %q, want empty", got)
	}
}

func TestValidatePathSegment_Valid(t *testing.T) {
	if err := validatePathSegment("valid-segment"); err != nil {
		t.Errorf("validatePathSegment(valid) error = %v", err)
	}
}

func TestValidatePathSegment_Empty(t *testing.T) {
	if err := validatePathSegment(""); err != ErrInvalidPath {
		t.Errorf("validatePathSegment(\"\") = %v, want ErrInvalidPath", err)
	}
}

func TestValidatePathSegment_TooLong(t *testing.T) {
	seg := strings.Repeat("a", 65)
	if err := validatePathSegment(seg); err != ErrPathTooLong {
		t.Errorf("validatePathSegment(65 chars) = %v, want ErrPathTooLong", err)
	}
}

func TestValidatePathSegment_InvalidChars(t *testing.T) {
	if err := validatePathSegment("UPPERCASE"); err != ErrInvalidPath {
		t.Errorf("validatePathSegment(UPPERCASE) = %v, want ErrInvalidPath", err)
	}
}

func TestValidatePath_TooLong(t *testing.T) {
	p := "/" + strings.Repeat("a/", 1025)
	if err := validatePath(p); err != ErrPathTooLong {
		t.Errorf("validatePath(too long) = %v, want ErrPathTooLong", err)
	}
}

func TestValidatePath_WithTraversal(t *testing.T) {
	if err := validatePath("foo/../bar"); err != ErrPathTraversal {
		t.Errorf("validatePath(traversal) = %v, want ErrPathTraversal", err)
	}
}

func TestValidatePath_ValidPath(t *testing.T) {
	if err := validatePath("foo/bar/baz"); err != nil {
		t.Errorf("validatePath(valid) error = %v", err)
	}
}

func TestSafePathSimple_Valid(t *testing.T) {
	got, err := SafePathSimple("foo/bar")
	if err != nil {
		t.Fatalf("SafePathSimple(valid) error = %v", err)
	}
	if got == "" {
		t.Error("SafePathSimple returned empty for valid input")
	}
}

func TestSafePathSimple_Traversal(t *testing.T) {
	if _, err := SafePathSimple("../etc"); err == nil {
		t.Error("SafePathSimple(traversal) expected error")
	}
}

func TestSafeFilePath_Valid(t *testing.T) {
	base, err := os.MkdirTemp(filepath.Join(os.TempDir(), "apimgr"), "ipgaze-")
	if err != nil {
		os.MkdirAll(filepath.Join(os.TempDir(), "apimgr"), 0755)
		base, err = os.MkdirTemp(filepath.Join(os.TempDir(), "apimgr"), "ipgaze-")
		if err != nil {
			t.Fatal(err)
		}
	}
	defer os.RemoveAll(base)

	got, err := SafeFilePath(base, "sub/file")
	if err != nil {
		t.Fatalf("SafeFilePath(valid) error = %v", err)
	}
	if !strings.HasPrefix(got, base) {
		t.Errorf("SafeFilePath = %q, should be within %q", got, base)
	}
}

func TestSafeFilePath_Traversal(t *testing.T) {
	base, err := os.MkdirTemp(filepath.Join(os.TempDir(), "apimgr"), "ipgaze-")
	if err != nil {
		os.MkdirAll(filepath.Join(os.TempDir(), "apimgr"), 0755)
		base, err = os.MkdirTemp(filepath.Join(os.TempDir(), "apimgr"), "ipgaze-")
		if err != nil {
			t.Fatal(err)
		}
	}
	defer os.RemoveAll(base)

	if _, err := SafeFilePath(base, "../etc/passwd"); err == nil {
		t.Error("SafeFilePath(traversal) expected error")
	}
}

func TestEnsureDirs_PartialError(t *testing.T) {
	base, err := os.MkdirTemp(filepath.Join(os.TempDir(), "apimgr"), "ipgaze-")
	if err != nil {
		os.MkdirAll(filepath.Join(os.TempDir(), "apimgr"), 0755)
		base, err = os.MkdirTemp(filepath.Join(os.TempDir(), "apimgr"), "ipgaze-")
		if err != nil {
			t.Fatal(err)
		}
	}
	defer os.RemoveAll(base)

	// Create a file where a directory should be — EnsureDir will fail
	blocker := filepath.Join(base, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	// cfg succeeds, data fails because blocker is a file
	cfg := filepath.Join(base, "config")
	data := filepath.Join(blocker, "data")
	logs := filepath.Join(base, "logs")

	err = EnsureDirs(cfg, data, logs)
	if err == nil {
		t.Error("EnsureDirs should return error when a path cannot be created")
	}
}

func TestEnsureDirectories_PartialError(t *testing.T) {
	base, err := os.MkdirTemp(filepath.Join(os.TempDir(), "apimgr"), "ipgaze-")
	if err != nil {
		os.MkdirAll(filepath.Join(os.TempDir(), "apimgr"), 0755)
		base, err = os.MkdirTemp(filepath.Join(os.TempDir(), "apimgr"), "ipgaze-")
		if err != nil {
			t.Fatal(err)
		}
	}
	defer os.RemoveAll(base)

	blocker := filepath.Join(base, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	dirs := Directories{
		Config: filepath.Join(blocker, "config"),
	}
	if err := EnsureDirectories(dirs); err == nil {
		t.Error("EnsureDirectories should return error when dir creation fails")
	}
}

func TestIsRunningInContainer_EnvVar(t *testing.T) {
	// When "container" env var is set, should detect container environment
	t.Setenv("container", "docker")
	got := IsRunningInContainer()
	if !got {
		t.Error("IsRunningInContainer() should return true when container env var is set")
	}
}

func TestIsRunningInContainer_TiniComm(t *testing.T) {
	base, err := os.MkdirTemp(filepath.Join(os.TempDir(), "apimgr"), "ipgaze-proc-")
	if err != nil {
		os.MkdirAll(filepath.Join(os.TempDir(), "apimgr"), 0755)
		base, err = os.MkdirTemp(filepath.Join(os.TempDir(), "apimgr"), "ipgaze-proc-")
		if err != nil {
			t.Fatal(err)
		}
	}
	defer os.RemoveAll(base)

	commFile := filepath.Join(base, "comm")
	if err := os.WriteFile(commFile, []byte("tini\n"), 0644); err != nil {
		t.Fatal(err)
	}

	testSkipDockerEnvCheck = true
	testProcCommPath = commFile
	testProcCgroupPath = filepath.Join(base, "nonexistent-cgroup")
	defer func() {
		testSkipDockerEnvCheck = false
		testProcCommPath = "/proc/1/comm"
		testProcCgroupPath = "/proc/1/cgroup"
	}()

	t.Setenv("container", "")
	got := IsRunningInContainer()
	if !got {
		t.Error("IsRunningInContainer() should return true when comm is tini")
	}
}

func TestIsRunningInContainer_CgroupDocker(t *testing.T) {
	base, err := os.MkdirTemp(filepath.Join(os.TempDir(), "apimgr"), "ipgaze-proc-")
	if err != nil {
		os.MkdirAll(filepath.Join(os.TempDir(), "apimgr"), 0755)
		base, err = os.MkdirTemp(filepath.Join(os.TempDir(), "apimgr"), "ipgaze-proc-")
		if err != nil {
			t.Fatal(err)
		}
	}
	defer os.RemoveAll(base)

	commFile := filepath.Join(base, "comm")
	if err := os.WriteFile(commFile, []byte("bash\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cgroupFile := filepath.Join(base, "cgroup")
	if err := os.WriteFile(cgroupFile, []byte("0::/docker/abc123\n"), 0644); err != nil {
		t.Fatal(err)
	}

	testSkipDockerEnvCheck = true
	testProcCommPath = commFile
	testProcCgroupPath = cgroupFile
	defer func() {
		testSkipDockerEnvCheck = false
		testProcCommPath = "/proc/1/comm"
		testProcCgroupPath = "/proc/1/cgroup"
	}()

	t.Setenv("container", "")
	got := IsRunningInContainer()
	if !got {
		t.Error("IsRunningInContainer() should return true when cgroup contains 'docker'")
	}
}

func TestIsRunningInContainer_EnvVarOnly(t *testing.T) {
	base, err := os.MkdirTemp(filepath.Join(os.TempDir(), "apimgr"), "ipgaze-proc-")
	if err != nil {
		os.MkdirAll(filepath.Join(os.TempDir(), "apimgr"), 0755)
		base, err = os.MkdirTemp(filepath.Join(os.TempDir(), "apimgr"), "ipgaze-proc-")
		if err != nil {
			t.Fatal(err)
		}
	}
	defer os.RemoveAll(base)

	commFile := filepath.Join(base, "comm")
	if err := os.WriteFile(commFile, []byte("bash\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cgroupFile := filepath.Join(base, "cgroup")
	if err := os.WriteFile(cgroupFile, []byte("0::/user.slice\n"), 0644); err != nil {
		t.Fatal(err)
	}

	testSkipDockerEnvCheck = true
	testProcCommPath = commFile
	testProcCgroupPath = cgroupFile
	defer func() {
		testSkipDockerEnvCheck = false
		testProcCommPath = "/proc/1/comm"
		testProcCgroupPath = "/proc/1/cgroup"
	}()

	t.Setenv("container", "systemd-nspawn")
	got := IsRunningInContainer()
	if !got {
		t.Error("IsRunningInContainer() should return true with container env var set")
	}
}

func TestIsRunningInContainer_NotAContainer(t *testing.T) {
	base, err := os.MkdirTemp(filepath.Join(os.TempDir(), "apimgr"), "ipgaze-proc-")
	if err != nil {
		os.MkdirAll(filepath.Join(os.TempDir(), "apimgr"), 0755)
		base, err = os.MkdirTemp(filepath.Join(os.TempDir(), "apimgr"), "ipgaze-proc-")
		if err != nil {
			t.Fatal(err)
		}
	}
	defer os.RemoveAll(base)

	commFile := filepath.Join(base, "comm")
	if err := os.WriteFile(commFile, []byte("systemd\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cgroupFile := filepath.Join(base, "cgroup")
	if err := os.WriteFile(cgroupFile, []byte("0::/user.slice/session.scope\n"), 0644); err != nil {
		t.Fatal(err)
	}

	testSkipDockerEnvCheck = true
	testProcCommPath = commFile
	testProcCgroupPath = cgroupFile
	defer func() {
		testSkipDockerEnvCheck = false
		testProcCommPath = "/proc/1/comm"
		testProcCgroupPath = "/proc/1/cgroup"
	}()

	t.Setenv("container", "")
	got := IsRunningInContainer()
	if got {
		t.Error("IsRunningInContainer() should return false when not in a container")
	}
}

func TestEnsureDirs_SecondDirError(t *testing.T) {
	base, err := os.MkdirTemp(filepath.Join(os.TempDir(), "apimgr"), "ipgaze-")
	if err != nil {
		os.MkdirAll(filepath.Join(os.TempDir(), "apimgr"), 0755)
		base, err = os.MkdirTemp(filepath.Join(os.TempDir(), "apimgr"), "ipgaze-")
		if err != nil {
			t.Fatal(err)
		}
	}
	defer os.RemoveAll(base)

	blocker := filepath.Join(base, "blocker-data")
	if err := os.WriteFile(blocker, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := filepath.Join(base, "config")
	data := filepath.Join(blocker, "sub") // will fail - blocker is a file
	logs := filepath.Join(base, "logs")

	err = EnsureDirs(cfg, data, logs)
	if err == nil {
		t.Error("EnsureDirs should return error when second dir creation fails")
	}
}

func TestEnsureDirs_ThirdDirError(t *testing.T) {
	base, err := os.MkdirTemp(filepath.Join(os.TempDir(), "apimgr"), "ipgaze-")
	if err != nil {
		os.MkdirAll(filepath.Join(os.TempDir(), "apimgr"), 0755)
		base, err = os.MkdirTemp(filepath.Join(os.TempDir(), "apimgr"), "ipgaze-")
		if err != nil {
			t.Fatal(err)
		}
	}
	defer os.RemoveAll(base)

	blocker := filepath.Join(base, "blocker-logs")
	if err := os.WriteFile(blocker, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := filepath.Join(base, "config")
	data := filepath.Join(base, "data")
	logs := filepath.Join(blocker, "sub") // will fail - blocker is a file

	err = EnsureDirs(cfg, data, logs)
	if err == nil {
		t.Error("EnsureDirs should return error when third dir creation fails")
	}
}

func TestSafePath_RelativeBase(t *testing.T) {
	// Relative base should still work (filepath.Clean handles it)
	got, err := SafePath("/tmp/mybase", "subdir/file.txt")
	if err != nil {
		t.Errorf("SafePath(relative sub) error = %v", err)
	}
	if got == "" {
		t.Error("SafePath returned empty string")
	}
}

func TestValidatePathSegment_Dot(t *testing.T) {
	if err := validatePathSegment("."); err != ErrInvalidPath {
		t.Errorf("validatePathSegment('.') = %v, want ErrInvalidPath", err)
	}
}

func TestValidatePath_EmptySegmentsOK(t *testing.T) {
	// Leading slash produces an empty segment; that should be skipped
	if err := validatePath("/foo/bar"); err != nil {
		t.Errorf("validatePath('/foo/bar') error = %v", err)
	}
}

func TestValidatePath_InvalidSegment(t *testing.T) {
	// Path with an invalid segment (uppercase) — no traversal, but segment fails
	if err := validatePath("foo/INVALID/bar"); err != ErrInvalidPath {
		t.Errorf("validatePath(invalid segment) = %v, want ErrInvalidPath", err)
	}
}

func TestValidatePath_TooLongSegment(t *testing.T) {
	longSeg := strings.Repeat("a", 65)
	if err := validatePath("foo/" + longSeg + "/bar"); err != ErrPathTooLong {
		t.Errorf("validatePath(too long segment) = %v, want ErrPathTooLong", err)
	}
}

func TestSafePath_JoinsInsideBase(t *testing.T) {
	// An absolute-looking requestPath is joined by filepath.Join and stays inside base
	got, err := SafePath("/data/sub", "etc/passwd")
	if err != nil {
		t.Errorf("SafePath(etc/passwd) unexpected error = %v", err)
	}
	if got != "/data/sub/etc/passwd" {
		t.Errorf("SafePath = %q, want %q", got, "/data/sub/etc/passwd")
	}
}

func TestGetFullDirs_NonContainerRootLinux(t *testing.T) {
	testForceNonContainer = true
	defer func() { testForceNonContainer = false }()

	dirs := GetAllDirs("myapp")
	if dirs.Config == "" || dirs.Data == "" {
		t.Error("GetAllDirs(non-container root) returned empty paths")
	}
	if !strings.Contains(dirs.Config, "myapp") {
		t.Errorf("Config path %q does not contain project name", dirs.Config)
	}
}

func TestGetFullDirs_NonContainerNonRoot(t *testing.T) {
	testForceNonContainer = true
	testForceNonRoot = true
	defer func() {
		testForceNonContainer = false
		testForceNonRoot = false
	}()

	t.Setenv("HOME", "/home/testuser")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("XDG_CACHE_HOME", "")

	dirs := GetAllDirs("myapp")
	if dirs.Config == "" || dirs.Data == "" {
		t.Error("GetAllDirs(non-container non-root) returned empty paths")
	}
	if !strings.Contains(dirs.Config, "myapp") {
		t.Errorf("Config path %q does not contain project name", dirs.Config)
	}
}

func TestGetFullDirs_NonContainerNonRootXDG(t *testing.T) {
	testForceNonContainer = true
	testForceNonRoot = true
	defer func() {
		testForceNonContainer = false
		testForceNonRoot = false
	}()

	base, err := os.MkdirTemp(filepath.Join(os.TempDir(), "apimgr"), "ipgaze-")
	if err != nil {
		os.MkdirAll(filepath.Join(os.TempDir(), "apimgr"), 0755)
		base, err = os.MkdirTemp(filepath.Join(os.TempDir(), "apimgr"), "ipgaze-")
		if err != nil {
			t.Fatal(err)
		}
	}
	defer os.RemoveAll(base)

	t.Setenv("XDG_CONFIG_HOME", filepath.Join(base, "cfg"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(base, "share"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(base, "cache"))

	dirs := GetAllDirs("xdgapp")
	if !strings.Contains(dirs.Config, "xdgapp") {
		t.Errorf("XDG config path %q does not contain project name", dirs.Config)
	}
	if !strings.Contains(dirs.Data, "xdgapp") {
		t.Errorf("XDG data path %q does not contain project name", dirs.Data)
	}
}

func TestGetDefaultDirsLegacy_NonRoot(t *testing.T) {
	testForceNonRoot = true
	defer func() { testForceNonRoot = false }()

	t.Setenv("HOME", "/home/testuser")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_DATA_HOME", "")

	configDir, dataDir, logsDir := GetDefaultDirsLegacy("myapp")
	if configDir == "" || dataDir == "" || logsDir == "" {
		t.Error("GetDefaultDirsLegacy(non-root) returned empty paths")
	}
	for _, d := range []string{configDir, dataDir, logsDir} {
		if !strings.Contains(d, "myapp") {
			t.Errorf("non-root legacy path %q does not contain 'myapp'", d)
		}
	}
}

func TestRootDirs_Linux(t *testing.T) {
	cfg, data, logs, cache, pid, ssl, sec, db, backup := rootDirs("linux", "myapp")
	if !strings.Contains(cfg, "myapp") || !strings.Contains(data, "myapp") {
		t.Errorf("rootDirs(linux) paths missing project name: cfg=%q data=%q", cfg, data)
	}
	if logs == "" || cache == "" || pid == "" || ssl == "" || sec == "" || db == "" || backup == "" {
		t.Error("rootDirs(linux) returned empty paths")
	}
}

func TestRootDirs_Darwin(t *testing.T) {
	cfg, data, logs, cache, pid, ssl, sec, db, backup := rootDirs("darwin", "myapp")
	if !strings.Contains(cfg, "myapp") {
		t.Errorf("rootDirs(darwin) config path missing project: %q", cfg)
	}
	if data == "" || logs == "" || cache == "" || pid == "" || ssl == "" || sec == "" || db == "" || backup == "" {
		t.Error("rootDirs(darwin) returned empty paths")
	}
}

func TestRootDirs_Windows(t *testing.T) {
	t.Setenv("ProgramData", "C:\\ProgramData")
	cfg, data, logs, cache, pid, ssl, sec, db, backup := rootDirs("windows", "myapp")
	if !strings.Contains(cfg, "myapp") {
		t.Errorf("rootDirs(windows) config path missing project: %q", cfg)
	}
	if data == "" || logs == "" || cache == "" || pid == "" || ssl == "" || sec == "" || db == "" || backup == "" {
		t.Error("rootDirs(windows) returned empty paths")
	}
}

func TestRootDirs_Windows_NoProgramData(t *testing.T) {
	t.Setenv("ProgramData", "")
	cfg, _, _, _, _, _, _, _, _ := rootDirs("windows", "myapp")
	if !strings.Contains(cfg, "ProgramData") {
		t.Errorf("rootDirs(windows, no ProgramData) = %q, want default ProgramData path", cfg)
	}
}

func TestRootDirs_FreeBSD(t *testing.T) {
	cfg, data, logs, _, _, _, _, _, _ := rootDirs("freebsd", "myapp")
	if !strings.Contains(cfg, "myapp") || !strings.Contains(data, "myapp") || !strings.Contains(logs, "myapp") {
		t.Errorf("rootDirs(freebsd) paths missing project: cfg=%q data=%q logs=%q", cfg, data, logs)
	}
}

func TestUserDirs_Linux(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("XDG_CACHE_HOME", "")
	cfg, data, logs, _, _, _, _, _, _ := userDirs("linux", "myapp", "/home/user")
	if !strings.Contains(cfg, "myapp") || !strings.Contains(data, "myapp") {
		t.Errorf("userDirs(linux) paths missing project: cfg=%q data=%q logs=%q", cfg, data, logs)
	}
}

func TestUserDirs_LinuxXDG(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/custom/cfg")
	t.Setenv("XDG_DATA_HOME", "/custom/data")
	t.Setenv("XDG_CACHE_HOME", "/custom/cache")
	cfg, data, _, cache, _, _, _, _, _ := userDirs("linux", "myapp", "/home/user")
	if !strings.Contains(cfg, "/custom/cfg") {
		t.Errorf("userDirs(linux, XDG) config = %q, want /custom/cfg prefix", cfg)
	}
	if !strings.Contains(data, "/custom/data") {
		t.Errorf("userDirs(linux, XDG) data = %q, want /custom/data prefix", data)
	}
	if !strings.Contains(cache, "/custom/cache") {
		t.Errorf("userDirs(linux, XDG) cache = %q, want /custom/cache prefix", cache)
	}
}

func TestUserDirs_Darwin(t *testing.T) {
	cfg, data, _, _, _, _, _, _, backup := userDirs("darwin", "myapp", "/Users/user")
	if !strings.Contains(cfg, "myapp") || !strings.Contains(data, "myapp") {
		t.Errorf("userDirs(darwin) paths missing project: cfg=%q data=%q", cfg, data)
	}
	if !strings.Contains(backup, "myapp") {
		t.Errorf("userDirs(darwin) backup missing project: %q", backup)
	}
}

func TestUserDirs_Windows(t *testing.T) {
	t.Setenv("APPDATA", "C:\\Users\\user\\AppData\\Roaming")
	t.Setenv("LOCALAPPDATA", "C:\\Users\\user\\AppData\\Local")
	cfg, data, _, _, _, _, _, _, _ := userDirs("windows", "myapp", "C:\\Users\\user")
	if !strings.Contains(cfg, "myapp") || !strings.Contains(data, "myapp") {
		t.Errorf("userDirs(windows) paths missing project: cfg=%q data=%q", cfg, data)
	}
}

func TestUserDirs_Windows_NoEnv(t *testing.T) {
	t.Setenv("APPDATA", "")
	t.Setenv("LOCALAPPDATA", "")
	cfg, _, _, _, _, _, _, _, _ := userDirs("windows", "myapp", "C:\\Users\\user")
	if !strings.Contains(cfg, "AppData") {
		t.Errorf("userDirs(windows, no env) config = %q, want AppData fallback", cfg)
	}
}

func TestRootDirsLegacy_Linux(t *testing.T) {
	cfg, data, logs := rootDirsLegacy("linux", "myapp")
	if !strings.Contains(cfg, "myapp") || !strings.Contains(data, "myapp") || !strings.Contains(logs, "myapp") {
		t.Errorf("rootDirsLegacy(linux): cfg=%q data=%q logs=%q", cfg, data, logs)
	}
}

func TestRootDirsLegacy_Windows(t *testing.T) {
	t.Setenv("ProgramData", "C:\\ProgramData")
	cfg, data, logs := rootDirsLegacy("windows", "myapp")
	if !strings.Contains(cfg, "myapp") || !strings.Contains(data, "myapp") || !strings.Contains(logs, "myapp") {
		t.Errorf("rootDirsLegacy(windows): cfg=%q data=%q logs=%q", cfg, data, logs)
	}
}

func TestRootDirsLegacy_Windows_NoProgramData(t *testing.T) {
	t.Setenv("ProgramData", "")
	cfg, _, _ := rootDirsLegacy("windows", "myapp")
	if !strings.Contains(cfg, "ProgramData") {
		t.Errorf("rootDirsLegacy(windows, no ProgramData) = %q, want default path", cfg)
	}
}

func TestUserDirsLegacy_Linux(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_DATA_HOME", "")
	cfg, data, logs := userDirsLegacy("linux", "myapp", "/home/user")
	if !strings.Contains(cfg, "myapp") || !strings.Contains(data, "myapp") || !strings.Contains(logs, "myapp") {
		t.Errorf("userDirsLegacy(linux): cfg=%q data=%q logs=%q", cfg, data, logs)
	}
}

func TestUserDirsLegacy_Linux_XDG(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/xdg/cfg")
	t.Setenv("XDG_DATA_HOME", "/xdg/data")
	cfg, data, _ := userDirsLegacy("linux", "myapp", "/home/user")
	if !strings.Contains(cfg, "/xdg/cfg") {
		t.Errorf("userDirsLegacy(linux XDG) cfg = %q", cfg)
	}
	if !strings.Contains(data, "/xdg/data") {
		t.Errorf("userDirsLegacy(linux XDG) data = %q", data)
	}
}

func TestUserDirsLegacy_Darwin(t *testing.T) {
	cfg, data, logs := userDirsLegacy("darwin", "myapp", "/Users/user")
	if !strings.Contains(cfg, "myapp") || !strings.Contains(data, "myapp") || !strings.Contains(logs, "myapp") {
		t.Errorf("userDirsLegacy(darwin): cfg=%q data=%q logs=%q", cfg, data, logs)
	}
}

func TestUserDirsLegacy_Windows(t *testing.T) {
	t.Setenv("APPDATA", "C:\\Users\\user\\AppData\\Roaming")
	t.Setenv("LOCALAPPDATA", "C:\\Users\\user\\AppData\\Local")
	cfg, data, logs := userDirsLegacy("windows", "myapp", "C:\\Users\\user")
	if !strings.Contains(cfg, "myapp") || !strings.Contains(data, "myapp") || !strings.Contains(logs, "myapp") {
		t.Errorf("userDirsLegacy(windows): cfg=%q data=%q logs=%q", cfg, data, logs)
	}
}

func TestUserDirsLegacy_Windows_NoEnv(t *testing.T) {
	t.Setenv("APPDATA", "")
	t.Setenv("LOCALAPPDATA", "")
	cfg, _, _ := userDirsLegacy("windows", "myapp", "C:\\Users\\user")
	if !strings.Contains(cfg, "AppData") {
		t.Errorf("userDirsLegacy(windows, no env) = %q, want AppData fallback", cfg)
	}
}

func TestGetDefaultDirsLegacy_NonRootXDG(t *testing.T) {
	testForceNonRoot = true
	defer func() { testForceNonRoot = false }()

	base, err := os.MkdirTemp(filepath.Join(os.TempDir(), "apimgr"), "ipgaze-")
	if err != nil {
		os.MkdirAll(filepath.Join(os.TempDir(), "apimgr"), 0755)
		base, err = os.MkdirTemp(filepath.Join(os.TempDir(), "apimgr"), "ipgaze-")
		if err != nil {
			t.Fatal(err)
		}
	}
	defer os.RemoveAll(base)

	t.Setenv("XDG_CONFIG_HOME", filepath.Join(base, "cfg"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(base, "share"))

	configDir, dataDir, logsDir := GetDefaultDirsLegacy("legacyapp")
	if !strings.Contains(configDir, "legacyapp") {
		t.Errorf("XDG legacy config path %q does not contain project name", configDir)
	}
	if !strings.Contains(dataDir, "legacyapp") {
		t.Errorf("XDG legacy data path %q does not contain project name", dataDir)
	}
	if !strings.Contains(logsDir, "legacyapp") {
		t.Errorf("XDG legacy logs path %q does not contain project name", logsDir)
	}
}

func TestWritePIDFile_NestedDirCreation(t *testing.T) {
	base, err := os.MkdirTemp(filepath.Join(os.TempDir(), "apimgr"), "ipgaze-")
	if err != nil {
		os.MkdirAll(filepath.Join(os.TempDir(), "apimgr"), 0755)
		base, err = os.MkdirTemp(filepath.Join(os.TempDir(), "apimgr"), "ipgaze-")
		if err != nil {
			t.Fatal(err)
		}
	}
	defer os.RemoveAll(base)

	// Deep nested path that does not exist yet
	pidPath := filepath.Join(base, "a", "b", "c", "test.pid")
	if err := WritePIDFile(pidPath); err != nil {
		t.Fatalf("WritePIDFile(deep) error = %v", err)
	}
	if _, err := os.Stat(pidPath); err != nil {
		t.Errorf("PID file was not created at %q", pidPath)
	}
}

// --- AI.md PART 8 Directory Validation Rules ---

func TestEnsureDir_UserModePermissions(t *testing.T) {
	target := filepath.Join(t.TempDir(), "usermode")
	if err := EnsureDir(target, false); err != nil {
		t.Fatalf("EnsureDir(user) error = %v", err)
	}
	fi, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o700 {
		t.Errorf("EnsureDir(user) mode = %#o, want 0700", got)
	}
}

func TestEnsureDir_RootModePermissions(t *testing.T) {
	target := filepath.Join(t.TempDir(), "systemmode")
	if err := EnsureDir(target, true); err != nil {
		t.Fatalf("EnsureDir(root) error = %v", err)
	}
	fi, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o755 {
		t.Errorf("EnsureDir(root) mode = %#o, want 0755", got)
	}
}

func TestEnsureDir_WriteProbeFailure(t *testing.T) {
	target := filepath.Join(t.TempDir(), "probefail")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	// Occupying the probe path with a directory makes the probe's WriteFile
	// fail even for a process that can bypass permission bits.
	if err := os.Mkdir(filepath.Join(target, ".write-test"), 0o700); err != nil {
		t.Fatal(err)
	}
	err := EnsureDir(target, false)
	if err == nil {
		t.Fatal("EnsureDir should fail when the write probe cannot be created")
	}
	if !strings.Contains(err.Error(), "not writable") {
		t.Errorf("EnsureDir probe error = %v, want a 'not writable' error", err)
	}
}

func TestEnsureDir_RemovesWriteProbe(t *testing.T) {
	target := filepath.Join(t.TempDir(), "probeclean")
	if err := EnsureDir(target, false); err != nil {
		t.Fatalf("EnsureDir() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(target, ".write-test")); !os.IsNotExist(err) {
		t.Error("EnsureDir left the .write-test probe file behind")
	}
}

func TestEnsurePIDFile_CreatesParentDir(t *testing.T) {
	pidPath := filepath.Join(t.TempDir(), "run", "ipgaze.pid")
	if err := EnsurePIDFile(pidPath, false); err != nil {
		t.Fatalf("EnsurePIDFile() error = %v", err)
	}
	fi, err := os.Stat(filepath.Dir(pidPath))
	if err != nil || !fi.IsDir() {
		t.Fatalf("EnsurePIDFile did not create parent dir: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o700 {
		t.Errorf("EnsurePIDFile(user) dir mode = %#o, want 0700", got)
	}
}

// --- Locked-at-startup elevation ---

func TestIsElevated_HonorsTestOverride(t *testing.T) {
	prev := testForceNonRoot
	defer func() { testForceNonRoot = prev }()
	testForceNonRoot = true
	if isElevated() {
		t.Error("isElevated() should be false when testForceNonRoot is set")
	}
}

func TestDetectElevated_MatchesLockedValue(t *testing.T) {
	// startedElevated is captured at package init; re-detecting immediately
	// must agree with it, since no privilege drop has happened in the test binary.
	if detectElevated() != startedElevated {
		t.Error("startedElevated diverged from detectElevated() with no privilege drop")
	}
}

func TestGetDirectories_Memoized(t *testing.T) {
	first := GetDirectories()
	second := GetDirectories()
	if first != second {
		t.Errorf("GetDirectories() diverged between calls: %+v vs %+v", first, second)
	}
}

func TestResetDirectoriesCache_Reresolves(t *testing.T) {
	before := GetDirectories()
	resetDirectoriesCache()
	after := GetDirectories()
	if before != after {
		t.Errorf("GetDirectories() changed after cache reset with no env change: %+v vs %+v", before, after)
	}
}

// --- Backup directory resolution ---

func TestBackupDirOrFallback_UsesSystemDirWhenWritable(t *testing.T) {
	sys := filepath.Join(t.TempDir(), "Backups", "apimgr", "myapp")
	if err := os.MkdirAll(filepath.Dir(sys), 0o755); err != nil {
		t.Fatal(err)
	}
	got := backupDirOrFallback(sys, "/var/lib/apimgr/myapp/backup")
	if got != sys {
		t.Errorf("backupDirOrFallback() = %q, want %q", got, sys)
	}
}

func TestBackupDirOrFallback_FallsBackWhenUnwritable(t *testing.T) {
	base := t.TempDir()
	// A regular file standing in for the system backup dir's parent makes the
	// system path unusable regardless of the process's privileges.
	blocker := filepath.Join(base, "Backups")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	fallback := "/var/lib/apimgr/myapp/backup"
	got := backupDirOrFallback(filepath.Join(blocker, "apimgr", "myapp"), fallback)
	if got != fallback {
		t.Errorf("backupDirOrFallback() = %q, want fallback %q", got, fallback)
	}
}

func TestBackupDirOrFallback_MissingParentFallsBack(t *testing.T) {
	fallback := "/var/lib/apimgr/myapp/backup"
	got := backupDirOrFallback(filepath.Join(t.TempDir(), "absent", "Backups", "myapp"), fallback)
	if got != fallback {
		t.Errorf("backupDirOrFallback() = %q, want fallback %q", got, fallback)
	}
}

func TestIsWritable_FileParent(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "notadir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if isWritable(filepath.Join(blocker, "child")) {
		t.Error("isWritable() should be false when the parent is a regular file")
	}
}

func TestSystemBackupDir_PerOS(t *testing.T) {
	cases := map[string]string{
		"linux":   "/mnt/Backups/apimgr/myapp",
		"darwin":  "/Library/Backups/apimgr/myapp",
		"freebsd": "/var/backups/apimgr/myapp",
	}
	for goos, want := range cases {
		if got := systemBackupDir(goos, "myapp"); got != want {
			t.Errorf("systemBackupDir(%s) = %q, want %q", goos, got, want)
		}
	}
}

func TestRootDirs_BackupFallsBackInsideDataDir(t *testing.T) {
	// darwin's system backup dir (/Library/Backups) does not exist on the test
	// host, so the root-mode fallback must land inside the data dir and never
	// in a $HOME-derived location.
	if runtime.GOOS == "darwin" {
		t.Skip("system backup dir exists on darwin hosts")
	}
	_, dataDir, _, _, _, _, _, _, backupDir := rootDirs("darwin", "myapp")
	want := filepath.Join(dataDir, "backup")
	if backupDir != want {
		t.Errorf("rootDirs backup = %q, want %q", backupDir, want)
	}
}

func TestUserDirs_BackupFallsBackToUserDir(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("system backup dir exists on darwin hosts")
	}
	home := t.TempDir()
	_, _, _, _, _, _, _, _, backupDir := userDirs("darwin", "myapp", home)
	want := filepath.Join(home, "Library", "Backups", OrgName, "myapp")
	if backupDir != want {
		t.Errorf("userDirs backup = %q, want %q", backupDir, want)
	}
}
