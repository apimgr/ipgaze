//go:build !windows

package main

import (
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestIsElevated_MatchesGeteuid(t *testing.T) {
	want := os.Geteuid() == 0
	if got := isElevated(); got != want {
		t.Errorf("isElevated() = %v, want %v", got, want)
	}
}

func TestEscalationMethods_PerGOOS(t *testing.T) {
	methods := escalationMethods()
	if len(methods) == 0 {
		t.Fatal("escalationMethods() returned an empty list")
	}

	var want []string
	switch runtime.GOOS {
	case "darwin":
		want = []string{"sudo", "osascript"}
	case "freebsd", "netbsd", "openbsd", "dragonfly":
		want = []string{"doas", "sudo", "su"}
	default:
		want = []string{"sudo", "su", "pkexec", "doas"}
	}

	if len(methods) != len(want) {
		t.Fatalf("escalationMethods() = %v, want %v", methods, want)
	}
	for i, m := range methods {
		if m != want[i] {
			t.Errorf("escalationMethods()[%d] = %q, want %q", i, m, want[i])
		}
	}
}

func TestShellJoin_QuotesAndEscapesArgs(t *testing.T) {
	got := shellJoin([]string{"plain", "with space", "it's"})
	want := `'plain' 'with space' 'it'\''s'`
	if got != want {
		t.Errorf("shellJoin() = %q, want %q", got, want)
	}
}

func TestShellJoin_Empty(t *testing.T) {
	if got := shellJoin(nil); got != "" {
		t.Errorf("shellJoin(nil) = %q, want empty", got)
	}
}

func TestOsaQuote_EscapesBackslashesAndQuotes(t *testing.T) {
	got := osaQuote(`say "hi" \ there`)
	want := `"say \"hi\" \\ there"`
	if got != want {
		t.Errorf("osaQuote() = %q, want %q", got, want)
	}
}

func TestBuildElevationCmd_Su(t *testing.T) {
	cmd := buildElevationCmd("su", []string{"echo", "hi there"})
	if cmd.Path == "" || !strings.HasSuffix(cmd.Path, "su") {
		t.Errorf("buildElevationCmd(su).Path = %q, want a path ending in su", cmd.Path)
	}
	if len(cmd.Args) != 3 || cmd.Args[1] != "-c" {
		t.Fatalf("buildElevationCmd(su).Args = %v, want [su -c <joined>]", cmd.Args)
	}
	want := shellJoin([]string{"echo", "hi there"})
	if cmd.Args[2] != want {
		t.Errorf("buildElevationCmd(su).Args[2] = %q, want %q", cmd.Args[2], want)
	}
}

func TestBuildElevationCmd_Osascript(t *testing.T) {
	cmd := buildElevationCmd("osascript", []string{"echo", "hi"})
	if len(cmd.Args) != 3 || cmd.Args[1] != "-e" {
		t.Fatalf("buildElevationCmd(osascript).Args = %v, want [osascript -e <script>]", cmd.Args)
	}
	if !strings.Contains(cmd.Args[2], "with administrator privileges") {
		t.Errorf("buildElevationCmd(osascript) script = %q, want it to request administrator privileges", cmd.Args[2])
	}
}

func TestBuildElevationCmd_Default(t *testing.T) {
	for _, method := range []string{"sudo", "pkexec", "doas"} {
		cmd := buildElevationCmd(method, []string{"a", "b"})
		if len(cmd.Args) != 3 || cmd.Args[1] != "a" || cmd.Args[2] != "b" {
			t.Errorf("buildElevationCmd(%s).Args = %v, want [%s a b]", method, cmd.Args, method)
		}
	}
}

func TestDropPrivileges_UnknownUser(t *testing.T) {
	err := dropPrivileges("no-such-user-ipgaze-test")
	if err == nil {
		t.Error("dropPrivileges() with unknown user: want error, got nil")
	}
}

func TestCanEscalate_DoesNotPanic(t *testing.T) {
	// canEscalate shells out to `sudo`/checks group membership; the exact
	// result depends on the host running the test, so only assert it
	// completes without panicking and returns a bool.
	_ = canEscalate()
}

func TestReservedSystemIDs_ContainsDocumentedRanges(t *testing.T) {
	for _, id := range []int{65534, 999, 980, 101, 110, 170, 179} {
		if !reservedSystemIDs[id] {
			t.Errorf("reservedSystemIDs[%d] = false, want true (documented in AI.md PART 23)", id)
		}
	}
	if reservedSystemIDs[500] {
		t.Error("reservedSystemIDs[500] = true, want false (mid-range safe ID)")
	}
}

func TestFindAvailableSystemID_ReturnsIDInSafeRange(t *testing.T) {
	id, err := findAvailableSystemID()
	if err != nil {
		t.Fatalf("findAvailableSystemID() error = %v", err)
	}
	if id < 200 || id > 899 {
		t.Errorf("findAvailableSystemID() = %d, want in range [200, 899]", id)
	}
	if reservedSystemIDs[id] {
		t.Errorf("findAvailableSystemID() = %d, want a non-reserved ID", id)
	}
	if _, lookErr := user.LookupId(strconv.Itoa(id)); lookErr == nil {
		t.Errorf("findAvailableSystemID() = %d, but UID already in use", id)
	}
}

func TestEnsureSystemUser_ExistingUser_ReturnsItsIDs(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Skipf("user.Current() unavailable: %v", err)
	}
	wantUID, _ := strconv.Atoi(current.Uid)
	wantGID, _ := strconv.Atoi(current.Gid)

	uid, gid, err := ensureSystemUser(current.Username, current.HomeDir)
	if err != nil {
		t.Fatalf("ensureSystemUser(%q) error = %v", current.Username, err)
	}
	if uid != wantUID || gid != wantGID {
		t.Errorf("ensureSystemUser(%q) = (%d, %d), want (%d, %d)", current.Username, uid, gid, wantUID, wantGID)
	}
}

func TestChownRecursive_EmptyPath_NoError(t *testing.T) {
	if err := chownRecursive("", 0, 0); err != nil {
		t.Errorf("chownRecursive(\"\") error = %v, want nil", err)
	}
}

func TestChownRecursive_SetsOwnershipOnTreeToOwnUser(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("chown to arbitrary owner requires root")
	}
	dir := t.TempDir()
	nested := filepath.Join(dir, "sub")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	file := filepath.Join(nested, "f.txt")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if err := chownRecursive(dir, os.Getuid(), os.Getgid()); err != nil {
		t.Fatalf("chownRecursive() error = %v", err)
	}

	for _, p := range []string{dir, nested, file} {
		info, statErr := os.Stat(p)
		if statErr != nil {
			t.Fatalf("Stat(%s): %v", p, statErr)
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			t.Fatalf("Stat(%s).Sys() not *syscall.Stat_t", p)
		}
		if int(st.Uid) != os.Getuid() || int(st.Gid) != os.Getgid() {
			t.Errorf("chownRecursive() left %s owned by %d:%d, want %d:%d", p, st.Uid, st.Gid, os.Getuid(), os.Getgid())
		}
	}
}
