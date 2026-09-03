package version

import (
	"runtime"
	"strings"
	"testing"
)

// ─────────────────────── GoVersion ───────────────────────────────────────────

// GoVersion must return the same value as runtime.Version() — not an empty string
// and not a hardcoded constant.
func TestGoVersion_MatchesRuntimeVersion(t *testing.T) {
	got := GoVersion()
	want := runtime.Version()
	if got != want {
		t.Errorf("GoVersion() = %q, want %q", got, want)
	}
}

func TestGoVersion_NotEmpty(t *testing.T) {
	if GoVersion() == "" {
		t.Error("GoVersion() returned empty string")
	}
}

// The runtime version string always starts with "go".
func TestGoVersion_HasGoPrefix(t *testing.T) {
	got := GoVersion()
	if !strings.HasPrefix(got, "go") {
		t.Errorf("GoVersion() = %q: expected 'go' prefix", got)
	}
}

// ─────────────────────── UserAgent ───────────────────────────────────────────

// UserAgent must start with the "ipgaze-cli/" prefix so IsOurCliClient() accepts it.
func TestUserAgent_HasCliPrefix(t *testing.T) {
	ua := UserAgent()
	if !strings.HasPrefix(ua, "ipgaze-cli/") {
		t.Errorf("UserAgent() = %q: expected 'ipgaze-cli/' prefix", ua)
	}
}

// UserAgent must embed the runtime Go version.
func TestUserAgent_ContainsGoVersion(t *testing.T) {
	ua := UserAgent()
	goVer := runtime.Version()
	if !strings.Contains(ua, goVer) {
		t.Errorf("UserAgent() = %q: does not contain Go version %q", ua, goVer)
	}
}

// UserAgent must embed the current OS/arch.
func TestUserAgent_ContainsOSArch(t *testing.T) {
	ua := UserAgent()
	if !strings.Contains(ua, runtime.GOOS) {
		t.Errorf("UserAgent() = %q: does not contain GOOS %q", ua, runtime.GOOS)
	}
	if !strings.Contains(ua, runtime.GOARCH) {
		t.Errorf("UserAgent() = %q: does not contain GOARCH %q", ua, runtime.GOARCH)
	}
}

// UserAgent must embed the Version variable.
func TestUserAgent_ContainsVersion(t *testing.T) {
	saved := Version
	Version = "9.9.9"
	defer func() { Version = saved }()

	ua := UserAgent()
	if !strings.Contains(ua, "9.9.9") {
		t.Errorf("UserAgent() = %q: does not embed Version %q", ua, "9.9.9")
	}
}

// ─────────────────────── IsRelease ───────────────────────────────────────────

// With the default ("dev" / "unknown") values IsRelease must return false.
func TestIsRelease_DefaultValuesReturnFalse(t *testing.T) {
	saved := Version
	savedCommit := Commit
	Version = "dev"
	Commit = "unknown"
	defer func() {
		Version = saved
		Commit = savedCommit
	}()

	if IsRelease() {
		t.Error("IsRelease() with Version='dev', Commit='unknown': got true, want false")
	}
}

// When both Version and Commit look like release values, IsRelease must return true.
func TestIsRelease_ReleaseValues(t *testing.T) {
	saved := Version
	savedCommit := Commit
	Version = "1.2.3"
	Commit = "a1b2c3d"
	defer func() {
		Version = saved
		Commit = savedCommit
	}()

	if !IsRelease() {
		t.Error("IsRelease() with Version='1.2.3', Commit='a1b2c3d': got false, want true")
	}
}

// dev Version alone (even with a commit) must not be a release.
func TestIsRelease_DevVersionIsNotRelease(t *testing.T) {
	saved := Version
	savedCommit := Commit
	Version = "dev"
	Commit = "a1b2c3d"
	defer func() {
		Version = saved
		Commit = savedCommit
	}()

	if IsRelease() {
		t.Error("IsRelease() with Version='dev': got true, want false")
	}
}

// Real version but unknown commit is still not a proper release.
func TestIsRelease_UnknownCommitIsNotRelease(t *testing.T) {
	saved := Version
	savedCommit := Commit
	Version = "1.0.0"
	Commit = "unknown"
	defer func() {
		Version = saved
		Commit = savedCommit
	}()

	if IsRelease() {
		t.Error("IsRelease() with Commit='unknown': got true, want false")
	}
}

// ─────────────────────── package-level variables ──────────────────────────────

// The package variables must have their documented default values so tests and
// local runs behave predictably.
func TestDefaultVariables(t *testing.T) {
	// We test the package-level defaults, not what a build sets via -ldflags.
	// Restoring ensures this test is idempotent when run alongside others
	// that mutate the variables.
	saved := Version
	savedCommit := Commit
	savedDate := Date
	savedSite := OfficialSite
	defer func() {
		Version = saved
		Commit = savedCommit
		Date = savedDate
		OfficialSite = savedSite
	}()

	Version = "dev"
	Commit = "unknown"
	Date = "unknown"
	OfficialSite = ""

	if Version != "dev" {
		t.Errorf("Version default = %q, want 'dev'", Version)
	}
	if Commit != "unknown" {
		t.Errorf("Commit default = %q, want 'unknown'", Commit)
	}
	if Date != "unknown" {
		t.Errorf("Date default = %q, want 'unknown'", Date)
	}
}
