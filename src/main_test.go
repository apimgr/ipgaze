package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/apimgr/ipgaze/src/config"
	paths "github.com/apimgr/ipgaze/src/path"
)

func TestMultiValueFlagString(t *testing.T) {
	var xmvf = []struct {
		values multiValueFlag
		expect string
	}{
		{
			values: multiValueFlag{
				"test",
				"with multiples",
				"flags",
			},
			expect: `test, with multiples, flags`,
		},
		{
			values: multiValueFlag{
				"test",
			},
			expect: `test`,
		},
		{
			values: multiValueFlag{
				"",
			},
			expect: ``,
		},
		{
			values: nil,
			expect: ``,
		},
	}

	for _, mvf := range xmvf {
		got := mvf.values.String()
		if got != mvf.expect {
			t.Errorf("\nFor: %#v\nExpected: %v\nGot: %v", mvf.values, mvf.expect, got)
		}
	}
}

// ---------------------------------------------------------------------------
// multiValueFlag.Set
// ---------------------------------------------------------------------------

func TestMultiValueFlagSet_AppendsValue(t *testing.T) {
	var f multiValueFlag
	if err := f.Set("alpha"); err != nil {
		t.Fatalf("Set() error: %v", err)
	}
	if err := f.Set("beta"); err != nil {
		t.Fatalf("Set() error: %v", err)
	}
	if len(f) != 2 {
		t.Errorf("len = %d, want 2", len(f))
	}
	if f[0] != "alpha" || f[1] != "beta" {
		t.Errorf("values = %v, want [alpha beta]", []string(f))
	}
}

func TestMultiValueFlagSet_EmptyString(t *testing.T) {
	var f multiValueFlag
	if err := f.Set(""); err != nil {
		t.Fatalf("Set() with empty string error: %v", err)
	}
	if len(f) != 1 {
		t.Errorf("len = %d, want 1", len(f))
	}
}

// ---------------------------------------------------------------------------
// parseDurationOrDefault
// ---------------------------------------------------------------------------

func TestParseDurationOrDefault_ValidDuration(t *testing.T) {
	d := parseDurationOrDefault("30s", 10*time.Second)
	if d != 30*time.Second {
		t.Errorf("got %v, want 30s", d)
	}
}

func TestParseDurationOrDefault_EmptyString_ReturnsFallback(t *testing.T) {
	d := parseDurationOrDefault("", 45*time.Second)
	if d != 45*time.Second {
		t.Errorf("got %v, want 45s", d)
	}
}

func TestParseDurationOrDefault_InvalidString_ReturnsFallback(t *testing.T) {
	d := parseDurationOrDefault("notaduration", 15*time.Second)
	if d != 15*time.Second {
		t.Errorf("got %v, want 15s", d)
	}
}

func TestParseDurationOrDefault_ZeroDuration_ReturnsFallback(t *testing.T) {
	d := parseDurationOrDefault("0s", 5*time.Second)
	if d != 5*time.Second {
		t.Errorf("got %v, want 5s (zero duration rejected)", d)
	}
}

func TestParseDurationOrDefault_NegativeDuration_ReturnsFallback(t *testing.T) {
	d := parseDurationOrDefault("-1s", 5*time.Second)
	if d != 5*time.Second {
		t.Errorf("got %v, want 5s (negative duration rejected)", d)
	}
}

func TestParseDurationOrDefault_MinuteDuration(t *testing.T) {
	d := parseDurationOrDefault("2m", time.Minute)
	if d != 2*time.Minute {
		t.Errorf("got %v, want 2m", d)
	}
}

// ---------------------------------------------------------------------------
// getLanguage
// ---------------------------------------------------------------------------

func TestGetLanguage_FlagLangTakesPriority(t *testing.T) {
	t.Setenv("LANG", "fr_FR.UTF-8")
	t.Setenv("LC_ALL", "de_DE.UTF-8")
	got := getLanguage("es")
	if got != "es" {
		t.Errorf("got %q, want es", got)
	}
}

func TestGetLanguage_LCAllOverLANG(t *testing.T) {
	t.Setenv("LC_ALL", "zh_CN.UTF-8")
	t.Setenv("LANG", "de_DE.UTF-8")
	got := getLanguage("")
	if got != "zh" {
		t.Errorf("got %q, want zh", got)
	}
}

func TestGetLanguage_LANGWhenNoLCAll(t *testing.T) {
	t.Setenv("LC_ALL", "")
	t.Setenv("LANG", "fr_FR.UTF-8")
	got := getLanguage("")
	if got != "fr" {
		t.Errorf("got %q, want fr", got)
	}
}

func TestGetLanguage_DefaultsToEn(t *testing.T) {
	t.Setenv("LC_ALL", "")
	t.Setenv("LANG", "")
	got := getLanguage("")
	if got != "en" {
		t.Errorf("got %q, want en", got)
	}
}

func TestGetLanguage_UnsupportedFlagLang_FallsBackToEn(t *testing.T) {
	got := getLanguage("xx")
	if got != "en" {
		t.Errorf("got %q, want en for unsupported lang", got)
	}
}

func TestGetLanguage_UnsupportedLCAll_FallsBackToEn(t *testing.T) {
	t.Setenv("LC_ALL", "xx_XX.UTF-8")
	t.Setenv("LANG", "")
	got := getLanguage("")
	if got != "en" {
		t.Errorf("got %q, want en for unsupported LC_ALL", got)
	}
}

// ---------------------------------------------------------------------------
// validateLang
// ---------------------------------------------------------------------------

func TestValidateLang_SupportedLanguages(t *testing.T) {
	supported := []string{"en", "es", "zh", "fr", "ar", "de", "ja"}
	for _, lang := range supported {
		got := validateLang(lang)
		if got != lang {
			t.Errorf("validateLang(%q) = %q, want %q", lang, got, lang)
		}
	}
}

func TestValidateLang_Uppercase_Normalised(t *testing.T) {
	got := validateLang("EN")
	if got != "en" {
		t.Errorf("validateLang(EN) = %q, want en", got)
	}
}

func TestValidateLang_UnsupportedReturnsEn(t *testing.T) {
	got := validateLang("klingon")
	if got != "en" {
		t.Errorf("validateLang(klingon) = %q, want en", got)
	}
}

func TestValidateLang_WhitespaceTrimmed(t *testing.T) {
	got := validateLang("  fr  ")
	if got != "fr" {
		t.Errorf("validateLang('  fr  ') = %q, want fr", got)
	}
}

// ---------------------------------------------------------------------------
// scheduleFor
// ---------------------------------------------------------------------------

func TestScheduleFor_EmptyOverride_ReturnsDefault(t *testing.T) {
	cfg := config.TaskScheduleConfig{}
	got := scheduleFor("0 3 * * *", cfg)
	if got != "0 3 * * *" {
		t.Errorf("got %q, want %q", got, "0 3 * * *")
	}
}

func TestScheduleFor_NonEmptyOverride_ReturnsOverride(t *testing.T) {
	cfg := config.TaskScheduleConfig{Schedule: "@hourly"}
	got := scheduleFor("0 3 * * *", cfg)
	if got != "@hourly" {
		t.Errorf("got %q, want @hourly", got)
	}
}

// ---------------------------------------------------------------------------
// enabledFor
// ---------------------------------------------------------------------------

func TestEnabledFor_NilPointer_ReturnsDefault(t *testing.T) {
	cfg := config.TaskScheduleConfig{}
	if got := enabledFor(true, cfg); !got {
		t.Error("enabledFor(true, nil) = false, want true")
	}
	if got := enabledFor(false, cfg); got {
		t.Error("enabledFor(false, nil) = true, want false")
	}
}

func TestEnabledFor_Pointer_ReturnsPointerValue(t *testing.T) {
	tr := true
	fa := false
	cfgTrue := config.TaskScheduleConfig{Enabled: &tr}
	cfgFalse := config.TaskScheduleConfig{Enabled: &fa}

	if got := enabledFor(false, cfgTrue); !got {
		t.Error("enabledFor(false, &true) = false, want true")
	}
	if got := enabledFor(true, cfgFalse); got {
		t.Error("enabledFor(true, &false) = true, want false")
	}
}

// ---------------------------------------------------------------------------
// randomPort
// ---------------------------------------------------------------------------

func TestRandomPort_InRange(t *testing.T) {
	maxSeen := 0
	for i := 0; i < 2000; i++ {
		port := randomPort()
		if len(port) == 0 {
			t.Fatal("randomPort() returned empty string")
		}
		n := 0
		for _, c := range port {
			if c < '0' || c > '9' {
				t.Fatalf("randomPort() = %q is not numeric", port)
			}
			n = n*10 + int(c-'0')
		}
		if n < 64000 || n > 64999 {
			t.Errorf("randomPort() = %d, want 64000-64999", n)
		}
		if n > maxSeen {
			maxSeen = n
		}
	}
	// guard against the single-byte truncation bug that capped the range at
	// 64255: over 2000 draws the upper sub-range must be reachable
	if maxSeen <= 64255 {
		t.Errorf("randomPort() never exceeded 64255 over 2000 draws (max=%d); upper range unreachable", maxSeen)
	}
}

// ---------------------------------------------------------------------------
// writePIDFile / removePIDFile
// ---------------------------------------------------------------------------

func TestWritePIDFile_CreatesFileWithPID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pid")
	writePIDFile(path)
	if paths.IsRunningInContainer() {
		// AI.md PART 8 "PID File Handling": containers get no PID file.
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("expected no PID file in container, got err=%v", err)
		}
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	content := strings.TrimSpace(string(data))
	if content == "" {
		t.Error("PID file is empty")
	}
	for _, c := range content {
		if c < '0' || c > '9' {
			t.Errorf("PID file contains non-numeric char %q: %q", c, content)
		}
	}
}

func TestWritePIDFile_CreatesParentDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "deep", "test.pid")
	writePIDFile(path)
	if paths.IsRunningInContainer() {
		// AI.md PART 8 "PID File Handling": containers get no PID file.
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("expected no PID file in container, got err=%v", err)
		}
		return
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("PID file not created at nested path: %v", err)
	}
}

func TestRemovePIDFile_RemovesExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pid")
	// Write current PID so paths.RemovePIDFile agrees to remove it (ownership check).
	if err := os.WriteFile(path, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	removePIDFile(path)
	if paths.IsRunningInContainer() {
		// AI.md PART 8 "PID File Handling": containers skip PID file
		// checking/removal entirely, so the file we planted stays put.
		if _, err := os.Stat(path); err != nil {
			t.Errorf("expected planted PID file to remain untouched in container: %v", err)
		}
		return
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("PID file still exists after removePIDFile()")
	}
}

func TestRemovePIDFile_NonExistentFile_NoError(t *testing.T) {
	removePIDFile("/tmp/apimgr-nonexistent-pid-file-xyz.pid")
}

// ---------------------------------------------------------------------------
// checkStalePID
// ---------------------------------------------------------------------------

func TestCheckStalePID_NoFile_NoOp(t *testing.T) {
	checkStalePID("/tmp/apimgr-nosuchpidfile-xyz.pid")
}

func TestCheckStalePID_InvalidPIDContent_RemovesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.pid")
	if err := os.WriteFile(path, []byte("not-a-pid\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	checkStalePID(path)
	if paths.IsRunningInContainer() {
		// AI.md PART 8 "PID File Handling": containers skip PID file
		// checking entirely, so the planted file stays put.
		if _, err := os.Stat(path); err != nil {
			t.Errorf("expected planted PID file to remain untouched in container: %v", err)
		}
		return
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("PID file with invalid content should be removed")
	}
}

func TestCheckStalePID_DeadPID_RemovesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dead.pid")
	// PID 999999 is very unlikely to exist on any system
	if err := os.WriteFile(path, []byte("999999\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	checkStalePID(path)
	if paths.IsRunningInContainer() {
		// AI.md PART 8 "PID File Handling": containers skip PID file
		// checking entirely, so the planted file stays put.
		if _, err := os.Stat(path); err != nil {
			t.Errorf("expected planted PID file to remain untouched in container: %v", err)
		}
		return
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("PID file pointing to dead process should be removed")
	}
}

func TestCheckStalePID_CurrentProcess_DifferentProgram(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "other.pid")
	pid := os.Getpid()
	if err := os.WriteFile(path, []byte(fmt.Sprintf("%d\n", pid)), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// The test binary is not named "ipgaze", so checkStalePID should remove the file.
	checkStalePID(path)
	// After the call the file is either removed (different program) or it still exists
	// if the current process happens to be ipgaze (won't happen in tests).
	// We only care that the function doesn't panic.
}

// ---------------------------------------------------------------------------
// printHelp
// ---------------------------------------------------------------------------

func captureStdout(fn func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	io.Copy(&buf, r) //nolint:errcheck
	return buf.String()
}

func TestPrintHelp_ContainsUsage(t *testing.T) {
	out := captureStdout(func() { printHelp("testbinary") })
	if !strings.Contains(out, "testbinary") {
		t.Errorf("printHelp() output missing binary name, got:\n%s", out)
	}
	if !strings.Contains(out, "Usage") {
		t.Errorf("printHelp() output missing Usage section, got:\n%s", out)
	}
}

func TestPrintHelp_ContainsFlags(t *testing.T) {
	out := captureStdout(func() { printHelp("ipgaze") })
	flags := []string{"--port", "--address", "--config", "--debug", "--service", "--version"}
	for _, f := range flags {
		if !strings.Contains(out, f) {
			t.Errorf("printHelp() missing flag %q", f)
		}
	}
}

// ---------------------------------------------------------------------------
// printShellCompletions
// ---------------------------------------------------------------------------

func TestPrintShellCompletions_Bash(t *testing.T) {
	out := captureStdout(func() { printShellCompletions("testbin", "bash") })
	if !strings.Contains(out, "testbin") {
		t.Errorf("bash completions missing binary name, got:\n%s", out)
	}
	if !strings.Contains(out, "complete") {
		t.Errorf("bash completions missing 'complete' keyword, got:\n%s", out)
	}
}

func TestPrintShellCompletions_Zsh(t *testing.T) {
	out := captureStdout(func() { printShellCompletions("testbin", "zsh") })
	if !strings.Contains(out, "testbin") {
		t.Errorf("zsh completions missing binary name, got:\n%s", out)
	}
	if !strings.Contains(out, "_arguments") {
		t.Errorf("zsh completions missing '_arguments', got:\n%s", out)
	}
}

func TestPrintShellCompletions_Fish(t *testing.T) {
	out := captureStdout(func() { printShellCompletions("testbin", "fish") })
	if !strings.Contains(out, "testbin") {
		t.Errorf("fish completions missing binary name, got:\n%s", out)
	}
	if !strings.Contains(out, "complete") {
		t.Errorf("fish completions missing 'complete' keyword, got:\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// printShellInit
// ---------------------------------------------------------------------------

func TestPrintShellInit_Bash(t *testing.T) {
	out := captureStdout(func() { printShellInit("mybin", "bash") })
	if !strings.Contains(out, "mybin") {
		t.Errorf("bash init missing binary name, got:\n%s", out)
	}
}

func TestPrintShellInit_Zsh(t *testing.T) {
	out := captureStdout(func() { printShellInit("mybin", "zsh") })
	if !strings.Contains(out, "mybin") {
		t.Errorf("zsh init missing binary name, got:\n%s", out)
	}
}

func TestPrintShellInit_Fish(t *testing.T) {
	out := captureStdout(func() { printShellInit("mybin", "fish") })
	if !strings.Contains(out, "mybin") {
		t.Errorf("fish init missing binary name, got:\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// handleI2PCommand
// ---------------------------------------------------------------------------

func TestHandleI2PCommand_NoArgsShowsUsage(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.AppConfig{}
	out := captureStdout(func() { handleI2PCommand(nil, dir, dir, dir, cfg) })
	if !strings.Contains(out, "Usage: ipgaze i2p") {
		t.Errorf("handleI2PCommand(nil) output missing usage, got:\n%s", out)
	}
}

func TestHandleI2PCommand_HelpFlagShowsUsage(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.AppConfig{}
	out := captureStdout(func() { handleI2PCommand([]string{"--help"}, dir, dir, dir, cfg) })
	if !strings.Contains(out, "Subcommands:") {
		t.Errorf("handleI2PCommand([--help]) output missing subcommands, got:\n%s", out)
	}
}

func TestHandleI2PCommand_StatusDisabled(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.AppConfig{}
	cfg.Server.I2P.Enabled = false
	out := captureStdout(func() { handleI2PCommand([]string{"status"}, dir, dir, dir, cfg) })
	if !strings.Contains(out, "I2P Eepsite: Disabled") {
		t.Errorf("handleI2PCommand([status]) with I2P disabled, got:\n%s", out)
	}
}

func TestHandleI2PCommand_StatusEnabledNoProvider(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.AppConfig{}
	cfg.Server.I2P.Enabled = true
	cfg.Server.I2P.Binary = "/nonexistent/i2pd"
	cfg.Server.I2P.SAMAddress = "127.0.0.1:1"
	out := captureStdout(func() { handleI2PCommand([]string{"status"}, dir, dir, dir, cfg) })
	if !strings.Contains(out, "No Provider") {
		t.Errorf("handleI2PCommand([status]) with no provider, got:\n%s", out)
	}
}
