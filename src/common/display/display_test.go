package display

import (
	"os"
	"testing"
)

// TestDisplayModeString covers the String() method for every defined constant
// and the default/unknown branch.
func TestDisplayModeString(t *testing.T) {
	tests := []struct {
		mode DisplayMode
		want string
	}{
		{DisplayModeHeadless, "headless"},
		{DisplayModeCLI, "cli"},
		{DisplayModeTUI, "tui"},
		{DisplayModeGUI, "gui"},
		{DisplayMode(99), "unknown"},
	}
	for _, tt := range tests {
		got := tt.mode.String()
		if got != tt.want {
			t.Errorf("DisplayMode(%d).String() = %q, want %q", tt.mode, got, tt.want)
		}
	}
}

// TestAutoDetectDisplayModePredicates confirms the four Is* helpers agree with
// the Mode field. Each is a pure predicate on a value receiver so we can
// construct DisplayEnv directly without touching the OS.
func TestAutoDetectDisplayModePredicates(t *testing.T) {
	tests := []struct {
		name         string
		mode         DisplayMode
		wantGUI      bool
		wantTUI      bool
		wantCLI      bool
		wantHeadless bool
	}{
		{"gui", DisplayModeGUI, true, false, false, false},
		{"tui", DisplayModeTUI, false, true, false, false},
		{"cli", DisplayModeCLI, false, false, true, false},
		{"headless", DisplayModeHeadless, false, false, false, true},
	}
	for _, tt := range tests {
		env := DisplayEnv{Mode: tt.mode}
		if got := env.IsAutoDetectDisplayModeGUI(); got != tt.wantGUI {
			t.Errorf("%s: IsAutoDetectDisplayModeGUI() = %v, want %v", tt.name, got, tt.wantGUI)
		}
		if got := env.IsAutoDetectDisplayModeTUI(); got != tt.wantTUI {
			t.Errorf("%s: IsAutoDetectDisplayModeTUI() = %v, want %v", tt.name, got, tt.wantTUI)
		}
		if got := env.IsAutoDetectDisplayModeCLI(); got != tt.wantCLI {
			t.Errorf("%s: IsAutoDetectDisplayModeCLI() = %v, want %v", tt.name, got, tt.wantCLI)
		}
		if got := env.IsAutoDetectDisplayModeHeadless(); got != tt.wantHeadless {
			t.Errorf("%s: IsAutoDetectDisplayModeHeadless() = %v, want %v", tt.name, got, tt.wantHeadless)
		}
	}
}

// TestIsHeadless and TestSupportsTUI cover the pointer-receiver helpers.
func TestIsHeadless(t *testing.T) {
	headless := &DisplayEnv{Mode: DisplayModeHeadless}
	if !headless.IsHeadless() {
		t.Error("IsHeadless() = false for DisplayModeHeadless")
	}

	tui := &DisplayEnv{Mode: DisplayModeTUI}
	if tui.IsHeadless() {
		t.Error("IsHeadless() = true for DisplayModeTUI")
	}
}

func TestIsDumbTerminal(t *testing.T) {
	dumb := &DisplayEnv{TerminalType: "dumb"}
	if !dumb.IsDumbTerminal() {
		t.Error("IsDumbTerminal() = false for TerminalType=dumb")
	}

	xterm := &DisplayEnv{TerminalType: "xterm"}
	if xterm.IsDumbTerminal() {
		t.Error("IsDumbTerminal() = true for TerminalType=xterm")
	}
}

func TestCanUseANSI(t *testing.T) {
	tests := []struct {
		name    string
		env     *DisplayEnv
		noColor string
		want    bool
	}{
		{"dumb terminal", &DisplayEnv{TerminalType: "dumb", IsTerminal: true}, "", false},
		{"no_color set", &DisplayEnv{TerminalType: "xterm", IsTerminal: true}, "1", false},
		{"not a tty", &DisplayEnv{TerminalType: "xterm", IsTerminal: false}, "", false},
		{"tty and no dumb/no_color", &DisplayEnv{TerminalType: "xterm", IsTerminal: true}, "", true},
	}
	for _, tt := range tests {
		t.Setenv("NO_COLOR", tt.noColor)
		if got := CanUseANSI(tt.env); got != tt.want {
			t.Errorf("%s: CanUseANSI() = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestSupportsTUI(t *testing.T) {
	tests := []struct {
		name string
		env  DisplayEnv
		want bool
	}{
		{"tui non-dumb", DisplayEnv{Mode: DisplayModeTUI, TerminalType: "xterm-256color"}, true},
		{"tui dumb", DisplayEnv{Mode: DisplayModeTUI, TerminalType: "dumb"}, false},
		{"gui mode", DisplayEnv{Mode: DisplayModeGUI}, false},
		{"headless", DisplayEnv{Mode: DisplayModeHeadless}, false},
		{"cli mode", DisplayEnv{Mode: DisplayModeCLI}, false},
	}
	for _, tt := range tests {
		env := tt.env
		if got := env.SupportsTUI(); got != tt.want {
			t.Errorf("%s: SupportsTUI() = %v, want %v", tt.name, got, tt.want)
		}
	}
}

// TestSupportsColor exercises SupportsColor across mode, TERM, NO_COLOR, and
// IsTerminal combinations.
func TestSupportsColor(t *testing.T) {
	tests := []struct {
		name    string
		env     DisplayEnv
		noColor string
		want    bool
	}{
		{"headless mode", DisplayEnv{Mode: DisplayModeHeadless, IsTerminal: true}, "", false},
		{"cli mode", DisplayEnv{Mode: DisplayModeCLI, IsTerminal: true}, "", false},
		{"tui dumb term", DisplayEnv{Mode: DisplayModeTUI, IsTerminal: true, TerminalType: "dumb"}, "", false},
		{"tui no-color env", DisplayEnv{Mode: DisplayModeTUI, IsTerminal: true, TerminalType: "xterm"}, "1", false},
		{"tui not a tty", DisplayEnv{Mode: DisplayModeTUI, IsTerminal: false, TerminalType: "xterm"}, "", false},
		{"gui not a tty", DisplayEnv{Mode: DisplayModeGUI, IsTerminal: false, TerminalType: "xterm"}, "", false},
	}
	for _, tt := range tests {
		t.Setenv("NO_COLOR", tt.noColor)
		env := tt.env
		if got := env.SupportsColor(); got != tt.want {
			t.Errorf("%s: SupportsColor() = %v, want %v", tt.name, got, tt.want)
		}
	}
}

// TestColorEnabled covers the colorFlag priority chain and NO_COLOR / TERM=dumb
// environment variables. Tests avoid relying on whether stdout is a TTY in CI.
func TestColorEnabled(t *testing.T) {
	tests := []struct {
		name      string
		colorFlag string
		noColor   string
		term      string
		want      bool
	}{
		{"flag yes", "yes", "", "", true},
		{"flag always", "always", "", "", true},
		{"flag no", "no", "", "", false},
		{"flag never", "never", "", "", false},
		// NO_COLOR and TERM=dumb override auto-detect
		{"auto no_color set", "auto", "1", "", false},
		{"auto term dumb", "auto", "", "dumb", false},
		// Both set — NO_COLOR wins over auto
		{"auto both inhibitors", "auto", "1", "dumb", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("NO_COLOR", tt.noColor)
			t.Setenv("TERM", tt.term)
			got := ColorEnabled(tt.colorFlag)
			// When flag explicitly forces, result must match regardless of TTY.
			// For auto mode with inhibitors set, result must be false.
			// We only assert the false cases here because "auto" without
			// inhibitors depends on whether the test runner has a TTY.
			if tt.want == false && got != false {
				t.Errorf("ColorEnabled(%q) = true, want false (NO_COLOR=%q, TERM=%q)", tt.colorFlag, tt.noColor, tt.term)
			}
			if tt.colorFlag == "yes" || tt.colorFlag == "always" {
				if !got {
					t.Errorf("ColorEnabled(%q) = false, want true", tt.colorFlag)
				}
			}
			if tt.colorFlag == "no" || tt.colorFlag == "never" {
				if got {
					t.Errorf("ColorEnabled(%q) = true, want false", tt.colorFlag)
				}
			}
		})
	}
}

// TestEmojiEnabled ensures emoji gates on ColorEnabled and TERM=dumb.
func TestEmojiEnabled(t *testing.T) {
	// With flag=no color is disabled, emoji must be false.
	t.Setenv("NO_COLOR", "")
	t.Setenv("TERM", "xterm-256color")
	if EmojiEnabled("no") {
		t.Error("EmojiEnabled(no) = true, want false")
	}
	if EmojiEnabled("never") {
		t.Error("EmojiEnabled(never) = true, want false")
	}

	// With TERM=dumb, emoji must be false even when color flag is "yes".
	t.Setenv("TERM", "dumb")
	if EmojiEnabled("yes") {
		t.Error("EmojiEnabled(yes) with TERM=dumb = true, want false")
	}

	// With flag=yes and a good TERM, emoji should be enabled.
	t.Setenv("TERM", "xterm-256color")
	if !EmojiEnabled("yes") {
		t.Error("EmojiEnabled(yes) with xterm-256color = false, want true")
	}

	// NO_COLOR disables emoji.
	t.Setenv("NO_COLOR", "1")
	if EmojiEnabled("yes") {
		t.Error("EmojiEnabled(yes) with NO_COLOR=1 = true, want false")
	}
}

// TestAutoDetectDisplayMode_Logic tests autoDetectDisplayMode() via the
// exported DetectDisplayEnv path by constructing controlled DisplayEnv
// values and calling the method directly.
// These cases don't require a real TTY.
func TestAutoDetectDisplayMode_Logic(t *testing.T) {
	tests := []struct {
		name     string
		env      DisplayEnv
		wantMode DisplayMode
	}{
		{
			"no terminal no display → headless",
			DisplayEnv{IsTerminal: false, HasDisplay: false, TerminalType: "xterm"},
			DisplayModeHeadless,
		},
		{
			"dumb term with terminal → cli",
			DisplayEnv{IsTerminal: true, HasDisplay: false, TerminalType: "dumb"},
			DisplayModeCLI,
		},
		{
			"has display no ssh → gui",
			DisplayEnv{IsTerminal: false, HasDisplay: true, IsSSH: false, IsMosh: false, TerminalType: "xterm"},
			DisplayModeGUI,
		},
		{
			"has display over ssh → tui (not gui)",
			DisplayEnv{IsTerminal: true, HasDisplay: true, IsSSH: true, IsMosh: false, TerminalType: "xterm"},
			DisplayModeTUI,
		},
		{
			"has display over mosh → tui (not gui)",
			DisplayEnv{IsTerminal: true, HasDisplay: true, IsSSH: false, IsMosh: true, TerminalType: "xterm"},
			DisplayModeTUI,
		},
		{
			"is terminal no display → tui",
			DisplayEnv{IsTerminal: true, HasDisplay: false, TerminalType: "xterm"},
			DisplayModeTUI,
		},
		{
			"no terminal no display dumb → headless (dumb check after no-terminal check)",
			DisplayEnv{IsTerminal: false, HasDisplay: false, TerminalType: "dumb"},
			DisplayModeHeadless,
		},
	}
	for _, tt := range tests {
		env := tt.env
		got := env.autoDetectDisplayMode()
		if got != tt.wantMode {
			t.Errorf("%s: autoDetectDisplayMode() = %v (%s), want %v (%s)",
				tt.name, got, got.String(), tt.wantMode, tt.wantMode.String())
		}
	}
}

// TestDetectUnixDisplay exercises detectUnixDisplay() through the exported
// DetectDisplayEnv() path by controlling DISPLAY and WAYLAND_DISPLAY.
// We only run this on Linux/FreeBSD but the env-var logic is platform-agnostic.
func TestDetectUnixDisplay_WaylandPreferred(t *testing.T) {
	t.Setenv("WAYLAND_DISPLAY", "wayland-0")
	t.Setenv("DISPLAY", "")
	env := DisplayEnv{}
	env.detectUnixDisplay()
	if !env.HasDisplay {
		t.Error("HasDisplay = false, want true when WAYLAND_DISPLAY is set")
	}
	if env.DisplayType != "wayland" {
		t.Errorf("DisplayType = %q, want %q", env.DisplayType, "wayland")
	}
}

func TestDetectUnixDisplay_X11Fallback(t *testing.T) {
	t.Setenv("WAYLAND_DISPLAY", "")
	t.Setenv("DISPLAY", ":0")
	env := DisplayEnv{}
	env.detectUnixDisplay()
	if !env.HasDisplay {
		t.Error("HasDisplay = false, want true when DISPLAY is set")
	}
	if env.DisplayType != "x11" {
		t.Errorf("DisplayType = %q, want %q", env.DisplayType, "x11")
	}
}

func TestDetectUnixDisplay_None(t *testing.T) {
	t.Setenv("WAYLAND_DISPLAY", "")
	t.Setenv("DISPLAY", "")
	env := DisplayEnv{}
	env.detectUnixDisplay()
	if env.HasDisplay {
		t.Error("HasDisplay = true, want false when no display env vars set")
	}
	if env.DisplayType != "none" {
		t.Errorf("DisplayType = %q, want %q", env.DisplayType, "none")
	}
}

// TestDetectMacOSDisplay tests the macOS detection helpers without executing
// on macOS — we just call the method directly.
func TestDetectMacOSDisplay_SSHBlocks(t *testing.T) {
	t.Setenv("__CFBundleIdentifier", "com.apple.Terminal")
	t.Setenv("TERM_PROGRAM", "Apple_Terminal")
	env := DisplayEnv{IsSSH: true}
	env.detectMacOSDisplay()
	if env.HasDisplay {
		t.Error("HasDisplay = true over SSH on macOS, want false")
	}
	if env.DisplayType != "none" {
		t.Errorf("DisplayType = %q, want %q", env.DisplayType, "none")
	}
}

func TestDetectMacOSDisplay_CFBundle(t *testing.T) {
	t.Setenv("__CFBundleIdentifier", "com.apple.Terminal")
	env := DisplayEnv{IsSSH: false}
	env.detectMacOSDisplay()
	if !env.HasDisplay {
		t.Error("HasDisplay = false, want true when __CFBundleIdentifier is set")
	}
	if env.DisplayType != "macos" {
		t.Errorf("DisplayType = %q, want %q", env.DisplayType, "macos")
	}
}

func TestDetectMacOSDisplay_TermProgram(t *testing.T) {
	t.Setenv("__CFBundleIdentifier", "")
	t.Setenv("TERM_PROGRAM", "iTerm.app")
	env := DisplayEnv{IsSSH: false}
	env.detectMacOSDisplay()
	if !env.HasDisplay {
		t.Error("HasDisplay = false, want true when TERM_PROGRAM is set")
	}
	if env.DisplayType != "macos" {
		t.Errorf("DisplayType = %q, want %q", env.DisplayType, "macos")
	}
}

func TestDetectMacOSDisplay_NeitherEnvSet(t *testing.T) {
	t.Setenv("__CFBundleIdentifier", "")
	t.Setenv("TERM_PROGRAM", "")
	env := DisplayEnv{IsSSH: false}
	env.detectMacOSDisplay()
	if env.HasDisplay {
		t.Error("HasDisplay = true, want false when no macOS env vars set")
	}
	if env.DisplayType != "none" {
		t.Errorf("DisplayType = %q, want %q", env.DisplayType, "none")
	}
}

// TestDetectWindowsDisplay tests the Windows display detection logic.
func TestDetectWindowsDisplay_ServiceSession(t *testing.T) {
	t.Setenv("SESSIONID", "0")
	t.Setenv("SESSIONNAME", "")
	env := DisplayEnv{}
	env.detectWindowsDisplay()
	if env.HasDisplay {
		t.Error("HasDisplay = true in session 0 (service), want false")
	}
	if env.DisplayType != "none" {
		t.Errorf("DisplayType = %q, want %q", env.DisplayType, "none")
	}
}

func TestDetectWindowsDisplay_RDP(t *testing.T) {
	t.Setenv("SESSIONID", "")
	t.Setenv("SESSIONNAME", "RDP-Tcp#0")
	env := DisplayEnv{}
	env.detectWindowsDisplay()
	if !env.HasDisplay {
		t.Error("HasDisplay = false for RDP session, want true")
	}
	if env.DisplayType != "windows-rdp" {
		t.Errorf("DisplayType = %q, want %q", env.DisplayType, "windows-rdp")
	}
}

func TestDetectWindowsDisplay_Interactive(t *testing.T) {
	t.Setenv("SESSIONID", "1")
	t.Setenv("SESSIONNAME", "Console")
	env := DisplayEnv{}
	env.detectWindowsDisplay()
	if !env.HasDisplay {
		t.Error("HasDisplay = false for interactive session, want true")
	}
	if env.DisplayType != "windows" {
		t.Errorf("DisplayType = %q, want %q", env.DisplayType, "windows")
	}
}

func TestDetectWindowsDisplay_NoEnvVars(t *testing.T) {
	t.Setenv("SESSIONID", "")
	t.Setenv("SESSIONNAME", "")
	env := DisplayEnv{}
	env.detectWindowsDisplay()
	if !env.HasDisplay {
		t.Error("HasDisplay = false, want true as default Windows behavior")
	}
	if env.DisplayType != "windows" {
		t.Errorf("DisplayType = %q, want %q", env.DisplayType, "windows")
	}
}

// TestDetectContainer checks env-var-based container detection.
func TestDetectContainer_ContainerEnvVar(t *testing.T) {
	t.Setenv("container", "podman")
	got := detectContainer()
	if !got {
		t.Error("detectContainer() = false, want true when container env var is set")
	}
}

func TestDetectContainer_EmptyEnvVar(t *testing.T) {
	t.Setenv("container", "")
	// /.dockerenv and /proc/1/cgroup may or may not indicate a container in CI;
	// we only assert the env-var path by setting it to empty and checking the
	// function doesn't panic.
	_ = detectContainer()
}

// TestDetectDisplayEnv_Smoke exercises the full DetectDisplayEnv() call path.
// In a headless CI environment (no DISPLAY, no TTY) it must return a
// DisplayEnv whose Mode is at most DisplayModeTUI (never panics, returns
// consistent data).
func TestDetectDisplayEnv_Smoke(t *testing.T) {
	got := DetectDisplayEnv()

	// Mode must be a valid defined constant.
	switch got.Mode {
	case DisplayModeHeadless, DisplayModeCLI, DisplayModeTUI, DisplayModeGUI:
		// valid
	default:
		t.Errorf("DetectDisplayEnv().Mode = %d, not a recognised DisplayMode", got.Mode)
	}

	// DisplayType must be a non-empty string.
	if got.DisplayType == "" {
		t.Error("DetectDisplayEnv().DisplayType is empty")
	}

	// TerminalType should match $TERM.
	if got.TerminalType != os.Getenv("TERM") {
		t.Errorf("TerminalType = %q, want %q", got.TerminalType, os.Getenv("TERM"))
	}

	// Predicate consistency: exactly one mode predicate must be true.
	count := 0
	if got.IsAutoDetectDisplayModeGUI() {
		count++
	}
	if got.IsAutoDetectDisplayModeTUI() {
		count++
	}
	if got.IsAutoDetectDisplayModeCLI() {
		count++
	}
	if got.IsAutoDetectDisplayModeHeadless() {
		count++
	}
	if count != 1 {
		t.Errorf("expected exactly 1 mode predicate true, got %d (mode=%s)", count, got.Mode.String())
	}
}

// TestDetectDisplayEnv_SSHVarsRecognised confirms SSH env-var detection.
func TestDetectDisplayEnv_SSHVarsRecognised(t *testing.T) {
	t.Setenv("SSH_TTY", "/dev/pts/0")
	t.Setenv("SSH_CLIENT", "")
	got := DetectDisplayEnv()
	if !got.IsSSH {
		t.Error("IsSSH = false, want true when SSH_TTY is set")
	}
}

func TestDetectDisplayEnv_MoshVarRecognised(t *testing.T) {
	t.Setenv("MOSH", "yes")
	got := DetectDisplayEnv()
	if !got.IsMosh {
		t.Error("IsMosh = false, want true when MOSH env var is set")
	}
}
