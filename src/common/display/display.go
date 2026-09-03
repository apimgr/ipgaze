package display

import (
	"os"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/term"
)

// DisplayMode represents how output should be formatted
type DisplayMode int

const (
	// DisplayModeHeadless means no display; daemon/service mode
	DisplayModeHeadless DisplayMode = iota
	// DisplayModeCLI means basic terminal with no ANSI escapes
	DisplayModeCLI
	// DisplayModeTUI means full terminal with colors/formatting
	DisplayModeTUI
	// DisplayModeGUI means native graphical UI
	DisplayModeGUI
)

// DisplayEnv holds the detected display environment.
type DisplayEnv struct {
	Mode DisplayMode
	// HasDisplay is true when an X11, Wayland, Windows, or macOS display is available
	HasDisplay bool
	// DisplayType is one of "x11", "wayland", "windows", "macos", "none"
	DisplayType string
	// IsTerminal is true when stdout is a TTY
	IsTerminal bool
	// IsSSH is true when running over SSH
	IsSSH bool
	// IsMosh is true when running over Mosh
	IsMosh bool
	// IsScreen is true when running inside screen or tmux
	IsScreen bool
	// IsContainer is true when running inside Docker/Incus/LXC
	IsContainer bool
	// TerminalType holds the $TERM value
	TerminalType string
	// Cols is the terminal column count (0 when there is no terminal)
	Cols int
	// Rows is the terminal row count (0 when there is no terminal)
	Rows int
}

// DetectDisplayEnv - auto-detect display environment
func DetectDisplayEnv() DisplayEnv {
	env := DisplayEnv{}

	// Detect terminal
	env.IsTerminal = term.IsTerminal(int(os.Stdout.Fd()))
	env.TerminalType = os.Getenv("TERM")

	// Detect SSH/Mosh/screen
	env.IsSSH = os.Getenv("SSH_TTY") != "" || os.Getenv("SSH_CLIENT") != ""
	env.IsMosh = os.Getenv("MOSH") != "" || strings.Contains(os.Getenv("TERM"), "mosh")
	env.IsScreen = os.Getenv("STY") != "" || os.Getenv("TMUX") != ""

	// Detect container environment
	env.IsContainer = detectContainer()

	// Get terminal size if available
	if env.IsTerminal {
		if cols, rows, err := term.GetSize(int(os.Stdout.Fd())); err == nil {
			env.Cols = cols
			env.Rows = rows
		}
	}

	// Detect platform-specific display
	env.detectPlatformDisplay()

	// Auto-detect display mode
	env.Mode = env.autoDetectDisplayMode()

	return env
}

// autoDetectDisplayMode - determine display mode from environment
func (e *DisplayEnv) autoDetectDisplayMode() DisplayMode {
	if !e.IsTerminal && !e.HasDisplay {
		return DisplayModeHeadless
	}
	// TERM=dumb: force CLI mode (no TUI, no ANSI escapes)
	if e.TerminalType == "dumb" {
		return DisplayModeCLI
	}
	if e.HasDisplay && !e.IsSSH && !e.IsMosh {
		return DisplayModeGUI
	}
	if e.IsTerminal {
		return DisplayModeTUI
	}
	return DisplayModeCLI
}

// detectContainer checks if running in a container
func detectContainer() bool {
	// Check for Docker
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}

	// Check cgroup for docker/lxc/incus
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		content := string(data)
		if strings.Contains(content, "docker") ||
			strings.Contains(content, "lxc") ||
			strings.Contains(content, "incus") ||
			strings.Contains(content, "kubepods") {
			return true
		}
	}

	// Check for container runtime environment variables
	if os.Getenv("container") != "" {
		return true
	}

	return false
}

// detectPlatformDisplay detects platform-specific display availability
func (e *DisplayEnv) detectPlatformDisplay() {
	switch runtime.GOOS {
	case "linux", "freebsd":
		e.detectUnixDisplay()
	case "darwin":
		e.detectMacOSDisplay()
	case "windows":
		e.detectWindowsDisplay()
	default:
		e.HasDisplay = false
		e.DisplayType = "none"
	}
}

// detectUnixDisplay detects X11/Wayland on Unix-like systems
func (e *DisplayEnv) detectUnixDisplay() {
	// Check for Wayland first (preferred on Linux)
	if waylandDisplay := os.Getenv("WAYLAND_DISPLAY"); waylandDisplay != "" {
		e.HasDisplay = true
		e.DisplayType = "wayland"
		return
	}

	// Check for X11
	if display := os.Getenv("DISPLAY"); display != "" {
		e.HasDisplay = true
		e.DisplayType = "x11"
		return
	}

	e.HasDisplay = false
	e.DisplayType = "none"
}

// detectMacOSDisplay detects macOS display availability
func (e *DisplayEnv) detectMacOSDisplay() {
	// macOS typically has a display unless:
	// - Running over SSH
	// - Running as a LaunchDaemon (no GUI session)
	if !e.IsSSH && os.Getenv("__CFBundleIdentifier") != "" {
		e.HasDisplay = true
		e.DisplayType = "macos"
		return
	}

	// Check if we're in an Aqua session
	// This is a simplified check; full implementation would use launchctl
	if !e.IsSSH && os.Getenv("TERM_PROGRAM") != "" {
		e.HasDisplay = true
		e.DisplayType = "macos"
		return
	}

	e.HasDisplay = false
	e.DisplayType = "none"
}

// detectWindowsDisplay detects Windows display availability
func (e *DisplayEnv) detectWindowsDisplay() {
	// Check for service mode (session 0)
	sessionIDStr := os.Getenv("SESSIONID")
	if sessionIDStr != "" {
		sessionID, _ := strconv.Atoi(sessionIDStr)
		if sessionID == 0 {
			// Running as a service (session 0) - no interactive desktop
			e.HasDisplay = false
			e.DisplayType = "none"
			return
		}
	}

	// Check for remote desktop session
	sessionName := os.Getenv("SESSIONNAME")
	if strings.HasPrefix(sessionName, "RDP-Tcp") {
		// Remote desktop - has display but may want different behavior
		e.HasDisplay = true
		e.DisplayType = "windows-rdp"
		return
	}

	// Default: assume Windows has a display unless proven otherwise
	// Full implementation would use Windows API (GetConsoleWindow)
	e.HasDisplay = true
	e.DisplayType = "windows"
}

// IsAutoDetectDisplayModeGUI returns true when the detected mode is GUI.
func (e DisplayEnv) IsAutoDetectDisplayModeGUI() bool { return e.Mode == DisplayModeGUI }

// IsAutoDetectDisplayModeTUI returns true when the detected mode is TUI.
func (e DisplayEnv) IsAutoDetectDisplayModeTUI() bool { return e.Mode == DisplayModeTUI }

// IsAutoDetectDisplayModeCLI returns true when the detected mode is CLI.
func (e DisplayEnv) IsAutoDetectDisplayModeCLI() bool { return e.Mode == DisplayModeCLI }

// IsAutoDetectDisplayModeHeadless returns true when the detected mode is Headless.
func (e DisplayEnv) IsAutoDetectDisplayModeHeadless() bool { return e.Mode == DisplayModeHeadless }

// IsHeadless returns true if running without any display.
func (e *DisplayEnv) IsHeadless() bool {
	return e.Mode == DisplayModeHeadless
}

// IsDumbTerminal returns true when TERM=dumb, meaning no ANSI support.
func (e *DisplayEnv) IsDumbTerminal() bool {
	return e.TerminalType == "dumb"
}

// CanUseANSI returns true when ANSI escape sequences (cursor movement, clear screen, etc.)
// are safe to use. Returns false for dumb terminals, NO_COLOR, and non-interactive stdout.
func CanUseANSI(e *DisplayEnv) bool {
	if e.IsDumbTerminal() {
		return false
	}
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	return e.IsTerminal
}

// SupportsTUI returns true if terminal supports TUI features.
func (e *DisplayEnv) SupportsTUI() bool {
	return e.Mode == DisplayModeTUI && e.TerminalType != "dumb"
}

// SupportsColor returns true if terminal supports ANSI colors
func (e *DisplayEnv) SupportsColor() bool {
	if e.Mode == DisplayModeHeadless || e.Mode == DisplayModeCLI {
		return false
	}
	if e.TerminalType == "dumb" {
		return false
	}
	// Check NO_COLOR environment variable (https://no-color.org/)
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	return e.IsTerminal
}

// ColorEnabled returns true when ANSI color output should be used.
// colorFlag is the value of the --color CLI flag: "yes", "no", or "auto" (default).
// Priority order: CLI flag > NO_COLOR env > auto-detect.
func ColorEnabled(colorFlag string) bool {
	switch colorFlag {
	case "yes", "always":
		return true
	case "no", "never":
		return false
	}
	// NO_COLOR (any non-empty value) and TERM=dumb disable color output
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	// Auto-detect: color only when stdout is a real terminal
	return term.IsTerminal(int(os.Stdout.Fd()))
}

// EmojiEnabled returns true when emoji/Unicode extended characters should be used.
// Emoji is disabled whenever NO_COLOR is set, TERM=dumb, color is disabled,
// or the terminal does not support it.  NO_COLOR is checked unconditionally
// here — it applies even when --color=yes is set — because NO_COLOR governs
// decorative output beyond just ANSI escapes.
func EmojiEnabled(colorFlag string) bool {
	// NO_COLOR always wins for decorative output including emoji
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	// TERM=dumb never renders emoji reliably
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	if !ColorEnabled(colorFlag) {
		return false
	}
	return true
}

// String returns a human-readable description of the display mode
func (m DisplayMode) String() string {
	switch m {
	case DisplayModeHeadless:
		return "headless"
	case DisplayModeCLI:
		return "cli"
	case DisplayModeTUI:
		return "tui"
	case DisplayModeGUI:
		return "gui"
	default:
		return "unknown"
	}
}
