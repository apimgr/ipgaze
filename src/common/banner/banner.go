// Package banner renders the responsive startup banner for all ipgaze binaries.
// The banner adapts to terminal width using the breakpoints defined in
// src/common/terminal/size.go and respects NO_COLOR / TERM=dumb.
package banner

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/apimgr/ipgaze/src/common/display"
	"github.com/apimgr/ipgaze/src/common/terminal"
)

// cacheMu guards CachedSize for concurrent read/write from WatchTerminalSize.
var cacheMu sync.RWMutex

// CachedSize holds the most recently detected terminal dimensions.
// It is updated by WatchTerminalSize (running in a goroutine) and can be
// read at any time without calling the OS. The zero value is safe: callers
// should fall back to terminal.GetTerminalSize() when Cols == 0.
var CachedSize terminal.TerminalSize

// BannerPrintConfig holds the values printed in the startup banner.
type BannerPrintConfig struct {
	AppName string
	Version string
	// AppMode is "production", "development", or "debug"
	AppMode string
	Debug   bool
	// URLs is the list of display URLs shown on the "Listening on" lines. Per
	// AI.md PART 12 startup step 20 these are always resolved {proto}://{fqdn}
	// URLs (e.g. ["https://example.com", "http://abc.onion"]) — never a raw
	// wildcard bind address such as 0.0.0.0 or [::].
	URLs []string
	// ColorFlag is the --color flag value: "always", "never", or "auto" (default)
	ColorFlag string
	// StartedAt is the time the server started. Zero value prints the current time.
	StartedAt time.Time
}

// modeEmoji returns the emoji for the given app mode, or "" when emoji is
// disabled (respects NO_COLOR / TERM=dumb via display.EmojiEnabled).
func modeEmoji(mode string, emoji bool) string {
	if !emoji {
		return ""
	}
	switch mode {
	case "development", "dev", "debug":
		// Debug mode renders as development per AI.md PART 6 "Debug Mode":
		// everything not explicitly called out there is as Development Mode.
		return "🔧"
	default:
		return "🔒"
	}
}

// emojiPrefix returns s+" " when emoji is enabled, or "" otherwise, so
// callers can build emoji-prefixed labels without conditional formatting
// at every call site.
func emojiPrefix(s string, emoji bool) string {
	if !emoji {
		return ""
	}
	return s + " "
}

// formatStartedAt formats the startup time as "Mon Jan 2, 2006 at 15:04:05 MST".
func formatStartedAt(t time.Time) string {
	if t.IsZero() {
		t = time.Now()
	}
	return t.Format("Mon Jan 2, 2006 at 15:04:05 MST")
}

// PrintStartupBanner prints the startup banner at the appropriate verbosity
// for the current terminal width. It respects NO_COLOR and TERM=dumb via the
// shared display.ColorEnabled() function.
func PrintStartupBanner(cfg BannerPrintConfig) {
	size := terminal.GetTerminalSize()
	color := display.ColorEnabled(cfg.ColorFlag)
	emoji := display.EmojiEnabled(cfg.ColorFlag)

	switch {
	case size.Mode >= terminal.SizeModeStandard:
		printFull(cfg, size, color, emoji)
	case size.Mode >= terminal.SizeModeCompact:
		printCompact(cfg, color, emoji)
	case size.Mode >= terminal.SizeModeMinimal:
		printMinimal(cfg, emoji)
	default:
		printMicro(cfg)
	}
}

func printFull(cfg BannerPrintConfig, size terminal.TerminalSize, color, emoji bool) {
	width := size.Cols
	if width > 100 {
		width = 100
	}

	sep := strings.Repeat("─", width-2)
	modeIcon := modeEmoji(cfg.AppMode, emoji)
	header := fmt.Sprintf("%s%s · %s%s", emojiPrefix("🚀", emoji), strings.ToUpper(cfg.AppName), emojiPrefix("📦", emoji), cfg.Version)
	modeLine := fmt.Sprintf("%sRunning in mode: %s", emojiPrefix(modeIcon, emoji), cfg.AppMode)
	startedLine := fmt.Sprintf("%sServer started on %s", emojiPrefix("✅", emoji), formatStartedAt(cfg.StartedAt))

	if color {
		fmt.Printf("\033[34m╭%s╮\033[0m\n", sep)
		fmt.Printf("\033[34m│\033[0m \033[1;36m%-*s\033[0m \033[34m│\033[0m\n", width-4, header)
		fmt.Printf("\033[34m├%s┤\033[0m\n", sep)
		fmt.Printf("\033[34m│\033[0m \033[90m%-*s\033[0m \033[34m│\033[0m\n", width-4, modeLine)
		if len(cfg.URLs) > 0 {
			fmt.Printf("\033[34m├%s┤\033[0m\n", sep)
		}
		for _, u := range cfg.URLs {
			fmt.Printf("\033[34m│\033[0m \033[32m%-*s\033[0m \033[34m│\033[0m\n", width-4, emojiPrefix("📡", emoji)+"Listening on "+u)
		}
		if cfg.Debug {
			fmt.Printf("\033[34m├%s┤\033[0m\n", sep)
			fmt.Printf("\033[34m│\033[0m \033[33m%-*s\033[0m \033[34m│\033[0m\n", width-4, emojiPrefix("🐛", emoji)+"Debug: enabled")
		}
		fmt.Printf("\033[34m├%s┤\033[0m\n", sep)
		fmt.Printf("\033[34m│\033[0m \033[32m%-*s\033[0m \033[34m│\033[0m\n", width-4, startedLine)
		fmt.Printf("\033[34m╰%s╯\033[0m\n", sep)
	} else {
		fmt.Printf("╭%s╮\n", sep)
		fmt.Printf("│ %-*s │\n", width-4, header)
		fmt.Printf("├%s┤\n", sep)
		fmt.Printf("│ %-*s │\n", width-4, modeLine)
		if len(cfg.URLs) > 0 {
			fmt.Printf("├%s┤\n", sep)
		}
		for _, u := range cfg.URLs {
			fmt.Printf("│ %-*s │\n", width-4, emojiPrefix("📡", emoji)+"Listening on "+u)
		}
		if cfg.Debug {
			fmt.Printf("├%s┤\n", sep)
			fmt.Printf("│ %-*s │\n", width-4, emojiPrefix("🐛", emoji)+"Debug: enabled")
		}
		fmt.Printf("├%s┤\n", sep)
		fmt.Printf("│ %-*s │\n", width-4, startedLine)
		fmt.Printf("╰%s╯\n", sep)
	}
}

func printCompact(cfg BannerPrintConfig, color, emoji bool) {
	modeIcon := modeEmoji(cfg.AppMode, emoji)
	rocket := emojiPrefix("🚀", emoji)
	pkg := emojiPrefix("📦", emoji)
	antenna := emojiPrefix("📡", emoji)
	check := emojiPrefix("✅", emoji)
	if color {
		fmt.Printf("\033[1;36m%s%s\033[0m %s\033[90m%s\033[0m  %s \033[90m%s\033[0m\n",
			rocket, strings.ToUpper(cfg.AppName), pkg, cfg.Version, modeIcon, cfg.AppMode)
		for _, u := range cfg.URLs {
			fmt.Printf("  \033[32m%sListening: %s\033[0m\n", antenna, u)
		}
		fmt.Printf("  \033[32m%sStarted: %s\033[0m\n", check, formatStartedAt(cfg.StartedAt))
	} else {
		fmt.Printf("%s%s %s%s  %s %s\n", rocket, strings.ToUpper(cfg.AppName), pkg, cfg.Version, modeIcon, cfg.AppMode)
		for _, u := range cfg.URLs {
			fmt.Printf("  %sListening: %s\n", antenna, u)
		}
		fmt.Printf("  %sStarted: %s\n", check, formatStartedAt(cfg.StartedAt))
	}
}

func printMinimal(cfg BannerPrintConfig, emoji bool) {
	modeIcon := modeEmoji(cfg.AppMode, emoji)
	fmt.Printf("%s%s %s%s  %s %s\n", emojiPrefix("🚀", emoji), strings.ToUpper(cfg.AppName), emojiPrefix("📦", emoji), cfg.Version, modeIcon, cfg.AppMode)
	fmt.Printf("%sStarted: %s\n", emojiPrefix("✅", emoji), formatStartedAt(cfg.StartedAt))
}

func printMicro(cfg BannerPrintConfig) {
	fmt.Printf("%s %s\n", cfg.AppName, cfg.Version)
}
