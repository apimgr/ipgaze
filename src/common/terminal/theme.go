package terminal

import (
	"os"
	"strings"

	"github.com/apimgr/ipgaze/src/common/theme"
)

// ResolveThemeName picks the terminal theme: an explicitly configured "dark"
// or "light" always wins (AI.md PART 32: the TUI theme comes from the
// `tui.theme` config key); "auto", an empty value, or anything unrecognised
// falls back to the COLORFGBG autodetection described in AI.md PART 16
// "System Theme Detection".
func ResolveThemeName(configured, colorFGBG string) theme.Name {
	switch theme.Name(strings.ToLower(strings.TrimSpace(configured))) {
	case theme.NameDark:
		return theme.NameDark
	case theme.NameLight:
		return theme.NameLight
	}
	return themeFromCOLORFGBG(colorFGBG)
}

// DetectThemeName resolves the theme for the current process, reading
// COLORFGBG from the environment when the configured value does not decide.
func DetectThemeName(configured string) theme.Name {
	return ResolveThemeName(configured, os.Getenv("COLORFGBG"))
}

// themeFromCOLORFGBG reads the "fg;bg" COLORFGBG value (e.g. "15;0"); a light
// background (ANSI index 7 or above) selects the light palette, everything
// else — including an absent COLORFGBG — defaults to dark.
func themeFromCOLORFGBG(v string) theme.Name {
	if v == "" {
		return theme.NameDark
	}
	parts := strings.Split(v, ";")
	bg := parts[len(parts)-1]
	switch bg {
	case "7", "8", "9", "10", "11", "12", "13", "14", "15":
		return theme.NameLight
	default:
		return theme.NameDark
	}
}
