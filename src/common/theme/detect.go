package theme

import (
	"os"
	"strings"
)

// SystemThemeName reads a "fg;bg" COLORFGBG value (e.g. "15;0") and reports
// the palette it implies: a light background (ANSI index 7 or above) selects
// the light palette, everything else — including an absent COLORFGBG —
// defaults to dark (AI.md PART 16 "System Theme Detection").
func SystemThemeName(colorFGBG string) Name {
	if colorFGBG == "" {
		return NameDark
	}
	parts := strings.Split(colorFGBG, ";")
	switch parts[len(parts)-1] {
	case "7", "8", "9", "10", "11", "12", "13", "14", "15":
		return NameLight
	default:
		return NameDark
	}
}

// IsSystemDarkTheme reports whether the current environment is using a dark
// background, reading COLORFGBG from the process environment.
func IsSystemDarkTheme() bool {
	return SystemThemeName(os.Getenv("COLORFGBG")) == NameDark
}
