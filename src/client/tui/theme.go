// Package tui provides terminal UI theme, styles, and layout for the ipgaze CLI.
// Uses charmbracelet/lipgloss for styled terminal output.
package tui

import (
	"github.com/apimgr/ipgaze/src/client/setup"
	"github.com/apimgr/ipgaze/src/common/terminal"
	"github.com/apimgr/ipgaze/src/common/theme"
)

// ActivePalette is the ANSI-mapped TerminalPalette in effect for this run,
// selected by detectMode() at package init. Per AI.md PART 16
// "CLI/TUI Color Mapping", the TUI consumes only these ANSI 16-color
// indices — never the literal hex ThemePalette.
var ActivePalette = theme.TerminalPaletteFor(detectMode())

// detectMode resolves dark vs. light for terminal output. The `tui.theme`
// key in cli.yml wins (AI.md PART 32 "Theme is set in cli.yml"); "auto" or an
// absent value falls back to COLORFGBG autodetection.
func detectMode() theme.Name {
	return terminal.DetectThemeName(setup.ConfiguredTUITheme())
}
