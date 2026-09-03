// Package terminal provides terminal size detection and size-mode classification.
package terminal

import (
	"os"

	"golang.org/x/term"
)

// SizeMode classifies terminal dimensions into display capability tiers.
type SizeMode int

const (
	// SizeModeMicro covers terminals smaller than 40 cols or 10 rows
	SizeModeMicro SizeMode = iota
	// SizeModeMinimal covers 40-59 cols or 10-15 rows
	SizeModeMinimal
	// SizeModeCompact covers 60-79 cols or 16-23 rows
	SizeModeCompact
	// SizeModeStandard covers 80-119 cols and 24-39 rows
	SizeModeStandard
	// SizeModeWide covers 120-199 cols and 40-59 rows
	SizeModeWide
	// SizeModeUltrawide covers 200-399 cols and 60-79 rows
	SizeModeUltrawide
	// SizeModeMassive covers 400+ cols and 80+ rows
	SizeModeMassive
)

// TerminalSize holds the detected terminal dimensions and their classified mode.
type TerminalSize struct {
	Cols int
	Rows int
	Mode SizeMode
}

// GetTerminalSize returns the current terminal size, defaulting to 80×24 when
// detection fails (non-TTY output, piped output, etc.).
func GetTerminalSize() TerminalSize {
	cols, rows, _ := term.GetSize(int(os.Stdout.Fd()))
	if cols == 0 {
		cols = 80
	}
	if rows == 0 {
		rows = 24
	}
	return TerminalSize{
		Cols: cols,
		Rows: rows,
		Mode: calculateMode(cols, rows),
	}
}

func calculateMode(cols, rows int) SizeMode {
	switch {
	case cols < 40 || rows < 10:
		return SizeModeMicro
	case cols < 60 || rows < 16:
		return SizeModeMinimal
	case cols < 80 || rows < 24:
		return SizeModeCompact
	case cols < 120 || rows < 40:
		return SizeModeStandard
	case cols < 200 || rows < 60:
		return SizeModeWide
	case cols < 400 || rows < 80:
		return SizeModeUltrawide
	default:
		return SizeModeMassive
	}
}

// ShowASCIIArt returns true when the terminal is wide enough for full banner art.
func (s SizeMode) ShowASCIIArt() bool { return s >= SizeModeStandard }

// ShowBorders returns true when the terminal supports box-drawing borders.
func (s SizeMode) ShowBorders() bool { return s >= SizeModeCompact }

// ShowSidebar returns true when the terminal has room for a sidebar panel.
func (s SizeMode) ShowSidebar() bool { return s >= SizeModeWide }

// ShowIcons returns true when there is enough space to display emoji icons.
func (s SizeMode) ShowIcons() bool { return s >= SizeModeMinimal }
