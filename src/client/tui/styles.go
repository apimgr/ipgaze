package tui

import (
	"github.com/charmbracelet/lipgloss"

	"github.com/apimgr/ipgaze/src/common/theme"
)

// TUIStyles holds lipgloss styles derived from a TerminalPalette (ANSI-safe
// — see AI.md PART 16 "CLI/TUI Color Mapping"; never the literal hex
// ThemePalette).
type TUIStyles struct {
	Base      lipgloss.Style
	Title     lipgloss.Style
	Highlight lipgloss.Style
	Label     lipgloss.Style
	Value     lipgloss.Style
	Selected  lipgloss.Style
	Error     lipgloss.Style
	Success   lipgloss.Style
	Warning   lipgloss.Style
	Muted     lipgloss.Style
	Border    lipgloss.Style
}

// StylesFromTerminalPalette builds TUIStyles from an ANSI-mapped
// TerminalPalette, per AI.md PART 32 "TUI Styles from Palette".
func StylesFromTerminalPalette(p theme.TerminalPalette) TUIStyles {
	return TUIStyles{
		Base: lipgloss.NewStyle().
			Foreground(lipgloss.Color(p.Foreground)),
		Title: lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color(p.Primary)).
			MarginBottom(1),
		Highlight: lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color(p.Primary)).
			Padding(0, 1),
		Label: lipgloss.NewStyle().
			Foreground(lipgloss.Color(p.Muted)).
			Width(16),
		Value: lipgloss.NewStyle().
			Foreground(lipgloss.Color(p.Foreground)),
		Selected: lipgloss.NewStyle().Reverse(true),
		Error:    lipgloss.NewStyle().Foreground(lipgloss.Color(p.Error)),
		Success:  lipgloss.NewStyle().Foreground(lipgloss.Color(p.Success)),
		Warning:  lipgloss.NewStyle().Foreground(lipgloss.Color(p.Warning)),
		Muted: lipgloss.NewStyle().
			Foreground(lipgloss.Color(p.Muted)).
			Italic(true),
		Border: lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color(p.Border)).
			Padding(1, 2),
	}
}

// Styles are the TUIStyles built from ActivePalette (detected once at
// package init — see theme.go's detectMode()).
var Styles = StylesFromTerminalPalette(ActivePalette)

// TitleStyle is used for section headers.
var TitleStyle = Styles.Title

// IPStyle is used for the main IP address display.
var IPStyle = Styles.Highlight

// LabelStyle is for field labels in the info table.
var LabelStyle = Styles.Label

// ValueStyle is for field values in the info table.
var ValueStyle = Styles.Value

// SuccessStyle is for success indicators.
var SuccessStyle = Styles.Success

// ErrorStyle is for error indicators.
var ErrorStyle = Styles.Error

// BorderStyle is for bordered containers.
var BorderStyle = Styles.Border

// MutedStyle is for secondary/muted text.
var MutedStyle = Styles.Muted

// SelectedStyle highlights the row under the navigation cursor.
var SelectedStyle = Styles.Selected
