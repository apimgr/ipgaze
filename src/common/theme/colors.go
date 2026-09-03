// Package theme defines the shared color palette used by the server web UI,
// client TUI/CLI/GUI, and all other output layers. Colors are defined once here
// and consumed everywhere — never duplicated.
package theme

// ThemePalette holds all semantic color values for a single color scheme.
// Colors are hex strings (e.g. "#1a1b26") compatible with CSS, lipgloss, and
// native widget toolkits.
type ThemePalette struct {
	Background string `json:"background"`
	Foreground string `json:"foreground"`
	Primary    string `json:"primary"`
	Secondary  string `json:"secondary"`
	Accent     string `json:"accent"`
	Success    string `json:"success"`
	Warning    string `json:"warning"`
	Error      string `json:"error"`
	Info       string `json:"info"`
	Surface    string `json:"surface"`
	SurfaceAlt string `json:"surface_alt"`
	Border     string `json:"border"`
	Muted      string `json:"muted"`
}

// ThemePaletteDark is the default dark-mode color palette (Dracula-based),
// the literal values given in AI.md PART 16 "Themes (NON-NEGOTIABLE)" and
// matched by the "CSS Variable Reference" section, except Muted (see its
// field comment below — adjusted to satisfy AI.md's own 4.5:1 WCAG AA
// requirement, which the spec's literal stock Dracula value fails).
var ThemePaletteDark = ThemePalette{
	Background: "#282a36",
	Foreground: "#f8f8f2",
	Primary:    "#bd93f9",
	Secondary:  "#50fa7b",
	Accent:     "#ff79c6",
	Success:    "#50fa7b",
	Warning:    "#ffb86c",
	Error:      "#ff5555",
	Info:       "#8be9fd",
	Surface:    "#2b2d3a",
	SurfaceAlt: "#21222c",
	Border:     "#44475a",
	// Lightened from Dracula's stock #6272a4 (3.03:1 against Background,
	// below WCAG AA's 4.5:1 for normal text) to #8894ba (4.74:1) — same
	// hue/muted-blue-gray character, sufficient contrast for label/caption
	// text that uses this role directly (see AI.md PART 16 "Accessibility"
	// "Color Contrast — Minimum 4.5:1 for normal text").
	Muted: "#8894ba",
}

// ThemePaletteLight is the light-mode color palette (GitHub-Light-based),
// the exact literal values given verbatim in AI.md PART 16 "Themes
// (NON-NEGOTIABLE)" and matched by the "CSS Variable Reference" section.
var ThemePaletteLight = ThemePalette{
	Background: "#ffffff",
	Foreground: "#1f2328",
	Primary:    "#0969da",
	Secondary:  "#1a7f37",
	Accent:     "#8250df",
	Success:    "#1a7f37",
	Warning:    "#9a6700",
	Error:      "#d1242f",
	Info:       "#0969da",
	Surface:    "#f6f8fa",
	SurfaceAlt: "#eff2f5",
	Border:     "#d1d9e0",
	Muted:      "#59636e",
}

// Name identifies a color theme by its human-readable name.
type Name string

const (
	NameDark  Name = "dark"
	NameLight Name = "light"
	NameAuto  Name = "auto"
)

// Palette returns the color palette for the given theme name.
// "auto" and unknown values default to the dark palette.
func Palette(name Name) ThemePalette {
	switch name {
	case NameLight:
		return ThemePaletteLight
	default:
		return ThemePaletteDark
	}
}

// TerminalPalette holds ANSI 16-color indices (0-15) for CLI/TUI — never
// the literal hex ThemePalette. lipgloss.Color() and the ESC[38;5;{n}m
// escape both accept these indices directly. Per AI.md PART 16
// "CLI/TUI Color Mapping": terminals render a fixed, user-configured
// 16/256-color set, so forcing exact hex values is not appropriate.
type TerminalPalette struct {
	Foreground string `json:"foreground"`
	Muted      string `json:"muted"`
	Primary    string `json:"primary"`
	Success    string `json:"success"`
	Warning    string `json:"warning"`
	Error      string `json:"error"`
	Info       string `json:"info"`
	Border     string `json:"border"`
}

// TerminalPaletteDark is the ANSI-mapped palette for dark terminal
// backgrounds, the exact literal values given in AI.md PART 16.
var TerminalPaletteDark = TerminalPalette{
	Foreground: "15", Muted: "7", Primary: "13",
	Success: "10", Warning: "11", Error: "9", Info: "12", Border: "13",
}

// TerminalPaletteLight is the ANSI-mapped palette for light terminal
// backgrounds, the exact literal values given in AI.md PART 16.
var TerminalPaletteLight = TerminalPalette{
	Foreground: "0", Muted: "8", Primary: "4",
	Success: "2", Warning: "3", Error: "1", Info: "4", Border: "4",
}

// TerminalPaletteFor returns the ANSI-mapped terminal palette for the given
// theme name. "auto" and unknown values default to the dark palette.
func TerminalPaletteFor(name Name) TerminalPalette {
	switch name {
	case NameLight:
		return TerminalPaletteLight
	default:
		return TerminalPaletteDark
	}
}
