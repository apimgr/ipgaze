// Package cli provides CLI output helpers with NO_COLOR support.
package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/apimgr/ipgaze/src/common/display"
	"github.com/apimgr/ipgaze/src/common/theme"
)

// Output handles formatted terminal output with NO_COLOR support.
// Colors are applied via the ANSI-mapped TerminalPalette — never the
// literal hex ThemePalette (see AI.md PART 16 "CLI/TUI Color Mapping").
type Output struct {
	out     io.Writer
	err     io.Writer
	colors  bool
	palette theme.TerminalPalette
}

// NewOutput creates an Output writer.
// colorMode is the value of the --color CLI flag: "auto" (default), "yes",
// or "no". Color gating goes through display.ColorEnabled per AI.md PART 8
// (CLI flag > NO_COLOR env > TTY/TERM auto-detect) — never a separate ad
// hoc check.
func NewOutput(colorMode string) *Output {
	return &Output{
		out:     os.Stdout,
		err:     os.Stderr,
		colors:  display.ColorEnabled(colorMode),
		palette: theme.TerminalPaletteFor(detectMode()),
	}
}

// detectMode resolves dark vs. light for CLI ANSI output. Per AI.md PART 16
// "System Theme Detection" -> Terminal: "COLORFGBG env or fallback to dark".
// COLORFGBG is "fg;bg" (e.g. "15;0"); a light background (bg >= 7) selects
// the light palette, everything else (including no COLORFGBG at all)
// defaults to dark.
func detectMode() theme.Name {
	v := os.Getenv("COLORFGBG")
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

// PrintSuccess prints a success message (palette-colored checkmark when
// color enabled). Plain "OK:" prefix when NO_COLOR is set or color is
// disabled.
func (o *Output) PrintSuccess(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if o.colors {
		fmt.Fprintf(o.out, "\033[38;5;%sm✓\033[0m %s\n", o.palette.Success, msg)
	} else {
		fmt.Fprintf(o.out, "OK: %s\n", msg)
	}
}

// PrintError prints an error message to stderr (palette-colored cross when
// color enabled). Plain "ERR:" prefix when NO_COLOR is set or color is
// disabled.
func (o *Output) PrintError(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if o.colors {
		fmt.Fprintf(o.err, "\033[38;5;%sm✗\033[0m %s\n", o.palette.Error, msg)
	} else {
		fmt.Fprintf(o.err, "ERR: %s\n", msg)
	}
}

// PrintWarning prints a warning message (palette-colored warning glyph when
// color enabled). Plain "WARN:" prefix when NO_COLOR is set or color is
// disabled.
func (o *Output) PrintWarning(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if o.colors {
		fmt.Fprintf(o.err, "\033[38;5;%sm⚠\033[0m %s\n", o.palette.Warning, msg)
	} else {
		fmt.Fprintf(o.err, "WARN: %s\n", msg)
	}
}

// PrintInfo prints an informational message (palette-colored info glyph
// when color enabled). Plain "INFO:" prefix when NO_COLOR is set or color
// is disabled.
func (o *Output) PrintInfo(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if o.colors {
		fmt.Fprintf(o.out, "\033[38;5;%smℹ\033[0m %s\n", o.palette.Info, msg)
	} else {
		fmt.Fprintf(o.out, "INFO: %s\n", msg)
	}
}

// Print prints a plain message to stdout.
func (o *Output) Print(format string, args ...interface{}) {
	fmt.Fprintf(o.out, format+"\n", args...)
}
