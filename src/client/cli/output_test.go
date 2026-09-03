package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/apimgr/ipgaze/src/common/theme"
)

// newOutputTo builds an Output that writes to provided buffers.
func newOutputTo(out, errBuf *bytes.Buffer, color bool) *Output {
	return &Output{out: out, err: errBuf, colors: color, palette: theme.TerminalPaletteDark}
}

// ---------------------------------------------------------------------------
// NewOutput — construction
// ---------------------------------------------------------------------------

func TestNewOutput_NeverColor(t *testing.T) {
	o := NewOutput("no")
	if o.colors {
		t.Error("NewOutput(no): colors should be false")
	}
}

func TestNewOutput_AlwaysColor(t *testing.T) {
	o := NewOutput("yes")
	if !o.colors {
		t.Error("NewOutput(yes): colors should be true")
	}
}

func TestNewOutput_AutoWithNoColor(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	o := NewOutput("auto")
	if o.colors {
		t.Error("NewOutput(auto) with NO_COLOR=1: colors should be false")
	}
}

func TestNewOutput_DefaultIsAuto(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	// Default / empty string treated as auto
	o := NewOutput("")
	if o.colors {
		t.Error("NewOutput(''): colors should be false when NO_COLOR set")
	}
}

// ---------------------------------------------------------------------------
// PrintSuccess
// ---------------------------------------------------------------------------

func TestPrintSuccess_NoColor_ContainsOKPrefix(t *testing.T) {
	var out bytes.Buffer
	o := newOutputTo(&out, &bytes.Buffer{}, false)
	o.PrintSuccess("done")
	if !strings.HasPrefix(out.String(), "OK:") {
		t.Errorf("PrintSuccess no-color: want 'OK:' prefix, got %q", out.String())
	}
	if !strings.Contains(out.String(), "done") {
		t.Errorf("PrintSuccess no-color: missing message in %q", out.String())
	}
}

func TestPrintSuccess_Color_ContainsANSI(t *testing.T) {
	var out bytes.Buffer
	o := newOutputTo(&out, &bytes.Buffer{}, true)
	o.PrintSuccess("done")
	got := out.String()
	if !strings.Contains(got, "\033[") {
		t.Errorf("PrintSuccess color: expected ANSI escape, got %q", got)
	}
	if !strings.Contains(got, "done") {
		t.Errorf("PrintSuccess color: missing message in %q", got)
	}
}

func TestPrintSuccess_Format(t *testing.T) {
	var out bytes.Buffer
	o := newOutputTo(&out, &bytes.Buffer{}, false)
	o.PrintSuccess("value=%d", 42)
	if !strings.Contains(out.String(), "value=42") {
		t.Errorf("PrintSuccess format: want 'value=42', got %q", out.String())
	}
}

// ---------------------------------------------------------------------------
// PrintError
// ---------------------------------------------------------------------------

func TestPrintError_NoColor_WritesToStderr(t *testing.T) {
	var errBuf bytes.Buffer
	o := newOutputTo(&bytes.Buffer{}, &errBuf, false)
	o.PrintError("boom")
	if !strings.HasPrefix(errBuf.String(), "ERR:") {
		t.Errorf("PrintError no-color: want 'ERR:' prefix, got %q", errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "boom") {
		t.Errorf("PrintError no-color: missing message in %q", errBuf.String())
	}
}

func TestPrintError_Color_ContainsANSI(t *testing.T) {
	var errBuf bytes.Buffer
	o := newOutputTo(&bytes.Buffer{}, &errBuf, true)
	o.PrintError("boom")
	if !strings.Contains(errBuf.String(), "\033[") {
		t.Errorf("PrintError color: expected ANSI escape, got %q", errBuf.String())
	}
}

// ---------------------------------------------------------------------------
// PrintWarning
// ---------------------------------------------------------------------------

func TestPrintWarning_NoColor_WritesToStderr(t *testing.T) {
	var errBuf bytes.Buffer
	o := newOutputTo(&bytes.Buffer{}, &errBuf, false)
	o.PrintWarning("careful")
	if !strings.HasPrefix(errBuf.String(), "WARN:") {
		t.Errorf("PrintWarning no-color: want 'WARN:' prefix, got %q", errBuf.String())
	}
}

func TestPrintWarning_Color_ContainsANSI(t *testing.T) {
	var errBuf bytes.Buffer
	o := newOutputTo(&bytes.Buffer{}, &errBuf, true)
	o.PrintWarning("careful")
	if !strings.Contains(errBuf.String(), "\033[") {
		t.Errorf("PrintWarning color: expected ANSI escape, got %q", errBuf.String())
	}
}

// ---------------------------------------------------------------------------
// PrintInfo
// ---------------------------------------------------------------------------

func TestPrintInfo_NoColor_ContainsINFOPrefix(t *testing.T) {
	var out bytes.Buffer
	o := newOutputTo(&out, &bytes.Buffer{}, false)
	o.PrintInfo("hello")
	if !strings.HasPrefix(out.String(), "INFO:") {
		t.Errorf("PrintInfo no-color: want 'INFO:' prefix, got %q", out.String())
	}
}

func TestPrintInfo_Color_ContainsANSI(t *testing.T) {
	var out bytes.Buffer
	o := newOutputTo(&out, &bytes.Buffer{}, true)
	o.PrintInfo("hello")
	if !strings.Contains(out.String(), "\033[") {
		t.Errorf("PrintInfo color: expected ANSI escape, got %q", out.String())
	}
}

// ---------------------------------------------------------------------------
// Print
// ---------------------------------------------------------------------------

func TestPrint_WritesMessageWithNewline(t *testing.T) {
	var out bytes.Buffer
	o := newOutputTo(&out, &bytes.Buffer{}, false)
	o.Print("line %d", 1)
	got := out.String()
	if !strings.Contains(got, "line 1") {
		t.Errorf("Print: want 'line 1', got %q", got)
	}
	if !strings.HasSuffix(got, "\n") {
		t.Errorf("Print: output should end with newline, got %q", got)
	}
}
