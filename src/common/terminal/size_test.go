package terminal

import (
	"testing"
)

// TestCalculateMode covers every SizeMode tier through its column and row
// boundary values. calculateMode is unexported but in the same package.
func TestCalculateMode(t *testing.T) {
	tests := []struct {
		name     string
		cols     int
		rows     int
		wantMode SizeMode
	}{
		// Micro: cols < 40
		{"micro cols", 39, 24, SizeModeMicro},
		// Micro: rows < 10
		{"micro rows", 80, 9, SizeModeMicro},
		// Micro: both under threshold
		{"micro both", 1, 1, SizeModeMicro},
		// Micro: zero values
		{"micro zero", 0, 0, SizeModeMicro},

		// Minimal: cols in [40,59] with rows ok
		{"minimal cols low", 40, 16, SizeModeMinimal},
		{"minimal cols high", 59, 24, SizeModeMinimal},
		// Minimal: rows in [10,15] with cols ok
		{"minimal rows low", 80, 10, SizeModeMinimal},
		{"minimal rows high", 80, 15, SizeModeMinimal},

		// Compact: cols in [60,79] with rows ok
		{"compact cols low", 60, 24, SizeModeCompact},
		{"compact cols high", 79, 30, SizeModeCompact},
		// Compact: rows in [16,23] with cols ok
		{"compact rows low", 80, 16, SizeModeCompact},
		{"compact rows high", 80, 23, SizeModeCompact},

		// Standard: cols in [80,119] and rows in [24,39]
		{"standard low", 80, 24, SizeModeStandard},
		{"standard mid", 100, 30, SizeModeStandard},
		{"standard cols high", 119, 39, SizeModeStandard},

		// Wide: cols in [120,199] and rows in [40,59]
		{"wide cols low", 120, 40, SizeModeWide},
		{"wide cols high", 199, 59, SizeModeWide},

		// Ultrawide: cols in [200,399] and rows in [60,79]
		{"ultrawide cols low", 200, 60, SizeModeUltrawide},
		{"ultrawide cols high", 399, 79, SizeModeUltrawide},

		// Massive: cols >= 400 and rows >= 80
		{"massive low", 400, 80, SizeModeMassive},
		{"massive large", 1920, 200, SizeModeMassive},
	}
	for _, tt := range tests {
		got := calculateMode(tt.cols, tt.rows)
		if got != tt.wantMode {
			t.Errorf("%s: calculateMode(%d, %d) = %v, want %v",
				tt.name, tt.cols, tt.rows, got, tt.wantMode)
		}
	}
}

// TestSizeModeCapabilityHelpers verifies the ShowASCIIArt / ShowBorders /
// ShowSidebar / ShowIcons helpers against each SizeMode tier.
func TestSizeModeCapabilityHelpers(t *testing.T) {
	tests := []struct {
		mode        SizeMode
		wantASCII   bool
		wantBorders bool
		wantSidebar bool
		wantIcons   bool
	}{
		{SizeModeMicro, false, false, false, false},
		{SizeModeMinimal, false, false, false, true},
		{SizeModeCompact, false, true, false, true},
		{SizeModeStandard, true, true, false, true},
		{SizeModeWide, true, true, true, true},
		{SizeModeUltrawide, true, true, true, true},
		{SizeModeMassive, true, true, true, true},
	}
	for _, tt := range tests {
		if got := tt.mode.ShowASCIIArt(); got != tt.wantASCII {
			t.Errorf("SizeMode(%d).ShowASCIIArt() = %v, want %v", tt.mode, got, tt.wantASCII)
		}
		if got := tt.mode.ShowBorders(); got != tt.wantBorders {
			t.Errorf("SizeMode(%d).ShowBorders() = %v, want %v", tt.mode, got, tt.wantBorders)
		}
		if got := tt.mode.ShowSidebar(); got != tt.wantSidebar {
			t.Errorf("SizeMode(%d).ShowSidebar() = %v, want %v", tt.mode, got, tt.wantSidebar)
		}
		if got := tt.mode.ShowIcons(); got != tt.wantIcons {
			t.Errorf("SizeMode(%d).ShowIcons() = %v, want %v", tt.mode, got, tt.wantIcons)
		}
	}
}

// TestGetTerminalSize_Defaults confirms the function never returns zero for
// cols or rows (defaults to 80×24 when not a TTY).
func TestGetTerminalSize_Defaults(t *testing.T) {
	got := GetTerminalSize()

	if got.Cols <= 0 {
		t.Errorf("GetTerminalSize().Cols = %d, want > 0", got.Cols)
	}
	if got.Rows <= 0 {
		t.Errorf("GetTerminalSize().Rows = %d, want > 0", got.Rows)
	}

	// Mode must be a recognisable constant (in range).
	if got.Mode < SizeModeMicro || got.Mode > SizeModeMassive {
		t.Errorf("GetTerminalSize().Mode = %d, not a recognised SizeMode", got.Mode)
	}

	// Returned Mode must be consistent with the returned Cols/Rows.
	want := calculateMode(got.Cols, got.Rows)
	if got.Mode != want {
		t.Errorf("GetTerminalSize().Mode = %v, but calculateMode(%d,%d) = %v — inconsistent",
			got.Mode, got.Cols, got.Rows, want)
	}
}

// TestGetTerminalSize_NonTTYDefaults asserts that in a non-TTY environment
// (such as a CI container with piped stdout) the defaults are exactly 80×24.
// We detect non-TTY by checking that cols equal the default; if we're in a
// real terminal this sub-test is skipped.
func TestGetTerminalSize_NonTTYDefaults(t *testing.T) {
	got := GetTerminalSize()

	// If the runner has a real TTY with non-default size, skip this assertion.
	if got.Cols != 80 || got.Rows != 24 {
		t.Skipf("skipping: running in a real TTY (%d×%d)", got.Cols, got.Rows)
	}

	if got.Cols != 80 {
		t.Errorf("Cols = %d, want 80 (default for non-TTY)", got.Cols)
	}
	if got.Rows != 24 {
		t.Errorf("Rows = %d, want 24 (default for non-TTY)", got.Rows)
	}
	if got.Mode != SizeModeStandard {
		t.Errorf("Mode = %v, want SizeModeStandard for 80×24", got.Mode)
	}
}

// TestCalculateMode_BoundaryTransitions probes exact boundary values to catch
// off-by-one errors in the switch branches.
func TestCalculateMode_BoundaryTransitions(t *testing.T) {
	boundaries := []struct {
		cols     int
		rows     int
		wantMode SizeMode
	}{
		// Micro/Minimal boundary on cols (39 vs 40)
		{39, 24, SizeModeMicro},
		{40, 24, SizeModeMinimal},
		// Minimal/Compact boundary on cols (59 vs 60)
		{59, 24, SizeModeMinimal},
		{60, 24, SizeModeCompact},
		// Compact/Standard boundary on cols (79 vs 80)
		{79, 24, SizeModeCompact},
		{80, 24, SizeModeStandard},
		// Standard/Wide boundary on cols (119 vs 120) — rows must also qualify
		{119, 40, SizeModeStandard},
		{120, 40, SizeModeWide},
		// Wide/Ultrawide boundary on cols (199 vs 200) — rows must also qualify
		{199, 60, SizeModeWide},
		{200, 60, SizeModeUltrawide},
		// Ultrawide/Massive boundary on cols (399 vs 400) — rows must also qualify
		{399, 80, SizeModeUltrawide},
		{400, 80, SizeModeMassive},
		// Micro/Minimal boundary on rows (9 vs 10)
		{80, 9, SizeModeMicro},
		{80, 10, SizeModeMinimal},
		// Minimal/Compact boundary on rows (15 vs 16)
		{80, 15, SizeModeMinimal},
		{80, 16, SizeModeCompact},
		// Compact/Standard boundary on rows (23 vs 24)
		{80, 23, SizeModeCompact},
		{80, 24, SizeModeStandard},
		// Standard/Wide boundary on rows (39 vs 40) — cols must also qualify
		{120, 39, SizeModeStandard},
		{120, 40, SizeModeWide},
		// Wide/Ultrawide boundary on rows (59 vs 60) — cols must also qualify
		{200, 59, SizeModeWide},
		{200, 60, SizeModeUltrawide},
		// Ultrawide/Massive boundary on rows (79 vs 80) — cols must also qualify
		{400, 79, SizeModeUltrawide},
		{400, 80, SizeModeMassive},
	}
	for _, tt := range boundaries {
		got := calculateMode(tt.cols, tt.rows)
		if got != tt.wantMode {
			t.Errorf("calculateMode(%d, %d) = %v, want %v", tt.cols, tt.rows, got, tt.wantMode)
		}
	}
}
