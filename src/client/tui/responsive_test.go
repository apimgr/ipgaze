package tui

import (
	"testing"

	"github.com/apimgr/ipgaze/src/common/terminal"
)

// TestGetLayoutConfig_AllTiers pins the per-tier layout values from AI.md
// PART 32 "TUI Responsive Layout" so a regression in any single tier fails.
func TestGetLayoutConfig_AllTiers(t *testing.T) {
	cases := []struct {
		name string
		mode terminal.SizeMode
		want LayoutConfig
	}{
		{
			name: "micro",
			mode: terminal.SizeModeMicro,
			want: LayoutConfig{
				MaxColumns:     2,
				TruncateAt:     30,
				UseAbbrev:      true,
				VerticalScroll: true,
			},
		},
		{
			name: "minimal",
			mode: terminal.SizeModeMinimal,
			want: LayoutConfig{
				ShowHeader:     true,
				ShowFooter:     true,
				MaxColumns:     3,
				TruncateAt:     40,
				UseAbbrev:      true,
				VerticalScroll: true,
			},
		},
		{
			name: "compact",
			mode: terminal.SizeModeCompact,
			want: LayoutConfig{
				ShowBorders:    true,
				ShowHeader:     true,
				ShowFooter:     true,
				MaxColumns:     4,
				TruncateAt:     60,
				VerticalScroll: true,
			},
		},
		{
			name: "standard",
			mode: terminal.SizeModeStandard,
			want: LayoutConfig{
				ShowBorders:    true,
				ShowHeader:     true,
				ShowFooter:     true,
				MaxColumns:     6,
				TruncateAt:     80,
				VerticalScroll: true,
			},
		},
		{
			name: "wide",
			mode: terminal.SizeModeWide,
			want: LayoutConfig{
				ShowBorders:    true,
				ShowHeader:     true,
				ShowFooter:     true,
				ShowSidebar:    true,
				SidebarWidth:   30,
				MaxColumns:     8,
				TruncateAt:     120,
				VerticalScroll: true,
			},
		},
		{
			name: "ultrawide",
			mode: terminal.SizeModeUltrawide,
			want: LayoutConfig{
				ShowBorders:  true,
				ShowHeader:   true,
				ShowFooter:   true,
				ShowSidebar:  true,
				SidebarWidth: 40,
				MaxColumns:   12,
				TruncateAt:   200,
				MultiPane:    true,
			},
		},
		{
			name: "massive",
			mode: terminal.SizeModeMassive,
			want: LayoutConfig{
				ShowBorders:  true,
				ShowHeader:   true,
				ShowFooter:   true,
				ShowSidebar:  true,
				SidebarWidth: 50,
				MaxColumns:   20,
				TruncateAt:   0,
				MultiPane:    true,
				TileLayout:   true,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := GetLayoutConfig(tc.mode); got != tc.want {
				t.Errorf("GetLayoutConfig(%s) =\n  %+v\nwant\n  %+v", tc.name, got, tc.want)
			}
		})
	}
}

func TestGetLayoutConfig_UnknownModeFallsBackToStandard(t *testing.T) {
	got := GetLayoutConfig(terminal.SizeMode(99))
	if got != GetLayoutConfig(terminal.SizeModeStandard) {
		t.Errorf("GetLayoutConfig(unknown) = %+v, want the standard tier", got)
	}
}

func TestSizeModeFor_Boundaries(t *testing.T) {
	cases := []struct {
		cols, rows int
		want       terminal.SizeMode
	}{
		{20, 5, terminal.SizeModeMicro},
		{50, 12, terminal.SizeModeMinimal},
		{70, 20, terminal.SizeModeCompact},
		{100, 30, terminal.SizeModeStandard},
		{150, 50, terminal.SizeModeWide},
		{250, 70, terminal.SizeModeUltrawide},
		{400, 100, terminal.SizeModeMassive},
	}
	for _, tc := range cases {
		if got := SizeModeFor(tc.cols, tc.rows); got != tc.want {
			t.Errorf("SizeModeFor(%d,%d) = %v, want %v", tc.cols, tc.rows, got, tc.want)
		}
	}
}

// TestModelResize_UpdatesSizeModeAndLayout verifies a tea.WindowSizeMsg-driven
// resize re-derives both the size mode and the matching layout.
func TestModelResize_UpdatesSizeModeAndLayout(t *testing.T) {
	m := NewModelWithLang("en")
	m.resize(30, 8)
	if m.sizeMode != terminal.SizeModeMicro {
		t.Errorf("resize(30,8): sizeMode = %v, want micro", m.sizeMode)
	}
	if !m.layout.UseAbbrev {
		t.Error("resize(30,8): expected the micro layout to abbreviate labels")
	}

	m.resize(250, 70)
	if m.sizeMode != terminal.SizeModeUltrawide {
		t.Errorf("resize(250,70): sizeMode = %v, want ultrawide", m.sizeMode)
	}
	if m.layout.SidebarWidth != 40 {
		t.Errorf("resize(250,70): SidebarWidth = %d, want 40", m.layout.SidebarWidth)
	}
}

func TestTruncate_RuneSafe(t *testing.T) {
	if got := Truncate("héllo wörld", 5); len([]rune(got)) > 5 {
		t.Errorf("Truncate to 5 produced %d runes: %q", len([]rune(got)), got)
	}
	if got := Truncate("keep everything", 0); got != "keep everything" {
		t.Errorf("Truncate with maxWidth 0 = %q, want the input unchanged", got)
	}
}
