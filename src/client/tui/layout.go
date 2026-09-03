package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/apimgr/ipgaze/src/common/i18n"
	"github.com/apimgr/ipgaze/src/common/terminal"
)

// LayoutConfig provides TUI-specific layout settings derived from a
// terminal.SizeMode, per AI.md PART 32 "TUI Responsive Layout".
type LayoutConfig struct {
	ShowBorders    bool
	ShowHeader     bool
	ShowFooter     bool
	ShowSidebar    bool
	SidebarWidth   int
	MaxColumns     int
	TruncateAt     int
	UseAbbrev      bool
	VerticalScroll bool
	MultiPane      bool
	TileLayout     bool
}

// layoutConfigs holds the exact per-SizeMode values given in AI.md PART 32.
var layoutConfigs = map[terminal.SizeMode]LayoutConfig{
	terminal.SizeModeMicro: {
		ShowBorders:    false,
		ShowHeader:     false,
		ShowFooter:     false,
		ShowSidebar:    false,
		MaxColumns:     2,
		TruncateAt:     30,
		UseAbbrev:      true,
		VerticalScroll: true,
	},
	terminal.SizeModeMinimal: {
		ShowBorders:    false,
		ShowHeader:     true,
		ShowFooter:     true,
		ShowSidebar:    false,
		MaxColumns:     3,
		TruncateAt:     40,
		UseAbbrev:      true,
		VerticalScroll: true,
	},
	terminal.SizeModeCompact: {
		ShowBorders:    true,
		ShowHeader:     true,
		ShowFooter:     true,
		ShowSidebar:    false,
		MaxColumns:     4,
		TruncateAt:     60,
		UseAbbrev:      false,
		VerticalScroll: true,
	},
	terminal.SizeModeStandard: {
		ShowBorders:    true,
		ShowHeader:     true,
		ShowFooter:     true,
		ShowSidebar:    false,
		MaxColumns:     6,
		TruncateAt:     80,
		UseAbbrev:      false,
		VerticalScroll: true,
	},
	terminal.SizeModeWide: {
		ShowBorders:    true,
		ShowHeader:     true,
		ShowFooter:     true,
		ShowSidebar:    true,
		SidebarWidth:   30,
		MaxColumns:     8,
		TruncateAt:     120,
		UseAbbrev:      false,
		VerticalScroll: true,
	},
	terminal.SizeModeUltrawide: {
		ShowBorders:  true,
		ShowHeader:   true,
		ShowFooter:   true,
		ShowSidebar:  true,
		SidebarWidth: 40,
		MaxColumns:   12,
		TruncateAt:   200,
		UseAbbrev:    false,
		// Full content is visible at this width, so no scrolling is needed.
		VerticalScroll: false,
		MultiPane:      true,
	},
	terminal.SizeModeMassive: {
		ShowBorders:  true,
		ShowHeader:   true,
		ShowFooter:   true,
		ShowSidebar:  true,
		SidebarWidth: 50,
		MaxColumns:   20,
		// Zero means never truncate.
		TruncateAt:     0,
		UseAbbrev:      false,
		VerticalScroll: false,
		MultiPane:      true,
		TileLayout:     true,
	},
}

// GetLayoutConfig returns the layout configuration for a SizeMode.
// Unknown modes fall back to the Standard tier.
func GetLayoutConfig(mode terminal.SizeMode) LayoutConfig {
	if cfg, ok := layoutConfigs[mode]; ok {
		return cfg
	}
	return layoutConfigs[terminal.SizeModeStandard]
}

// InfoRow is a single label/value pair rendered in the IP information view.
type InfoRow struct {
	Label string
	Value string
}

// BuildInfoRows returns the translated, non-empty label/value rows for an IP
// lookup result. Labels are abbreviated when the layout requests it.
func BuildInfoRows(lang string, layout LayoutConfig, d IPData) []InfoRow {
	fields := []struct {
		key   string
		value string
	}{
		{"hostname", d.Hostname},
		{"country", formatCountry(d.Country, d.CountryISO)},
		{"city", d.City},
		{"region", formatRegion(d.RegionName, d.RegionCode)},
		{"postal_code", d.PostalCode},
		{"timezone", d.Timezone},
		{"asn", formatASN(d.ASN, d.ASNOrg)},
		{"coordinates", formatCoords(d.Latitude, d.Longitude)},
	}

	rows := make([]InfoRow, 0, len(fields))
	for _, f := range fields {
		if f.value == "" {
			continue
		}
		key := "tui.field_" + f.key
		if layout.UseAbbrev {
			key = "tui.abbrev_" + f.key
		}
		rows = append(rows, InfoRow{Label: i18n.Translate(lang, key), Value: f.value})
	}
	return rows
}

// RenderIPInfo renders an IP lookup result, honouring the layout's header,
// border, and truncation settings.
func RenderIPInfo(lang string, layout LayoutConfig, d IPData) string {
	var sb strings.Builder

	if layout.ShowHeader {
		sb.WriteString(TitleStyle.Render(i18n.Translate(lang, "tui.title")) + "\n\n")
	}

	ip := Truncate(d.IP, layout.TruncateAt)
	if layout.ShowBorders {
		sb.WriteString(BorderStyle.Render(IPStyle.Render(ip)) + "\n\n")
	} else {
		sb.WriteString(IPStyle.Render(ip) + "\n\n")
	}

	for _, row := range BuildInfoRows(lang, layout, d) {
		sb.WriteString(RenderInfoRow(row, layout, false))
		sb.WriteString("\n")
	}

	return sb.String()
}

// RenderInfoRow renders one label/value row. selected rows are highlighted
// with a cursor marker; values are truncated to the layout's TruncateAt.
func RenderInfoRow(row InfoRow, layout LayoutConfig, selected bool) string {
	marker := "  "
	if selected {
		marker = "> "
	}
	value := Truncate(row.Value, layout.TruncateAt)
	line := marker + LabelStyle.Render(row.Label+":") + " " + ValueStyle.Render(value)
	if selected {
		return SelectedStyle.Render(line)
	}
	return line
}

// RenderError renders an error message.
func RenderError(msg string) string {
	return ErrorStyle.Render("✗ " + msg)
}

// RenderSuccess renders a success message.
func RenderSuccess(msg string) string {
	return SuccessStyle.Render("✓ " + msg)
}

// RenderMuted renders muted/secondary text.
func RenderMuted(msg string) string {
	return MutedStyle.Render(msg)
}

// HorizontalRule renders a horizontal divider.
func HorizontalRule(width int) string {
	return lipgloss.NewStyle().
		Foreground(lipgloss.Color(ActivePalette.Border)).
		Render(strings.Repeat("─", width))
}

// Truncate shortens s to at most maxWidth display runes, adding an ellipsis
// when it has to cut. A maxWidth of zero or less means "never truncate"
// (AI.md PART 32: Massive terminals set TruncateAt to 0).
func Truncate(s string, maxWidth int) string {
	if maxWidth <= 0 {
		return s
	}
	r := []rune(s)
	if len(r) <= maxWidth {
		return s
	}
	if maxWidth <= 3 {
		return string(r[:maxWidth])
	}
	return string(r[:maxWidth-3]) + "..."
}

// TruncateMiddle shortens s by removing the middle, keeping both ends
// visible. Used for paths and URLs where the tail carries meaning.
func TruncateMiddle(s string, maxWidth int) string {
	if maxWidth <= 0 {
		return s
	}
	r := []rune(s)
	if len(r) <= maxWidth {
		return s
	}
	if maxWidth <= 5 {
		return string(r[:maxWidth])
	}
	half := (maxWidth - 3) / 2
	return string(r[:half]) + "..." + string(r[len(r)-half:])
}

func formatCountry(country, iso string) string {
	if country == "" {
		return ""
	}
	if iso != "" {
		return country + " (" + iso + ")"
	}
	return country
}

func formatRegion(name, code string) string {
	if name == "" {
		return code
	}
	if code != "" {
		return name + " (" + code + ")"
	}
	return name
}

func formatASN(asn, org string) string {
	if asn == "" {
		return ""
	}
	if org != "" {
		return asn + " — " + org
	}
	return asn
}

func formatCoords(lat, lon float64) string {
	if lat == 0 && lon == 0 {
		return ""
	}
	return fmt.Sprintf("%.4f, %.4f", lat, lon)
}
