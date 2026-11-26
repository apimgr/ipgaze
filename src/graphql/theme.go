package graphql

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/apimgr/ipgaze/src/common/theme"
)

// getGraphiQLThemeCSS binds GraphiQL's theme roles to the shared application
// palette. All modes are included so the page theme toggle updates the tool
// without reloading the GraphiQL application.
func getGraphiQLThemeCSS(_ string) string {
	return fmt.Sprintf(`
html.theme-dark .graphiql-container,
html.theme-auto .graphiql-container {
%s}

html.theme-light .graphiql-container {
%s}

@media (prefers-color-scheme: light) {
  html.theme-auto .graphiql-container {
%s  }
}
`, graphiqlPaletteCSS(theme.ThemePaletteDark), graphiqlPaletteCSS(theme.ThemePaletteLight), graphiqlPaletteCSS(theme.ThemePaletteLight))
}

func graphiqlPaletteCSS(p theme.ThemePalette) string {
	return fmt.Sprintf(`  --color-base: %s;
  --color-neutral: %s;
  --color-primary: %s;
  --color-secondary: %s;
  --color-tertiary: %s;
  --color-info: %s;
  --color-success: %s;
  --color-warning: %s;
  --color-error: %s;
`, hexToHSL(p.Background), hexToHSL(p.Foreground), hexToHSL(p.Primary), hexToHSL(p.Secondary), hexToHSL(p.Accent), hexToHSL(p.Info), hexToHSL(p.Success), hexToHSL(p.Warning), hexToHSL(p.Error))
}

func hexToHSL(value string) string {
	value = strings.TrimPrefix(value, "#")
	if len(value) != 6 {
		return "0, 0%, 0%"
	}
	red, redErr := strconv.ParseUint(value[:2], 16, 8)
	green, greenErr := strconv.ParseUint(value[2:4], 16, 8)
	blue, blueErr := strconv.ParseUint(value[4:], 16, 8)
	if redErr != nil || greenErr != nil || blueErr != nil {
		return "0, 0%, 0%"
	}
	r := float64(red) / 255
	g := float64(green) / 255
	b := float64(blue) / 255
	maximum := max(r, g, b)
	minimum := min(r, g, b)
	delta := maximum - minimum
	hue := 0.0
	if delta != 0 {
		switch maximum {
		case r:
			hue = 60 * math.Mod((g-b)/delta, 6)
		case g:
			hue = 60 * ((b-r)/delta + 2)
		default:
			hue = 60 * ((r-g)/delta + 4)
		}
	}
	if hue < 0 {
		hue += 360
	}
	lightness := (maximum + minimum) / 2
	saturation := 0.0
	if delta != 0 {
		saturation = delta / (1 - math.Abs(2*lightness-1))
	}
	return fmt.Sprintf("%.0f, %.1f%%, %.1f%%", hue, saturation*100, lightness*100)
}
