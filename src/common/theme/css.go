package theme

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// themeExtras holds the CSS variables AI.md PART 16 "CSS Variable
// Reference" gives as fixed per-theme literals rather than as ThemePalette
// struct fields (they don't reduce to a simple formula over the 13 base
// colors — e.g. dark --color-bg-hover #343746 isn't a clean mix of
// Background/Foreground). One instance per theme, copied verbatim from the
// spec's :root and html.theme-light blocks.
type themeExtras struct {
	BgHover     string
	BgActive    string
	CodeBg      string
	BorderHover string
}

var extrasDark = themeExtras{
	BgHover:     "#343746",
	BgActive:    "#44475a",
	CodeBg:      "rgba(255, 255, 255, 0.1)",
	BorderHover: "#6272a4",
}

var extrasLight = themeExtras{
	BgHover:     "#eff2f5",
	BgActive:    "#e6eaef",
	CodeBg:      "rgba(0, 0, 0, 0.05)",
	BorderHover: "#818b98",
}

// statusBgAlpha is the fixed opacity AI.md's literal --color-*-bg values use
// (verified against the spec: e.g. dark success-bg rgba(80, 250, 123, 0.15)
// is exactly Success's own RGB at 0.15 alpha; light success-bg
// rgba(26, 127, 55, 0.12) is the same pattern at 0.12).
func statusBgAlpha(dark bool) float64 {
	if dark {
		return 0.15
	}
	return 0.12
}

// cssVarBlock renders one palette as a sequence of "--name: value;" lines,
// including the semantic variables consumed by the web CSS (common.css,
// components.css, public.css, swagger, graphql) that have no direct 1:1
// ThemePalette field.
// Values match AI.md PART 16 "CSS Variable Reference" and "Themes
// (NON-NEGOTIABLE)" verbatim, per theme, except dark Muted — see its
// field comment in colors.go for the WCAG AA contrast fix.
func cssVarBlock(p ThemePalette, extras themeExtras, dark bool) string {
	var b strings.Builder

	// Direct 1:1 mappings from the ThemePalette struct.
	fmt.Fprintf(&b, "  --color-bg: %s;\n", p.Background)
	fmt.Fprintf(&b, "  --color-bg-secondary: %s;\n", p.SurfaceAlt)
	fmt.Fprintf(&b, "  --color-bg-card: %s;\n", p.Surface)
	fmt.Fprintf(&b, "  --color-bg-hover: %s;\n", extras.BgHover)
	fmt.Fprintf(&b, "  --color-bg-active: %s;\n", extras.BgActive)
	fmt.Fprintf(&b, "  --color-code-bg: %s;\n", extras.CodeBg)
	fmt.Fprintf(&b, "  --color-text: %s;\n", p.Foreground)
	fmt.Fprintf(&b, "  --color-muted: %s;\n", p.Muted)
	fmt.Fprintf(&b, "  --color-border: %s;\n", p.Border)
	fmt.Fprintf(&b, "  --color-border-hover: %s;\n", extras.BorderHover)
	fmt.Fprintf(&b, "  --color-primary: %s;\n", p.Primary)
	fmt.Fprintf(&b, "  --color-secondary: %s;\n", p.Secondary)
	fmt.Fprintf(&b, "  --color-accent: %s;\n", p.Accent)

	// Text color guaranteed >= 4.5:1 contrast against --color-primary,
	// computed server-side (CSS cannot branch on luminance).
	fmt.Fprintf(&b, "  --color-text-on-primary: %s;\n", ReadableTextOn(p.Primary))

	// Status colors plus their translucent -bg pairs (own color at fixed
	// alpha, per AI.md's literal rgba() values) and -text pairs (the same
	// solid semantic color, matching the spec's badge examples where the
	// full-strength color is used as both border and text over its own
	// translucent background).
	alpha := statusBgAlpha(dark)
	for _, s := range []struct {
		name string
		hex  string
	}{
		{"success", p.Success},
		{"warning", p.Warning},
		{"error", p.Error},
		{"info", p.Info},
	} {
		fmt.Fprintf(&b, "  --color-%s: %s;\n", s.name, s.hex)
		fmt.Fprintf(&b, "  --color-%s-bg: %s;\n", s.name, hexToRGBA(s.hex, alpha))
		fmt.Fprintf(&b, "  --color-%s-text: %s;\n", s.name, s.hex)
	}
	fmt.Fprintf(&b, "  --color-primary-bg: %s;\n", hexToRGBA(p.Primary, alpha))

	return b.String()
}

// hexToRGBA renders a "#rrggbb" hex color as a CSS rgba() string at the
// given alpha. Falls back to the literal hex (opaque) if parsing fails.
func hexToRGBA(hex string, alpha float64) string {
	r, g, b, ok := hexToRGB(hex)
	if !ok {
		return hex
	}
	return fmt.Sprintf("rgba(%d, %d, %d, %s)", r, g, b, strconv.FormatFloat(alpha, 'f', -1, 64))
}

// ReadableTextOn returns "#000000" or "#ffffff", whichever gives the higher
// WCAG contrast ratio against bg, so button/badge text stays >= 4.5:1
// readable regardless of how a palette's accent color is tuned. Exported for
// reuse by non-CSS consumers (e.g. src/graphql's inline-styled explorer)
// that render solid-color buttons against palette accent colors.
func ReadableTextOn(bg string) string {
	r, g, bl, ok := hexToRGB(bg)
	if !ok {
		return "#ffffff"
	}
	lum := relativeLuminance(r, g, bl)
	contrastBlack := (lum + 0.05) / 0.05
	contrastWhite := 1.05 / (lum + 0.05)
	if contrastBlack >= contrastWhite {
		return "#000000"
	}
	return "#ffffff"
}

// hexToRGB parses a "#rrggbb" string into 0-255 channel values.
func hexToRGB(hex string) (r, g, b int, ok bool) {
	h := strings.TrimPrefix(hex, "#")
	if len(h) != 6 {
		return 0, 0, 0, false
	}
	rv, err1 := strconv.ParseInt(h[0:2], 16, 32)
	gv, err2 := strconv.ParseInt(h[2:4], 16, 32)
	bv, err3 := strconv.ParseInt(h[4:6], 16, 32)
	if err1 != nil || err2 != nil || err3 != nil {
		return 0, 0, 0, false
	}
	return int(rv), int(gv), int(bv), true
}

// relativeLuminance implements the WCAG 2.1 relative luminance formula.
func relativeLuminance(r, g, b int) float64 {
	toLinear := func(c int) float64 {
		cs := float64(c) / 255
		if cs <= 0.03928 {
			return cs / 12.92
		}
		return math.Pow((cs+0.055)/1.055, 2.4)
	}
	return 0.2126*toLinear(r) + 0.7152*toLinear(g) + 0.0722*toLinear(b)
}

// CSSVariables renders the complete theme CSS block for injection into
// base.tmpl as an inline <style>: dark values on :root (default), light
// overrides scoped to html.theme-light, and an auto branch that follows
// prefers-color-scheme when no explicit theme class is set. This is the
// single source of truth referenced by AI.md PART 16 "Theme Implementation
// Location" -> "CSS variables: Embedded in templates".
func CSSVariables() string {
	var b strings.Builder
	b.WriteString(":root {\n")
	b.WriteString(cssVarBlock(ThemePaletteDark, extrasDark, true))
	b.WriteString("}\n\n")

	b.WriteString("html.theme-light {\n")
	b.WriteString(cssVarBlock(ThemePaletteLight, extrasLight, false))
	b.WriteString("}\n\n")

	b.WriteString("@media (prefers-color-scheme: light) {\n")
	b.WriteString("  html:not(.theme-dark):not(.theme-light),\n")
	b.WriteString("  html.theme-auto {\n")
	for _, line := range strings.Split(strings.TrimRight(cssVarBlock(ThemePaletteLight, extrasLight, false), "\n"), "\n") {
		b.WriteString("  " + line + "\n")
	}
	b.WriteString("  }\n")
	b.WriteString("}\n")

	return b.String()
}
