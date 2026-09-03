package theme

import (
	"strings"
	"testing"
)

// TestPalette_KnownNames confirms that Palette() returns the right struct for
// every defined Name constant and that unknown / empty values fall back to dark.
func TestPalette_KnownNames(t *testing.T) {
	tests := []struct {
		name      Name
		wantBG    string
		wantLabel string
	}{
		{NameDark, ThemePaletteDark.Background, "dark"},
		{NameLight, ThemePaletteLight.Background, "light"},
		// "auto" is defined but maps to dark
		{NameAuto, ThemePaletteDark.Background, "auto"},
		// Unknown value must also fall back to dark
		{Name("solarized"), ThemePaletteDark.Background, "unknown"},
		// Empty string → dark
		{Name(""), ThemePaletteDark.Background, "empty"},
	}
	for _, tt := range tests {
		got := Palette(tt.name)
		if got.Background != tt.wantBG {
			t.Errorf("Palette(%q).Background = %q, want %q (%s)", tt.name, got.Background, tt.wantBG, tt.wantLabel)
		}
	}
}

// TestPalette_ReturnsIndependentCopies ensures Palette() returns a value
// (struct copy), not a pointer — mutating the result must not change the
// package-level variables.
func TestPalette_ReturnsIndependentCopies(t *testing.T) {
	got := Palette(NameDark)
	original := got.Background
	got.Background = "#000000"

	// The package-level palette must be unchanged.
	if ThemePaletteDark.Background != original {
		t.Errorf("ThemePaletteDark.Background mutated to %q after copy modification", ThemePaletteDark.Background)
	}
}

// TestThemePaletteDark_AllFieldsPopulated ensures every field in the dark
// palette is a non-empty, valid hex color string.
func TestThemePaletteDark_AllFieldsPopulated(t *testing.T) {
	assertValidHex(t, "Dark.Background", ThemePaletteDark.Background)
	assertValidHex(t, "Dark.Foreground", ThemePaletteDark.Foreground)
	assertValidHex(t, "Dark.Primary", ThemePaletteDark.Primary)
	assertValidHex(t, "Dark.Secondary", ThemePaletteDark.Secondary)
	assertValidHex(t, "Dark.Accent", ThemePaletteDark.Accent)
	assertValidHex(t, "Dark.Success", ThemePaletteDark.Success)
	assertValidHex(t, "Dark.Warning", ThemePaletteDark.Warning)
	assertValidHex(t, "Dark.Error", ThemePaletteDark.Error)
	assertValidHex(t, "Dark.Info", ThemePaletteDark.Info)
	assertValidHex(t, "Dark.Surface", ThemePaletteDark.Surface)
	assertValidHex(t, "Dark.SurfaceAlt", ThemePaletteDark.SurfaceAlt)
	assertValidHex(t, "Dark.Border", ThemePaletteDark.Border)
	assertValidHex(t, "Dark.Muted", ThemePaletteDark.Muted)
}

// TestThemePaletteLight_AllFieldsPopulated ensures every field in the light
// palette is a non-empty, valid hex color string.
func TestThemePaletteLight_AllFieldsPopulated(t *testing.T) {
	assertValidHex(t, "Light.Background", ThemePaletteLight.Background)
	assertValidHex(t, "Light.Foreground", ThemePaletteLight.Foreground)
	assertValidHex(t, "Light.Primary", ThemePaletteLight.Primary)
	assertValidHex(t, "Light.Secondary", ThemePaletteLight.Secondary)
	assertValidHex(t, "Light.Accent", ThemePaletteLight.Accent)
	assertValidHex(t, "Light.Success", ThemePaletteLight.Success)
	assertValidHex(t, "Light.Warning", ThemePaletteLight.Warning)
	assertValidHex(t, "Light.Error", ThemePaletteLight.Error)
	assertValidHex(t, "Light.Info", ThemePaletteLight.Info)
	assertValidHex(t, "Light.Surface", ThemePaletteLight.Surface)
	assertValidHex(t, "Light.SurfaceAlt", ThemePaletteLight.SurfaceAlt)
	assertValidHex(t, "Light.Border", ThemePaletteLight.Border)
	assertValidHex(t, "Light.Muted", ThemePaletteLight.Muted)
}

// TestDarkAndLightPalettes_AreDifferent ensures the two palettes are not
// accidentally identical (a copy-paste bug).
func TestDarkAndLightPalettes_AreDifferent(t *testing.T) {
	if ThemePaletteDark.Background == ThemePaletteLight.Background {
		t.Errorf("dark and light palettes share the same Background %q — they must be different",
			ThemePaletteDark.Background)
	}
	if ThemePaletteDark.Foreground == ThemePaletteLight.Foreground {
		t.Errorf("dark and light palettes share the same Foreground %q — they must be different",
			ThemePaletteDark.Foreground)
	}
	if ThemePaletteDark.Primary == ThemePaletteLight.Primary {
		t.Errorf("dark and light palettes share the same Primary %q — they must be different",
			ThemePaletteDark.Primary)
	}
}

// TestNameConstants ensures the Name constants have the expected string values.
func TestNameConstants(t *testing.T) {
	tests := []struct {
		name Name
		want string
	}{
		{NameDark, "dark"},
		{NameLight, "light"},
		{NameAuto, "auto"},
	}
	for _, tt := range tests {
		if string(tt.name) != tt.want {
			t.Errorf("Name constant = %q, want %q", tt.name, tt.want)
		}
	}
}

// TestPalette_LightVsDarkBrightness is a semantic sanity check: the light
// palette's Background should be visually lighter (higher RGB sum) than dark's.
func TestPalette_LightVsDarkBrightness(t *testing.T) {
	darkBG := hexRGBSum(ThemePaletteDark.Background)
	lightBG := hexRGBSum(ThemePaletteLight.Background)
	if lightBG <= darkBG {
		t.Errorf("light background RGB sum (%d) is not greater than dark background RGB sum (%d) — palettes may be swapped",
			lightBG, darkBG)
	}
}

// assertValidHex fails the test if color is not a "#RRGGBB" hex string.
func assertValidHex(t *testing.T, field, color string) {
	t.Helper()
	if color == "" {
		t.Errorf("%s: color is empty", field)
		return
	}
	if !strings.HasPrefix(color, "#") {
		t.Errorf("%s: color %q does not start with '#'", field, color)
		return
	}
	// Accept #RGB (3 hex digits) and #RRGGBB (6 hex digits).
	hex := color[1:]
	if len(hex) != 6 && len(hex) != 3 {
		t.Errorf("%s: color %q has %d hex digits, want 3 or 6", field, color, len(hex))
		return
	}
	for _, ch := range hex {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
			t.Errorf("%s: color %q contains non-hex character %q", field, color, ch)
		}
	}
}

// hexRGBSum parses a "#RRGGBB" color and returns R+G+B as an integer.
// Panics on malformed input — only call with values already validated by assertValidHex.
func hexRGBSum(color string) int {
	h := strings.TrimPrefix(color, "#")
	if len(h) == 3 {
		h = string([]byte{h[0], h[0], h[1], h[1], h[2], h[2]})
	}
	parseHex := func(s string) int {
		val := 0
		for _, ch := range s {
			val <<= 4
			switch {
			case ch >= '0' && ch <= '9':
				val += int(ch - '0')
			case ch >= 'a' && ch <= 'f':
				val += int(ch-'a') + 10
			case ch >= 'A' && ch <= 'F':
				val += int(ch-'A') + 10
			}
		}
		return val
	}
	return parseHex(h[0:2]) + parseHex(h[2:4]) + parseHex(h[4:6])
}
