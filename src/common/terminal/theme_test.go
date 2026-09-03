package terminal

import (
	"testing"

	"github.com/apimgr/ipgaze/src/common/theme"
)

func TestResolveThemeName_ConfigWinsOverCOLORFGBG(t *testing.T) {
	cases := []struct {
		name       string
		configured string
		colorFGBG  string
		want       theme.Name
	}{
		{"config light beats dark COLORFGBG", "light", "15;0", theme.NameLight},
		{"config dark beats light COLORFGBG", "dark", "0;15", theme.NameDark},
		{"config is case and space insensitive", "  Light  ", "15;0", theme.NameLight},
		{"auto defers to light COLORFGBG", "auto", "0;15", theme.NameLight},
		{"auto defers to dark COLORFGBG", "auto", "15;0", theme.NameDark},
		{"empty config defers to COLORFGBG", "", "0;15", theme.NameLight},
		{"unknown config defers to COLORFGBG", "solarized", "0;15", theme.NameLight},
		{"absent COLORFGBG defaults to dark", "", "", theme.NameDark},
		{"malformed COLORFGBG defaults to dark", "", "nonsense", theme.NameDark},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ResolveThemeName(tc.configured, tc.colorFGBG); got != tc.want {
				t.Errorf("ResolveThemeName(%q, %q) = %v, want %v",
					tc.configured, tc.colorFGBG, got, tc.want)
			}
		})
	}
}

func TestDetectThemeName_ReadsEnvironment(t *testing.T) {
	t.Setenv("COLORFGBG", "0;15")
	if got := DetectThemeName(""); got != theme.NameLight {
		t.Errorf("DetectThemeName('') with a light COLORFGBG = %v, want light", got)
	}
	if got := DetectThemeName("dark"); got != theme.NameDark {
		t.Errorf("DetectThemeName('dark') = %v, want dark — config must win", got)
	}
}
