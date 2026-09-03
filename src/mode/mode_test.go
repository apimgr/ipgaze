package mode

import "testing"

// ---------------------------------------------------------------------------
// ParseMode
// ---------------------------------------------------------------------------

func TestParseMode_ValidInputs(t *testing.T) {
	cases := []struct {
		input string
		want  AppMode
	}{
		{"dev", AppModeDevelopment},
		{"development", AppModeDevelopment},
		{"DEV", AppModeDevelopment},
		{"Development", AppModeDevelopment},
		{"prod", AppModeProduction},
		{"production", AppModeProduction},
		{"PROD", AppModeProduction},
		{"Production", AppModeProduction},
		// whitespace is trimmed
		{" dev ", AppModeDevelopment},
		{" production ", AppModeProduction},
	}
	for _, tc := range cases {
		got, err := ParseMode(tc.input)
		if err != nil {
			t.Errorf("ParseMode(%q) error: %v", tc.input, err)
		}
		if got != tc.want {
			t.Errorf("ParseMode(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestParseMode_InvalidInputs(t *testing.T) {
	cases := []string{"", "debug", "staging", "test", "1", "devmode"}
	for _, s := range cases {
		got, err := ParseMode(s)
		if err == nil {
			t.Errorf("ParseMode(%q): expected error, got nil (returned %q)", s, got)
		}
		// Default must be production even on error
		if got != AppModeProduction {
			t.Errorf("ParseMode(%q) default = %q, want %q", s, got, AppModeProduction)
		}
	}
}

// ---------------------------------------------------------------------------
// ParseModeWithDebugAlias
// ---------------------------------------------------------------------------

func TestParseModeWithDebugAlias_DebugAlias(t *testing.T) {
	m, impliedDebug, err := ParseModeWithDebugAlias("debug")
	if err != nil {
		t.Fatalf("ParseModeWithDebugAlias(debug): %v", err)
	}
	if m != AppModeDebug {
		t.Errorf("ParseModeWithDebugAlias(debug) mode = %q, want debug", m)
	}
	if !impliedDebug {
		t.Error("ParseModeWithDebugAlias(debug) impliedDebug = false, want true")
	}
}

func TestParseModeWithDebugAlias_NormalModes(t *testing.T) {
	cases := []struct {
		input string
		want  AppMode
	}{
		{"prod", AppModeProduction},
		{"development", AppModeDevelopment},
	}
	for _, tc := range cases {
		m, impliedDebug, err := ParseModeWithDebugAlias(tc.input)
		if err != nil {
			t.Errorf("ParseModeWithDebugAlias(%q): %v", tc.input, err)
		}
		if m != tc.want {
			t.Errorf("ParseModeWithDebugAlias(%q) = %q, want %q", tc.input, m, tc.want)
		}
		if impliedDebug {
			t.Errorf("ParseModeWithDebugAlias(%q) impliedDebug = true, want false", tc.input)
		}
	}
}

func TestParseModeWithDebugAlias_Invalid(t *testing.T) {
	_, impliedDebug, err := ParseModeWithDebugAlias("garbage")
	if err == nil {
		t.Error("ParseModeWithDebugAlias(garbage): expected error, got nil")
	}
	if impliedDebug {
		t.Error("ParseModeWithDebugAlias(garbage) impliedDebug = true, want false")
	}
}

// ---------------------------------------------------------------------------
// AppMode.String
// ---------------------------------------------------------------------------

func TestAppModeString(t *testing.T) {
	cases := []struct {
		m    AppMode
		want string
	}{
		{AppModeProduction, "production"},
		{AppModeDevelopment, "development"},
		{AppModeDebug, "debug"},
		{AppMode("custom"), "custom"},
	}
	for _, tc := range cases {
		if got := tc.m.String(); got != tc.want {
			t.Errorf("AppMode(%q).String() = %q, want %q", tc.m, got, tc.want)
		}
	}
}
