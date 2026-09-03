package config

import (
	"strings"
	"testing"
)

// ─────────────────────────────── ParseBool ───────────────────────────────────

func TestParseBool_EmptyStringReturnsDefault(t *testing.T) {
	for _, def := range []bool{true, false} {
		got, err := ParseBool("", def)
		if err != nil {
			t.Errorf("ParseBool(\"\", %v): unexpected error: %v", def, err)
		}
		if got != def {
			t.Errorf("ParseBool(\"\", %v): got %v, want %v", def, got, def)
		}
	}
}

func TestParseBool_WhitespaceOnlyReturnsDefault(t *testing.T) {
	got, err := ParseBool("   ", true)
	if err != nil {
		t.Errorf("ParseBool whitespace: unexpected error: %v", err)
	}
	if !got {
		t.Error("ParseBool whitespace: got false, want true (default)")
	}
}

func TestParseBool_TruthyValues(t *testing.T) {
	truthy := []string{
		"1", "y", "t", "yes", "true", "on", "ok",
		"enable", "enabled",
		"yep", "yup", "yeah",
		"aye", "si", "oui", "da", "hai",
		"affirmative", "accept", "allow", "grant",
		"sure", "totally",
	}
	for _, v := range truthy {
		for _, input := range []string{v, strings.ToUpper(v), " " + v + " "} {
			got, err := ParseBool(input, false)
			if err != nil {
				t.Errorf("ParseBool(%q): unexpected error: %v", input, err)
			}
			if !got {
				t.Errorf("ParseBool(%q): got false, want true", input)
			}
		}
	}
}

func TestParseBool_FalsyValues(t *testing.T) {
	falsy := []string{
		"0", "n", "f", "no", "false", "off",
		"disable", "disabled",
		"nope", "nah", "nay",
		"nein", "non", "niet", "iie", "lie",
		"negative", "reject", "block", "revoke",
		"deny", "never", "noway",
	}
	for _, v := range falsy {
		for _, input := range []string{v, strings.ToUpper(v), " " + v + " "} {
			got, err := ParseBool(input, true)
			if err != nil {
				t.Errorf("ParseBool(%q): unexpected error: %v", input, err)
			}
			if got {
				t.Errorf("ParseBool(%q): got true, want false", input)
			}
		}
	}
}

func TestParseBool_InvalidValueReturnsError(t *testing.T) {
	invalid := []string{"maybe", "2", "truE!", "random", "yessir"}
	for _, v := range invalid {
		_, err := ParseBool(v, false)
		if err == nil {
			t.Errorf("ParseBool(%q): want error, got nil", v)
		}
	}
}

func TestParseBool_InvalidValueReturnsFalse(t *testing.T) {
	got, err := ParseBool("gibberish", true)
	if err == nil {
		t.Error("ParseBool invalid: want error, got nil")
	}
	// return value on error must be false per spec
	if got {
		t.Error("ParseBool invalid: got true, want false on error")
	}
}

// ─────────────────────────────── MustParseBool ───────────────────────────────

func TestMustParseBool_ValidTruthy(t *testing.T) {
	if !MustParseBool("yes", false) {
		t.Error("MustParseBool(\"yes\", false): got false, want true")
	}
}

func TestMustParseBool_ValidFalsy(t *testing.T) {
	if MustParseBool("no", true) {
		t.Error("MustParseBool(\"no\", true): got true, want false")
	}
}

func TestMustParseBool_EmptyReturnsDefault(t *testing.T) {
	if MustParseBool("", true) != true {
		t.Error("MustParseBool(\"\", true): want true")
	}
	if MustParseBool("", false) != false {
		t.Error("MustParseBool(\"\", false): want false")
	}
}

func TestMustParseBool_InvalidPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("MustParseBool invalid value: want panic, got none")
		}
	}()
	MustParseBool("notabool", false)
}

// ─────────────────────────────── IsTruthy ────────────────────────────────────

func TestIsTruthy_TruthyValues(t *testing.T) {
	truthy := []string{"1", "yes", "true", "on", "enabled", "y", "t"}
	for _, v := range truthy {
		if !IsTruthy(v) {
			t.Errorf("IsTruthy(%q): got false, want true", v)
		}
		// case-insensitive
		if !IsTruthy(strings.ToUpper(v)) {
			t.Errorf("IsTruthy(%q upper): got false, want true", v)
		}
	}
}

func TestIsTruthy_FalsyValues(t *testing.T) {
	falsy := []string{"0", "no", "false", "off", "disabled", "n", "f"}
	for _, v := range falsy {
		if IsTruthy(v) {
			t.Errorf("IsTruthy(%q): got true, want false", v)
		}
	}
}

func TestIsTruthy_EmptyString(t *testing.T) {
	if IsTruthy("") {
		t.Error("IsTruthy(\"\") should be false")
	}
}

func TestIsTruthy_WhitespaceStripped(t *testing.T) {
	if !IsTruthy("  yes  ") {
		t.Error("IsTruthy(\"  yes  \"): got false, want true (whitespace should be stripped)")
	}
}

func TestIsTruthy_UnknownValue(t *testing.T) {
	if IsTruthy("maybe") {
		t.Error("IsTruthy(\"maybe\"): got true, want false")
	}
}

// ─────────────────────────────── IsFalsy ─────────────────────────────────────

func TestIsFalsy_FalsyValues(t *testing.T) {
	falsy := []string{"0", "no", "false", "off", "disabled", "n", "f", "deny", "never"}
	for _, v := range falsy {
		if !IsFalsy(v) {
			t.Errorf("IsFalsy(%q): got false, want true", v)
		}
		if !IsFalsy(strings.ToUpper(v)) {
			t.Errorf("IsFalsy(%q upper): got false, want true", v)
		}
	}
}

func TestIsFalsy_TruthyValues(t *testing.T) {
	truthy := []string{"1", "yes", "true", "on", "enabled"}
	for _, v := range truthy {
		if IsFalsy(v) {
			t.Errorf("IsFalsy(%q): got true, want false", v)
		}
	}
}

func TestIsFalsy_EmptyString(t *testing.T) {
	if IsFalsy("") {
		t.Error("IsFalsy(\"\") should be false")
	}
}

func TestIsFalsy_WhitespaceStripped(t *testing.T) {
	if !IsFalsy("  no  ") {
		t.Error("IsFalsy(\"  no  \"): got false, want true (whitespace should be stripped)")
	}
}

func TestIsFalsy_UnknownValue(t *testing.T) {
	if IsFalsy("maybe") {
		t.Error("IsFalsy(\"maybe\"): got true, want false")
	}
}

// ─────────────────────────── Mutual exclusivity ──────────────────────────────

// A value that is truthy must not also be falsy, and vice versa.
// Unknown values are neither.
func TestTruthyFalsy_MutualExclusion(t *testing.T) {
	allTruthy := []string{"1", "yes", "true", "on", "ok", "enable", "enabled"}
	for _, v := range allTruthy {
		if IsFalsy(v) {
			t.Errorf("%q is truthy but IsFalsy returned true", v)
		}
	}

	allFalsy := []string{"0", "no", "false", "off", "disable", "disabled"}
	for _, v := range allFalsy {
		if IsTruthy(v) {
			t.Errorf("%q is falsy but IsTruthy returned true", v)
		}
	}
}
