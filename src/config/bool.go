package config

import (
	"fmt"
	"strings"
)

// Truthy values (case-insensitive)
var truthyValues = map[string]bool{
	"1": true, "y": true, "t": true,
	"yes": true, "true": true, "on": true, "ok": true,
	"enable": true, "enabled": true,
	"yep": true, "yup": true, "yeah": true,
	"aye": true, "si": true, "oui": true, "da": true, "hai": true,
	"affirmative": true, "accept": true, "allow": true, "grant": true,
	"sure": true, "totally": true,
}

// Falsy values (case-insensitive)
var falsyValues = map[string]bool{
	"0": true, "n": true, "f": true,
	"no": true, "false": true, "off": true,
	"disable": true, "disabled": true,
	"nope": true, "nah": true, "nay": true,
	"nein": true, "non": true, "niet": true, "iie": true, "lie": true,
	"negative": true, "reject": true, "block": true, "revoke": true,
	"deny": true, "never": true, "noway": true,
}

// ParseBool parses a string into a boolean using truthy/falsy values.
// Returns the parsed value and nil on success.
// Returns false and an error for invalid values.
// Empty string returns the provided default value.
func ParseBool(s string, defaultVal bool) (bool, error) {
	s = strings.TrimSpace(strings.ToLower(s))

	if s == "" {
		return defaultVal, nil
	}

	if truthyValues[s] {
		return true, nil
	}

	if falsyValues[s] {
		return false, nil
	}

	return false, fmt.Errorf("invalid boolean value: %q", s)
}

// MustParseBool parses a string into a boolean, panics on invalid value.
// Use only during initialization where invalid config should halt startup.
func MustParseBool(s string, defaultVal bool) bool {
	val, err := ParseBool(s, defaultVal)
	if err != nil {
		panic(err)
	}
	return val
}

// IsTruthy checks if a string represents a truthy value.
// Returns false for empty strings (unlike ParseBool which uses default).
func IsTruthy(s string) bool {
	s = strings.TrimSpace(strings.ToLower(s))
	return truthyValues[s]
}

// IsFalsy checks if a string represents a falsy value.
// Returns false for empty strings (unlike ParseBool which uses default).
func IsFalsy(s string) bool {
	s = strings.TrimSpace(strings.ToLower(s))
	return falsyValues[s]
}
