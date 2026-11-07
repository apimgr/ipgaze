package updatechannel

import "testing"

func TestNormalize(t *testing.T) {
	tests := []struct {
		input string
		want  string
		ok    bool
	}{
		{"stable", "stable", true},
		{"beta", "beta", true},
		{"devel", "devel", true},
		{"daily", "devel", true},
		{"rolling", "devel", true},
		{"dev", "devel", true},
		{"development", "devel", true},
		{" DeVeLoPmEnT ", "devel", true},
		{"unknown", "", false},
	}
	for _, tc := range tests {
		got, ok := Normalize(tc.input)
		if got != tc.want || ok != tc.ok {
			t.Errorf("Normalize(%q) = (%q, %t), want (%q, %t)", tc.input, got, ok, tc.want, tc.ok)
		}
	}
}
