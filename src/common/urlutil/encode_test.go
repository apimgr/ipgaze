package urlutil

import (
	"testing"
)

func TestBuildAPIURL(t *testing.T) {
	tests := []struct {
		base    string
		version string
		path    string
		want    string
	}{
		{"https://ifcfg.us", "v1", "/server/healthz", "https://ifcfg.us/api/v1/server/healthz"},
		{"https://ifcfg.us/", "v1", "ip", "https://ifcfg.us/api/v1/ip"},
		{"http://localhost:8080", "v1", "/ip", "http://localhost:8080/api/v1/ip"},
	}
	for _, tt := range tests {
		got := BuildAPIURL(tt.base, tt.version, tt.path)
		if got != tt.want {
			t.Errorf("BuildAPIURL(%q, %q, %q) = %q, want %q", tt.base, tt.version, tt.path, got, tt.want)
		}
	}
}

func TestEncodePathSegment(t *testing.T) {
	got := EncodePathSegment("hello world/path")
	if got != "hello%20world%2Fpath" {
		t.Errorf("unexpected: %q", got)
	}
}

func TestBuildQueryString(t *testing.T) {
	got := BuildQueryString(map[string]string{"a": "1", "b": "2"})
	if got == "" || got[0] != '?' {
		t.Errorf("expected query string starting with ?, got %q", got)
	}
}

func TestBuildQueryString_Empty(t *testing.T) {
	if got := BuildQueryString(map[string]string{}); got != "" {
		t.Errorf("BuildQueryString(empty) = %q, want empty string", got)
	}
}

func TestEncodeQueryValue(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"hello world", "hello+world"},
		{"a&b=c", "a%26b%3Dc"},
		{"", ""},
		{"plain", "plain"},
	}
	for _, tt := range tests {
		if got := EncodeQueryValue(tt.in); got != tt.want {
			t.Errorf("EncodeQueryValue(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
