package config

import (
	"strings"
	"testing"
)

// TestSanitizeFooterHTML_Sentinels verifies the "" (default) and " " (disable)
// sentinel values pass through untouched per AI.md PART 16.
func TestSanitizeFooterHTML_Sentinels(t *testing.T) {
	if got := SanitizeFooterHTML(""); got != "" {
		t.Fatalf(`SanitizeFooterHTML("") = %q, want ""`, got)
	}
	if got := SanitizeFooterHTML(" "); got != " " {
		t.Fatalf(`SanitizeFooterHTML(" ") = %q, want " "`, got)
	}
}

// TestSanitizeFooterHTML_Allowed verifies allowed formatting is preserved.
func TestSanitizeFooterHTML_Allowed(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  []string // substrings that must be present
	}{
		{"paragraph+strong", "<p>Powered by <strong>MyCompany</strong></p>", []string{"<p>", "Powered by", "<strong>MyCompany</strong>"}},
		{"headings+list", "<h3>Team</h3><ul><li>One</li></ul>", []string{"<h3>Team</h3>", "<ul>", "<li>One</li>"}},
		{"span+div+class", `<div class="brand"><span id="x">Hi</span></div>`, []string{`class="brand"`, `id="x"`, "Hi"}},
		{"https image", `<img src="https://ex.com/l.png" alt="Logo" width="100">`, []string{`src="https://ex.com/l.png"`, `alt="Logo"`, `width="100"`}},
		{"data image", `<img src="data:image/png;base64,AAAA" alt="d">`, []string{"data:image/png;base64,AAAA"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SanitizeFooterHTML(tc.input)
			for _, want := range tc.want {
				if !strings.Contains(got, want) {
					t.Errorf("SanitizeFooterHTML(%q) = %q, missing %q", tc.input, got, want)
				}
			}
		})
	}
}

// TestSanitizeFooterHTML_Blocked verifies dangerous elements/attributes are stripped
// per the AI.md PART 16 allowed-vs-blocked table.
func TestSanitizeFooterHTML_Blocked(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		mustNot  []string
		mustHave []string
	}{
		{"script", "<script>alert('xss')</script>", []string{"<script", "alert"}, nil},
		{"noscript", "<noscript>x</noscript>", []string{"<noscript"}, nil},
		{"iframe", `<iframe src="https://evil.com"></iframe>`, []string{"<iframe", "evil.com"}, nil},
		{"object", `<object data="x"></object>`, []string{"<object"}, nil},
		{"form+input", `<form action="/steal"><input type="text"></form>`, []string{"<form", "<input"}, nil},
		{"event handler", `<img src="https://e.com/a.png" onerror="alert(1)">`, []string{"onerror", "alert"}, []string{"https://e.com/a.png"}},
		{"javascript url", `<a href="javascript:alert(1)">Click</a>`, []string{"javascript:"}, []string{"Click"}},
		{"http image scheme", `<img src="http://insecure/a.png" alt="a">`, []string{"http://insecure"}, nil},
		{"style attribute", `<p style="color:red">Text</p>`, []string{"style", "color:red"}, []string{"<p>", "Text"}},
		{"link+style tag", `<link rel="x"><style>body{}</style>`, []string{"<link", "<style"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SanitizeFooterHTML(tc.input)
			for _, bad := range tc.mustNot {
				if strings.Contains(got, bad) {
					t.Errorf("SanitizeFooterHTML(%q) = %q, must not contain %q", tc.input, got, bad)
				}
			}
			for _, good := range tc.mustHave {
				if !strings.Contains(got, good) {
					t.Errorf("SanitizeFooterHTML(%q) = %q, must contain %q", tc.input, got, good)
				}
			}
		})
	}
}

// TestSanitizeFooterHTML_LinkRelForced verifies external links get a
// noreferrer rel per RequireNoReferrerOnLinks (AI.md PART 16).
func TestSanitizeFooterHTML_LinkRelForced(t *testing.T) {
	got := SanitizeFooterHTML(`<a href="https://example.com" target="_blank">L</a>`)
	if !strings.Contains(got, "noreferrer") {
		t.Errorf("expected forced noreferrer rel, got %q", got)
	}
	if !strings.Contains(got, `href="https://example.com"`) {
		t.Errorf("expected href preserved, got %q", got)
	}
}

// TestValidateFooterHTML verifies error/no-error behavior per AI.md PART 16.
func TestValidateFooterHTML(t *testing.T) {
	// Sentinels: no error, pass through.
	for _, in := range []string{"", " "} {
		got, err := ValidateFooterHTML(in)
		if err != nil {
			t.Fatalf("ValidateFooterHTML(%q) unexpected error: %v", in, err)
		}
		if got != in {
			t.Fatalf("ValidateFooterHTML(%q) = %q, want %q", in, got, in)
		}
	}

	// Valid custom HTML: no error, content preserved.
	got, err := ValidateFooterHTML("<p>Hello</p>")
	if err != nil {
		t.Fatalf("unexpected error for valid HTML: %v", err)
	}
	if !strings.Contains(got, "<p>Hello</p>") {
		t.Fatalf("valid HTML altered unexpectedly: %q", got)
	}

	// All-disallowed content: error, empty result.
	got, err = ValidateFooterHTML("<script>alert('xss')</script>")
	if err == nil {
		t.Fatalf("expected error for all-disallowed content, got sanitized %q", got)
	}
	if got != "" {
		t.Fatalf("expected empty result on error, got %q", got)
	}
}
