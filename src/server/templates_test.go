package server

import (
	"html/template"
	"testing"
)

// TestTemplateFuncMap_MarkdownToHTML covers the markdownToHTML template func
// used by privacy.tmpl (AI.md PART 16 "/server/privacy") to render
// operator-supplied Markdown content blocks.
func TestTemplateFuncMap_MarkdownToHTML(t *testing.T) {
	fn, ok := templateFuncMap("stamp")["markdownToHTML"].(func(string) template.HTML)
	if !ok {
		t.Fatal("markdownToHTML not registered or has unexpected signature")
	}
	got := fn("We collect **IP addresses**.")
	if got != `<p>We collect <strong>IP addresses</strong>.</p>
` {
		t.Errorf("markdownToHTML() = %q, want rendered <strong> markup", got)
	}
}

// TestTemplateFuncMap_Humanize covers the humanize template func used by
// privacy.tmpl's "Data Storage & Third-Party Sharing" section (AI.md PART 16
// "/server/privacy") to turn a SharingCondition.Condition value into a
// human-readable label.
func TestTemplateFuncMap_Humanize(t *testing.T) {
	fn, ok := templateFuncMap("stamp")["humanize"].(func(string) string)
	if !ok {
		t.Fatal("humanize not registered or has unexpected signature")
	}
	tests := map[string]string{
		"user_initiated": "User Initiated",
		"analytics":      "Analytics",
		"":               "",
	}
	for in, want := range tests {
		if got := fn(in); got != want {
			t.Errorf("humanize(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestInitTemplates_Parses guards the embedded template set against a parse
// error (an unregistered func, a malformed action) that would otherwise only
// surface at first render in production.
func TestInitTemplates_Parses(t *testing.T) {
	if err := InitTemplates(); err != nil {
		t.Fatalf("InitTemplates() error = %v", err)
	}
}

// TestTemplateFuncMap_NextTheme covers the nextTheme func the theme toggle
// form uses to compute its POST target (AI.md PART 16 "Theme Cycle Logic").
func TestTemplateFuncMap_NextTheme(t *testing.T) {
	fn, ok := templateFuncMap("stamp")["nextTheme"].(func(string) string)
	if !ok {
		t.Fatal("nextTheme not registered or has unexpected signature")
	}
	tests := map[string]string{
		"dark":  "light",
		"light": "auto",
		"auto":  "dark",
		"":      "dark",
	}
	for in, want := range tests {
		if got := fn(in); got != want {
			t.Errorf("nextTheme(%q) = %q, want %q", in, got, want)
		}
	}
}
