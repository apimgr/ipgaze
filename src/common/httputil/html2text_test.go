package httputil

import (
	"strings"
	"testing"
)

// ─────────────────────── HTML2TextConverter ───────────────────────────────────

// Zero/negative width must fall back to 80 — no panic.
func TestHTML2TextConverter_ZeroWidthDefaultsTo80(t *testing.T) {
	out := HTML2TextConverter("<p>hello</p>", 0)
	if out == "" {
		t.Error("HTML2TextConverter with width=0: expected non-empty output")
	}
	if !strings.Contains(out, "hello") {
		t.Errorf("HTML2TextConverter with width=0: output %q does not contain 'hello'", out)
	}
}

func TestHTML2TextConverter_NegativeWidthDefaultsTo80(t *testing.T) {
	out := HTML2TextConverter("<p>world</p>", -5)
	if !strings.Contains(out, "world") {
		t.Errorf("HTML2TextConverter with width=-5: output %q does not contain 'world'", out)
	}
}

// Empty input must not panic and should return an empty or whitespace-only string.
func TestHTML2TextConverter_EmptyHTML(t *testing.T) {
	out := HTML2TextConverter("", 80)
	if strings.TrimSpace(out) != "" {
		t.Errorf("HTML2TextConverter with empty HTML: want empty output, got %q", out)
	}
}

// <h1> must be rendered upper-case and surrounded by box-drawing separators.
func TestHTML2TextConverter_H1RenderedUppercase(t *testing.T) {
	out := HTML2TextConverter("<h1>hello world</h1>", 80)
	if !strings.Contains(out, "HELLO WORLD") {
		t.Errorf("HTML2TextConverter h1: want 'HELLO WORLD' in output, got:\n%s", out)
	}
	if !strings.Contains(out, "═") {
		t.Errorf("HTML2TextConverter h1: want box-drawing separator '═', got:\n%s", out)
	}
}

// <h2> must be rendered with the "─── text ───" prefix format.
func TestHTML2TextConverter_H2Format(t *testing.T) {
	out := HTML2TextConverter("<h2>Section</h2>", 80)
	if !strings.Contains(out, "Section") {
		t.Errorf("HTML2TextConverter h2: 'Section' missing from output:\n%s", out)
	}
	if !strings.Contains(out, "─── Section ───") {
		t.Errorf("HTML2TextConverter h2: expected '─── Section ───' format, got:\n%s", out)
	}
}

// <h3> must be rendered with the "► text" prefix.
func TestHTML2TextConverter_H3Format(t *testing.T) {
	out := HTML2TextConverter("<h3>Subsection</h3>", 80)
	if !strings.Contains(out, "► Subsection") {
		t.Errorf("HTML2TextConverter h3: expected '► Subsection' format, got:\n%s", out)
	}
}

// <p> content must appear in the output.
func TestHTML2TextConverter_Paragraph(t *testing.T) {
	out := HTML2TextConverter("<p>This is a paragraph.</p>", 80)
	if !strings.Contains(out, "This is a paragraph.") {
		t.Errorf("HTML2TextConverter p: paragraph text missing from output:\n%s", out)
	}
}

// <ul> must render bullet items with "•".
func TestHTML2TextConverter_UnorderedList(t *testing.T) {
	out := HTML2TextConverter("<ul><li>Alpha</li><li>Beta</li></ul>", 80)
	if !strings.Contains(out, "•") {
		t.Errorf("HTML2TextConverter ul: bullet '•' missing from output:\n%s", out)
	}
	if !strings.Contains(out, "Alpha") || !strings.Contains(out, "Beta") {
		t.Errorf("HTML2TextConverter ul: list items missing from output:\n%s", out)
	}
}

// <ol> must render numbered items starting at 1.
func TestHTML2TextConverter_OrderedList(t *testing.T) {
	out := HTML2TextConverter("<ol><li>First</li><li>Second</li></ol>", 80)
	if !strings.Contains(out, "1.") {
		t.Errorf("HTML2TextConverter ol: '1.' missing from output:\n%s", out)
	}
	if !strings.Contains(out, "2.") {
		t.Errorf("HTML2TextConverter ol: '2.' missing from output:\n%s", out)
	}
}

// <a> with href must include the URL in square brackets.
func TestHTML2TextConverter_AnchorWithHref(t *testing.T) {
	out := HTML2TextConverter(`<a href="https://example.com">Click here</a>`, 80)
	if !strings.Contains(out, "Click here") {
		t.Errorf("HTML2TextConverter a: anchor text missing from output:\n%s", out)
	}
	if !strings.Contains(out, "[https://example.com]") {
		t.Errorf("HTML2TextConverter a: href URL missing from output:\n%s", out)
	}
}

// <a> without href must render only the link text with no brackets.
func TestHTML2TextConverter_AnchorWithoutHref(t *testing.T) {
	out := HTML2TextConverter(`<a>No link</a>`, 80)
	if !strings.Contains(out, "No link") {
		t.Errorf("HTML2TextConverter a without href: text missing from output:\n%s", out)
	}
	if strings.Contains(out, "[") {
		t.Errorf("HTML2TextConverter a without href: unexpected '[' in output:\n%s", out)
	}
}

// <strong> and <b> must wrap content in asterisks.
func TestHTML2TextConverter_StrongAndBold(t *testing.T) {
	for _, tag := range []string{"strong", "b"} {
		out := HTML2TextConverter("<"+tag+">important</"+tag+">", 80)
		if !strings.Contains(out, "*important*") {
			t.Errorf("HTML2TextConverter <%s>: expected '*important*' in output:\n%s", tag, out)
		}
	}
}

// <em> and <i> must wrap content in underscores.
func TestHTML2TextConverter_EmAndItalic(t *testing.T) {
	for _, tag := range []string{"em", "i"} {
		out := HTML2TextConverter("<"+tag+">emphasis</"+tag+">", 80)
		if !strings.Contains(out, "_emphasis_") {
			t.Errorf("HTML2TextConverter <%s>: expected '_emphasis_' in output:\n%s", tag, out)
		}
	}
}

// <code> must wrap content in backticks.
func TestHTML2TextConverter_Code(t *testing.T) {
	out := HTML2TextConverter("<code>fmt.Println</code>", 80)
	if !strings.Contains(out, "`fmt.Println`") {
		t.Errorf("HTML2TextConverter code: expected backtick wrapping, got:\n%s", out)
	}
}

// <pre> must indent each line with four spaces.
func TestHTML2TextConverter_Pre(t *testing.T) {
	out := HTML2TextConverter("<pre>line one\nline two</pre>", 80)
	if !strings.Contains(out, "    line one") {
		t.Errorf("HTML2TextConverter pre: expected 4-space indent, got:\n%s", out)
	}
}

// <hr> must render a separator of dashes.
func TestHTML2TextConverter_HR(t *testing.T) {
	out := HTML2TextConverter("<hr/>", 80)
	if !strings.Contains(out, "─") {
		t.Errorf("HTML2TextConverter hr: expected '─' separator, got:\n%s", out)
	}
}

// <blockquote> must prefix each line with "│ ".
func TestHTML2TextConverter_Blockquote(t *testing.T) {
	out := HTML2TextConverter("<blockquote>Quoted text</blockquote>", 80)
	if !strings.Contains(out, "│ ") {
		t.Errorf("HTML2TextConverter blockquote: expected '│ ' prefix, got:\n%s", out)
	}
}

// <script>, <style>, and <form> elements must be completely suppressed.
func TestHTML2TextConverter_SkippedElements(t *testing.T) {
	for _, tag := range []string{"script", "style", "form"} {
		html := "<" + tag + ">should be hidden</" + tag + ">"
		out := HTML2TextConverter(html, 80)
		if strings.Contains(out, "should be hidden") {
			t.Errorf("HTML2TextConverter <%s>: content should be suppressed, got:\n%s", tag, out)
		}
	}
}

// <head> must not appear in output.
func TestHTML2TextConverter_HeadSuppressed(t *testing.T) {
	out := HTML2TextConverter("<html><head><title>Page Title</title></head><body><p>body</p></body></html>", 80)
	if strings.Contains(out, "Page Title") {
		t.Errorf("HTML2TextConverter head: <head> content leaked into output:\n%s", out)
	}
	if !strings.Contains(out, "body") {
		t.Errorf("HTML2TextConverter head: body content missing from output:\n%s", out)
	}
}

// Table must render as ASCII table with separator lines.
func TestHTML2TextConverter_Table(t *testing.T) {
	html := `<table>
		<tr><th>Name</th><th>Age</th></tr>
		<tr><td>Alice</td><td>30</td></tr>
	</table>`
	out := HTML2TextConverter(html, 80)
	if !strings.Contains(out, "Name") || !strings.Contains(out, "Alice") {
		t.Errorf("HTML2TextConverter table: table content missing from output:\n%s", out)
	}
	if !strings.Contains(out, "+") {
		t.Errorf("HTML2TextConverter table: ASCII table separator '+' missing from output:\n%s", out)
	}
}

// Empty table must not panic.
func TestHTML2TextConverter_EmptyTable(t *testing.T) {
	out := HTML2TextConverter("<table></table>", 80)
	_ = out
}

// <br> must produce a newline.
func TestHTML2TextConverter_LineBreak(t *testing.T) {
	out := HTML2TextConverter("before<br/>after", 80)
	if !strings.Contains(out, "\n") {
		t.Errorf("HTML2TextConverter br: expected newline in output:\n%s", out)
	}
}

// ─────────────────────── wordWrap ────────────────────────────────────────────

func TestWordWrap_ShortTextUnchanged(t *testing.T) {
	got := wordWrap("hello", 80)
	if got != "hello" {
		t.Errorf("wordWrap short text: got %q, want %q", got, "hello")
	}
}

func TestWordWrap_ExactWidthUnchanged(t *testing.T) {
	text := strings.Repeat("a", 80)
	got := wordWrap(text, 80)
	if got != text {
		t.Errorf("wordWrap exact-width text: got %q, want input unchanged", got)
	}
}

func TestWordWrap_WrapsLongText(t *testing.T) {
	// A 5-word sentence that exceeds width=10 must be split into multiple lines.
	got := wordWrap("one two three four five", 10)
	lines := strings.Split(got, "\n")
	if len(lines) < 2 {
		t.Errorf("wordWrap long text: expected multiple lines, got: %q", got)
	}
	for _, l := range lines {
		if len(l) > 10 {
			t.Errorf("wordWrap: line %q exceeds width 10", l)
		}
	}
}

func TestWordWrap_ZeroWidthReturnsText(t *testing.T) {
	got := wordWrap("hello world", 0)
	if got != "hello world" {
		t.Errorf("wordWrap width=0: got %q, want original text", got)
	}
}

func TestWordWrap_EmptyText(t *testing.T) {
	got := wordWrap("", 80)
	if got != "" {
		t.Errorf("wordWrap empty text: got %q, want empty string", got)
	}
}

// ─────────────────────── centerText ──────────────────────────────────────────

func TestCenterText_ShortText(t *testing.T) {
	got := centerText("hi", 10)
	if len(got) > 10 {
		t.Errorf("centerText: got %q (len %d), want len ≤ 10", got, len(got))
	}
	if !strings.Contains(got, "hi") {
		t.Errorf("centerText: %q does not contain 'hi'", got)
	}
}

func TestCenterText_TextLongerThanWidth(t *testing.T) {
	// When text is wider than width, the text must be returned unchanged.
	long := strings.Repeat("x", 20)
	got := centerText(long, 10)
	if got != long {
		t.Errorf("centerText overflow: got %q, want original text", got)
	}
}

// ─────────────────────── stripAllTags ────────────────────────────────────────

func TestStripAllTags_RemovesTags(t *testing.T) {
	got := stripAllTags("<b>bold</b> and <i>italic</i>")
	if strings.Contains(got, "<") || strings.Contains(got, ">") {
		t.Errorf("stripAllTags: tags not removed, got %q", got)
	}
	if !strings.Contains(got, "bold") || !strings.Contains(got, "italic") {
		t.Errorf("stripAllTags: text content missing, got %q", got)
	}
}

func TestStripAllTags_EmptyInput(t *testing.T) {
	got := stripAllTags("")
	if got != "" {
		t.Errorf("stripAllTags empty: got %q, want empty string", got)
	}
}

func TestStripAllTags_NoTags(t *testing.T) {
	in := "plain text"
	got := stripAllTags(in)
	if got != in {
		t.Errorf("stripAllTags no tags: got %q, want %q", got, in)
	}
}
