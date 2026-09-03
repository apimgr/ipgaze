// Package httputil provides HTTP utility helpers.
package httputil

import (
	"fmt"
	"strings"

	"golang.org/x/net/html"
)

// HTML2TextConverter converts rendered HTML to readable plain text for terminal output.
// Used for HTTP tools (curl, wget) that are non-interactive — AI.md PART 14.
// width controls the terminal column width used for wrapping and centering.
func HTML2TextConverter(rawHTML string, width int) string {
	if width <= 0 {
		width = 80
	}
	doc, err := html.Parse(strings.NewReader(rawHTML))
	if err != nil {
		return stripAllTags(rawHTML)
	}
	var buf strings.Builder
	convertNode(&buf, doc, width, 0)
	return buf.String()
}

// convertNode recursively converts an HTML node tree to plain text.
func convertNode(buf *strings.Builder, n *html.Node, width, indent int) {
	switch n.Type {
	case html.ElementNode:
		switch n.Data {
		case "script", "style", "form", "input", "button", "textarea", "select":
			// Skip non-interactive and scripting elements entirely.
			return
		case "h1":
			text := getTextContent(n)
			line := strings.Repeat("═", width)
			buf.WriteString(line + "\n")
			buf.WriteString(centerText(strings.ToUpper(text), width) + "\n")
			buf.WriteString(line + "\n\n")
			return
		case "h2":
			text := getTextContent(n)
			buf.WriteString("─── " + text + " ───\n\n")
			return
		case "h3":
			text := getTextContent(n)
			buf.WriteString("► " + text + "\n\n")
			return
		case "h4", "h5", "h6":
			text := getTextContent(n)
			buf.WriteString(text + "\n\n")
			return
		case "p":
			text := strings.TrimSpace(getTextContent(n))
			if text != "" {
				buf.WriteString(wordWrap(text, width-indent) + "\n\n")
			}
			return
		case "ul":
			convertList(buf, n, width, indent, false)
			buf.WriteString("\n")
			return
		case "ol":
			convertList(buf, n, width, indent, true)
			buf.WriteString("\n")
			return
		case "li":
			text := strings.TrimSpace(getTextContent(n))
			buf.WriteString(strings.Repeat(" ", indent) + "  • " + text + "\n")
			return
		case "a":
			text := strings.TrimSpace(getTextContent(n))
			href := getAttr(n, "href")
			if href != "" {
				buf.WriteString(text + " [" + href + "]")
			} else {
				buf.WriteString(text)
			}
			return
		case "strong", "b":
			buf.WriteString("*" + strings.TrimSpace(getTextContent(n)) + "*")
			return
		case "em", "i":
			buf.WriteString("_" + strings.TrimSpace(getTextContent(n)) + "_")
			return
		case "code":
			buf.WriteString("`" + getTextContent(n) + "`")
			return
		case "pre":
			text := getTextContent(n)
			for _, line := range strings.Split(text, "\n") {
				buf.WriteString("    " + line + "\n")
			}
			buf.WriteString("\n")
			return
		case "table":
			convertTable(buf, n, width)
			return
		case "hr":
			buf.WriteString(strings.Repeat("─", width) + "\n\n")
			return
		case "blockquote":
			text := getTextContent(n)
			for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
				buf.WriteString("│ " + line + "\n")
			}
			buf.WriteString("\n")
			return
		case "br":
			buf.WriteString("\n")
			return
		case "head":
			// Skip head entirely — no visible content.
			return
		}
		// Default: recurse into children.
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			convertNode(buf, c, width, indent)
		}
	case html.TextNode:
		text := strings.TrimSpace(n.Data)
		if text != "" {
			buf.WriteString(text)
		}
	default:
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			convertNode(buf, c, width, indent)
		}
	}
}

// convertList renders an HTML <ul> or <ol> node as a bulleted/numbered list.
func convertList(buf *strings.Builder, n *html.Node, width, indent int, ordered bool) {
	counter := 1
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode && c.Data == "li" {
			text := strings.TrimSpace(getTextContent(c))
			prefix := strings.Repeat(" ", indent)
			if ordered {
				buf.WriteString(fmt.Sprintf("%s  %d. %s\n", prefix, counter, text))
				counter++
			} else {
				buf.WriteString(prefix + "  • " + text + "\n")
			}
		}
	}
}

// convertTable renders an HTML <table> as an ASCII table.
func convertTable(buf *strings.Builder, n *html.Node, width int) {
	var rows [][]string
	var walkTable func(*html.Node)
	walkTable = func(node *html.Node) {
		if node.Type == html.ElementNode && (node.Data == "tr") {
			var cells []string
			for c := node.FirstChild; c != nil; c = c.NextSibling {
				if c.Type == html.ElementNode && (c.Data == "td" || c.Data == "th") {
					cells = append(cells, strings.TrimSpace(getTextContent(c)))
				}
			}
			if len(cells) > 0 {
				rows = append(rows, cells)
			}
		}
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			walkTable(c)
		}
	}
	walkTable(n)

	if len(rows) == 0 {
		return
	}

	// Determine column widths.
	cols := 0
	for _, row := range rows {
		if len(row) > cols {
			cols = len(row)
		}
	}
	colWidths := make([]int, cols)
	for _, row := range rows {
		for i, cell := range row {
			if len(cell) > colWidths[i] {
				colWidths[i] = len(cell)
			}
		}
	}

	// Build separator line.
	sep := "+"
	for _, w := range colWidths {
		sep += strings.Repeat("─", w+2) + "+"
	}

	buf.WriteString(sep + "\n")
	for rowIdx, row := range rows {
		line := "│"
		for i := 0; i < cols; i++ {
			cell := ""
			if i < len(row) {
				cell = row[i]
			}
			line += fmt.Sprintf(" %-*s │", colWidths[i], cell)
		}
		buf.WriteString(line + "\n")
		if rowIdx == 0 {
			// Header separator.
			buf.WriteString(sep + "\n")
		}
	}
	buf.WriteString(sep + "\n\n")
}

// getTextContent extracts all text content from a node and its descendants.
func getTextContent(n *html.Node) string {
	var sb strings.Builder
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.TextNode {
			sb.WriteString(node.Data)
		}
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return sb.String()
}

// getAttr returns the value of the named attribute on an element node.
func getAttr(n *html.Node, name string) string {
	for _, a := range n.Attr {
		if a.Key == name {
			return a.Val
		}
	}
	return ""
}

// centerText centers text within the given width by padding with spaces.
func centerText(text string, width int) string {
	if len(text) >= width {
		return text
	}
	pad := (width - len(text)) / 2
	return strings.Repeat(" ", pad) + text
}

// wordWrap wraps text at width characters, preserving word boundaries.
func wordWrap(text string, width int) string {
	if width <= 0 || len(text) <= width {
		return text
	}
	words := strings.Fields(text)
	var lines []string
	current := ""
	for _, w := range words {
		if current == "" {
			current = w
		} else if len(current)+1+len(w) <= width {
			current += " " + w
		} else {
			lines = append(lines, current)
			current = w
		}
	}
	if current != "" {
		lines = append(lines, current)
	}
	return strings.Join(lines, "\n")
}

// stripAllTags is a fallback that removes all HTML tags via simple string scanning.
func stripAllTags(s string) string {
	var buf strings.Builder
	inTag := false
	for _, r := range s {
		switch {
		case r == '<':
			inTag = true
		case r == '>':
			inTag = false
		case !inTag:
			buf.WriteRune(r)
		}
	}
	return strings.TrimSpace(buf.String())
}
