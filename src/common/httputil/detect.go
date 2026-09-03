// Package httputil provides HTTP client detection helpers.
package httputil

import "strings"

// IsOurCliClient returns true if the User-Agent is the ipgaze-cli binary.
// Our CLI client is INTERACTIVE — it receives JSON and renders its own TUI/GUI.
func IsOurCliClient(ua string) bool {
	return strings.HasPrefix(ua, "ipgaze-cli/")
}

// IsTextBrowser returns true for text-mode browsers (lynx, w3m, links, elinks, etc.).
// Text browsers are INTERACTIVE but do NOT support JavaScript.
// They receive server-rendered no-JS HTML.
func IsTextBrowser(ua string) bool {
	ua = strings.ToLower(ua)
	for _, b := range []string{
		// Lynx - classic text browser
		"lynx/",
		// w3m - text browser with table support
		"w3m/",
		// Links - text browser (space after name)
		"links ",
		// Links alternative format
		"links/",
		// ELinks - enhanced links
		"elinks/",
		// Browsh - modern text browser
		"browsh/",
		// Carbonyl - Chromium in terminal
		"carbonyl/",
		// NetSurf - lightweight browser (limited JS)
		"netsurf",
	} {
		if strings.Contains(ua, b) {
			return true
		}
	}
	return false
}

// IsHttpTool returns true for command-line HTTP tools (curl, wget, httpie, etc.).
// HTTP tools are NON-INTERACTIVE — they just dump output to the terminal.
// An empty User-Agent is treated as an HTTP tool (no browser would omit UA).
func IsHttpTool(ua string) bool {
	if ua == "" {
		return true
	}
	lower := strings.ToLower(ua)
	for _, t := range []string{
		"curl/", "wget/", "httpie/",
		"libcurl/", "python-requests/",
		"go-http-client/", "axios/", "node-fetch/",
		"xh/",
	} {
		if strings.Contains(lower, t) {
			return true
		}
	}
	return false
}

// IsNonInteractiveClient returns true for clients that need pre-formatted plain text.
// ONLY HTTP tools are non-interactive; our CLI client and text browsers are interactive.
func IsNonInteractiveClient(ua string) bool {
	// Our client is INTERACTIVE - receives JSON, renders own TUI/GUI
	if IsOurCliClient(ua) {
		return false
	}
	// Text browsers are INTERACTIVE - receive no-JS HTML, render it themselves
	if IsTextBrowser(ua) {
		return false
	}
	// HTTP tools are NON-INTERACTIVE - need pre-formatted text
	return IsHttpTool(ua)
}
