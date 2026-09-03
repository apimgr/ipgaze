package httputil

import "testing"

// ─────────────────────── IsOurCliClient ──────────────────────────────────────

func TestIsOurCliClient_ValidPrefix(t *testing.T) {
	cases := []string{
		"ipgaze-cli/1.0.0",
		"ipgaze-cli/0.0.1",
		"ipgaze-cli/dev",
		"ipgaze-cli/ ",
	}
	for _, ua := range cases {
		if !IsOurCliClient(ua) {
			t.Errorf("IsOurCliClient(%q): got false, want true", ua)
		}
	}
}

func TestIsOurCliClient_InvalidUA(t *testing.T) {
	cases := []string{
		"",
		"Mozilla/5.0",
		"curl/8.1.2",
		"IPGaze-cli/1.0.0",
		"ipgaze/1.0.0",
		"ipgaze-cli",
	}
	for _, ua := range cases {
		if IsOurCliClient(ua) {
			t.Errorf("IsOurCliClient(%q): got true, want false", ua)
		}
	}
}

// IsOurCliClient is case-sensitive; mixed case must not match.
func TestIsOurCliClient_CaseSensitive(t *testing.T) {
	if IsOurCliClient("IPGAZE-CLI/1.0.0") {
		t.Error("IsOurCliClient(\"IPGAZE-CLI/1.0.0\"): got true, want false (case-sensitive prefix)")
	}
}

// ─────────────────────── IsTextBrowser ───────────────────────────────────────

func TestIsTextBrowser_KnownBrowsers(t *testing.T) {
	cases := []struct {
		ua   string
		want bool
	}{
		{"Lynx/2.9.0dev.6", true},
		{"w3m/0.5.3", true},
		// Links with a space separator
		{"Links (2.28; Linux 6.1)", true},
		// Links with slash separator
		{"Links/2.28", true},
		{"ELinks/0.13.0", true},
		{"Browsh/1.6.4", true},
		{"Carbonyl/0.0.3", true},
		{"NetSurf/3.10", true},
		// Upper-case input must match because the check lowercases the UA.
		{"LYNX/2.9.0", true},
		{"W3M/0.5.3", true},
	}
	for _, tc := range cases {
		got := IsTextBrowser(tc.ua)
		if got != tc.want {
			t.Errorf("IsTextBrowser(%q) = %v, want %v", tc.ua, got, tc.want)
		}
	}
}

func TestIsTextBrowser_NonTextBrowsers(t *testing.T) {
	cases := []string{
		"",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
		"curl/8.1.2",
		"ipgaze-cli/1.0.0",
		"python-requests/2.28.0",
	}
	for _, ua := range cases {
		if IsTextBrowser(ua) {
			t.Errorf("IsTextBrowser(%q): got true, want false", ua)
		}
	}
}

// ─────────────────────── IsHttpTool ──────────────────────────────────────────

func TestIsHttpTool_KnownTools(t *testing.T) {
	cases := []string{
		"curl/8.1.2",
		"Wget/1.21.3",
		"HTTPie/3.2.1",
		"libcurl/8.0.0",
		"python-requests/2.28.0",
		"Go-http-client/2.0",
		"axios/1.0.0",
		"node-fetch/3.3.0",
		"xh/0.19.0",
	}
	for _, ua := range cases {
		if !IsHttpTool(ua) {
			t.Errorf("IsHttpTool(%q): got false, want true", ua)
		}
	}
}

// Empty UA is treated as an HTTP tool per the inline spec comment.
func TestIsHttpTool_EmptyUAIsHttpTool(t *testing.T) {
	if !IsHttpTool("") {
		t.Error("IsHttpTool(\"\"): got false, want true (empty UA treated as HTTP tool)")
	}
}

func TestIsHttpTool_BrowserIsNotHttpTool(t *testing.T) {
	cases := []string{
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
		"ipgaze-cli/1.0.0",
		"Lynx/2.9.0",
	}
	for _, ua := range cases {
		if IsHttpTool(ua) {
			t.Errorf("IsHttpTool(%q): got true, want false", ua)
		}
	}
}

// IsHttpTool must be case-insensitive for tool strings.
func TestIsHttpTool_CaseInsensitive(t *testing.T) {
	if !IsHttpTool("CURL/8.1.2") {
		t.Error("IsHttpTool(\"CURL/8.1.2\"): got false, want true (case-insensitive match)")
	}
}

// ─────────────────── IsNonInteractiveClient ──────────────────────────────────

func TestIsNonInteractiveClient_HttpToolIsNonInteractive(t *testing.T) {
	cases := []string{
		"curl/8.1.2",
		"wget/1.21.3",
		"",
	}
	for _, ua := range cases {
		if !IsNonInteractiveClient(ua) {
			t.Errorf("IsNonInteractiveClient(%q): got false, want true", ua)
		}
	}
}

// Our CLI client is interactive — must not be classified as non-interactive.
func TestIsNonInteractiveClient_OurCliIsInteractive(t *testing.T) {
	if IsNonInteractiveClient("ipgaze-cli/1.0.0") {
		t.Error("IsNonInteractiveClient(\"ipgaze-cli/1.0.0\"): got true, want false (our CLI is interactive)")
	}
}

// Text browsers are interactive — must not be classified as non-interactive.
func TestIsNonInteractiveClient_TextBrowserIsInteractive(t *testing.T) {
	cases := []string{
		"Lynx/2.9.0",
		"w3m/0.5.3",
		"ELinks/0.13.0",
	}
	for _, ua := range cases {
		if IsNonInteractiveClient(ua) {
			t.Errorf("IsNonInteractiveClient(%q): got true, want false (text browsers are interactive)", ua)
		}
	}
}

// Regular web browsers are not HTTP tools so must not be classified as non-interactive.
func TestIsNonInteractiveClient_WebBrowserIsNotNonInteractive(t *testing.T) {
	ua := "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
	if IsNonInteractiveClient(ua) {
		t.Errorf("IsNonInteractiveClient(%q): got true, want false (web browser is interactive)", ua)
	}
}
