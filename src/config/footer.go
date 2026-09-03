package config

import (
	"errors"
	"log"
	"strings"
	"sync"

	"github.com/microcosm-cc/bluemonday"
)

// footerPolicy is the strict bluemonday policy used to sanitize operator
// footer HTML per AI.md PART 16 "Footer Customization". Built once and reused
// so per-request sanitization stays cheap.
var (
	footerPolicy     *bluemonday.Policy
	footerPolicyOnce sync.Once
)

// footerSanitizePolicy lazily builds the strict footer sanitization policy.
// Only basic text-formatting tags, safe links, and https/data images are
// permitted. Scripts, iframes, forms, event handlers, javascript: URLs, and
// the style attribute are stripped automatically by bluemonday.
func footerSanitizePolicy() *bluemonday.Policy {
	footerPolicyOnce.Do(func() {
		p := bluemonday.NewPolicy()
		p.AllowElements("p", "br", "span", "div")
		p.AllowElements("strong", "b", "em", "i", "u", "s", "small")
		p.AllowElements("h1", "h2", "h3", "h4", "h5", "h6")
		p.AllowElements("ul", "ol", "li")
		p.AllowAttrs("href", "title", "target", "rel").OnElements("a")
		p.RequireNoReferrerOnLinks(true)
		p.AllowAttrs("src", "alt", "title", "width", "height").OnElements("img")
		p.AllowURLSchemes("https", "data")
		p.AllowAttrs("class", "id").Globally()
		footerPolicy = p
	})
	return footerPolicy
}

// SanitizeFooterHTML sanitizes operator-supplied footer HTML per AI.md PART 16.
// The empty string (default branding) and a single space (disable branding)
// are sentinel values that pass through untouched; any other value is run
// through the strict sanitization policy.
func SanitizeFooterHTML(input string) string {
	if input == "" || input == " " {
		return input
	}
	return footerSanitizePolicy().Sanitize(input)
}

// ValidateFooterHTML sanitizes footer HTML and reports whether the input
// consisted entirely of disallowed content per AI.md PART 16. A warning is
// logged when the sanitizer modified real custom HTML (potential attack or
// mistake), so operators notice their configured markup was altered.
func ValidateFooterHTML(input string) (string, error) {
	sanitized := SanitizeFooterHTML(input)

	// Real custom HTML that sanitizes to nothing was entirely disallowed.
	if input != "" && input != " " && strings.TrimSpace(sanitized) == "" {
		return "", errors.New("footer custom_html contained only disallowed elements")
	}

	if input != "" && input != " " && input != sanitized {
		log.Printf("footer custom_html was sanitized: removed potentially dangerous content")
	}

	return sanitized, nil
}

// LogFooterSanitizationPreview logs the raw and sanitized footer HTML at
// startup per AI.md PART 16 "Sanitization Preview (Startup Log)". It is a
// no-op for the default ("") and disable (" ") sentinel values, which carry
// no custom markup to preview.
func LogFooterSanitizationPreview(input string) {
	if input == "" || input == " " {
		return
	}
	sanitized, err := ValidateFooterHTML(input)
	log.Printf("footer custom_html raw input: %s", input)
	if err != nil {
		log.Printf("footer custom_html WARNING: %v — falling back to default branding", err)
		return
	}
	log.Printf("footer custom_html sanitized output: %s", sanitized)
	if input != sanitized {
		log.Printf("footer custom_html WARNING: sanitizer modified the configured content")
	}
}
