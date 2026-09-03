package server

import "net/http"

// ThemeCookieName is the first-party cookie that persists the visitor's
// theme choice (AI.md PART 16 "Themes": light/dark/auto, 1-year expiry).
const ThemeCookieName = "theme"

// DefaultTheme is used whenever no theme cookie is present or its value is
// not one of the recognized themes.
const DefaultTheme = "dark"

// DetectTheme reads the theme cookie from r and returns the active theme
// ("light", "dark", or "auto"), falling back to DefaultTheme.
//
// This is the "Theme core logic" described by AI.md PART 16's "Theme
// Implementation Location" table (src/server/theme.go: "Theme detection,
// switching, persistence"). DefaultHandler in src/server/http.go calls this
// directly (same package). handler.PagesHandler.NewPageData
// (src/server/handler/pages.go) cannot import this package directly —
// src/server (package server) already imports src/server/handler (package
// handler) one-directionally to build PagesHandler, so the reverse import
// would be a Go import cycle. Instead this function is injected into
// PagesHandler.DetectTheme at construction time (see http.go, where
// s.PagesHandler is built), so both call sites resolve theme from this one
// implementation without ever duplicating the cookie-read logic.
func DetectTheme(r *http.Request) string {
	c, err := r.Cookie(ThemeCookieName)
	if err != nil {
		return DefaultTheme
	}
	return ValidateTheme(c.Value)
}

// ValidateTheme normalizes a theme value, returning it unchanged if it is
// one of the recognized themes ("light", "dark", "auto") or DefaultTheme
// otherwise. Used both for detection (cookie read) and switching
// (the theme toggle's form submission) so both paths agree on what counts as a
// valid theme.
func ValidateTheme(theme string) string {
	switch theme {
	case "light", "dark", "auto":
		return theme
	default:
		return DefaultTheme
	}
}

// ThemeCookie builds the first-party persistence cookie for a validated
// theme choice (AI.md PART 16 "Themes": 1-year expiry, SameSite=Lax,
// readable by client-side JS so it is not HttpOnly).
func ThemeCookie(theme string, secure bool) *http.Cookie {
	return &http.Cookie{
		Name:     ThemeCookieName,
		Value:    ValidateTheme(theme),
		Path:     "/",
		MaxAge:   365 * 24 * 60 * 60,
		HttpOnly: false,
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
	}
}
