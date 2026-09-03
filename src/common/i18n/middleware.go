package i18n

import "net/http"

// LanguageMiddleware detects the request locale using the priority chain
// defined in AI.md PART 30:
//
//  1. ?lang= query parameter (sets a persistent cookie)
//  2. lang cookie (1-year persistence)
//  3. Accept-Language HTTP header (best supported match)
//  4. Default: "en"
//
// The resolved locale is stored in the request context via WithLang so that
// downstream handlers can call LangFromContext or T(ctx, key).
func LanguageMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lang := ""

		// 1. Query parameter (highest priority, also sets cookie)
		if q := r.URL.Query().Get("lang"); q != "" && IsSupported(q) {
			lang = q
			http.SetCookie(w, &http.Cookie{
				Name:  "lang",
				Value: lang,
				Path:  "/",
				// 1 year in seconds
				MaxAge:   365 * 24 * 60 * 60,
				SameSite: http.SameSiteLaxMode,
				Secure:   r.TLS != nil,
				HttpOnly: true,
			})
		}

		// 2. Cookie
		if lang == "" {
			if c, err := r.Cookie("lang"); err == nil && IsSupported(c.Value) {
				lang = c.Value
			}
		}

		// 3. Accept-Language header
		if lang == "" {
			lang = parseAcceptLanguage(r.Header.Get("Accept-Language"))
		}

		// 4. Default
		if lang == "" {
			lang = "en"
		}

		next.ServeHTTP(w, r.WithContext(WithLang(r.Context(), lang)))
	})
}

// parseAcceptLanguage parses the Accept-Language header and returns the best
// supported locale, or "en" if none match.
func parseAcceptLanguage(header string) string {
	if header == "" {
		return "en"
	}
	// Walk comma-separated parts in order (client preference order).
	// Each part has the form "lang-tag;q=weight" or just "lang-tag".
	for _, part := range splitAcceptLanguage(header) {
		tag := part
		if idx := indexByte(tag, ';'); idx >= 0 {
			tag = tag[:idx]
		}
		tag = trimSpace(tag)
		if tag == "" || tag == "*" {
			continue
		}
		if parsed := ParseLocale(tag); IsSupported(parsed) {
			return parsed
		}
	}
	return "en"
}

// splitAcceptLanguage splits a comma-separated Accept-Language header value.
func splitAcceptLanguage(s string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			parts = append(parts, trimSpace(s[start:i]))
			start = i + 1
		}
	}
	parts = append(parts, trimSpace(s[start:]))
	return parts
}

func trimSpace(s string) string {
	start := 0
	for start < len(s) && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	end := len(s)
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
