// Package i18n provides internationalization support for ipgaze.
// All locale JSON files are embedded in the binary at build time.
package i18n

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
)

//go:embed locales/*.json
var localeFS embed.FS

// SupportedLocales lists all locales compiled into the binary.
var SupportedLocales = []string{"en", "es", "fr", "de", "zh", "ar", "ja"}

// Direction represents text direction (ltr or rtl).
type Direction string

const (
	DirectionLTR Direction = "ltr"
	DirectionRTL Direction = "rtl"
)

// LocaleDirection returns the text direction for the given locale code.
func LocaleDirection(code string) Direction {
	if code == "ar" {
		return DirectionRTL
	}
	return DirectionLTR
}

// Manager holds loaded translations for all locales.
type I18NManager struct {
	translations map[string]map[string]any
	fallback     string
	mu           sync.RWMutex
}

// NewTranslationManager creates a Manager and loads all embedded locale files.
// Panics on embed errors (config problem at build time).
func NewTranslationManager() *I18NManager {
	m := &I18NManager{
		translations: make(map[string]map[string]any),
		fallback:     "en",
	}
	for _, lang := range SupportedLocales {
		data, err := localeFS.ReadFile(fmt.Sprintf("locales/%s.json", lang))
		if err != nil {
			panic(fmt.Sprintf("i18n: missing embedded locale %s: %v", lang, err))
		}
		var flat map[string]any
		if err := json.Unmarshal(data, &flat); err != nil {
			panic(fmt.Sprintf("i18n: invalid JSON in locale %s: %v", lang, err))
		}
		m.translations[lang] = flattenJSON("", flat)
	}
	return m
}

// flattenJSON converts a nested JSON map to a flat dot-notation map.
// {"nav":{"home":"Home"}} → {"nav.home":"Home"}
func flattenJSON(prefix string, v map[string]any) map[string]any {
	out := make(map[string]any)
	for k, val := range v {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		switch child := val.(type) {
		case map[string]any:
			for subk, subv := range flattenJSON(key, child) {
				out[subk] = subv
			}
		default:
			out[key] = val
		}
	}
	return out
}

// T returns the translation for key in the given locale, falling back to English.
func (m *I18NManager) T(locale, key string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if t, ok := m.translations[locale]; ok {
		if v, ok := t[key]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
	}
	// Fall back to English
	if t, ok := m.translations[m.fallback]; ok {
		if v, ok := t[key]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
	}
	return key
}

// Tf returns the translation for key with placeholder substitution.
// Placeholders use {name} syntax: Tf("es", "errors.too_short", "min", "8")
// Arguments are key-value pairs: Tf(locale, key, "min", "8", "max", "32")
func (m *I18NManager) Tf(locale, key string, args ...string) string {
	s := m.T(locale, key)
	for i := 0; i+1 < len(args); i += 2 {
		s = strings.ReplaceAll(s, "{"+args[i]+"}", args[i+1])
	}
	return s
}

// IsSupported returns true if the locale is compiled into the binary.
func IsSupported(code string) bool {
	for _, l := range SupportedLocales {
		if l == code {
			return true
		}
	}
	return false
}

// ParseLocale parses an Accept-Language header or language tag and returns
// the best matching supported locale, defaulting to "en".
func ParseLocale(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	// Normalise region subtags: en-US → en, zh-Hant → zh
	if idx := strings.IndexAny(s, "-_"); idx > 0 {
		s = s[:idx]
	}
	if IsSupported(s) {
		return s
	}
	return "en"
}

// DetectLocale resolves the locale from the HTTP request using the
// fallback chain: ?lang= → lang cookie → Accept-Language → "en".
func DetectLocale(r *http.Request) string {
	// 1. Query parameter
	if q := r.URL.Query().Get("lang"); q != "" && IsSupported(q) {
		return q
	}
	// 2. Cookie
	if c, err := r.Cookie("lang"); err == nil && IsSupported(c.Value) {
		return c.Value
	}
	// 3. Accept-Language header
	if al := r.Header.Get("Accept-Language"); al != "" {
		for _, part := range strings.Split(al, ",") {
			lang := strings.TrimSpace(strings.SplitN(part, ";", 2)[0])
			if parsed := ParseLocale(lang); parsed != "en" || strings.HasPrefix(lang, "en") {
				return parsed
			}
		}
	}
	return "en"
}

// SetLangCookie writes the lang cookie to the response.
func SetLangCookie(w http.ResponseWriter, r *http.Request, lang string) {
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

// LocaleJSON returns the raw JSON bytes for the given locale, for serving at /locales/{lang}.json.
func LocaleJSON(lang string) ([]byte, error) {
	if !IsSupported(lang) {
		lang = "en"
	}
	return localeFS.ReadFile(fmt.Sprintf("locales/%s.json", lang))
}

// contextKey is the unexported type for context values in this package.
type contextKey struct{}

// WithLang returns a new context with the given language code stored.
// The language is validated; unsupported codes are silently replaced with "en".
func WithLang(ctx context.Context, lang string) context.Context {
	if !IsSupported(lang) {
		lang = "en"
	}
	return context.WithValue(ctx, contextKey{}, lang)
}

// LangFromContext returns the language code stored by WithLang.
// Returns "en" if no language is set or if the stored value is invalid.
func LangFromContext(ctx context.Context) string {
	if lang, ok := ctx.Value(contextKey{}).(string); ok && lang != "" {
		return lang
	}
	return "en"
}

// defaultManager is the package-level Manager used by T and TN.
// It is initialised once on first use.
var (
	defaultManager     *I18NManager
	defaultManagerOnce sync.Once
)

func getDefaultManager() *I18NManager {
	defaultManagerOnce.Do(func() {
		defaultManager = NewTranslationManager()
	})
	return defaultManager
}

// T translates key using the language stored in ctx.
// Falls back to English if the language is unsupported or the key is missing.
func T(ctx context.Context, key string) string {
	lang := LangFromContext(ctx)
	return getDefaultManager().T(lang, key)
}

// TN returns a pluralised translation for the given count using the language in ctx.
// The plural form is selected from the nested key (e.g. "plurals.items") using
// CLDR categories. Falls back to English when the key or form is missing.
func TN(ctx context.Context, key string, count int) string {
	lang := LangFromContext(ctx)
	m := getDefaultManager()

	// Determine the CLDR plural form for this language and count.
	form := pluralForm(lang, count)

	// Try lang + form first, then English + form, then lang "other", then key itself.
	for _, try := range []struct{ l, f string }{
		{lang, form},
		{"en", form},
		{lang, "other"},
		{"en", "other"},
	} {
		if val := m.T(try.l, key+"."+try.f); val != key+"."+try.f {
			return strings.ReplaceAll(val, "{count}", fmt.Sprintf("%d", count))
		}
	}
	return key
}

// Translate returns the translation for key in the given locale.
// Falls back to English then to the raw key. Intended for use as the "t"
// template FuncMap entry, where templates pass a locale string (e.g. .Lang)
// rather than a context.Context.
func Translate(locale, key string) string {
	return getDefaultManager().T(locale, key)
}

// TranslateFormat returns the translation for key in the given locale with
// "{name}" placeholders substituted from args, which must be passed as
// alternating name/value pairs (e.g. "days", "7"). Intended for use as the
// "tf" template FuncMap entry.
func TranslateFormat(locale, key string, args ...string) string {
	return getDefaultManager().Tf(locale, key, args...)
}

// TranslatePlural returns a pluralised translation for count in the given
// locale, selecting the CLDR plural category from the nested key
// (e.g. "plurals.items"). Falls back to English when the key or form is
// missing. Intended for use as the "tp" template FuncMap entry.
func TranslatePlural(locale, key string, count int) string {
	m := getDefaultManager()
	form := pluralForm(locale, count)

	for _, try := range []struct{ l, f string }{
		{locale, form},
		{"en", form},
		{locale, "other"},
		{"en", "other"},
	} {
		if val := m.T(try.l, key+"."+try.f); val != key+"."+try.f {
			return strings.ReplaceAll(val, "{count}", fmt.Sprintf("%d", count))
		}
	}
	return key
}

// pluralForm returns the CLDR plural category name for the given count in the
// given language.  Only categories needed for the supported languages are handled.
func pluralForm(lang string, count int) string {
	switch lang {
	case "ar":
		switch {
		case count == 0:
			return "zero"
		case count == 1:
			return "one"
		case count == 2:
			return "two"
		case count%100 >= 3 && count%100 <= 10:
			return "few"
		case count%100 >= 11 && count%100 <= 99:
			return "many"
		default:
			return "other"
		}
	case "fr":
		// French: 0 and 1 are "one"
		if count == 0 || count == 1 {
			return "one"
		}
		return "other"
	case "zh", "ja":
		// No plural distinction
		return "other"
	default:
		// en, es, de: 1 is "one", everything else is "other"
		if count == 1 {
			return "one"
		}
		return "other"
	}
}

// validateKeys checks that every key present in the English locale also exists
// in every other supported locale.  It returns a map from locale code to a
// slice of missing key paths.
func validateKeys(m *I18NManager) map[string][]string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	en := m.translations["en"]
	result := make(map[string][]string)
	for _, lang := range SupportedLocales {
		if lang == "en" {
			continue
		}
		other := m.translations[lang]
		for key := range en {
			if _, ok := other[key]; !ok {
				result[lang] = append(result[lang], key)
			}
		}
	}
	return result
}

// init performs build-time key validation at startup.
// If MODE=production is set, missing keys emit a warning to stdout.
// In any other mode (development, testing, unset) the process panics so
// translation gaps are caught before deployment.
func init() {
	m := getDefaultManager()
	missing := validateKeys(m)
	if len(missing) == 0 {
		return
	}
	var sb strings.Builder
	for lang, keys := range missing {
		fmt.Fprintf(&sb, "i18n: locale %q is missing %d key(s): %v\n", lang, len(keys), keys)
	}
	msg := strings.TrimSpace(sb.String())
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("MODE")))
	if mode == "production" {
		fmt.Printf("WARNING: %s\n", msg)
		return
	}
	panic("i18n validation failed:\n" + msg)
}
