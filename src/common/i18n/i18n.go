// Package i18n provides internationalization support for ipgaze.
// All locale JSON files are embedded in the binary at build time.
package i18n

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
)

//go:embed locales/*.json
var localeFS embed.FS

// Direction represents text direction (ltr or rtl).
type Direction string

const (
	DirectionLTR Direction = "ltr"
	DirectionRTL Direction = "rtl"
)

// LocaleSpec is the single source of metadata for every embedded locale.
type LocaleSpec struct {
	Code             string
	Name             string
	NativeName       string
	Direction        Direction
	PluralCategories []string
	PluralRule       string
}

var localeRegistry = []LocaleSpec{
	{Code: "en", Name: "English", NativeName: "English", Direction: DirectionLTR, PluralCategories: []string{"one", "other"}, PluralRule: "one-other"},
	{Code: "es", Name: "Spanish", NativeName: "Español", Direction: DirectionLTR, PluralCategories: []string{"one", "other"}, PluralRule: "one-other"},
	{Code: "fr", Name: "French", NativeName: "Français", Direction: DirectionLTR, PluralCategories: []string{"one", "other"}, PluralRule: "french"},
	{Code: "de", Name: "German", NativeName: "Deutsch", Direction: DirectionLTR, PluralCategories: []string{"one", "other"}, PluralRule: "one-other"},
	{Code: "it", Name: "Italian", NativeName: "Italiano", Direction: DirectionLTR, PluralCategories: []string{"one", "many", "other"}, PluralRule: "italian"},
	{Code: "zh", Name: "Chinese", NativeName: "中文", Direction: DirectionLTR, PluralCategories: []string{"other"}, PluralRule: "other"},
	{Code: "ar", Name: "Arabic", NativeName: "العربية", Direction: DirectionRTL, PluralCategories: []string{"zero", "one", "two", "few", "many", "other"}, PluralRule: "arabic"},
	{Code: "ja", Name: "Japanese", NativeName: "日本語", Direction: DirectionLTR, PluralCategories: []string{"other"}, PluralRule: "other"},
}

var translationPlaceholderPattern = regexp.MustCompile(`\{[a-zA-Z][a-zA-Z0-9_]*\}`)
var forbiddenTranslationFormatPattern = regexp.MustCompile(`%(?:[-+#0 ]*)?[0-9]*(?:\.[0-9]+)?[sd]|\{[0-9]+\}`)

// SupportedLocales lists all locales compiled into the binary, derived from
// the registry so consumers do not maintain an independent language list.
var SupportedLocales = localeCodes()

func localeCodes() []string {
	codes := make([]string, 0, len(localeRegistry))
	for _, locale := range localeRegistry {
		codes = append(codes, locale.Code)
	}
	return codes
}

// LocaleRegistry returns a copy of the embedded locale metadata.
func LocaleRegistry() []LocaleSpec {
	registry := make([]LocaleSpec, len(localeRegistry))
	for i, locale := range localeRegistry {
		registry[i] = locale
		registry[i].PluralCategories = append([]string(nil), locale.PluralCategories...)
	}
	return registry
}

// DefaultLocales returns every locale enabled by default.
func DefaultLocales() []string {
	return localeCodes()
}

// LocaleDirection returns the text direction for the given locale code.
func LocaleDirection(code string) Direction {
	for _, locale := range localeRegistry {
		if locale.Code == code {
			return locale.Direction
		}
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
	if err := ValidateEmbeddedLocales(); err != nil {
		panic("i18n validation failed: " + err.Error())
	}
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
	for _, locale := range localeRegistry {
		if locale.Code == code {
			return true
		}
	}
	return false
}

// LanguageOption describes one selectable locale for the language selector
// rendered in the site header (AI.md PART 30 "Language Selection via Query
// Parameter"). NativeName is the locale's own "meta.native_name" value, so
// each option reads in its own language rather than in the active one.
type LanguageOption struct {
	Code       string
	NativeName string
}

// AvailableLanguages returns every compiled-in locale with its native name,
// in SupportedLocales order, for rendering the language selector.
func AvailableLanguages() []LanguageOption {
	opts := make([]LanguageOption, 0, len(SupportedLocales))
	for _, locale := range localeRegistry {
		opts = append(opts, LanguageOption{Code: locale.Code, NativeName: locale.NativeName})
	}
	return opts
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
	var rule string
	var categories []string
	for _, locale := range localeRegistry {
		if locale.Code == lang {
			rule = locale.PluralRule
			categories = locale.PluralCategories
			break
		}
	}
	form := "other"
	switch rule {
	case "arabic":
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
	case "french":
		// French: 0 and 1 are "one"
		if count == 0 || count == 1 {
			return "one"
		}
		return "other"
	case "italian":
		if count == 1 {
			return "one"
		}
		if count != 0 && count%1_000_000 == 0 {
			return "many"
		}
	case "one-other":
		if count == 1 {
			form = "one"
		}
	}
	for _, category := range categories {
		if category == form {
			return form
		}
	}
	return "other"
}

// ValidateEmbeddedLocales verifies required locales, registry/file parity,
// locale metadata, message keys, plural categories, and placeholders.
func ValidateEmbeddedLocales() error {
	seenCodes := make(map[string]struct{}, len(localeRegistry))
	validCategories := map[string]struct{}{"zero": {}, "one": {}, "two": {}, "few": {}, "many": {}, "other": {}}
	ruleCategories := map[string][]string{
		"arabic":    {"zero", "one", "two", "few", "many", "other"},
		"french":    {"one", "other"},
		"italian":   {"one", "many", "other"},
		"one-other": {"one", "other"},
		"other":     {"other"},
	}
	for _, locale := range localeRegistry {
		if locale.Code == "" || locale.Name == "" || locale.NativeName == "" || locale.Direction != DirectionLTR && locale.Direction != DirectionRTL || len(locale.PluralCategories) == 0 || locale.PluralRule == "" {
			return fmt.Errorf("locale registry entry %q has incomplete metadata", locale.Code)
		}
		if _, duplicate := seenCodes[locale.Code]; duplicate {
			return fmt.Errorf("locale registry contains duplicate code %q", locale.Code)
		}
		seenCodes[locale.Code] = struct{}{}
		expectedCategories, validRule := ruleCategories[locale.PluralRule]
		if !validRule || strings.Join(locale.PluralCategories, ",") != strings.Join(expectedCategories, ",") {
			return fmt.Errorf("locale %q has invalid categories for plural rule %q", locale.Code, locale.PluralRule)
		}
		seenCategories := make(map[string]struct{}, len(locale.PluralCategories))
		for _, category := range locale.PluralCategories {
			if _, valid := validCategories[category]; !valid {
				return fmt.Errorf("locale %q has invalid CLDR plural category %q", locale.Code, category)
			}
			if _, duplicate := seenCategories[category]; duplicate {
				return fmt.Errorf("locale %q repeats CLDR plural category %q", locale.Code, category)
			}
			seenCategories[category] = struct{}{}
		}
	}
	for _, required := range []string{"en", "es", "fr", "ar", "de", "it"} {
		if _, ok := seenCodes[required]; !ok {
			return fmt.Errorf("locale registry is missing required locale %q", required)
		}
	}
	entries, err := localeFS.ReadDir("locales")
	if err != nil {
		return fmt.Errorf("read embedded locales: %w", err)
	}
	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		files = append(files, strings.TrimSuffix(entry.Name(), ".json"))
	}
	sort.Strings(files)
	registered := localeCodes()
	sort.Strings(registered)
	if strings.Join(files, ",") != strings.Join(registered, ",") {
		return fmt.Errorf("locale registry codes %v do not match embedded files %v", registered, files)
	}
	translations := make(map[string]map[string]any, len(registered))
	for _, code := range registered {
		data, err := localeFS.ReadFile("locales/" + code + ".json")
		if err != nil {
			return fmt.Errorf("read locale %q: %w", code, err)
		}
		var nested map[string]any
		if err := json.Unmarshal(data, &nested); err != nil {
			return fmt.Errorf("invalid JSON in locale %q: %w", code, err)
		}
		translations[code] = flattenJSON("", nested)
	}
	english, ok := translations["en"]
	if !ok {
		return fmt.Errorf("locale registry must include en")
	}
	englishPluralMessages := pluralMessages(english, validCategories)
	englishRegularMessages := regularMessages(english, englishPluralMessages)
	for code, locale := range translations {
		if err := validatePluralCategoryKeys(code, locale, validCategories); err != nil {
			return err
		}
		registered := registeredLocale(code)
		for key, expected := range map[string]string{
			"meta.language":    registered.Code,
			"meta.name":        registered.Name,
			"meta.native_name": registered.NativeName,
			"meta.direction":   string(registered.Direction),
		} {
			if actual, ok := locale[key].(string); !ok || actual != expected {
				return fmt.Errorf("locale %q metadata %q does not match the registry", code, key)
			}
		}
		for key, rawValue := range locale {
			value, ok := rawValue.(string)
			if !ok {
				return fmt.Errorf("locale %q translation %q is not a string", code, key)
			}
			if strings.TrimSpace(value) == "" {
				return fmt.Errorf("locale %q translation %q is empty", code, key)
			}
			if forbiddenTranslationFormatPattern.MatchString(value) {
				return fmt.Errorf("locale %q translation %q uses a forbidden positional or printf placeholder", code, key)
			}
		}
		localizedPluralMessages := pluralMessages(locale, validCategories)
		if len(localizedPluralMessages) != len(englishPluralMessages) {
			return fmt.Errorf("locale %q plural message keys do not match English", code)
		}
		for base := range englishPluralMessages {
			localizedCategories, exists := localizedPluralMessages[base]
			if !exists {
				return fmt.Errorf("locale %q is missing plural message %q", code, base)
			}
			requiredCategories := make(map[string]struct{}, len(registeredLocaleCategories(code))+1)
			for _, category := range registeredLocaleCategories(code) {
				requiredCategories[category] = struct{}{}
			}
			if _, optionalZero := localizedCategories["zero"]; optionalZero {
				requiredCategories["zero"] = struct{}{}
			}
			if len(localizedCategories) != len(requiredCategories) {
				return fmt.Errorf("locale %q has unsupported or missing plural categories for %q", code, base)
			}
			for category := range requiredCategories {
				localizedValue, categoryExists := localizedCategories[category]
				if !categoryExists {
					return fmt.Errorf("locale %q is missing plural category %q for %q", code, category, base)
				}
				if !equalPluralPlaceholders(localizedValue, localizedCategories["other"]) {
					return fmt.Errorf("locale %q plural category %q has mismatched placeholders for %q", code, category, base)
				}
			}
			for category, localizedValue := range localizedCategories {
				if !equalPluralPlaceholders(localizedValue, englishPluralMessages[base]["other"]) {
					return fmt.Errorf("locale %q plural category %q has mismatched placeholders for %q", code, category, base)
				}
			}
		}
		localizedRegularMessages := regularMessages(locale, localizedPluralMessages)
		if len(localizedRegularMessages) != len(englishRegularMessages) {
			return fmt.Errorf("locale %q message keys do not match English", code)
		}
		for key, englishValue := range englishRegularMessages {
			localizedValue, exists := localizedRegularMessages[key]
			if !exists {
				return fmt.Errorf("locale %q is missing translation key %q", code, key)
			}
			if !equalPlaceholders(localizedValue, englishValue) {
				return fmt.Errorf("locale %q translation %q has mismatched placeholders", code, key)
			}
		}
	}
	return nil
}

func validatePluralCategoryKeys(code string, translations map[string]any, validCategories map[string]struct{}) error {
	for key := range translations {
		if !strings.HasPrefix(key, "plurals.") {
			continue
		}
		parts := strings.Split(key, ".")
		if len(parts) != 3 || parts[1] == "" {
			return fmt.Errorf("locale %q has malformed plural key %q", code, key)
		}
		category := parts[len(parts)-1]
		if _, ok := validCategories[category]; !ok {
			return fmt.Errorf("locale %q has orphaned plural category %q in %q", code, category, key)
		}
	}
	return nil
}

func equalPlaceholders(left, right string) bool {
	leftMatches := translationPlaceholderPattern.FindAllString(left, -1)
	rightMatches := translationPlaceholderPattern.FindAllString(right, -1)
	sort.Strings(leftMatches)
	sort.Strings(rightMatches)
	return strings.Join(leftMatches, "\x00") == strings.Join(rightMatches, "\x00")
}

func equalPluralPlaceholders(left, right string) bool {
	leftMatches := translationPlaceholderPattern.FindAllString(left, -1)
	rightMatches := translationPlaceholderPattern.FindAllString(right, -1)
	leftMatches = withoutCountPlaceholder(leftMatches)
	rightMatches = withoutCountPlaceholder(rightMatches)
	sort.Strings(leftMatches)
	sort.Strings(rightMatches)
	return strings.Join(leftMatches, "\x00") == strings.Join(rightMatches, "\x00")
}

func withoutCountPlaceholder(placeholders []string) []string {
	filtered := placeholders[:0]
	for _, placeholder := range placeholders {
		if placeholder != "{count}" {
			filtered = append(filtered, placeholder)
		}
	}
	return filtered
}

func pluralMessages(translations map[string]any, validCategories map[string]struct{}) map[string]map[string]string {
	messages := make(map[string]map[string]string)
	for key, rawValue := range translations {
		if !strings.HasPrefix(key, "plurals.") {
			continue
		}
		parts := strings.Split(key, ".")
		if len(parts) < 3 {
			continue
		}
		category := parts[len(parts)-1]
		if _, valid := validCategories[category]; !valid {
			continue
		}
		value, ok := rawValue.(string)
		if !ok {
			continue
		}
		base := strings.Join(parts[:len(parts)-1], ".")
		if messages[base] == nil {
			messages[base] = make(map[string]string)
		}
		messages[base][category] = value
	}
	return messages
}

func registeredLocaleCategories(code string) []string {
	for _, locale := range localeRegistry {
		if locale.Code == code {
			return locale.PluralCategories
		}
	}
	return nil
}

func regularMessages(translations map[string]any, pluralMessages map[string]map[string]string) map[string]string {
	messages := make(map[string]string)
	for key, rawValue := range translations {
		if !strings.HasPrefix(key, "plurals.") {
			if value, ok := rawValue.(string); ok {
				messages[key] = value
			}
			continue
		}
		parts := strings.Split(key, ".")
		if len(parts) < 3 {
			if value, ok := rawValue.(string); ok {
				messages[key] = value
			}
			continue
		}
		base := strings.Join(parts[:len(parts)-1], ".")
		category := parts[len(parts)-1]
		if _, isPluralMessage := pluralMessages[base]; !isPluralMessage {
			if value, ok := rawValue.(string); ok {
				messages[key] = value
			}
			continue
		}
		if _, validCategory := pluralMessages[base][category]; !validCategory {
			if value, ok := rawValue.(string); ok {
				messages[key] = value
			}
		}
	}
	return messages
}

func registeredLocale(code string) LocaleSpec {
	for _, locale := range localeRegistry {
		if locale.Code == code {
			return locale
		}
	}
	return LocaleSpec{}
}
