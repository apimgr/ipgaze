package i18n_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/apimgr/ipgaze/src/common/i18n"
)

func TestNew(t *testing.T) {
	m := i18n.NewTranslationManager()
	if m == nil {
		t.Fatal("New() returned nil")
	}
}

func TestT_English(t *testing.T) {
	m := i18n.NewTranslationManager()
	got := m.T("en", "app.name")
	if got != "IPGaze" {
		t.Errorf("T(en, app.name) = %q, want %q", got, "IPGaze")
	}
}

func TestT_FallbackToEnglish(t *testing.T) {
	m := i18n.NewTranslationManager()
	// "es" may not have every key; all should fall back to "en" not return key
	got := m.T("es", "app.name")
	if got == "" {
		t.Error("T(es, app.name) returned empty string")
	}
}

func TestT_MissingKeyReturnsKey(t *testing.T) {
	m := i18n.NewTranslationManager()
	got := m.T("en", "nonexistent.key")
	if got != "nonexistent.key" {
		t.Errorf("T(en, nonexistent.key) = %q, want key itself", got)
	}
}

func TestT_UnsupportedLocale(t *testing.T) {
	m := i18n.NewTranslationManager()
	// Unsupported locale should fall back to English without panic
	got := m.T("xx", "app.name")
	if got != "IPGaze" {
		t.Errorf("T(xx, app.name) = %q, want %q (English fallback)", got, "IPGaze")
	}
}

func TestTf_Substitution(t *testing.T) {
	m := i18n.NewTranslationManager()
	got := m.Tf("en", "common.page_x_of_y", "current", "2", "total", "5")
	want := "Page 2 of 5"
	if got != want {
		t.Errorf("Tf substitution = %q, want %q", got, want)
	}
}

func TestIsSupported(t *testing.T) {
	supported := []string{"en", "es", "fr", "de", "zh", "ar", "ja"}
	for _, lang := range supported {
		if !i18n.IsSupported(lang) {
			t.Errorf("IsSupported(%q) = false, want true", lang)
		}
	}
	if i18n.IsSupported("xx") {
		t.Error("IsSupported(xx) = true, want false")
	}
}

func TestParseLocale(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"en", "en"},
		{"es", "es"},
		{"en-US", "en"},
		{"zh-CN", "zh"},
		{"fr-FR", "fr"},
		{"XX", "en"}, // unsupported → fallback
		{"", "en"},
	}
	for _, tt := range tests {
		got := i18n.ParseLocale(tt.input)
		if got != tt.want {
			t.Errorf("ParseLocale(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestAllLocalesHaveAppName(t *testing.T) {
	m := i18n.NewTranslationManager()
	for _, lang := range i18n.SupportedLocales {
		got := m.T(lang, "app.name")
		if got != "IPGaze" {
			t.Errorf("T(%s, app.name) = %q, want %q", lang, got, "IPGaze")
		}
	}
}

func TestLocaleDirection(t *testing.T) {
	if i18n.LocaleDirection("ar") != i18n.DirectionRTL {
		t.Error("Arabic should be RTL")
	}
	for _, lang := range []string{"en", "es", "fr", "de", "zh", "ja"} {
		if i18n.LocaleDirection(lang) != i18n.DirectionLTR {
			t.Errorf("%s should be LTR", lang)
		}
	}
}

func TestLocaleJSON(t *testing.T) {
	data, err := i18n.LocaleJSON("en")
	if err != nil {
		t.Fatalf("LocaleJSON(en): %v", err)
	}
	if len(data) == 0 {
		t.Error("LocaleJSON(en) returned empty data")
	}
}

func TestLocaleJSON_Unsupported(t *testing.T) {
	// Unsupported lang falls back to "en"
	data, err := i18n.LocaleJSON("xx")
	if err != nil {
		t.Fatalf("LocaleJSON(xx) error = %v", err)
	}
	if len(data) == 0 {
		t.Error("LocaleJSON(xx) returned empty data")
	}
}

func TestLocaleJSON_AllSupported(t *testing.T) {
	for _, lang := range i18n.SupportedLocales {
		data, err := i18n.LocaleJSON(lang)
		if err != nil {
			t.Errorf("LocaleJSON(%s) error = %v", lang, err)
		}
		if len(data) == 0 {
			t.Errorf("LocaleJSON(%s) returned empty data", lang)
		}
	}
}

func TestWithLang_AndLangFromContext(t *testing.T) {
	ctx := context.Background()
	ctx = i18n.WithLang(ctx, "es")
	got := i18n.LangFromContext(ctx)
	if got != "es" {
		t.Errorf("LangFromContext = %q, want %q", got, "es")
	}
}

func TestWithLang_UnsupportedFallsToEn(t *testing.T) {
	ctx := i18n.WithLang(context.Background(), "xx")
	got := i18n.LangFromContext(ctx)
	if got != "en" {
		t.Errorf("LangFromContext(unsupported) = %q, want %q", got, "en")
	}
}

func TestLangFromContext_Empty(t *testing.T) {
	got := i18n.LangFromContext(context.Background())
	if got != "en" {
		t.Errorf("LangFromContext(empty ctx) = %q, want %q", got, "en")
	}
}

func TestT_PackageLevel(t *testing.T) {
	ctx := i18n.WithLang(context.Background(), "en")
	got := i18n.T(ctx, "app.name")
	if got != "IPGaze" {
		t.Errorf("T(ctx, app.name) = %q, want %q", got, "IPGaze")
	}
}

func TestT_PackageLevel_MissingKey(t *testing.T) {
	ctx := i18n.WithLang(context.Background(), "en")
	got := i18n.T(ctx, "totally.missing.key")
	if got != "totally.missing.key" {
		t.Errorf("T(ctx, missing) = %q, want key itself", got)
	}
}

func TestTN_English(t *testing.T) {
	ctx := i18n.WithLang(context.Background(), "en")
	// plurals.items.one and plurals.items.other must exist in en.json
	one := i18n.TN(ctx, "plurals.items", 1)
	many := i18n.TN(ctx, "plurals.items", 5)
	if one == "" {
		t.Error("TN(en, plurals.items, 1) returned empty")
	}
	if many == "" {
		t.Error("TN(en, plurals.items, 5) returned empty")
	}
	// one != many unless they have the same string
	_ = one
	_ = many
}

func TestTN_Arabic(t *testing.T) {
	ctx := i18n.WithLang(context.Background(), "ar")
	// Must not panic; CLDR forms: zero, one, two, few, many, other
	for _, n := range []int{0, 1, 2, 3, 11, 100} {
		got := i18n.TN(ctx, "plurals.items", n)
		_ = got
	}
}

func TestTN_French(t *testing.T) {
	ctx := i18n.WithLang(context.Background(), "fr")
	for _, n := range []int{0, 1, 2} {
		got := i18n.TN(ctx, "plurals.items", n)
		_ = got
	}
}

func TestTN_ChineseJapanese(t *testing.T) {
	for _, lang := range []string{"zh", "ja"} {
		ctx := i18n.WithLang(context.Background(), lang)
		got := i18n.TN(ctx, "plurals.items", 42)
		_ = got
	}
}

func TestTN_MissingKey(t *testing.T) {
	ctx := i18n.WithLang(context.Background(), "en")
	got := i18n.TN(ctx, "no.such.key", 1)
	if got != "no.such.key" {
		t.Errorf("TN(missing) = %q, want key itself", got)
	}
}

func TestDetectLocale_QueryParam(t *testing.T) {
	r := httptest.NewRequest("GET", "/?lang=es", nil)
	got := i18n.DetectLocale(r)
	if got != "es" {
		t.Errorf("DetectLocale(?lang=es) = %q, want %q", got, "es")
	}
}

func TestDetectLocale_QueryParamUnsupported(t *testing.T) {
	r := httptest.NewRequest("GET", "/?lang=xx", nil)
	got := i18n.DetectLocale(r)
	if got != "en" {
		t.Errorf("DetectLocale(?lang=xx) = %q, want %q", got, "en")
	}
}

func TestDetectLocale_Cookie(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: "lang", Value: "fr"})
	got := i18n.DetectLocale(r)
	if got != "fr" {
		t.Errorf("DetectLocale(cookie=fr) = %q, want %q", got, "fr")
	}
}

func TestDetectLocale_AcceptLanguage(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Accept-Language", "de-DE,de;q=0.9,en;q=0.8")
	got := i18n.DetectLocale(r)
	if got != "de" {
		t.Errorf("DetectLocale(Accept-Language=de) = %q, want %q", got, "de")
	}
}

func TestDetectLocale_Default(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	got := i18n.DetectLocale(r)
	if got != "en" {
		t.Errorf("DetectLocale(nothing) = %q, want %q", got, "en")
	}
}

func TestDetectLocale_AcceptLanguageEnglish(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Accept-Language", "en-US,en;q=0.9")
	got := i18n.DetectLocale(r)
	if got != "en" {
		t.Errorf("DetectLocale(Accept-Language=en) = %q, want %q", got, "en")
	}
}

func TestSetLangCookie_WritesHeader(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	i18n.SetLangCookie(w, r, "ja")
	resp := w.Result()
	cookies := resp.Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "lang" && c.Value == "ja" {
			found = true
		}
	}
	if !found {
		t.Error("SetLangCookie did not set lang=ja cookie")
	}
}

func TestSetLangCookie_MaxAge(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	i18n.SetLangCookie(w, r, "zh")
	resp := w.Result()
	for _, c := range resp.Cookies() {
		if c.Name == "lang" {
			if c.MaxAge != 365*24*60*60 {
				t.Errorf("SetLangCookie MaxAge = %d, want %d", c.MaxAge, 365*24*60*60)
			}
		}
	}
}

func TestLanguageMiddleware_QueryParam(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lang := i18n.LangFromContext(r.Context())
		w.Header().Set("X-Lang", lang)
	})
	handler := i18n.LanguageMiddleware(next)

	r := httptest.NewRequest("GET", "/?lang=de", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if got := w.Header().Get("X-Lang"); got != "de" {
		t.Errorf("middleware lang = %q, want %q", got, "de")
	}
	// Must also set a cookie
	resp := w.Result()
	found := false
	for _, c := range resp.Cookies() {
		if c.Name == "lang" && c.Value == "de" {
			found = true
		}
	}
	if !found {
		t.Error("middleware should set lang cookie when ?lang= is provided")
	}
}

func TestLanguageMiddleware_Cookie(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lang := i18n.LangFromContext(r.Context())
		w.Header().Set("X-Lang", lang)
	})
	handler := i18n.LanguageMiddleware(next)

	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: "lang", Value: "ar"})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if got := w.Header().Get("X-Lang"); got != "ar" {
		t.Errorf("middleware lang = %q, want %q", got, "ar")
	}
}

func TestLanguageMiddleware_AcceptLanguage(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lang := i18n.LangFromContext(r.Context())
		w.Header().Set("X-Lang", lang)
	})
	handler := i18n.LanguageMiddleware(next)

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Accept-Language", "ja")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if got := w.Header().Get("X-Lang"); got != "ja" {
		t.Errorf("middleware lang = %q, want %q", got, "ja")
	}
}

func TestLanguageMiddleware_Default(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lang := i18n.LangFromContext(r.Context())
		w.Header().Set("X-Lang", lang)
	})
	handler := i18n.LanguageMiddleware(next)

	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if got := w.Header().Get("X-Lang"); got != "en" {
		t.Errorf("middleware default lang = %q, want %q", got, "en")
	}
}

func TestLanguageMiddleware_UnsupportedQueryParam(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lang := i18n.LangFromContext(r.Context())
		w.Header().Set("X-Lang", lang)
	})
	handler := i18n.LanguageMiddleware(next)

	r := httptest.NewRequest("GET", "/?lang=xx", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	// Unsupported lang param is ignored; falls through to default "en"
	if got := w.Header().Get("X-Lang"); got != "en" {
		t.Errorf("middleware unsupported lang = %q, want %q", got, "en")
	}
}

func TestParseLocale_Underscore(t *testing.T) {
	got := i18n.ParseLocale("zh_TW")
	if got != "zh" {
		t.Errorf("ParseLocale(zh_TW) = %q, want %q", got, "zh")
	}
}

func TestParseLocale_Arabic(t *testing.T) {
	got := i18n.ParseLocale("ar")
	if got != "ar" {
		t.Errorf("ParseLocale(ar) = %q, want %q", got, "ar")
	}
}

func TestTf_NoSubstitution(t *testing.T) {
	m := i18n.NewTranslationManager()
	key := "app.name"
	got := m.Tf("en", key)
	want := m.T("en", key)
	if got != want {
		t.Errorf("Tf(no args) = %q, want %q", got, want)
	}
}

func TestTf_OddArgCount(t *testing.T) {
	m := i18n.NewTranslationManager()
	// Odd number of args — last arg is ignored
	got := m.Tf("en", "app.name", "orphan")
	want := m.T("en", "app.name")
	if got != want {
		t.Errorf("Tf(odd args) = %q, want %q", got, want)
	}
}

func TestTranslate(t *testing.T) {
	got := i18n.Translate("en", "app.name")
	want := "IPGaze"
	if got != want {
		t.Errorf("Translate(en, app.name) = %q, want %q", got, want)
	}
}

func TestTranslate_FallbackToEnglish(t *testing.T) {
	// Unsupported locale falls back to English.
	got := i18n.Translate("xx", "app.name")
	want := "IPGaze"
	if got != want {
		t.Errorf("Translate(xx, app.name) = %q, want %q", got, want)
	}
}

func TestTranslate_MissingKey(t *testing.T) {
	got := i18n.Translate("en", "totally.missing.key")
	want := "totally.missing.key"
	if got != want {
		t.Errorf("Translate(en, missing) = %q, want key itself", got)
	}
}

func TestTranslateFormat(t *testing.T) {
	got := i18n.TranslateFormat("en", "common.page_x_of_y", "current", "2", "total", "5")
	want := "Page 2 of 5"
	if got != want {
		t.Errorf("TranslateFormat substitution = %q, want %q", got, want)
	}
}

func TestTranslateFormat_NoArgs(t *testing.T) {
	got := i18n.TranslateFormat("en", "app.name")
	want := i18n.Translate("en", "app.name")
	if got != want {
		t.Errorf("TranslateFormat(no args) = %q, want %q", got, want)
	}
}

func TestTranslatePlural(t *testing.T) {
	one := i18n.TranslatePlural("en", "plurals.items", 1)
	many := i18n.TranslatePlural("en", "plurals.items", 5)
	if one == "" {
		t.Error("TranslatePlural(en, plurals.items, 1) returned empty")
	}
	if many == "" {
		t.Error("TranslatePlural(en, plurals.items, 5) returned empty")
	}
}

func TestTranslatePlural_Arabic(t *testing.T) {
	// Arabic has zero/one/two/few/many/other categories per PART 30.
	zero := i18n.TranslatePlural("ar", "plurals.items", 0)
	two := i18n.TranslatePlural("ar", "plurals.items", 2)
	if zero == "" {
		t.Error("TranslatePlural(ar, plurals.items, 0) returned empty")
	}
	if two == "" {
		t.Error("TranslatePlural(ar, plurals.items, 2) returned empty")
	}
}

func TestTranslatePlural_MissingKey(t *testing.T) {
	got := i18n.TranslatePlural("en", "totally.missing.plural", 1)
	want := "totally.missing.plural"
	if got != want {
		t.Errorf("TranslatePlural(en, missing) = %q, want key itself", got)
	}
}
