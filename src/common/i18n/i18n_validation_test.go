package i18n

import "testing"

func TestValidatePluralCategoryKeys(t *testing.T) {
	validCategories := map[string]struct{}{
		"zero": {}, "one": {}, "two": {}, "few": {}, "many": {}, "other": {},
	}
	tests := []struct {
		name    string
		key     string
		wantErr bool
	}{
		{name: "ordinary message", key: "common.save"},
		{name: "supported plural category", key: "plurals.items.few"},
		{name: "orphaned category", key: "plurals.items.singular", wantErr: true},
		{name: "malformed plural key", key: "plurals.items", wantErr: true},
		{name: "empty plural message", key: "plurals..one", wantErr: true},
		{name: "nested plural message", key: "plurals.items.count.one", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validatePluralCategoryKeys("en", map[string]any{test.key: "value"}, validCategories)
			if (err != nil) != test.wantErr {
				t.Fatalf("validatePluralCategoryKeys(%q) error = %v, wantErr %t", test.key, err, test.wantErr)
			}
		})
	}
}

func TestForbiddenTranslationFormatPattern(t *testing.T) {
	tests := []struct {
		value     string
		forbidden bool
	}{
		{value: "Hello, {name}"},
		{value: "%s", forbidden: true},
		{value: "%02d", forbidden: true},
		{value: "{0}", forbidden: true},
	}
	for _, test := range tests {
		if got := forbiddenTranslationFormatPattern.MatchString(test.value); got != test.forbidden {
			t.Errorf("forbiddenTranslationFormatPattern.MatchString(%q) = %t, want %t", test.value, got, test.forbidden)
		}
	}
}
