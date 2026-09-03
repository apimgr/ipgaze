package setup

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestSetupModel_ServerURLNormalisation(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"  ", ""},
		{"example.com", "https://example.com"},
		{"https://example.com/", "https://example.com"},
		{"http://localhost:8080", "http://localhost:8080"},
	}
	for _, tc := range cases {
		m := newSetupModel("en", wizardPalette())
		m.inputs[focusServer].value = tc.in
		if got := m.serverURL(); got != tc.want {
			t.Errorf("serverURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSetupModel_InvalidURLIsRejected(t *testing.T) {
	m := newSetupModel("en", wizardPalette())
	m.inputs[focusServer].value = "not a url"
	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	updated, ok := next.(setupModel)
	if !ok {
		t.Fatalf("Update returned %T, want setupModel", next)
	}
	if cmd != nil {
		t.Error("an invalid URL must not start a connection test")
	}
	if updated.validErr == "" {
		t.Error("an invalid URL must set a validation message")
	}
}

func TestSetupModel_SpaceTogglesSaveCheckbox(t *testing.T) {
	m := newSetupModel("en", wizardPalette())
	m.focus = focusSave
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}})
	updated, ok := next.(setupModel)
	if !ok {
		t.Fatalf("Update returned %T, want setupModel", next)
	}
	if updated.saveToCfg {
		t.Error("space on the save checkbox should toggle it off")
	}
}

func TestSetupModel_EscapeCancels(t *testing.T) {
	m := newSetupModel("en", wizardPalette())
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	updated, ok := next.(setupModel)
	if !ok {
		t.Fatalf("Update returned %T, want setupModel", next)
	}
	if !updated.cancelled {
		t.Error("esc should cancel the wizard")
	}
}

func TestTextField_MaskedViewHidesValue(t *testing.T) {
	f := textField{value: "secret", masked: true}
	if got := f.View(); got == "secret" {
		t.Error("a masked field must not render its value")
	}
	if f.Value() != "secret" {
		t.Errorf("Value() = %q, want the unmasked text", f.Value())
	}
}

func TestTextField_BackspaceIsRuneSafe(t *testing.T) {
	f := textField{value: "héllo"}
	f.handleKey(tea.KeyMsg{Type: tea.KeyBackspace})
	if f.Value() != "héll" {
		t.Errorf("after backspace: %q, want %q", f.Value(), "héll")
	}
}

func TestTextField_CharLimitEnforced(t *testing.T) {
	f := textField{charLimit: 3}
	f.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("abc")})
	f.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("d")})
	if f.Value() != "abc" {
		t.Errorf("charLimit not enforced: %q", f.Value())
	}
}

func TestSetupModel_ViewRendersLabels(t *testing.T) {
	view := newSetupModel("en", wizardPalette()).View()
	for _, want := range []string{"Server URL", "API Token", "Test Connection"} {
		if !strings.Contains(view, want) {
			t.Errorf("wizard view missing %q:\n%s", want, view)
		}
	}
}
