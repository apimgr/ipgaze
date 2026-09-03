package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// resultModel returns a model in the result state with a full row set so
// cursor movement and filtering have something to act on.
func resultModel() Model {
	m := NewModelWithLang("en")
	m.state = stateResult
	m.data = &IPData{
		IP:         "1.2.3.4",
		Hostname:   "host.example.com",
		Country:    "United States",
		CountryISO: "US",
		City:       "San Francisco",
		RegionName: "California",
		RegionCode: "CA",
		PostalCode: "94107",
		Timezone:   "America/Los_Angeles",
		ASN:        "AS15169",
		ASNOrg:     "Google LLC",
		Latitude:   37.7749,
		Longitude:  -122.4194,
	}
	return m
}

func runeKey(r rune) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}}
}

func press(t *testing.T, m Model, keys ...tea.KeyMsg) Model {
	t.Helper()
	var next tea.Model = m
	for _, k := range keys {
		next, _ = next.Update(k)
	}
	updated, ok := next.(Model)
	if !ok {
		t.Fatalf("Update returned %T, want tui.Model", next)
	}
	return updated
}

func TestKeyMap_QuestionMarkTogglesHelp(t *testing.T) {
	m := press(t, resultModel(), runeKey('?'))
	if m.state != stateHelp {
		t.Fatalf("after '?': state = %v, want stateHelp", m.state)
	}
	if !strings.Contains(m.View(), "Keyboard Shortcuts") {
		t.Errorf("help view missing its title: %q", m.View())
	}

	m = press(t, m, runeKey('?'))
	if m.state != stateResult {
		t.Errorf("after second '?': state = %v, want stateResult", m.state)
	}
}

func TestKeyMap_SlashStartsSearchAndFilters(t *testing.T) {
	m := press(t, resultModel(), runeKey('/'))
	if !m.searching {
		t.Fatal("after '/': searching = false, want true")
	}

	m = press(t, m, runeKey('c'), runeKey('i'), runeKey('t'), runeKey('y'))
	if m.searchQuery != "city" {
		t.Fatalf("searchQuery = %q, want %q", m.searchQuery, "city")
	}

	rows := m.visibleRows()
	if len(rows) != 1 || rows[0].Label != "City" {
		t.Fatalf("filtered rows = %+v, want only the City row", rows)
	}

	m = press(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.searching {
		t.Error("enter should commit the search and leave search mode")
	}

	m = press(t, m, tea.KeyMsg{Type: tea.KeyEsc})
	if m.searchQuery != "" {
		t.Errorf("esc should clear the committed query, got %q", m.searchQuery)
	}
}

func TestKeyMap_SearchEscapeClearsQuery(t *testing.T) {
	m := press(t, resultModel(), runeKey('/'), runeKey('a'), tea.KeyMsg{Type: tea.KeyEsc})
	if m.searching {
		t.Error("esc in search mode should leave search mode")
	}
	if m.searchQuery != "" {
		t.Errorf("esc in search mode should clear the query, got %q", m.searchQuery)
	}
}

func TestKeyMap_JKMoveCursor(t *testing.T) {
	m := resultModel()
	m.clampCursor()
	if m.cursor != 0 {
		t.Fatalf("initial cursor = %d, want 0", m.cursor)
	}

	m = press(t, m, runeKey('j'), runeKey('j'))
	if m.cursor != 2 {
		t.Errorf("after 'jj': cursor = %d, want 2", m.cursor)
	}

	m = press(t, m, runeKey('k'))
	if m.cursor != 1 {
		t.Errorf("after 'k': cursor = %d, want 1", m.cursor)
	}

	m = press(t, m, runeKey('k'), runeKey('k'), runeKey('k'))
	if m.cursor != 0 {
		t.Errorf("'k' past the top: cursor = %d, want it clamped to 0", m.cursor)
	}
}

func TestKeyMap_GJumpsToFirstAndLast(t *testing.T) {
	m := resultModel()
	last := len(m.visibleRows()) - 1
	if last < 1 {
		t.Fatalf("test fixture produced %d rows, need at least 2", last+1)
	}

	m = press(t, m, runeKey('G'))
	if m.cursor != last {
		t.Errorf("after 'G': cursor = %d, want %d", m.cursor, last)
	}

	m = press(t, m, runeKey('g'))
	if m.cursor != 0 {
		t.Errorf("after 'g': cursor = %d, want 0", m.cursor)
	}
}

func TestKeyMap_LExpandsAndHCollapses(t *testing.T) {
	m := press(t, resultModel(), runeKey('l'))
	if !m.expanded {
		t.Fatal("after 'l': expanded = false, want true")
	}
	m = press(t, m, runeKey('h'))
	if m.expanded {
		t.Error("after 'h': expanded = true, want false")
	}
}

func TestKeyMap_QQuits(t *testing.T) {
	var next tea.Model = resultModel()
	next, cmd := next.Update(runeKey('q'))
	if cmd == nil {
		t.Fatal("'q' should return a quit command")
	}
	if _, ok := next.(Model); !ok {
		t.Fatalf("Update returned %T, want tui.Model", next)
	}
}

func TestWindowSizeMsg_RecalculatesLayout(t *testing.T) {
	m := resultModel()
	updated, _ := m.Update(tea.WindowSizeMsg{Width: 30, Height: 8})
	got, ok := updated.(Model)
	if !ok {
		t.Fatalf("Update returned %T, want tui.Model", updated)
	}
	if got.width != 30 || got.height != 8 {
		t.Errorf("size = %dx%d, want 30x8", got.width, got.height)
	}
	if !got.layout.UseAbbrev {
		t.Error("a 30x8 terminal should select an abbreviating layout")
	}
}
