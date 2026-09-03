// Package tui provides the bubbletea-based terminal UI for the ipgaze CLI.
// The Model is the main interactive component; it displays IP lookup results
// and allows the user to navigate, search, and read per-field detail.
package tui

import (
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/apimgr/ipgaze/src/common/i18n"
	"github.com/apimgr/ipgaze/src/common/terminal"
)

// IPData holds the resolved IP lookup fields shown in the TUI view.
type IPData struct {
	IP         string
	Hostname   string
	Country    string
	CountryISO string
	City       string
	RegionName string
	RegionCode string
	ASN        string
	ASNOrg     string
	Latitude   float64
	Longitude  float64
	Timezone   string
	PostalCode string
}

// state tracks what the TUI is currently showing.
type state int

const (
	stateLoading state = iota
	stateResult
	stateError
	stateHelp
)

// Model is the bubbletea model for the ipgaze TUI.
type Model struct {
	spinner spinner.Model
	state   state
	data    *IPData
	errMsg  string
	// lang is the resolved locale used for every user-facing string.
	lang string
	// width and height are the current terminal dimensions.
	width  int
	height int
	// sizeMode classifies the terminal into a responsive tier.
	sizeMode terminal.SizeMode
	// layout holds the settings derived from sizeMode.
	layout LayoutConfig
	// viewportWidth and viewportHeight are the usable content dimensions
	// after reserving space for header, footer, and borders.
	viewportWidth  int
	viewportHeight int
	// cursor is the index of the selected row within the visible rows.
	cursor int
	// scrollOffset is the index of the first visible row.
	scrollOffset int
	// expanded shows the selected row's untruncated value when true.
	expanded bool
	// searching is true while the search input is accepting keystrokes.
	searching bool
	// searchQuery filters rows by label or value substring.
	searchQuery string
	// previousState is restored when the help screen is closed.
	previousState state
}

// IPResultMsg carries a resolved IPData from the API fetch command.
type IPResultMsg struct {
	Data *IPData
}

// IPErrorMsg carries an error from the API fetch command.
type IPErrorMsg struct {
	Err error
}

// NewModel creates a new TUI Model in the loading state, using the detected
// terminal size for its initial responsive layout.
func NewModel() Model {
	return NewModelWithLang("en")
}

// NewModelWithLang creates a Model that renders all text in the given locale.
func NewModelWithLang(lang string) Model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color(ActivePalette.Primary))

	size := terminal.GetTerminalSize()
	m := Model{
		spinner:  s,
		state:    stateLoading,
		lang:     lang,
		width:    size.Cols,
		height:   size.Rows,
		sizeMode: size.Mode,
		layout:   GetLayoutConfig(size.Mode),
	}
	m.calculateLayout()
	return m
}

// Init starts the spinner tick and any initial fetch commands.
func (m Model) Init() tea.Cmd {
	return m.spinner.Tick
}

// resize recomputes the size mode, layout, and viewport for new dimensions.
func (m *Model) resize(width, height int) {
	if width > 0 {
		m.width = width
	}
	if height > 0 {
		m.height = height
	}
	m.sizeMode = SizeModeFor(m.width, m.height)
	m.layout = GetLayoutConfig(m.sizeMode)
	m.calculateLayout()
	m.ensureVisible(m.cursor)
}

// calculateLayout reserves space for chrome and clamps the viewport to a
// minimum usable size, per AI.md PART 32 "Viewport Management".
func (m *Model) calculateLayout() {
	headerHeight := 0
	if m.layout.ShowHeader {
		headerHeight = 1
	}
	footerHeight := 0
	if m.layout.ShowFooter {
		footerHeight = 1
	}
	borderHeight := 0
	if m.layout.ShowBorders {
		borderHeight = 2
	}

	m.viewportHeight = m.height - headerHeight - footerHeight - borderHeight
	m.viewportWidth = m.width

	if m.layout.ShowSidebar {
		m.viewportWidth = m.width - m.layout.SidebarWidth
	}

	if m.viewportHeight < 3 {
		m.viewportHeight = 3
	}
	if m.viewportWidth < 20 {
		m.viewportWidth = 20
	}
}

// ensureVisible scrolls so that index is inside the viewport.
func (m *Model) ensureVisible(index int) {
	if index < m.scrollOffset {
		m.scrollOffset = index
	}
	if index >= m.scrollOffset+m.viewportHeight {
		m.scrollOffset = index - m.viewportHeight + 1
	}
	if m.scrollOffset < 0 {
		m.scrollOffset = 0
	}
}

// visibleRows returns the rows matching the current search query.
func (m Model) visibleRows() []InfoRow {
	if m.data == nil {
		return nil
	}
	rows := BuildInfoRows(m.lang, m.layout, *m.data)
	if m.searchQuery == "" {
		return rows
	}
	q := strings.ToLower(m.searchQuery)
	filtered := make([]InfoRow, 0, len(rows))
	for _, row := range rows {
		if strings.Contains(strings.ToLower(row.Label), q) ||
			strings.Contains(strings.ToLower(row.Value), q) {
			filtered = append(filtered, row)
		}
	}
	return filtered
}

// clampCursor keeps the cursor inside the current row set.
func (m *Model) clampCursor() {
	n := len(m.visibleRows())
	if m.cursor >= n {
		m.cursor = n - 1
	}
	if m.cursor < 0 {
		m.cursor = 0
	}
	m.ensureVisible(m.cursor)
}

// Update processes incoming messages and updates the model.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		return m.handleKey(msg)

	case tea.WindowSizeMsg:
		m.resize(msg.Width, msg.Height)

	case spinner.TickMsg:
		if m.state == stateLoading {
			var cmd tea.Cmd
			m.spinner, cmd = m.spinner.Update(msg)
			return m, cmd
		}

	case IPResultMsg:
		m.state = stateResult
		m.data = msg.Data
		m.clampCursor()

	case IPErrorMsg:
		m.state = stateError
		m.errMsg = msg.Err.Error()
	}

	return m, nil
}

// handleKey implements the phone-friendly vim-style key map from
// AI.md PART 32 "Phone-Friendly Key Bindings".
func (m Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	if m.searching {
		switch key {
		case "enter":
			m.searching = false
			m.clampCursor()
		case "esc":
			m.searching = false
			m.searchQuery = ""
			m.clampCursor()
		case "ctrl+c":
			return m, tea.Quit
		case "backspace":
			if r := []rune(m.searchQuery); len(r) > 0 {
				m.searchQuery = string(r[:len(r)-1])
			}
			m.clampCursor()
		default:
			if len(msg.Runes) > 0 {
				m.searchQuery += string(msg.Runes)
				m.clampCursor()
			}
		}
		return m, nil
	}

	switch key {
	case "q", "Q", "ctrl+c":
		return m, tea.Quit

	case "esc", "h":
		switch {
		case m.state == stateHelp:
			m.state = m.previousState
		case m.expanded:
			m.expanded = false
		case m.searchQuery != "":
			m.searchQuery = ""
			m.clampCursor()
		case key == "esc":
			return m, tea.Quit
		}

	case "?":
		if m.state == stateHelp {
			m.state = m.previousState
		} else {
			m.previousState = m.state
			m.state = stateHelp
		}

	case "/":
		if m.state == stateResult {
			m.searching = true
			m.searchQuery = ""
		}

	case "j", "down":
		if m.state == stateResult {
			m.cursor++
			m.clampCursor()
		}

	case "k", "up":
		if m.state == stateResult {
			m.cursor--
			m.clampCursor()
		}

	case "g", "home":
		m.cursor = 0
		m.ensureVisible(m.cursor)

	case "G", "end":
		m.cursor = len(m.visibleRows()) - 1
		m.clampCursor()

	case "l", "right", "enter":
		if m.state == stateResult {
			m.expanded = true
		}
	}

	return m, nil
}

// renderHelpHint returns the size-aware footer hint from AI.md PART 32.
func (m Model) renderHelpHint() string {
	switch m.sizeMode {
	case terminal.SizeModeMicro, terminal.SizeModeMinimal:
		return i18n.Translate(m.lang, "tui.hint_minimal")
	case terminal.SizeModeCompact:
		return i18n.Translate(m.lang, "tui.hint_compact")
	default:
		return i18n.Translate(m.lang, "tui.hint_full")
	}
}

// renderFooter renders the search prompt while searching, otherwise the hint.
func (m Model) renderFooter() string {
	if m.searching {
		return RenderMuted(i18n.TranslateFormat(m.lang, "tui.search_prompt", "query", m.searchQuery))
	}
	if m.searchQuery != "" {
		return RenderMuted(i18n.TranslateFormat(m.lang, "tui.search_active", "query", m.searchQuery) +
			"  " + m.renderHelpHint())
	}
	return RenderMuted(m.renderHelpHint())
}

// renderHelpScreen lists every key binding, translated.
func (m Model) renderHelpScreen() string {
	bindings := []struct {
		keys string
		key  string
	}{
		{"j / k / ↓ / ↑", "tui.help_navigate"},
		{"g / G", "tui.help_jump"},
		{"l / enter", "tui.help_expand"},
		{"h / esc", "tui.help_back"},
		{"/", "tui.help_search"},
		{"?", "tui.help_help"},
		{"q / ctrl+c", "tui.help_quit"},
	}

	var sb strings.Builder
	if m.layout.ShowHeader {
		sb.WriteString(TitleStyle.Render(i18n.Translate(m.lang, "tui.help_title")) + "\n\n")
	}
	for _, b := range bindings {
		label := LabelStyle.Render(b.keys)
		sb.WriteString("  " + label + " " +
			ValueStyle.Render(Truncate(i18n.Translate(m.lang, b.key), m.layout.TruncateAt)) + "\n")
	}
	return sb.String()
}

// renderRows renders the scrolled, filtered row list with the cursor.
func (m Model) renderRows() string {
	rows := m.visibleRows()
	if len(rows) == 0 {
		return RenderMuted(i18n.TranslateFormat(m.lang, "tui.search_no_match", "query", m.searchQuery)) + "\n"
	}

	end := m.scrollOffset + m.viewportHeight
	if !m.layout.VerticalScroll || end > len(rows) {
		end = len(rows)
	}
	start := m.scrollOffset
	if start > end {
		start = end
	}

	var sb strings.Builder
	for i := start; i < end; i++ {
		selected := i == m.cursor
		sb.WriteString(RenderInfoRow(rows[i], m.layout, selected))
		sb.WriteString("\n")
		if selected && m.expanded {
			sb.WriteString("    " + ValueStyle.Render(rows[i].Value) + "\n")
		}
	}
	return sb.String()
}

// View renders the current state of the TUI to a string.
func (m Model) View() string {
	switch m.state {
	case stateLoading:
		return "\n  " + m.spinner.View() + " " +
			i18n.Translate(m.lang, "tui.loading") + "\n\n  " +
			m.renderHelpHint() + "\n"

	case stateError:
		return "\n  " + RenderError(Truncate(m.errMsg, m.layout.TruncateAt)) +
			"\n\n  " + m.renderHelpHint() + "\n"

	case stateHelp:
		return m.frame(m.renderHelpScreen())

	case stateResult:
		if m.data == nil {
			return RenderError(i18n.Translate(m.lang, "tui.no_data")) + "\n"
		}
		var sb strings.Builder
		if m.layout.ShowHeader {
			sb.WriteString(TitleStyle.Render(i18n.Translate(m.lang, "tui.title")) + "\n\n")
		}
		sb.WriteString(IPStyle.Render(Truncate(m.data.IP, m.layout.TruncateAt)) + "\n\n")
		sb.WriteString(m.renderRows())
		return m.frame(sb.String())

	default:
		return ""
	}
}

// frame applies the border and footer chrome allowed by the current layout.
func (m Model) frame(body string) string {
	out := body
	if m.layout.ShowBorders {
		out = BorderStyle.Render(strings.TrimRight(body, "\n"))
	}
	if m.layout.ShowFooter {
		out += "\n" + m.renderFooter()
	}
	return "\n" + out + "\n"
}

// SizeModeFor classifies explicit dimensions into a responsive tier using the
// same breakpoints as terminal.GetTerminalSize(), for resize events where the
// dimensions arrive from bubbletea rather than from the TTY.
func SizeModeFor(cols, rows int) terminal.SizeMode {
	switch {
	case cols < 40 || rows < 10:
		return terminal.SizeModeMicro
	case cols < 60 || rows < 16:
		return terminal.SizeModeMinimal
	case cols < 80 || rows < 24:
		return terminal.SizeModeCompact
	case cols < 120 || rows < 40:
		return terminal.SizeModeStandard
	case cols < 200 || rows < 60:
		return terminal.SizeModeWide
	case cols < 400 || rows < 80:
		return terminal.SizeModeUltrawide
	default:
		return terminal.SizeModeMassive
	}
}

// RunTUIModel launches the bubbletea program with the given model and returns when done.
func RunTUIModel(m Model) error {
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

// RunWithCmd launches the TUI with an extra initial command (e.g., API fetch).
// The fetchCmd is dispatched alongside Init() so the spinner and fetch run concurrently.
func RunWithCmd(m Model, fetchCmd tea.Cmd) error {
	p := tea.NewProgram(m, tea.WithAltScreen())
	// Send the fetch command as an initial batch alongside Init().
	go func() {
		msg := fetchCmd()
		p.Send(msg)
	}()
	_, err := p.Run()
	return err
}

// HorizontalDivider renders a horizontal divider scaled to width.
// Re-exported here so callers in tui don't need to import layout.go functions.
func HorizontalDivider(width int) string {
	if width <= 0 {
		width = 80
	}
	return lipgloss.NewStyle().
		Foreground(lipgloss.Color(ActivePalette.Border)).
		Render(strings.Repeat("─", width))
}
