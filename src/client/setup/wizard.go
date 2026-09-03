package setup

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	paths "github.com/apimgr/ipgaze/src/client/path"
	"github.com/apimgr/ipgaze/src/common/display"
	"github.com/apimgr/ipgaze/src/common/i18n"
	"github.com/apimgr/ipgaze/src/common/terminal"
	"github.com/apimgr/ipgaze/src/common/theme"
)

// ErrSetupCancelled is returned when the user aborts the setup wizard.
var ErrSetupCancelled = errors.New("setup cancelled")

// ErrNoInteractiveSetup is returned when neither a terminal nor a display is
// available, so the wizard cannot be shown (AI.md PART 32: headless CLI is an
// error and must be configured with flags or environment variables).
var ErrNoInteractiveSetup = errors.New("no terminal or display available for interactive setup")

// SetupMode is the interface the setup wizard should be presented in.
type SetupMode int

const (
	// SetupModeTUI runs the terminal wizard.
	SetupModeTUI SetupMode = iota
	// SetupModeGUI runs the native graphical wizard.
	SetupModeGUI
	// SetupModeError means interactive setup is impossible.
	SetupModeError
)

// selectSetupMode picks the wizard presentation, per AI.md PART 32
// "Detection priority for setup wizard". Remote sessions always use the TUI —
// X11 forwarding is slow and Mosh has none at all — a local display gets the
// GUI, a plain terminal gets the TUI, and anything else is an error.
func selectSetupMode() SetupMode {
	env := display.DetectDisplayEnv()

	if env.IsSSH || env.IsMosh {
		return SetupModeTUI
	}
	if env.HasDisplay {
		return SetupModeGUI
	}
	if env.IsTerminal {
		return SetupModeTUI
	}
	return SetupModeError
}

// wizardLang resolves the wizard's locale from the environment using the
// AI.md PART 30 priority chain (LC_ALL, then LANG, then English).
func wizardLang() string {
	for _, key := range []string{"LC_ALL", "LANG"} {
		v := os.Getenv(key)
		if v == "" {
			continue
		}
		code := strings.ToLower(strings.Split(strings.Split(v, ".")[0], "_")[0])
		if i18n.IsSupported(code) {
			return code
		}
	}
	return "en"
}

// focusIndex identifies the focused control in the wizard form.
type focusIndex int

const (
	focusServer focusIndex = iota
	focusToken
	focusSave
	focusTest
	focusCount
)

// testResultMsg carries the outcome of a connection test.
type testResultMsg struct {
	err        error
	serverName string
	version    string
}

// textField is a minimal single-line text input. bubbles/textinput is not
// used here because its clipboard dependency has no go.sum entry in this
// module and adding one is out of scope for the wizard.
type textField struct {
	value       string
	placeholder string
	focused     bool
	masked      bool
	charLimit   int
}

// Focus marks the field as receiving keystrokes.
func (f *textField) Focus() {
	f.focused = true
}

// Blur stops the field from receiving keystrokes.
func (f *textField) Blur() {
	f.focused = false
}

// Value returns the text entered so far.
func (f textField) Value() string {
	return f.value
}

// insert appends text, respecting the character limit.
func (f *textField) insert(s string) {
	if f.charLimit > 0 && len([]rune(f.value))+len([]rune(s)) > f.charLimit {
		return
	}
	f.value += s
}

// handleKey applies one keystroke to the field.
func (f *textField) handleKey(msg tea.KeyMsg) {
	switch msg.Type {
	case tea.KeyBackspace:
		if r := []rune(f.value); len(r) > 0 {
			f.value = string(r[:len(r)-1])
		}
	case tea.KeySpace:
		f.insert(" ")
	case tea.KeyRunes:
		f.insert(string(msg.Runes))
	}
}

// View renders the field contents, masking a secret and showing a cursor while the field is focused.
func (f textField) View() string {
	text := f.value
	if f.masked {
		text = strings.Repeat("*", len([]rune(f.value)))
	}
	if text == "" && !f.focused {
		return f.placeholder
	}
	if f.focused {
		text += "_"
	}
	return text
}

// setupModel is the bubbletea model backing the TUI setup wizard.
type setupModel struct {
	lang      string
	inputs    []textField
	focus     focusIndex
	saveToCfg bool
	testing   bool
	tested    bool
	testErr   string
	serverMsg string
	validErr  string
	cancelled bool
	confirmed bool
	width     int
	palette   theme.TerminalPalette
}

// newSetupModel builds the wizard form with the server URL and token inputs.
func newSetupModel(lang string, palette theme.TerminalPalette) setupModel {
	server := textField{placeholder: "https://", charLimit: 512, focused: true}
	token := textField{
		placeholder: i18n.Translate(lang, "setup.token_placeholder"),
		charLimit:   512,
		masked:      true,
	}

	return setupModel{
		lang:      lang,
		inputs:    []textField{server, token},
		saveToCfg: true,
		width:     72,
		palette:   palette,
	}
}

// Init has no startup work; the wizard renders its own cursor.
func (m setupModel) Init() tea.Cmd {
	return nil
}

// serverURL returns the trimmed server URL entered by the user, defaulting to
// an https:// scheme when the user typed a bare host.
func (m setupModel) serverURL() string {
	v := strings.TrimSpace(m.inputs[focusServer].Value())
	if v == "" {
		return ""
	}
	if !strings.HasPrefix(v, "http://") && !strings.HasPrefix(v, "https://") {
		v = "https://" + v
	}
	return strings.TrimSuffix(v, "/")
}

// token returns the trimmed API token entered by the user.
func (m setupModel) token() string {
	return strings.TrimSpace(m.inputs[focusToken].Value())
}

// focusInput moves keyboard focus to the given control.
func (m *setupModel) focusInput(idx focusIndex) tea.Cmd {
	m.focus = idx
	for i := range m.inputs {
		if focusIndex(i) == idx {
			m.inputs[i].Focus()
			continue
		}
		m.inputs[i].Blur()
	}
	return nil
}

// testConnection returns a command that validates the server URL format and
// probes the server's health endpoint, per AI.md PART 32 "CONNECTION TEST".
func testConnection(url, token string) tea.Cmd {
	return func() tea.Msg {
		req, err := http.NewRequest(http.MethodGet, url+"/healthz", nil)
		if err != nil {
			return testResultMsg{err: err}
		}
		req.Header.Set("Accept", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return testResultMsg{err: err}
		}
		defer resp.Body.Close() //nolint:errcheck

		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return testResultMsg{err: errors.New(http.StatusText(resp.StatusCode))}
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return testResultMsg{err: fmt.Errorf("HTTP %d", resp.StatusCode)}
		}

		var health struct {
			Project struct {
				Name string `json:"name"`
			} `json:"project"`
			Version string `json:"version"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
			return testResultMsg{serverName: url}
		}
		name := health.Project.Name
		if name == "" {
			name = url
		}
		return testResultMsg{serverName: name, version: health.Version}
	}
}

// Update handles keyboard navigation, form editing, and connection results.
func (m setupModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		if msg.Width > 0 {
			m.width = msg.Width
		}

	case testResultMsg:
		m.testing = false
		m.tested = true
		if msg.err != nil {
			m.testErr = msg.err.Error()
			m.serverMsg = ""
			return m, nil
		}
		m.testErr = ""
		m.serverMsg = i18n.TranslateFormat(m.lang, "setup.connected",
			"server", msg.serverName, "version", displayVersion(msg.version))
		m.confirmed = true
		return m, tea.Quit

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "esc":
			m.cancelled = true
			return m, tea.Quit

		case "tab", "down":
			return m, m.focusInput((m.focus + 1) % focusCount)

		case "shift+tab", "up":
			return m, m.focusInput((m.focus + focusCount - 1) % focusCount)

		case " ":
			if m.focus == focusSave {
				m.saveToCfg = !m.saveToCfg
				return m, nil
			}

		case "enter":
			if m.focus == focusSave {
				m.saveToCfg = !m.saveToCfg
				return m, nil
			}
			url := m.serverURL()
			if !ValidateServerURL(url) {
				m.validErr = i18n.Translate(m.lang, "setup.invalid_url")
				return m, m.focusInput(focusServer)
			}
			m.validErr = ""
			m.testErr = ""
			m.testing = true
			return m, testConnection(url, m.token())
		}
	}

	key, ok := msg.(tea.KeyMsg)
	if ok && (m.focus == focusServer || m.focus == focusToken) {
		m.inputs[m.focus].handleKey(key)
	}
	return m, nil
}

// displayVersion returns the server version or a placeholder when unknown.
func displayVersion(v string) string {
	if v == "" {
		return "unknown"
	}
	return v
}

// View renders the wizard screen drawn in AI.md PART 32
// "TUI Setup Wizard (Terminal - Bubbletea)".
func (m setupModel) View() string {
	title := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color(m.palette.Primary))
	label := lipgloss.NewStyle().Foreground(lipgloss.Color(m.palette.Foreground))
	muted := lipgloss.NewStyle().Foreground(lipgloss.Color(m.palette.Muted))
	errStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(m.palette.Error))
	okStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(m.palette.Success))

	var sb strings.Builder
	sb.WriteString(title.Render(i18n.TranslateFormat(m.lang, "setup.title", "app", appDisplayName)) + "\n\n")
	sb.WriteString(label.Render(i18n.Translate(m.lang, "setup.intro")) + "\n\n")

	sb.WriteString(label.Render(i18n.Translate(m.lang, "setup.server_url_label")+":") + "\n")
	sb.WriteString(m.renderField(focusServer) + "\n\n")

	sb.WriteString(label.Render(i18n.Translate(m.lang, "setup.token_label")+":") + "\n")
	sb.WriteString(m.renderField(focusToken) + "\n\n")

	check := "[ ]"
	if m.saveToCfg {
		check = "[x]"
	}
	saveLine := check + " " + i18n.Translate(m.lang, "setup.save_option")
	sb.WriteString(m.renderControl(focusSave, saveLine) + "\n\n")

	sb.WriteString(m.renderControl(focusTest, "["+i18n.Translate(m.lang, "setup.test_connection")+"]") + "\n\n")

	switch {
	case m.testing:
		sb.WriteString(muted.Render(i18n.TranslateFormat(m.lang, "setup.testing", "server", m.serverURL())) + "\n")
	case m.validErr != "":
		sb.WriteString(errStyle.Render("✗ "+m.validErr) + "\n")
	case m.testErr != "":
		sb.WriteString(errStyle.Render("✗ "+i18n.TranslateFormat(m.lang, "setup.failed", "error", m.testErr)) + "\n")
	case m.serverMsg != "":
		sb.WriteString(okStyle.Render("✓ "+m.serverMsg) + "\n")
	default:
		sb.WriteString("\n")
	}

	sb.WriteString("\n" + muted.Render(i18n.Translate(m.lang, "setup.hint")) + "\n")

	box := lipgloss.NewStyle().
		Border(lipgloss.DoubleBorder()).
		BorderForeground(lipgloss.Color(m.palette.Border)).
		Padding(1, 2)
	return box.Render(strings.TrimRight(sb.String(), "\n")) + "\n"
}

// renderField renders one text input with a focus marker.
func (m setupModel) renderField(idx focusIndex) string {
	marker := "  "
	if m.focus == idx {
		marker = "> "
	}
	return marker + "[" + m.inputs[idx].View() + "]"
}

// renderControl renders a non-text control (checkbox, button) with a marker.
func (m setupModel) renderControl(idx focusIndex, text string) string {
	marker := "  "
	if m.focus == idx {
		marker = "> "
	}
	return marker + text
}

// appDisplayName is the application name shown in the wizard header.
const appDisplayName = "IPGaze"

// ConfiguredTUITheme returns the raw `tui.theme` value from cli.yml, or an
// empty string when the file is missing or the key is unset (AI.md PART 32
// "Theme is set in cli.yml"). The raw field is read rather than the
// TUITheme() accessor because the accessor substitutes DefaultTUITheme,
// which would suppress COLORFGBG autodetection for an unset key.
func ConfiguredTUITheme() string {
	cfg, err := LoadCLIConfigFromFile()
	if err != nil || cfg == nil {
		return ""
	}
	return cfg.TUI.Theme
}

// wizardPalette returns the ANSI palette for the wizard, honouring the
// configured TUI theme and falling back to COLORFGBG autodetection.
func wizardPalette() theme.TerminalPalette {
	return theme.TerminalPaletteFor(terminal.DetectThemeName(ConfiguredTUITheme()))
}

// RunSetupWizard launches the interactive wizard and persists the result.
// It returns nil immediately when a server is already configured.
func RunSetupWizard() error {
	cfg, err := LoadCLIConfigFromFile()
	if err == nil && cfg != nil && cfg.Server.Primary != "" {
		return nil
	}
	if cfg == nil {
		cfg = &CLIConfig{}
	}

	// A GUI toolkit is not compiled into this binary, so the GUI branch runs
	// the terminal wizard when a terminal is present and errors otherwise.
	mode := selectSetupMode()
	if mode == SetupModeError {
		return ErrNoInteractiveSetup
	}
	if mode == SetupModeGUI && !display.DetectDisplayEnv().IsTerminal {
		return ErrNoInteractiveSetup
	}

	lang := wizardLang()
	p := tea.NewProgram(newSetupModel(lang, wizardPalette()))
	result, err := p.Run()
	if err != nil {
		return err
	}

	model, ok := result.(setupModel)
	if !ok || model.cancelled || !model.confirmed {
		return ErrSetupCancelled
	}

	cfg.Server.Primary = model.serverURL()
	if tok := model.token(); tok != "" {
		cfg.Auth.Token = tok
	}
	if !model.saveToCfg {
		return nil
	}
	target := paths.ConfigFile()
	if err := SaveCLIConfigToFile(cfg, target); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, i18n.TranslateFormat(lang, "setup.saved", "path", target))
	return nil
}

// EnsureConfigured runs the setup wizard when no server is configured yet.
// Called once at CLI startup, before the server URL is required.
func EnsureConfigured() error {
	cfg, _ := LoadCLIConfigFromFile()
	if cfg == nil || cfg.Server.Primary == "" {
		return RunSetupWizard()
	}
	return nil
}
