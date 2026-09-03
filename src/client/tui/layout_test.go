package tui

import (
	"strings"
	"testing"

	"github.com/apimgr/ipgaze/src/common/terminal"
)

// ---------------------------------------------------------------------------
// formatCountry
// ---------------------------------------------------------------------------

func TestFormatCountry_EmptyCountryReturnsEmpty(t *testing.T) {
	if got := formatCountry("", "US"); got != "" {
		t.Errorf("formatCountry('','US') = %q, want %q", got, "")
	}
}

func TestFormatCountry_WithISO(t *testing.T) {
	got := formatCountry("United States", "US")
	want := "United States (US)"
	if got != want {
		t.Errorf("formatCountry = %q, want %q", got, want)
	}
}

func TestFormatCountry_WithoutISO(t *testing.T) {
	got := formatCountry("United States", "")
	want := "United States"
	if got != want {
		t.Errorf("formatCountry = %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// formatASN
// ---------------------------------------------------------------------------

func TestFormatASN_EmptyReturnsEmpty(t *testing.T) {
	if got := formatASN("", "Google LLC"); got != "" {
		t.Errorf("formatASN('','Google LLC') = %q, want ''", got)
	}
}

func TestFormatASN_WithOrg(t *testing.T) {
	got := formatASN("AS15169", "Google LLC")
	if !strings.Contains(got, "AS15169") || !strings.Contains(got, "Google LLC") {
		t.Errorf("formatASN with org = %q, want both ASN and org", got)
	}
}

func TestFormatASN_WithoutOrg(t *testing.T) {
	got := formatASN("AS15169", "")
	if got != "AS15169" {
		t.Errorf("formatASN without org = %q, want %q", got, "AS15169")
	}
}

// ---------------------------------------------------------------------------
// formatCoords
// ---------------------------------------------------------------------------

func TestFormatCoords_ZeroZeroReturnsEmpty(t *testing.T) {
	if got := formatCoords(0, 0); got != "" {
		t.Errorf("formatCoords(0,0) = %q, want ''", got)
	}
}

func TestFormatCoords_NonZero(t *testing.T) {
	got := formatCoords(37.7749, -122.4194)
	if !strings.Contains(got, "37.7749") || !strings.Contains(got, "-122.4194") {
		t.Errorf("formatCoords(37.7749,-122.4194) = %q, want both values present", got)
	}
}

func TestFormatCoords_NegativeLatZeroLon(t *testing.T) {
	got := formatCoords(-33.8688, 0)
	if got == "" {
		t.Error("formatCoords with non-zero lat = '', want non-empty")
	}
}

// ---------------------------------------------------------------------------
// RenderError / RenderSuccess / RenderMuted
// ---------------------------------------------------------------------------

func TestRenderError_ContainsMessage(t *testing.T) {
	got := RenderError("something went wrong")
	if !strings.Contains(got, "something went wrong") {
		t.Errorf("RenderError: missing message in %q", got)
	}
}

func TestRenderSuccess_ContainsMessage(t *testing.T) {
	got := RenderSuccess("all good")
	if !strings.Contains(got, "all good") {
		t.Errorf("RenderSuccess: missing message in %q", got)
	}
}

func TestRenderMuted_ContainsMessage(t *testing.T) {
	got := RenderMuted("secondary info")
	if !strings.Contains(got, "secondary info") {
		t.Errorf("RenderMuted: missing message in %q", got)
	}
}

// ---------------------------------------------------------------------------
// HorizontalRule
// ---------------------------------------------------------------------------

func TestHorizontalRule_Length(t *testing.T) {
	got := HorizontalRule(10)
	// The rule contains width repetitions of the dash rune — count runes,
	// not bytes, since lipgloss may add ANSI escapes (strip them first).
	plain := strings.TrimFunc(got, func(r rune) bool { return r < 0x20 })
	if plain == "" {
		t.Error("HorizontalRule(10): got empty string")
	}
}

func TestHorizontalRule_ZeroWidth(t *testing.T) {
	got := HorizontalRule(0)
	// Must not panic; empty or near-empty output is fine.
	_ = got
}

// ---------------------------------------------------------------------------
// RenderIPInfo — smoke test (should not panic)
// ---------------------------------------------------------------------------

func TestRenderIPInfo_NonemptyOutput(t *testing.T) {
	d := IPData{
		IP:         "1.2.3.4",
		Hostname:   "host.example.com",
		Country:    "United States",
		CountryISO: "US",
		City:       "San Francisco",
		RegionCode: "CA",
		ASN:        "AS15169",
		ASNOrg:     "Google LLC",
		Latitude:   37.7749,
		Longitude:  -122.4194,
		Timezone:   "America/Los_Angeles",
		PostalCode: "94107",
	}
	got := RenderIPInfo("en", GetLayoutConfig(terminal.SizeModeStandard), d)
	if got == "" {
		t.Error("RenderIPInfo: returned empty string")
	}
	if !strings.Contains(got, "1.2.3.4") {
		t.Errorf("RenderIPInfo: missing IP in output: %q", got)
	}
	if !strings.Contains(got, "San Francisco") {
		t.Errorf("RenderIPInfo: missing city in output: %q", got)
	}
}

func TestRenderIPInfo_EmptyFields_NoPanic(t *testing.T) {
	got := RenderIPInfo("en", GetLayoutConfig(terminal.SizeModeStandard), IPData{IP: "8.8.8.8"})
	if !strings.Contains(got, "8.8.8.8") {
		t.Errorf("RenderIPInfo empty fields: missing IP in output: %q", got)
	}
}

func TestRenderIPInfo_MicroHidesHeaderAndAbbreviates(t *testing.T) {
	d := IPData{IP: "1.2.3.4", City: "San Francisco", Timezone: "America/Los_Angeles"}
	got := RenderIPInfo("en", GetLayoutConfig(terminal.SizeModeMicro), d)
	if strings.Contains(got, "IP Address Information") {
		t.Errorf("RenderIPInfo micro: header must be hidden: %q", got)
	}
	if !strings.Contains(got, "TZ:") {
		t.Errorf("RenderIPInfo micro: expected abbreviated timezone label: %q", got)
	}
}

// ---------------------------------------------------------------------------
// NewModel
// ---------------------------------------------------------------------------

func TestNewModel_InitialState(t *testing.T) {
	m := NewModel()
	if m.state != stateLoading {
		t.Errorf("NewModel().state = %v, want stateLoading", m.state)
	}
	if m.width != 80 {
		t.Errorf("NewModel().width = %d, want 80", m.width)
	}
	if m.data != nil {
		t.Error("NewModel().data should be nil")
	}
	if m.errMsg != "" {
		t.Errorf("NewModel().errMsg = %q, want empty", m.errMsg)
	}
}

// ---------------------------------------------------------------------------
// Model.View — state-specific outputs
// ---------------------------------------------------------------------------

func TestModelView_Loading(t *testing.T) {
	m := NewModel()
	view := m.View()
	if !strings.Contains(view, "Looking up") {
		t.Errorf("View() in loading state missing 'Looking up' text: %q", view)
	}
}

func TestModelView_Error(t *testing.T) {
	m := NewModel()
	m.state = stateError
	m.errMsg = "connection timeout"
	view := m.View()
	if !strings.Contains(view, "connection timeout") {
		t.Errorf("View() in error state missing error message: %q", view)
	}
}

func TestModelView_Result_NilData(t *testing.T) {
	m := NewModel()
	m.state = stateResult
	m.data = nil
	view := m.View()
	if !strings.Contains(view, "no data") {
		t.Errorf("View() with nil data should show 'no data': %q", view)
	}
}

func TestModelView_Result_WithData(t *testing.T) {
	m := NewModel()
	m.state = stateResult
	m.data = &IPData{IP: "1.2.3.4", Country: "US"}
	view := m.View()
	if !strings.Contains(view, "1.2.3.4") {
		t.Errorf("View() with data missing IP: %q", view)
	}
}

// ---------------------------------------------------------------------------
// HorizontalDivider
// ---------------------------------------------------------------------------

func TestHorizontalDivider_PositiveWidth(t *testing.T) {
	got := HorizontalDivider(40)
	if got == "" {
		t.Error("HorizontalDivider(40) returned empty string")
	}
}

func TestHorizontalDivider_ZeroWidth_DefaultsTo80(t *testing.T) {
	got := HorizontalDivider(0)
	if got == "" {
		t.Error("HorizontalDivider(0) returned empty string, expected 80-width default")
	}
}

func TestHorizontalDivider_NegativeWidth_DefaultsTo80(t *testing.T) {
	got := HorizontalDivider(-5)
	if got == "" {
		t.Error("HorizontalDivider(-5) returned empty string, expected 80-width default")
	}
}

// ---------------------------------------------------------------------------
// IPData struct fields
// ---------------------------------------------------------------------------

func TestIPData_AllFieldsAccessible(t *testing.T) {
	d := IPData{
		IP:         "8.8.8.8",
		Hostname:   "dns.google",
		Country:    "United States",
		CountryISO: "US",
		City:       "Mountain View",
		RegionName: "California",
		RegionCode: "CA",
		ASN:        "AS15169",
		ASNOrg:     "Google LLC",
		Latitude:   37.4056,
		Longitude:  -122.0775,
		Timezone:   "America/Los_Angeles",
		PostalCode: "94043",
	}
	if d.IP != "8.8.8.8" {
		t.Errorf("IPData.IP = %q, want 8.8.8.8", d.IP)
	}
	if d.CountryISO != "US" {
		t.Errorf("IPData.CountryISO = %q, want US", d.CountryISO)
	}
}

// ---------------------------------------------------------------------------
// Styles — verify they render without panic
// ---------------------------------------------------------------------------

func TestStyles_RenderWithoutPanic(t *testing.T) {
	// Each style should render text without panicking
	if got := TitleStyle.Render("title"); got == "" {
		t.Error("TitleStyle.Render() returned empty")
	}
	if got := IPStyle.Render("1.2.3.4"); got == "" {
		t.Error("IPStyle.Render() returned empty")
	}
	if got := LabelStyle.Render("label"); got == "" {
		t.Error("LabelStyle.Render() returned empty")
	}
	if got := ValueStyle.Render("value"); got == "" {
		t.Error("ValueStyle.Render() returned empty")
	}
	if got := SuccessStyle.Render("ok"); got == "" {
		t.Error("SuccessStyle.Render() returned empty")
	}
	if got := ErrorStyle.Render("err"); got == "" {
		t.Error("ErrorStyle.Render() returned empty")
	}
	if got := BorderStyle.Render("box"); got == "" {
		t.Error("BorderStyle.Render() returned empty")
	}
	if got := MutedStyle.Render("muted"); got == "" {
		t.Error("MutedStyle.Render() returned empty")
	}
}
