package handler

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/apimgr/ipgaze/src/config"
	"github.com/apimgr/ipgaze/src/netutil"
)

func newTestPagesHandler() *PagesHandler {
	return NewPagesHandler("1.0.0", "2024-01-01", netutil.NewTrustResolver(config.TrustedProxiesConfig{}, ""), func(w http.ResponseWriter, _ *http.Request, page string, data interface{}) error {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte("<!-- template: " + page + " -->")) //nolint:errcheck
		return nil
	})
}

func TestNewPagesHandler(t *testing.T) {
	h := newTestPagesHandler()
	if h.Version != "1.0.0" {
		t.Errorf("Version = %q, want %q", h.Version, "1.0.0")
	}
	if h.BuildDate != "2024-01-01" {
		t.Errorf("BuildDate = %q, want %q", h.BuildDate, "2024-01-01")
	}
	if h.Render == nil {
		t.Error("Render = nil, want non-nil")
	}
}

func TestServerRedirectHandler(t *testing.T) {
	h := newTestPagesHandler()
	req := httptest.NewRequest(http.MethodGet, "/server", nil)
	w := httptest.NewRecorder()

	h.ServerRedirectHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusMovedPermanently {
		t.Errorf("StatusCode = %d, want %d", res.StatusCode, http.StatusMovedPermanently)
	}
	loc := res.Header.Get("Location")
	if loc != "/server/about" {
		t.Errorf("Location = %q, want %q", loc, "/server/about")
	}
}

func TestBuildAboutResponse_DefaultVersion(t *testing.T) {
	h := NewPagesHandler("", "2024-01-01", netutil.NewTrustResolver(config.TrustedProxiesConfig{}, ""), nil)
	resp := h.buildAboutResponse()
	if resp.Version != "dev" {
		t.Errorf("Version = %q, want %q", resp.Version, "dev")
	}
}

func TestBuildAboutResponse_Fields(t *testing.T) {
	h := newTestPagesHandler()
	resp := h.buildAboutResponse()
	if resp.Name != "IPGaze" {
		t.Errorf("Name = %q, want %q", resp.Name, "IPGaze")
	}
	if len(resp.Features) == 0 {
		t.Error("Features is empty, want at least one entry")
	}
	if resp.Links.Repository == "" {
		t.Error("Links.Repository is empty")
	}
	if resp.Links.Website == "" {
		t.Error("Links.Website is empty")
	}
}

func TestServerAboutHandler_HTML(t *testing.T) {
	h := newTestPagesHandler()
	req := httptest.NewRequest(http.MethodGet, "/server/about", nil)
	w := httptest.NewRecorder()

	h.ServerAboutHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", res.StatusCode, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "about.tmpl") {
		t.Errorf("body does not reference about.tmpl: %q", body)
	}
}

func TestServerAboutHandler_RenderError(t *testing.T) {
	h := NewPagesHandler("1.0.0", "", netutil.NewTrustResolver(config.TrustedProxiesConfig{}, ""), func(w http.ResponseWriter, _ *http.Request, page string, data interface{}) error {
		return &testRenderError{}
	})
	req := httptest.NewRequest(http.MethodGet, "/server/about", nil)
	w := httptest.NewRecorder()

	h.ServerAboutHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusInternalServerError {
		t.Errorf("StatusCode = %d, want %d on render error", res.StatusCode, http.StatusInternalServerError)
	}
}

type testRenderError struct{}

func (e *testRenderError) Error() string { return "template render failed" }

func TestAPIV1ServerAboutHandler(t *testing.T) {
	h := newTestPagesHandler()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/server/about", nil)
	w := httptest.NewRecorder()

	h.APIV1ServerAboutHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", res.StatusCode, http.StatusOK)
	}
	ct := res.Header.Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}

	var body AboutResponse
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if body.Name != "IPGaze" {
		t.Errorf("Name = %q, want %q", body.Name, "IPGaze")
	}
	if body.Version != "1.0.0" {
		t.Errorf("Version = %q, want %q", body.Version, "1.0.0")
	}
}

func TestServerHelpHandler(t *testing.T) {
	h := newTestPagesHandler()
	req := httptest.NewRequest(http.MethodGet, "/server/help", nil)
	w := httptest.NewRecorder()

	h.ServerHelpHandler(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "help.tmpl") {
		t.Errorf("body does not reference help.tmpl: %q", body)
	}
}

func TestAPIV1ServerHelpHandler(t *testing.T) {
	h := newTestPagesHandler()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/server/help", nil)
	w := httptest.NewRecorder()

	h.APIV1ServerHelpHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", res.StatusCode, http.StatusOK)
	}
	var body HelpResponse
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if len(body.Sections) == 0 {
		t.Error("Sections is empty")
	}
}

func TestServerPrivacyHandler(t *testing.T) {
	h := newTestPagesHandler()
	req := httptest.NewRequest(http.MethodGet, "/server/privacy", nil)
	w := httptest.NewRecorder()

	h.ServerPrivacyHandler(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "privacy.tmpl") {
		t.Errorf("body does not reference privacy.tmpl: %q", body)
	}
}

func TestAPIV1ServerPrivacyHandler(t *testing.T) {
	h := newTestPagesHandler()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/server/privacy", nil)
	w := httptest.NewRecorder()

	h.APIV1ServerPrivacyHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", res.StatusCode, http.StatusOK)
	}
	var body PrivacyResponse
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if body.Summary.DataStoredOnServer {
		t.Error("DataStoredOnServer = true, want false")
	}
	if body.Summary.DataSold {
		t.Error("DataSold = true, want false")
	}
	if !body.Summary.UserControl {
		t.Error("UserControl = false, want true")
	}
}

func TestServerContactHandler_GET(t *testing.T) {
	h := newTestPagesHandler()
	req := httptest.NewRequest(http.MethodGet, "/server/contact", nil)
	w := httptest.NewRecorder()

	h.ServerContactHandler(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "contact.tmpl") {
		t.Errorf("body does not reference contact.tmpl: %q", body)
	}
}

func TestServerContactHandler_POST(t *testing.T) {
	h := newTestPagesHandler()
	req := httptest.NewRequest(http.MethodPost, "/server/contact", nil)
	w := httptest.NewRecorder()

	h.ServerContactHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusSeeOther {
		t.Errorf("StatusCode = %d, want %d for POST", res.StatusCode, http.StatusSeeOther)
	}
}

func TestAPIV1ServerContactHandler_POST(t *testing.T) {
	h := newTestPagesHandler()
	reqBody := strings.NewReader(`{"email":"user@example.com","message":"hello"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/server/contact", reqBody)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.APIV1ServerContactHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", res.StatusCode, http.StatusOK)
	}
	var body ContactResponse
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if !body.Success {
		t.Error("Success = false, want true")
	}
}

func TestAPIV1ServerContactHandler_EmptyBody_BadRequest(t *testing.T) {
	h := newTestPagesHandler()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/server/contact", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.APIV1ServerContactHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("StatusCode = %d, want %d for empty email/message", res.StatusCode, http.StatusBadRequest)
	}
}

func TestAPIV1ServerContactHandler_MethodNotAllowed(t *testing.T) {
	h := newTestPagesHandler()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/server/contact", nil)
	w := httptest.NewRecorder()

	h.APIV1ServerContactHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("StatusCode = %d, want %d for GET", res.StatusCode, http.StatusMethodNotAllowed)
	}
}

func TestServerTermsHandler(t *testing.T) {
	h := newTestPagesHandler()
	req := httptest.NewRequest(http.MethodGet, "/server/terms", nil)
	w := httptest.NewRecorder()

	h.ServerTermsHandler(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "terms.tmpl") {
		t.Errorf("body does not reference terms.tmpl: %q", body)
	}
}

func TestAPIV1ServerTermsHandler(t *testing.T) {
	h := newTestPagesHandler()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/server/terms", nil)
	w := httptest.NewRecorder()

	h.APIV1ServerTermsHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", res.StatusCode, http.StatusOK)
	}
	var body TermsResponse
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if len(body.Sections) == 0 {
		t.Error("Sections is empty")
	}
	if body.LastUpdated == "" {
		t.Error("LastUpdated is empty")
	}
}

func TestNewPageData_HTTP(t *testing.T) {
	h := newTestPagesHandler()
	req := httptest.NewRequest(http.MethodGet, "/server/about", nil)
	req.Host = "example.com"
	data := h.NewPageData(req)

	if data.Lang == "" {
		t.Error("Lang is empty")
	}
	if data.Dir == "" {
		t.Error("Dir is empty")
	}
	if data.Theme != "dark" {
		t.Errorf("Theme = %q, want %q", data.Theme, "dark")
	}
	if !strings.HasPrefix(data.CanonicalURL, "http://") {
		t.Errorf("CanonicalURL = %q, want http:// prefix", data.CanonicalURL)
	}
}

func TestNewPageData_HTTPS(t *testing.T) {
	h := newTestPagesHandler()
	req := httptest.NewRequest(http.MethodGet, "/server/about", nil)
	req.Host = "example.com"
	// Use a loopback peer so IsTrustedPeer returns true and X-Forwarded-Proto is honored.
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Forwarded-Proto", "https")
	data := h.NewPageData(req)

	if !strings.HasPrefix(data.CanonicalURL, "https://") {
		t.Errorf("CanonicalURL = %q, want https:// prefix", data.CanonicalURL)
	}
}

func TestServerHelpHandler_RenderError(t *testing.T) {
	h := NewPagesHandler("1.0.0", "", netutil.NewTrustResolver(config.TrustedProxiesConfig{}, ""), func(w http.ResponseWriter, _ *http.Request, page string, data interface{}) error {
		return &testRenderError{}
	})
	req := httptest.NewRequest(http.MethodGet, "/server/help", nil)
	w := httptest.NewRecorder()

	h.ServerHelpHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusInternalServerError {
		t.Errorf("StatusCode = %d, want %d on render error", res.StatusCode, http.StatusInternalServerError)
	}
}

func TestServerPrivacyHandler_RenderError(t *testing.T) {
	h := NewPagesHandler("1.0.0", "", netutil.NewTrustResolver(config.TrustedProxiesConfig{}, ""), func(w http.ResponseWriter, _ *http.Request, page string, data interface{}) error {
		return &testRenderError{}
	})
	req := httptest.NewRequest(http.MethodGet, "/server/privacy", nil)
	w := httptest.NewRecorder()

	h.ServerPrivacyHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusInternalServerError {
		t.Errorf("StatusCode = %d, want %d on render error", res.StatusCode, http.StatusInternalServerError)
	}
}

func TestServerContactHandler_RenderError(t *testing.T) {
	h := NewPagesHandler("1.0.0", "", netutil.NewTrustResolver(config.TrustedProxiesConfig{}, ""), func(w http.ResponseWriter, _ *http.Request, page string, data interface{}) error {
		return &testRenderError{}
	})
	req := httptest.NewRequest(http.MethodGet, "/server/contact", nil)
	w := httptest.NewRecorder()

	h.ServerContactHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusInternalServerError {
		t.Errorf("StatusCode = %d, want %d on render error", res.StatusCode, http.StatusInternalServerError)
	}
}

func TestServerTermsHandler_RenderError(t *testing.T) {
	h := NewPagesHandler("1.0.0", "", netutil.NewTrustResolver(config.TrustedProxiesConfig{}, ""), func(w http.ResponseWriter, _ *http.Request, page string, data interface{}) error {
		return &testRenderError{}
	})
	req := httptest.NewRequest(http.MethodGet, "/server/terms", nil)
	w := httptest.NewRecorder()

	h.ServerTermsHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusInternalServerError {
		t.Errorf("StatusCode = %d, want %d on render error", res.StatusCode, http.StatusInternalServerError)
	}
}

// consentCookieValue decodes the JSON cookie_consent cookie value set by ConsentHandler.
func consentCookieValue(t *testing.T, cookies []*http.Cookie) (found *http.Cookie, preferences, analytics bool) {
	t.Helper()
	for _, c := range cookies {
		if c.Name == "cookie_consent" {
			found = c
			break
		}
	}
	if found == nil {
		return nil, false, false
	}
	raw, err := url.QueryUnescape(found.Value)
	if err != nil {
		t.Fatalf("cookie_consent value not valid URL-encoding: %v", err)
	}
	var decoded struct {
		Essential   bool  `json:"essential"`
		Preferences bool  `json:"preferences"`
		Analytics   bool  `json:"analytics"`
		Timestamp   int64 `json:"timestamp"`
	}
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		t.Fatalf("cookie_consent value not valid JSON: %v", err)
	}
	return found, decoded.Preferences, decoded.Analytics
}

func TestConsentHandler_Accept(t *testing.T) {
	h := newTestPagesHandler()
	req := httptest.NewRequest(http.MethodPost, "/consent", strings.NewReader("choice=accept"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.ConsentHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusNoContent {
		t.Errorf("StatusCode = %d, want %d", res.StatusCode, http.StatusNoContent)
	}
	found, preferences, analytics := consentCookieValue(t, res.Cookies())
	if found == nil {
		t.Fatal("cookie_consent cookie not set")
	}
	if !preferences || !analytics {
		t.Errorf("cookie_consent preferences=%v analytics=%v, want both true", preferences, analytics)
	}
}

func TestConsentHandler_Decline(t *testing.T) {
	h := newTestPagesHandler()
	req := httptest.NewRequest(http.MethodPost, "/consent", strings.NewReader("choice=decline"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.ConsentHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusNoContent {
		t.Errorf("StatusCode = %d, want %d", res.StatusCode, http.StatusNoContent)
	}
}

func TestConsentHandler_InvalidChoice_Defaults_Declined(t *testing.T) {
	h := newTestPagesHandler()
	req := httptest.NewRequest(http.MethodPost, "/consent", strings.NewReader("choice=bad"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.ConsentHandler(w, req)

	res := w.Result()
	_, preferences, analytics := consentCookieValue(t, res.Cookies())
	if preferences || analytics {
		t.Errorf("cookie_consent preferences=%v analytics=%v, want both false for invalid choice", preferences, analytics)
	}
}

func TestConsentHandler_MethodNotAllowed(t *testing.T) {
	h := newTestPagesHandler()
	req := httptest.NewRequest(http.MethodGet, "/consent", nil)
	w := httptest.NewRecorder()

	h.ConsentHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("StatusCode = %d, want %d", res.StatusCode, http.StatusMethodNotAllowed)
	}
}

func TestConsentHandler_HTMLAccept_RedirectsToReferer(t *testing.T) {
	h := newTestPagesHandler()
	req := httptest.NewRequest(http.MethodPost, "/consent", strings.NewReader("choice=accepted"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Referer", "/some/page")
	w := httptest.NewRecorder()

	h.ConsentHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusSeeOther {
		t.Errorf("StatusCode = %d, want %d", res.StatusCode, http.StatusSeeOther)
	}
	if loc := res.Header.Get("Location"); loc != "/some/page" {
		t.Errorf("Location = %q, want %q", loc, "/some/page")
	}
}

func TestConsentHandler_HTMLAccept_NoReferer_RedirectsToRoot(t *testing.T) {
	h := newTestPagesHandler()
	req := httptest.NewRequest(http.MethodPost, "/consent", strings.NewReader("choice=accepted"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()

	h.ConsentHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusSeeOther {
		t.Errorf("StatusCode = %d, want %d", res.StatusCode, http.StatusSeeOther)
	}
	if loc := res.Header.Get("Location"); loc != "/" {
		t.Errorf("Location = %q, want %q", loc, "/")
	}
}

func TestCCPAHandler_OptOut(t *testing.T) {
	h := newTestPagesHandler()
	req := httptest.NewRequest(http.MethodPost, "/server/ccpa", strings.NewReader("choice=opt-out"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.CCPAHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusNoContent {
		t.Errorf("StatusCode = %d, want %d", res.StatusCode, http.StatusNoContent)
	}
	var found *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == "ccpa_opt_out" {
			found = c
			break
		}
	}
	if found == nil {
		t.Fatal("ccpa_opt_out cookie not set")
	}
	if found.Value != "true" {
		t.Errorf("ccpa_opt_out = %q, want %q", found.Value, "true")
	}
}

func TestCCPAHandler_OptIn(t *testing.T) {
	h := newTestPagesHandler()
	req := httptest.NewRequest(http.MethodPost, "/server/ccpa", strings.NewReader("choice=opt-in"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.CCPAHandler(w, req)

	res := w.Result()
	for _, c := range res.Cookies() {
		if c.Name == "ccpa_opt_out" && c.Value != "false" {
			t.Errorf("ccpa_opt_out = %q, want %q", c.Value, "false")
		}
	}
}

func TestCCPAHandler_MethodNotAllowed(t *testing.T) {
	h := newTestPagesHandler()
	req := httptest.NewRequest(http.MethodGet, "/server/ccpa", nil)
	w := httptest.NewRecorder()

	h.CCPAHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("StatusCode = %d, want %d", res.StatusCode, http.StatusMethodNotAllowed)
	}
}

func TestCCPAHandler_HTMLAccept_RedirectsToReferer(t *testing.T) {
	h := newTestPagesHandler()
	req := httptest.NewRequest(http.MethodPost, "/server/ccpa", strings.NewReader("choice=opt-out"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Referer", "/server/privacy")
	w := httptest.NewRecorder()

	h.CCPAHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusSeeOther {
		t.Errorf("StatusCode = %d, want %d", res.StatusCode, http.StatusSeeOther)
	}
	if loc := res.Header.Get("Location"); loc != "/server/privacy" {
		t.Errorf("Location = %q, want %q", loc, "/server/privacy")
	}
}

func TestDismissAnnouncementHandler_NewID(t *testing.T) {
	h := newTestPagesHandler()
	req := httptest.NewRequest(http.MethodPost, "/announcements/dismiss", strings.NewReader("id=ann-1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.DismissAnnouncementHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusNoContent {
		t.Errorf("StatusCode = %d, want %d", res.StatusCode, http.StatusNoContent)
	}
	var found *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == "dismissed_announcements" {
			found = c
			break
		}
	}
	if found == nil {
		t.Fatal("dismissed_announcements cookie not set")
	}
	if !strings.Contains(found.Value, "ann-1") {
		t.Errorf("cookie value %q does not contain %q", found.Value, "ann-1")
	}
}

func TestDismissAnnouncementHandler_AppendsToPrior(t *testing.T) {
	h := newTestPagesHandler()
	req := httptest.NewRequest(http.MethodPost, "/announcements/dismiss", strings.NewReader("id=ann-2"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "dismissed_announcements", Value: "ann-1"})
	w := httptest.NewRecorder()

	h.DismissAnnouncementHandler(w, req)

	res := w.Result()
	var found *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == "dismissed_announcements" {
			found = c
			break
		}
	}
	if found == nil {
		t.Fatal("dismissed_announcements cookie not set")
	}
	if !strings.Contains(found.Value, "ann-1") || !strings.Contains(found.Value, "ann-2") {
		t.Errorf("cookie value %q does not contain both IDs", found.Value)
	}
}

func TestDismissAnnouncementHandler_NoDuplicates(t *testing.T) {
	h := newTestPagesHandler()
	req := httptest.NewRequest(http.MethodPost, "/announcements/dismiss", strings.NewReader("id=ann-1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "dismissed_announcements", Value: "ann-1"})
	w := httptest.NewRecorder()

	h.DismissAnnouncementHandler(w, req)

	res := w.Result()
	for _, c := range res.Cookies() {
		if c.Name == "dismissed_announcements" {
			parts := strings.Split(c.Value, ",")
			count := 0
			for _, p := range parts {
				if strings.TrimSpace(p) == "ann-1" {
					count++
				}
			}
			if count > 1 {
				t.Errorf("ann-1 appears %d times in cookie, want 1", count)
			}
		}
	}
}

func TestDismissAnnouncementHandler_EmptyID(t *testing.T) {
	h := newTestPagesHandler()
	req := httptest.NewRequest(http.MethodPost, "/announcements/dismiss", strings.NewReader("id="))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.DismissAnnouncementHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("StatusCode = %d, want %d for empty id", res.StatusCode, http.StatusBadRequest)
	}
}

func TestDismissAnnouncementHandler_MethodNotAllowed(t *testing.T) {
	h := newTestPagesHandler()
	req := httptest.NewRequest(http.MethodGet, "/announcements/dismiss", nil)
	w := httptest.NewRecorder()

	h.DismissAnnouncementHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("StatusCode = %d, want %d", res.StatusCode, http.StatusMethodNotAllowed)
	}
}

func TestNewPageData_WithAnnouncements(t *testing.T) {
	h := newTestPagesHandler()
	h.WebUI = &config.WebUIConfig{
		Announcements: config.AnnouncementsConfig{
			Enabled: true,
			Messages: []config.AnnouncementMessage{
				{ID: "ann-1", Type: "info", Title: "Test", Message: "Hello", Dismissible: true},
			},
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	data := h.NewPageData(req)

	if len(data.Announcements) != 1 {
		t.Errorf("Announcements len = %d, want 1", len(data.Announcements))
	}
	if data.Announcements[0].ID != "ann-1" {
		t.Errorf("Announcements[0].ID = %q, want %q", data.Announcements[0].ID, "ann-1")
	}
}

func TestNewPageData_DismissedAnnouncement_Excluded(t *testing.T) {
	h := newTestPagesHandler()
	h.WebUI = &config.WebUIConfig{
		Announcements: config.AnnouncementsConfig{
			Enabled: true,
			Messages: []config.AnnouncementMessage{
				{ID: "ann-1", Type: "info", Message: "Hello", Dismissible: true},
			},
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "dismissed_announcements", Value: "ann-1"})
	data := h.NewPageData(req)

	if len(data.Announcements) != 0 {
		t.Errorf("Announcements len = %d, want 0 (dismissed)", len(data.Announcements))
	}
}

func TestNewPageData_ShowConsentBanner_WhenNoCookie(t *testing.T) {
	h := newTestPagesHandler()
	h.Privacy = &config.PrivacyConfig{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	data := h.NewPageData(req)

	if !data.ShowConsentBanner {
		t.Error("ShowConsentBanner = false, want true when no cookie set")
	}
}

func TestNewPageData_HideConsentBanner_WhenCookiePresent(t *testing.T) {
	h := newTestPagesHandler()
	h.Privacy = &config.PrivacyConfig{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "cookie_consent", Value: "accept"})
	data := h.NewPageData(req)

	if data.ShowConsentBanner {
		t.Error("ShowConsentBanner = true, want false when cookie present")
	}
}

// testValidateTheme mirrors src/server/theme.go's ValidateTheme enum
// (light/dark/auto, default "dark") without importing package server, which
// would create an import cycle (see PagesHandler.ValidateTheme doc comment).
func testValidateTheme(theme string) string {
	switch theme {
	case "light", "dark", "auto":
		return theme
	default:
		return "dark"
	}
}

func TestServerPreferencesHandler_RendersCurrentValues(t *testing.T) {
	h := newTestPagesHandler()
	req := httptest.NewRequest(http.MethodGet, "/server/preferences", nil)
	req.AddCookie(&http.Cookie{Name: "lang", Value: "fr"})
	w := httptest.NewRecorder()

	h.ServerPreferencesHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", res.StatusCode, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "preferences.tmpl") {
		t.Errorf("body = %q, want it to render preferences.tmpl", body)
	}
}

func TestAPIV1ServerPreferencesHandler_ReturnsThemeAndLang(t *testing.T) {
	h := newTestPagesHandler()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/server/preferences", nil)
	req.AddCookie(&http.Cookie{Name: "lang", Value: "es"})
	w := httptest.NewRecorder()

	h.APIV1ServerPreferencesHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", res.StatusCode, http.StatusOK)
	}
	var resp struct {
		OK   bool                `json:"ok"`
		Data PreferencesResponse `json:"data"`
	}
	if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.OK {
		t.Error("OK = false, want true")
	}
	if resp.Data.Lang != "es" {
		t.Errorf("Lang = %q, want %q", resp.Data.Lang, "es")
	}
	if resp.Data.Theme != "dark" {
		t.Errorf("Theme = %q, want %q (default, no DetectTheme injected)", resp.Data.Theme, "dark")
	}
	if resp.Data.ExportURL == "" || resp.Data.ExportCode == "" {
		t.Error("ExportURL/ExportCode empty, want populated")
	}
}

func TestAPIV1ServerPreferencesExportHandler_OnlyExportsThemeAndLang(t *testing.T) {
	h := newTestPagesHandler()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/server/preferences/export", nil)
	req.AddCookie(&http.Cookie{Name: "lang", Value: "de"})
	req.AddCookie(&http.Cookie{Name: "cookie_consent", Value: `{"essential":true}`})
	req.AddCookie(&http.Cookie{Name: "ccpa_opt_out", Value: "true"})
	w := httptest.NewRecorder()

	h.APIV1ServerPreferencesExportHandler(w, req)

	body := w.Body.String()
	if strings.Contains(body, "cookie_consent") || strings.Contains(body, "ccpa_opt_out") {
		t.Errorf("export body leaked non-exportable cookie name: %q", body)
	}
	if !strings.Contains(body, "theme=dark") || !strings.Contains(body, "lang=de") {
		t.Errorf("export body = %q, want it to contain theme=dark and lang=de", body)
	}
}

func TestServerPreferencesImportHandler_ValidValues_SetsCookiesAndRedirects(t *testing.T) {
	h := newTestPagesHandler()
	h.ValidateTheme = testValidateTheme
	req := httptest.NewRequest(http.MethodGet, "/server/preferences/import?theme=light&lang=fr", nil)
	req.Header.Set("Referer", "/server/preferences")
	w := httptest.NewRecorder()

	h.ServerPreferencesImportHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusSeeOther {
		t.Errorf("StatusCode = %d, want %d", res.StatusCode, http.StatusSeeOther)
	}
	if loc := res.Header.Get("Location"); loc != "/server/preferences" {
		t.Errorf("Location = %q, want %q", loc, "/server/preferences")
	}
	var gotTheme, gotLang string
	for _, c := range res.Cookies() {
		switch c.Name {
		case "theme":
			gotTheme = c.Value
		case "lang":
			gotLang = c.Value
		}
	}
	if gotTheme != "light" {
		t.Errorf("theme cookie = %q, want %q", gotTheme, "light")
	}
	if gotLang != "fr" {
		t.Errorf("lang cookie = %q, want %q", gotLang, "fr")
	}
}

func TestServerPreferencesImportHandler_InvalidValues_DroppedNotDefaulted(t *testing.T) {
	h := newTestPagesHandler()
	h.ValidateTheme = testValidateTheme
	req := httptest.NewRequest(http.MethodGet, "/server/preferences/import?theme=not-a-theme&lang=not-a-lang", nil)
	w := httptest.NewRecorder()

	h.ServerPreferencesImportHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusSeeOther {
		t.Errorf("StatusCode = %d, want %d", res.StatusCode, http.StatusSeeOther)
	}
	for _, c := range res.Cookies() {
		if c.Name == "theme" || c.Name == "lang" {
			t.Errorf("cookie %q was set to %q, want no cookie for an invalid/malformed value", c.Name, c.Value)
		}
	}
}

func TestServerPreferencesImportHandler_ViaShortCode(t *testing.T) {
	h := newTestPagesHandler()
	h.ValidateTheme = testValidateTheme
	code := base64.RawURLEncoding.EncodeToString([]byte("theme=light&lang=ja"))
	req := httptest.NewRequest(http.MethodGet, "/server/preferences/import?code="+code, nil)
	w := httptest.NewRecorder()

	h.ServerPreferencesImportHandler(w, req)

	var gotTheme, gotLang string
	for _, c := range w.Result().Cookies() {
		switch c.Name {
		case "theme":
			gotTheme = c.Value
		case "lang":
			gotLang = c.Value
		}
	}
	if gotTheme != "light" || gotLang != "ja" {
		t.Errorf("theme=%q lang=%q, want theme=light lang=ja (decoded from short code)", gotTheme, gotLang)
	}
}

func TestServerPreferencesImportHandler_MalformedCode_NoCookiesSet(t *testing.T) {
	h := newTestPagesHandler()
	h.ValidateTheme = testValidateTheme
	req := httptest.NewRequest(http.MethodGet, "/server/preferences/import?code=%%%not-base64%%%", nil)
	w := httptest.NewRecorder()

	h.ServerPreferencesImportHandler(w, req)

	if len(w.Result().Cookies()) != 0 {
		t.Errorf("cookies = %v, want none for a malformed code", w.Result().Cookies())
	}
}

func TestAPIV1ServerPreferencesImportHandler_ReturnsAppliedValues(t *testing.T) {
	h := newTestPagesHandler()
	h.ValidateTheme = testValidateTheme
	req := httptest.NewRequest(http.MethodGet, "/api/v1/server/preferences/import?theme=auto&lang=zh", nil)
	w := httptest.NewRecorder()

	h.APIV1ServerPreferencesImportHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", res.StatusCode, http.StatusOK)
	}
	var resp struct {
		OK   bool                      `json:"ok"`
		Data PreferencesImportResponse `json:"data"`
	}
	if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Data.Theme != "auto" || resp.Data.Lang != "zh" {
		t.Errorf("Theme=%q Lang=%q, want auto/zh", resp.Data.Theme, resp.Data.Lang)
	}
}

func TestAPIV1ServerPreferencesImportHandler_UnvalidatedTheme_NoRedirect(t *testing.T) {
	h := newTestPagesHandler()
	h.ValidateTheme = testValidateTheme
	req := httptest.NewRequest(http.MethodGet, "/api/v1/server/preferences/import?theme=bogus", nil)
	w := httptest.NewRecorder()

	h.APIV1ServerPreferencesImportHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d (API path never redirects)", res.StatusCode, http.StatusOK)
	}
	if len(res.Cookies()) != 0 {
		t.Errorf("cookies = %v, want none for an invalid theme", res.Cookies())
	}
}

// TestResolveRobotsDirective covers the per-route robots meta value
// (AI.md PART 16 "Robots Directive"): explicitly public routes are
// indexable, everything else fails closed.
func TestResolveRobotsDirective(t *testing.T) {
	tests := map[string]string{
		"/":                          "index,follow",
		"/server/about":              "index,follow",
		"/server/about/":             "index,follow",
		"/server/help":               "index,follow",
		"/server/healthz":            "noindex,nofollow",
		"/server/preferences":        "noindex,nofollow",
		"/api/v1/server/about":       "noindex,nofollow",
		"/debug/pprof":               "noindex,nofollow",
		"/8.8.8.8":                   "noindex,nofollow",
		"/server/preferences/export": "noindex,nofollow",
	}
	for path, want := range tests {
		if got := ResolveRobotsDirective(path); got != want {
			t.Errorf("ResolveRobotsDirective(%q) = %q, want %q", path, got, want)
		}
	}
}

// TestNextTheme covers the dark -> light -> auto -> dark cycle the theme
// toggle renders as its POST target (AI.md PART 16 "Theme Cycle Logic").
func TestNextTheme(t *testing.T) {
	tests := map[string]string{
		"dark":  "light",
		"light": "auto",
		"auto":  "dark",
		"":      "dark",
		"bogus": "dark",
	}
	for in, want := range tests {
		if got := NextTheme(in); got != want {
			t.Errorf("NextTheme(%q) = %q, want %q", in, got, want)
		}
	}
}
