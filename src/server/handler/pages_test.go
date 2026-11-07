package handler

import (
	"bufio"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/apimgr/ipgaze/src/config"
	"github.com/apimgr/ipgaze/src/db"
	"github.com/apimgr/ipgaze/src/email"
	"github.com/apimgr/ipgaze/src/netutil"
	"github.com/apimgr/ipgaze/src/security"
	_ "modernc.org/sqlite"
)

// browserUserAgent is a graphical-browser User-Agent. Frontend page tests that
// assert on rendered HTML must send one: under AI.md PART 14 a request with no
// User-Agent is classified as an HTTP tool and receives HTML2TextConverter
// output instead of the HTML document.
const browserUserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"

// newBrowserRequest builds a GET request that the PART 14 dispatch classifies
// as a graphical browser.
func newBrowserRequest(target string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Header.Set("User-Agent", browserUserAgent)
	return req
}

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

func TestFormatUserTimestamp(t *testing.T) {
	if got := formatUserTimestamp("2026-11-06T16:00:00Z"); !strings.HasPrefix(got, "November 06, 2026 at ") {
		t.Errorf("formatUserTimestamp() = %q, want localized human-readable date", got)
	}
	if got := formatUserTimestamp("N/A"); got != "N/A" {
		t.Errorf("formatUserTimestamp(N/A) = %q, want unchanged fallback", got)
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
	req := newBrowserRequest("/server/about")
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

	var body APIResponse
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if !body.OK {
		t.Fatal("OK = false, want success envelope")
	}
	data, ok := body.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("Data type = %T, want object", body.Data)
	}
	if data["name"] != "IPGaze" {
		t.Errorf("Name = %v, want IPGaze", data["name"])
	}
	if data["version"] != "1.0.0" {
		t.Errorf("Version = %v, want 1.0.0", data["version"])
	}
}

func TestServerHelpHandler(t *testing.T) {
	h := newTestPagesHandler()
	req := newBrowserRequest("/server/help")
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
	var body APIResponse
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	data, ok := body.Data.(map[string]interface{})
	if !body.OK || !ok || len(data["sections"].([]interface{})) == 0 {
		t.Error("success envelope has no help sections")
		return
	}
	sections := data["sections"].([]interface{})
	ids := make(map[string]bool, len(sections))
	for _, sectionValue := range sections {
		section, ok := sectionValue.(map[string]interface{})
		if !ok {
			continue
		}
		ids[section["id"].(string)] = true
	}
	for _, id := range []string{"getting-started", "features", "faq", "troubleshooting"} {
		if !ids[id] {
			t.Errorf("help response is missing required %q section", id)
		}
	}
}

func TestAPIV1ServerMCPHelpHandler(t *testing.T) {
	h := newTestPagesHandler()
	h.MCPEnabled = true
	h.MCPTools = func(*http.Request) []MCPToolDescription {
		return []MCPToolDescription{{Name: "lookup_ip", Description: "Look up an IP address"}}
	}
	req := httptest.NewRequest(http.MethodGet, "https://example.test/api/v1/server/help/mcp", nil)
	w := httptest.NewRecorder()
	h.APIV1ServerMCPHelpHandler(w, req)

	var body APIResponse
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	data, ok := body.Data.(map[string]interface{})
	if !body.OK || !ok {
		t.Fatalf("response data = %T, want success object", body.Data)
	}
	if data["url"] != "https://example.test/api/v1/server/mcp" {
		t.Errorf("url = %v, want request-aware MCP URL", data["url"])
	}
	tools, ok := data["tools"].([]interface{})
	if !ok || len(tools) != 1 || tools[0].(map[string]interface{})["name"] != "lookup_ip" {
		t.Errorf("tools = %#v, want the registered tool", data["tools"])
	}
}

func TestAPIV1ServerMCPHelpHandlerDisabled(t *testing.T) {
	h := newTestPagesHandler()
	w := httptest.NewRecorder()
	h.APIV1ServerMCPHelpHandler(w, httptest.NewRequest(http.MethodGet, "/api/v1/server/help/mcp", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
	var body APIResponse
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if body.OK || body.Error != "NOT_FOUND" {
		t.Errorf("error envelope = %#v, want NOT_FOUND", body)
	}
}

func TestSecurityPolicyPageAndAPI(t *testing.T) {
	h := newTestPagesHandler()
	pageResponse := httptest.NewRecorder()
	h.ServerSecurityPolicyHandler(pageResponse, newBrowserRequest("/server/security/policy"))
	if !strings.Contains(pageResponse.Body.String(), "security_policy.tmpl") {
		t.Fatalf("page body = %q, want security policy template", pageResponse.Body.String())
	}

	apiResponse := httptest.NewRecorder()
	h.APIV1ServerSecurityPolicyHandler(apiResponse, httptest.NewRequest(http.MethodGet, "/api/v1/server/security/policy", nil))
	var envelope APIResponse
	if err := json.NewDecoder(apiResponse.Body).Decode(&envelope); err != nil {
		t.Fatalf("decode policy response: %v", err)
	}
	data, ok := envelope.Data.(map[string]interface{})
	if !envelope.OK || !ok || data["disclosure_window"] == "" || len(data["in_scope"].([]interface{})) == 0 {
		t.Fatalf("policy envelope = %#v, want populated policy", envelope)
	}

	localizedRequest := httptest.NewRequest(http.MethodGet, "/api/v1/server/security/policy", nil)
	localizedRequest.Header.Set("Accept-Language", "es")
	localizedResponse := httptest.NewRecorder()
	h.APIV1ServerSecurityPolicyHandler(localizedResponse, localizedRequest)
	var localizedEnvelope APIResponse
	if err := json.NewDecoder(localizedResponse.Body).Decode(&localizedEnvelope); err != nil {
		t.Fatalf("decode localized policy response: %v", err)
	}
	localizedData, ok := localizedEnvelope.Data.(map[string]interface{})
	if !localizedEnvelope.OK || !ok || !strings.HasPrefix(localizedData["disclosure_window"].(string), "Solicitamos") {
		t.Fatalf("localized policy envelope = %#v, want Spanish disclosure policy", localizedEnvelope)
	}
}

func TestSecurityThanksAPI(t *testing.T) {
	h := newTestPagesHandler()
	w := httptest.NewRecorder()
	h.APIV1ServerSecurityThanksHandler(w, httptest.NewRequest(http.MethodGet, "/api/v1/server/security/thanks", nil))
	var envelope APIResponse
	if err := json.NewDecoder(w.Body).Decode(&envelope); err != nil {
		t.Fatalf("decode acknowledgments response: %v", err)
	}
	data, ok := envelope.Data.(map[string]interface{})
	if !envelope.OK || !ok || len(data["researchers"].([]interface{})) != 0 {
		t.Fatalf("acknowledgments envelope = %#v, want empty list", envelope)
	}
}

func TestServerPrivacyHandler(t *testing.T) {
	h := newTestPagesHandler()
	req := newBrowserRequest("/server/privacy")
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
	var body APIResponse
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	data, ok := body.Data.(map[string]interface{})
	if !body.OK || !ok {
		t.Fatalf("response = %#v, want success envelope", body)
	}
	summary, ok := data["summary"].(map[string]interface{})
	if !ok {
		t.Fatalf("summary = %#v, want object", data["summary"])
	}
	if summary["data_stored_on_server"].(bool) {
		t.Error("DataStoredOnServer = true, want false")
	}
	if summary["data_sold"].(bool) {
		t.Error("DataSold = true, want false")
	}
	if !summary["user_control"].(bool) {
		t.Error("UserControl = false, want true")
	}
}

func TestAPIV1ServerSecurityHandler(t *testing.T) {
	h := newTestPagesHandler()
	h.PGPFingerprint = func() string { return strings.Repeat("a", 64) }
	w := httptest.NewRecorder()
	h.APIV1ServerSecurityHandler(w, httptest.NewRequest(http.MethodGet, "https://example.test/api/v1/server/security", nil))
	var envelope APIResponse
	if err := json.NewDecoder(w.Body).Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	data, ok := envelope.Data.(map[string]interface{})
	if !envelope.OK || !ok || data["security_txt"] != "https://example.test/.well-known/security.txt" {
		t.Fatalf("security response = %#v, want request-aware security.txt URL", envelope)
	}
	if data["fingerprint"] != strings.Repeat("a", 64) {
		t.Fatalf("fingerprint = %v, want full SHA-256 fingerprint", data["fingerprint"])
	}
}

func TestSecurityReportStatusWithoutDatabaseReturnsNotFound(t *testing.T) {
	h := newTestPagesHandler()
	w := httptest.NewRecorder()
	h.ServerSecurityReportHandler(w, newBrowserRequest("/server/security/report/sec_missing?token=invalid"), "sec_missing")
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

func TestSecurityReportStatusConsumesToken(t *testing.T) {
	conn, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := db.EnsureSchema(conn); err != nil {
		t.Fatal(err)
	}
	trackingID, err := security.NewSecurityTrackingID()
	if err != nil {
		t.Fatal(err)
	}
	token, tokenHash, err := security.NewSecurityAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := security.StoreSecurityReport(conn, security.SecurityReportMetadata{
		TrackingID: trackingID, Ciphertext: []byte("encrypted report"), Encryption: "aes-256-gcm",
		Severity: "high", AccessTokenHash: tokenHash,
	}); err != nil {
		t.Fatal(err)
	}
	h := newTestPagesHandler()
	h.DB = conn
	request := newBrowserRequest("/server/security/report/" + trackingID + "?token=" + token)
	response := httptest.NewRecorder()
	h.ServerSecurityReportHandler(response, request, trackingID)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "security_report_status.tmpl") {
		t.Fatalf("status response = %d %q, want rendered report status", response.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", response.Header().Get("Cache-Control"))
	}
	reused := httptest.NewRecorder()
	h.ServerSecurityReportHandler(reused, request, trackingID)
	if reused.Code != http.StatusNotFound {
		t.Errorf("reused token status = %d, want %d", reused.Code, http.StatusNotFound)
	}
}

func TestServerContactHandler_GET(t *testing.T) {
	h := newTestPagesHandler()
	req := newBrowserRequest("/server/contact")
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
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE app_secrets (name TEXT PRIMARY KEY, value TEXT NOT NULL, previous_value TEXT, previous_until INTEGER, created_at INTEGER, rotated_at INTEGER)`); err != nil {
		t.Fatal(err)
	}
	h.DB = db
	question, token, err := newSimpleCaptcha(db, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Fields(strings.TrimSuffix(strings.TrimPrefix(question, "What is "), "?"))
	answer := 0
	for _, part := range parts {
		if part == "+" {
			continue
		}
		value, err := strconv.Atoi(part)
		if err != nil {
			t.Fatal(err)
		}
		answer += value
	}
	encoded, err := json.Marshal(ContactRequest{Name: "Example User", Email: "user@example.com", Subject: "Question", Message: "hello", Captcha: strconv.Itoa(answer), CaptchaToken: token})
	if err != nil {
		t.Fatal(err)
	}
	reqBody := strings.NewReader(string(encoded))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/server/contact", reqBody)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.APIV1ServerContactHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", res.StatusCode, http.StatusOK)
	}
	var body APIResponse
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	data, ok := body.Data.(map[string]interface{})
	if !body.OK || !ok || data["success"] != true {
		t.Errorf("response = %#v, want successful envelope (question %s)", body, question)
	}
}

func TestSimpleCaptcha_ValidWrongExpiredAndTampered(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE app_secrets (name TEXT PRIMARY KEY, value TEXT NOT NULL, previous_value TEXT, previous_until INTEGER, created_at INTEGER, rotated_at INTEGER)`); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.November, 6, 12, 0, 0, 0, time.UTC)
	question, token, err := newSimpleCaptcha(db, now)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Fields(strings.TrimSuffix(strings.TrimPrefix(question, "What is "), "?"))
	answer := 0
	for _, part := range parts {
		if part == "+" {
			continue
		}
		value, err := strconv.Atoi(part)
		if err != nil {
			t.Fatal(err)
		}
		answer += value
	}
	if !verifySimpleCaptcha(db, token, strconv.Itoa(answer), now) {
		t.Fatal("valid captcha answer was rejected")
	}
	if verifySimpleCaptcha(db, token, strconv.Itoa(answer+1), now) {
		t.Fatal("incorrect captcha answer was accepted")
	}
	if verifySimpleCaptcha(db, token, strconv.Itoa(answer), now.Add(21*time.Minute)) {
		t.Fatal("expired captcha token was accepted")
	}
	if verifySimpleCaptcha(db, token+"tampered", strconv.Itoa(answer), now) {
		t.Fatal("tampered captcha token was accepted")
	}
}

func TestSubmitSecurityReportEncryptedAndNotifies(t *testing.T) {
	conn, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := db.EnsureSchema(conn); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	securityID, err := security.CurrentSecurityID(conn, now)
	if err != nil {
		t.Fatal(err)
	}
	question, captchaToken, err := newSimpleCaptcha(conn, now)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Fields(strings.TrimSuffix(strings.TrimPrefix(question, "What is "), "?"))
	first, err := strconv.Atoi(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	second, err := strconv.Atoi(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	host, port, messages := fakeTwoMessageSMTPServer(t)
	cfg := config.DefaultConfig()
	encryptionKey := make([]byte, 32)
	cfg.Server.Security.EncryptionKey = base64.StdEncoding.EncodeToString(encryptionKey)
	cfg.Server.Contact.Security.Email = "security@example.com"
	h := newTestPagesHandler()
	h.DB = conn
	h.Config = cfg
	h.EmailMgr = email.NewEmailManager(email.SMTPConfig{Enabled: true, Host: host, Port: port, From: "noreply@example.com", TLS: "none"}, "")
	req := ContactRequest{
		Name: "Reporter Name", Email: "reporter@example.net", SecurityID: securityID,
		AffectedComponent: "API", Severity: "high", Summary: "Private vulnerability details",
		StepsToReproduce: "Private reproduction steps", Impact: "Private impact details",
		CreditPreference: "anonymous", CoordinatedAgreement: true,
		Captcha: strconv.Itoa(first + second), CaptchaToken: captchaToken,
	}
	trackingID, err := h.submitSecurityReport(httptest.NewRequest(http.MethodPost, "https://example.test/api/v1/server/contact", nil), req)
	if err != nil {
		t.Fatalf("submitSecurityReport: %v", err)
	}
	if !strings.HasPrefix(trackingID, "sec_") {
		t.Fatalf("tracking ID = %q, want sec_ prefix", trackingID)
	}
	var ciphertext []byte
	var encryption string
	if err := conn.QueryRow(`SELECT encrypted_body, encryption FROM security_reports WHERE tracking_id = ?`, trackingID).Scan(&ciphertext, &encryption); err != nil {
		t.Fatal(err)
	}
	if encryption != "aes-256-gcm" || strings.Contains(string(ciphertext), "Private vulnerability details") || strings.Contains(string(ciphertext), "reporter@example.net") {
		t.Fatalf("stored report encryption=%q body must not contain plaintext, got %q", encryption, ciphertext)
	}
	plain, err := security.DecryptWithSecret(encryptionKey, ciphertext, "security-reports")
	if err != nil || !strings.Contains(string(plain), "Private vulnerability details") || !strings.Contains(string(plain), "reporter@example.net") {
		t.Fatalf("stored encrypted payload did not decrypt to the private report: err=%v", err)
	}
	firstMessage, secondMessage := <-messages, <-messages
	firstMessage = strings.ReplaceAll(firstMessage, "=\r\n", "")
	if !strings.Contains(firstMessage, "/server/security/report/"+trackingID+"?token=3D") || !strings.Contains(secondMessage, trackingID+".enc") {
		t.Errorf("notification messages missing acknowledgment status URL or encrypted attachment")
	}
}

func fakeTwoMessageSMTPServer(t *testing.T) (string, int, <-chan string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	messages := make(chan string, 2)
	go func() {
		for range 2 {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			serveFakeSMTPConnection(conn, messages)
		}
	}()
	host, portString, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portString)
	if err != nil {
		t.Fatal(err)
	}
	return host, port, messages
}

func serveFakeSMTPConnection(conn net.Conn, messages chan<- string) {
	defer func() { _ = conn.Close() }()
	write := func(response string) { _, _ = fmt.Fprint(conn, response) }
	reader := bufio.NewReader(conn)
	write("220 test.smtp.local ESMTP\r\n")
	var message strings.Builder
	inData := false
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		command := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case inData:
			if strings.TrimRight(line, "\r\n") == "." {
				messages <- message.String()
				inData = false
				write("250 OK queued\r\n")
			} else {
				message.WriteString(line)
			}
		case strings.HasPrefix(command, "EHLO"):
			write("250-test.smtp.local\r\n250 OK\r\n")
		case strings.HasPrefix(command, "MAIL FROM"), strings.HasPrefix(command, "RCPT TO"):
			write("250 OK\r\n")
		case command == "DATA":
			inData = true
			message.Reset()
			write("354 Start mail input\r\n")
		case command == "QUIT":
			write("221 Bye\r\n")
			return
		default:
			write("500 unrecognized command\r\n")
		}
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
	var body APIResponse
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if body.OK || body.Error != "BAD_REQUEST" {
		t.Errorf("response = %#v, want BAD_REQUEST error envelope", body)
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
	req := newBrowserRequest("/server/terms")
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
	var body APIResponse
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	data, ok := body.Data.(map[string]interface{})
	if !body.OK || !ok || len(data["sections"].([]interface{})) == 0 {
		t.Error("success envelope has no terms sections")
	}
	if data["last_updated"] == "" {
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
	req := newBrowserRequest("/server/preferences")
	req.AddCookie(&http.Cookie{Name: "lang", Value: "fr"})
	req.AddCookie(&http.Cookie{Name: lookupWidgetPreferenceCookie, Value: "city"})
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
	if got := h.NewPageData(req).DefaultWidget; got != "city" {
		t.Errorf("NewPageData().DefaultWidget = %q, want city", got)
	}
}

func TestServerPreferencesUpdateHandler_SetsWidgetPreference(t *testing.T) {
	h := newTestPagesHandler()
	req := httptest.NewRequest(http.MethodPost, "/server/preferences", strings.NewReader("ipgaze_pref_widget=city"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.ServerPreferencesUpdateHandler(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusSeeOther)
	}
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == lookupWidgetPreferenceCookie && cookie.Value == "city" && cookie.MaxAge == 365*24*60*60 && !cookie.HttpOnly {
			return
		}
	}
	t.Fatal("expected a one-year readable ipgaze_pref_widget cookie")
}

func TestAPIV1ServerPreferencesUpdateHandler_AppliesWidgetPreference(t *testing.T) {
	h := newTestPagesHandler()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/server/preferences", strings.NewReader(`{"prefs":{"widget":"json"}}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.APIV1ServerPreferencesUpdateHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", w.Code, http.StatusOK, w.Body.String())
	}
	var response struct {
		Data PreferencesResponse `json:"data"`
	}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Data.Prefs["widget"] != "json" || !containsPreference(response.Data.Applied, lookupWidgetPreferenceCookie) {
		t.Errorf("response data = %#v, want widget=json applied", response.Data)
	}
}

func TestAPIV1ServerPreferencesUpdateHandler_RejectsNoValidValues(t *testing.T) {
	h := newTestPagesHandler()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/server/preferences", strings.NewReader(`{"prefs":{"widget":"invalid"}}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.APIV1ServerPreferencesUpdateHandler(w, req)

	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "VALIDATION_FAILED") {
		t.Errorf("status/body = %d %q, want 400 VALIDATION_FAILED", w.Code, w.Body.String())
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
	if resp.Data.Prefs == nil || len(resp.Data.Prefs) != 0 {
		t.Errorf("Prefs = %#v, want an empty preference map", resp.Data.Prefs)
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

func TestAPIV1ServerPreferencesExportHandler_ExportsWidgetPreference(t *testing.T) {
	h := newTestPagesHandler()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/server/preferences/export", nil)
	req.AddCookie(&http.Cookie{Name: lookupWidgetPreferenceCookie, Value: "city"})
	w := httptest.NewRecorder()

	h.APIV1ServerPreferencesExportHandler(w, req)

	var body struct {
		Data PreferencesExportResponse `json:"data"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Data.Prefs["widget"] != "city" || !strings.Contains(body.Data.URL, "ipgaze_pref_widget=city") {
		t.Errorf("export = %#v, want widget=city in prefs and URL", body.Data)
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
	if loc := res.Header.Get("Location"); loc != "/" {
		t.Errorf("Location = %q, want fallback %q for preferences route", loc, "/")
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

func TestServerPreferencesImportHandler_PaddedCodeAndDirectValuesWin(t *testing.T) {
	h := newTestPagesHandler()
	code := base64.URLEncoding.EncodeToString([]byte("theme=light&ipgaze_pref_widget=city"))
	req := httptest.NewRequest(http.MethodGet, "/server/preferences/import?code="+url.QueryEscape(code)+"&theme=dark&ipgaze_pref_widget=asn", nil)
	w := httptest.NewRecorder()

	h.ServerPreferencesImportHandler(w, req)

	got := map[string]string{}
	for _, cookie := range w.Result().Cookies() {
		got[cookie.Name] = cookie.Value
	}
	if got["theme"] != "dark" || got[lookupWidgetPreferenceCookie] != "asn" {
		t.Errorf("imported cookies = %#v, want direct theme/widget values", got)
	}
}

func TestServerPreferencesImportHandler_AppliesWidgetPreference(t *testing.T) {
	h := newTestPagesHandler()
	req := httptest.NewRequest(http.MethodGet, "/server/preferences/import?ipgaze_pref_widget=asn", nil)
	w := httptest.NewRecorder()

	h.ServerPreferencesImportHandler(w, req)

	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == lookupWidgetPreferenceCookie {
			if cookie.Value != "asn" {
				t.Fatalf("widget preference cookie = %q, want asn", cookie.Value)
			}
			return
		}
	}
	t.Fatal("widget preference cookie missing")
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

func TestAPIV1ServerPreferencesImportHandler_AppliesWidgetAndIgnoresConsent(t *testing.T) {
	h := newTestPagesHandler()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/server/preferences/import?ipgaze_pref_widget=port&cookie_consent=accepted", nil)
	w := httptest.NewRecorder()

	h.APIV1ServerPreferencesImportHandler(w, req)

	var response struct {
		Data PreferencesImportResponse `json:"data"`
	}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Data.Prefs["widget"] != "port" || !containsPreference(response.Data.Applied, lookupWidgetPreferenceCookie) {
		t.Errorf("import response = %#v, want widget=port applied", response.Data)
	}
	if !containsPreference(response.Data.Ignored, "cookie_consent") {
		t.Errorf("ignored = %#v, want cookie_consent", response.Data.Ignored)
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

// TestAllowContactSubmissionPrunesExpiredEntries verifies the per-IP throttle
// map is bounded: once it reaches contactThrottleMaxEntries, entries older
// than the cooldown window are swept instead of accumulating forever.
func TestAllowContactSubmissionPrunesExpiredEntries(t *testing.T) {
	contactThrottle.mu.Lock()
	contactThrottle.last = make(map[string]time.Time)
	stale := time.Now().Add(-2 * contactThrottleWindow)
	for i := 0; i < contactThrottleMaxEntries; i++ {
		contactThrottle.last["10.0."+strconv.Itoa(i/256)+"."+strconv.Itoa(i%256)] = stale
	}
	contactThrottle.mu.Unlock()

	if !allowContactSubmission("203.0.113.7") {
		t.Fatal("first submission from a fresh IP should be allowed")
	}

	contactThrottle.mu.Lock()
	size := len(contactThrottle.last)
	contactThrottle.mu.Unlock()
	if size != 1 {
		t.Errorf("expected stale entries pruned leaving 1 entry, got %d", size)
	}

	if allowContactSubmission("203.0.113.7") {
		t.Error("second submission inside the cooldown window should be rejected")
	}

	contactThrottle.mu.Lock()
	contactThrottle.last = make(map[string]time.Time)
	contactThrottle.mu.Unlock()
}

func TestRenderNegotiated_OurCLIGetsJSON(t *testing.T) {
	h := newTestPagesHandler()
	req := httptest.NewRequest(http.MethodGet, "/server/about", nil)
	req.Header.Set("User-Agent", "ipgaze-cli/1.2.3")
	w := httptest.NewRecorder()

	h.ServerAboutHandler(w, req)

	res := w.Result()
	if ct := res.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}
	var body APIResponse
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	data, ok := body.Data.(map[string]interface{})
	if !body.OK || !ok || data["name"] != "IPGaze" {
		t.Errorf("response = %#v, want IPGaze success envelope", body)
	}
}

func TestRenderNegotiated_HTTPToolGetsPlainText(t *testing.T) {
	h := NewPagesHandler("1.0.0", "2024-01-01", netutil.NewTrustResolver(config.TrustedProxiesConfig{}, ""), func(w http.ResponseWriter, _ *http.Request, page string, data interface{}) error {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte("<html><body><h1>" + page + "</h1></body></html>")) //nolint:errcheck
		return nil
	})
	req := httptest.NewRequest(http.MethodGet, "/server/about", nil)
	req.Header.Set("User-Agent", "curl/8.5.0")
	w := httptest.NewRecorder()

	h.ServerAboutHandler(w, req)

	res := w.Result()
	if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
	body := w.Body.String()
	if strings.Contains(body, "<h1>") {
		t.Errorf("body still contains HTML markup: %q", body)
	}
	// HTML2TextConverter renders an <h1> as an uppercase banner heading, so
	// match case-insensitively rather than on the raw template name.
	if !strings.Contains(strings.ToLower(body), "about.tmpl") {
		t.Errorf("body lost its content: %q", body)
	}
}

func TestRenderNegotiated_TextBrowserGetsHTML(t *testing.T) {
	h := newTestPagesHandler()
	req := httptest.NewRequest(http.MethodGet, "/server/about", nil)
	req.Header.Set("User-Agent", "Lynx/2.9.0dev.10 libwww-FM/2.14")
	w := httptest.NewRecorder()

	h.ServerAboutHandler(w, req)

	res := w.Result()
	if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	if !strings.Contains(w.Body.String(), "about.tmpl") {
		t.Errorf("body does not reference about.tmpl: %q", w.Body.String())
	}
}
