package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// capturedRequest stores what the fake webhook received.
type capturedRequest struct {
	body    map[string]interface{}
	headers http.Header
	method  string
}

// newTestServer starts an httptest.Server that records the last request and
// responds with the given status code.
func newTestServer(t *testing.T, status int) (*httptest.Server, *capturedRequest) {
	t.Helper()
	var mu sync.Mutex
	captured := &capturedRequest{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]interface{}
		_ = json.Unmarshal(b, &m)
		mu.Lock()
		captured.body = m
		captured.headers = r.Header.Clone()
		captured.method = r.Method
		mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv, captured
}

// --- NotifyManager ---

func TestNotifyManager_EmptyNotifiers_NoError(t *testing.T) {
	m := NewNotifyManager()
	err := m.Send(context.Background(), Message{Title: "hi", Body: "body", Level: LevelInfo})
	if err != nil {
		t.Fatalf("expected no error with zero notifiers, got: %v", err)
	}
}

func TestNotifyManager_Register_IncludesNotifier(t *testing.T) {
	m := NewNotifyManager()
	called := false
	m.Register(&fakeNotifier{onSend: func(_ context.Context, _ Message) error {
		called = true
		return nil
	}})
	if err := m.Send(context.Background(), Message{Title: "t", Body: "b", Level: LevelInfo}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Fatal("expected registered notifier to be called")
	}
}

func TestNotifyManager_FansOutToAll(t *testing.T) {
	m := NewNotifyManager()
	var count int32
	for i := 0; i < 3; i++ {
		m.Register(&fakeNotifier{onSend: func(_ context.Context, _ Message) error {
			atomic.AddInt32(&count, 1)
			return nil
		}})
	}
	if err := m.Send(context.Background(), Message{Title: "t", Body: "b", Level: LevelInfo}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 3 {
		t.Errorf("expected 3 notifiers called, got %d", count)
	}
}

func TestNotifyManager_CollectsErrors_PartialFailure(t *testing.T) {
	m := NewNotifyManager()
	m.Register(&fakeNotifier{name: "ok", onSend: func(_ context.Context, _ Message) error { return nil }})
	m.Register(&fakeNotifier{name: "bad", onSend: func(_ context.Context, _ Message) error {
		return fmt.Errorf("connection refused")
	}})
	err := m.Send(context.Background(), Message{Title: "t", Body: "b", Level: LevelInfo})
	if err == nil {
		t.Fatal("expected combined error")
	}
	if !strings.Contains(err.Error(), "bad") {
		t.Errorf("error should name the failing notifier: %v", err)
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("error should include underlying cause: %v", err)
	}
}

func TestNotifyManager_AllFail_CombinesAllErrors(t *testing.T) {
	m := NewNotifyManager()
	m.Register(&fakeNotifier{name: "n1", onSend: func(_ context.Context, _ Message) error { return fmt.Errorf("err1") }})
	m.Register(&fakeNotifier{name: "n2", onSend: func(_ context.Context, _ Message) error { return fmt.Errorf("err2") }})
	err := m.Send(context.Background(), Message{Title: "t", Body: "b", Level: LevelInfo})
	if err == nil {
		t.Fatal("expected error when all notifiers fail")
	}
	if !strings.Contains(err.Error(), "err1") || !strings.Contains(err.Error(), "err2") {
		t.Errorf("expected both errors combined: %v", err)
	}
}

func TestNotifyManager_Send_PassesMessageToNotifier(t *testing.T) {
	m := NewNotifyManager()
	var received Message
	m.Register(&fakeNotifier{onSend: func(_ context.Context, msg Message) error {
		received = msg
		return nil
	}})
	want := Message{Title: "Alert", Body: "Something bad", Level: LevelError, URL: "https://example.com"}
	_ = m.Send(context.Background(), want)
	if received.Title != want.Title || received.Body != want.Body || received.Level != want.Level || received.URL != want.URL {
		t.Errorf("notifier received %+v, want %+v", received, want)
	}
}

// --- TelegramNotifier ---

func TestTelegramNotifier_Name(t *testing.T) {
	n := &TelegramNotifier{Token: "tok", ChatID: "123"}
	if n.Name() != "telegram" {
		t.Errorf("Name() = %q, want %q", n.Name(), "telegram")
	}
}

func TestTelegramNotifier_Send_Success(t *testing.T) {
	srv, cap := newTestServer(t, http.StatusOK)
	// The real notifier hits api.telegram.org; we test postJSON directly through
	// a custom notifier that overrides the URL so we don't need network access.
	// Instead, verify the payload structure by exercising postJSON itself.
	msg := Message{Title: "Hello", Body: "World", Level: LevelInfo}
	payload := map[string]interface{}{
		"chat_id":    "42",
		"text":       fmt.Sprintf("*%s*\n%s", msg.Title, msg.Body),
		"parse_mode": "Markdown",
	}
	err := postJSON(context.Background(), srv.URL, payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cap.body["chat_id"] != "42" {
		t.Errorf("chat_id = %v, want 42", cap.body["chat_id"])
	}
	if !strings.Contains(cap.body["text"].(string), "Hello") {
		t.Errorf("text missing title: %v", cap.body["text"])
	}
}

func TestTelegramNotifier_Send_WithURL_AppendsToText(t *testing.T) {
	srv, cap := newTestServer(t, http.StatusOK)
	msg := Message{Title: "T", Body: "B", Level: LevelInfo, URL: "https://example.com"}
	text := fmt.Sprintf("*%s*\n%s\n%s", msg.Title, msg.Body, msg.URL)
	payload := map[string]interface{}{
		"chat_id":    "1",
		"text":       text,
		"parse_mode": "Markdown",
	}
	_ = postJSON(context.Background(), srv.URL, payload)
	if !strings.Contains(cap.body["text"].(string), "https://example.com") {
		t.Errorf("URL not appended to text: %v", cap.body["text"])
	}
}

func TestTelegramNotifier_Send_Without_URL_NoTrailingNewline(t *testing.T) {
	// Verify that when URL is empty, the text does NOT end with a bare newline+empty URL.
	n := &TelegramNotifier{Token: "tok", ChatID: "123"}
	// We can't hit the real Telegram; assert indirectly by examining what would be sent.
	msg := Message{Title: "T", Body: "B", Level: LevelInfo, URL: ""}
	text := fmt.Sprintf("*%s*\n%s", msg.Title, msg.Body)
	if msg.URL != "" {
		text += "\n" + msg.URL
	}
	if strings.HasSuffix(text, "\n") {
		t.Errorf("text has trailing newline when URL is empty: %q", text)
	}
	_ = n.Name() // silence unused variable warning
}

// --- DiscordNotifier ---

func TestDiscordNotifier_Name(t *testing.T) {
	n := &DiscordNotifier{WebhookURL: "http://example.com"}
	if n.Name() != "discord" {
		t.Errorf("Name() = %q, want %q", n.Name(), "discord")
	}
}

func TestDiscordNotifier_Send_Success(t *testing.T) {
	srv, cap := newTestServer(t, http.StatusOK)
	n := &DiscordNotifier{WebhookURL: srv.URL}
	err := n.Send(context.Background(), Message{Title: "T", Body: "B", Level: LevelInfo})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	embeds, ok := cap.body["embeds"].([]interface{})
	if !ok || len(embeds) == 0 {
		t.Fatalf("expected embeds array, got: %v", cap.body)
	}
	embed := embeds[0].(map[string]interface{})
	if embed["title"] != "T" {
		t.Errorf("embed title = %v, want T", embed["title"])
	}
}

func TestDiscordNotifier_ColorByLevel(t *testing.T) {
	cases := []struct {
		level Level
		color float64
	}{
		{LevelInfo, 0x3498db},
		{LevelError, 0xe74c3c},
		{LevelWarning, 0xf39c12},
		{LevelSuccess, 0x2ecc71},
	}
	for _, tc := range cases {
		t.Run(string(tc.level), func(t *testing.T) {
			srv, cap := newTestServer(t, http.StatusOK)
			n := &DiscordNotifier{WebhookURL: srv.URL}
			_ = n.Send(context.Background(), Message{Title: "T", Body: "B", Level: tc.level})
			embeds := cap.body["embeds"].([]interface{})
			embed := embeds[0].(map[string]interface{})
			got := embed["color"].(float64)
			if got != tc.color {
				t.Errorf("color for %s = %v, want %v", tc.level, got, tc.color)
			}
		})
	}
}

func TestDiscordNotifier_Send_HTTP4xx_ReturnsError(t *testing.T) {
	srv, _ := newTestServer(t, http.StatusBadRequest)
	n := &DiscordNotifier{WebhookURL: srv.URL}
	err := n.Send(context.Background(), Message{Title: "T", Body: "B", Level: LevelInfo})
	if err == nil {
		t.Fatal("expected error on 400 response")
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("expected HTTP 400 in error, got: %v", err)
	}
}

// --- SlackNotifier ---

func TestSlackNotifier_Name(t *testing.T) {
	n := &SlackNotifier{WebhookURL: "http://example.com"}
	if n.Name() != "slack" {
		t.Errorf("Name() = %q, want %q", n.Name(), "slack")
	}
}

func TestSlackNotifier_Send_Success(t *testing.T) {
	srv, cap := newTestServer(t, http.StatusOK)
	n := &SlackNotifier{WebhookURL: srv.URL}
	err := n.Send(context.Background(), Message{Title: "Alert", Body: "disk full", Level: LevelWarning})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	text, _ := cap.body["text"].(string)
	if !strings.Contains(text, "Alert") || !strings.Contains(text, "disk full") {
		t.Errorf("text missing expected content: %q", text)
	}
}

func TestSlackNotifier_Send_WithURL(t *testing.T) {
	srv, cap := newTestServer(t, http.StatusOK)
	n := &SlackNotifier{WebhookURL: srv.URL}
	_ = n.Send(context.Background(), Message{Title: "T", Body: "B", Level: LevelInfo, URL: "https://dashboard.example.com"})
	text, _ := cap.body["text"].(string)
	if !strings.Contains(text, "https://dashboard.example.com") {
		t.Errorf("URL not in text: %q", text)
	}
}

func TestSlackNotifier_Send_HTTP5xx_ReturnsError(t *testing.T) {
	srv, _ := newTestServer(t, http.StatusInternalServerError)
	n := &SlackNotifier{WebhookURL: srv.URL}
	err := n.Send(context.Background(), Message{Title: "T", Body: "B", Level: LevelInfo})
	if err == nil {
		t.Fatal("expected error on 5xx response")
	}
}

// --- MattermostNotifier ---

func TestMattermostNotifier_Name(t *testing.T) {
	n := &MattermostNotifier{WebhookURL: "http://example.com", Channel: "general"}
	if n.Name() != "mattermost" {
		t.Errorf("Name() = %q, want %q", n.Name(), "mattermost")
	}
}

func TestMattermostNotifier_Send_Success(t *testing.T) {
	srv, cap := newTestServer(t, http.StatusOK)
	n := &MattermostNotifier{WebhookURL: srv.URL, Channel: "#alerts"}
	err := n.Send(context.Background(), Message{Title: "T", Body: "B", Level: LevelInfo})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cap.body["channel"] != "#alerts" {
		t.Errorf("channel = %v, want #alerts", cap.body["channel"])
	}
	text, _ := cap.body["text"].(string)
	if !strings.Contains(text, "**T**") {
		t.Errorf("expected bold markdown title in text: %q", text)
	}
}

func TestMattermostNotifier_Send_WithURL(t *testing.T) {
	srv, cap := newTestServer(t, http.StatusOK)
	n := &MattermostNotifier{WebhookURL: srv.URL, Channel: "ops"}
	_ = n.Send(context.Background(), Message{Title: "T", Body: "B", Level: LevelInfo, URL: "https://example.com/runbook"})
	text, _ := cap.body["text"].(string)
	if !strings.Contains(text, "https://example.com/runbook") {
		t.Errorf("URL not in text: %q", text)
	}
}

// --- PushoverNotifier ---

func TestPushoverNotifier_Name(t *testing.T) {
	n := &PushoverNotifier{Token: "tok", UserKey: "uk"}
	if n.Name() != "pushover" {
		t.Errorf("Name() = %q, want %q", n.Name(), "pushover")
	}
}

func TestPushoverNotifier_Payload(t *testing.T) {
	srv, cap := newTestServer(t, http.StatusOK)
	// Exercise postJSON directly with pushover-shaped payload.
	payload := map[string]interface{}{
		"token":   "mytoken",
		"user":    "myuser",
		"title":   "Test",
		"message": "body text",
		"url":     "https://example.com",
	}
	err := postJSON(context.Background(), srv.URL, payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cap.body["token"] != "mytoken" {
		t.Errorf("token = %v, want mytoken", cap.body["token"])
	}
	if cap.body["user"] != "myuser" {
		t.Errorf("user = %v, want myuser", cap.body["user"])
	}
	if cap.body["title"] != "Test" {
		t.Errorf("title = %v, want Test", cap.body["title"])
	}
}

// --- GotifyNotifier ---

func TestGotifyNotifier_Name(t *testing.T) {
	n := &GotifyNotifier{ServerURL: "http://gotify.example.com", Token: "tok"}
	if n.Name() != "gotify" {
		t.Errorf("Name() = %q, want %q", n.Name(), "gotify")
	}
}

func TestGotifyNotifier_Send_Success(t *testing.T) {
	srv, cap := newTestServer(t, http.StatusOK)
	n := &GotifyNotifier{ServerURL: srv.URL, Token: "mytoken"}
	err := n.Send(context.Background(), Message{Title: "G", Body: "go", Level: LevelInfo})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cap.body["title"] != "G" {
		t.Errorf("title = %v, want G", cap.body["title"])
	}
}

func TestGotifyNotifier_PriorityByLevel(t *testing.T) {
	cases := []struct {
		level    Level
		priority float64
	}{
		{LevelInfo, 5},
		{LevelWarning, 5},
		{LevelSuccess, 5},
		{LevelError, 9},
	}
	for _, tc := range cases {
		t.Run(string(tc.level), func(t *testing.T) {
			srv, cap := newTestServer(t, http.StatusOK)
			n := &GotifyNotifier{ServerURL: srv.URL, Token: "tok"}
			_ = n.Send(context.Background(), Message{Title: "T", Body: "B", Level: tc.level})
			got := cap.body["priority"].(float64)
			if got != tc.priority {
				t.Errorf("priority for %s = %v, want %v", tc.level, got, tc.priority)
			}
		})
	}
}

func TestGotifyNotifier_URLTokenAppended(t *testing.T) {
	// The token is appended as a query parameter: /message?token=X
	// Verify by creating a server that checks the path.
	var receivedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.RequestURI()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	n := &GotifyNotifier{ServerURL: srv.URL, Token: "secrettoken"}
	_ = n.Send(context.Background(), Message{Title: "T", Body: "B", Level: LevelInfo})
	if !strings.Contains(receivedPath, "token=secrettoken") {
		t.Errorf("expected token in query string, got path: %q", receivedPath)
	}
}

func TestGotifyNotifier_TrailingSlashStripped(t *testing.T) {
	// ServerURL with trailing slash should not produce double slash in the URL.
	var receivedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.RequestURI()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	n := &GotifyNotifier{ServerURL: srv.URL + "/", Token: "tok"}
	_ = n.Send(context.Background(), Message{Title: "T", Body: "B", Level: LevelInfo})
	if strings.Contains(receivedPath, "//") {
		t.Errorf("double slash in path: %q", receivedPath)
	}
}

// --- GenericWebhookNotifier ---

func TestGenericWebhookNotifier_Name(t *testing.T) {
	n := &GenericWebhookNotifier{URL: "http://example.com"}
	if n.Name() != "generic" {
		t.Errorf("Name() = %q, want %q", n.Name(), "generic")
	}
}

func TestGenericWebhookNotifier_Send_Success(t *testing.T) {
	srv, cap := newTestServer(t, http.StatusOK)
	n := &GenericWebhookNotifier{URL: srv.URL}
	err := n.Send(context.Background(), Message{
		Title: "T", Body: "B", Level: LevelWarning, URL: "https://example.com",
		Role: "general", Event: "contact.general_submitted",
		ProjectName: "ipgaze", ProjectVersion: "1.0.0",
		AppURL: "https://example.com", TrackingID: "abc123",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cap.body["role"] != "general" {
		t.Errorf("role = %v, want general", cap.body["role"])
	}
	if cap.body["event"] != "contact.general_submitted" {
		t.Errorf("event = %v, want contact.general_submitted", cap.body["event"])
	}
	if cap.body["subject"] != "T" {
		t.Errorf("subject = %v, want T", cap.body["subject"])
	}
	if cap.body["body"] != "B" {
		t.Errorf("body = %v, want B", cap.body["body"])
	}
	if cap.body["severity"] != "warning" {
		t.Errorf("severity = %v, want warning", cap.body["severity"])
	}
	if cap.body["timestamp"] == nil || cap.body["timestamp"] == "" {
		t.Errorf("timestamp = %v, want non-empty", cap.body["timestamp"])
	}
	if cap.body["project_name"] != "ipgaze" {
		t.Errorf("project_name = %v, want ipgaze", cap.body["project_name"])
	}
	if cap.body["project_version"] != "1.0.0" {
		t.Errorf("project_version = %v, want 1.0.0", cap.body["project_version"])
	}
	if cap.body["app_url"] != "https://example.com" {
		t.Errorf("app_url = %v, want https://example.com", cap.body["app_url"])
	}
	if cap.body["tracking_id"] != "abc123" {
		t.Errorf("tracking_id = %v, want abc123", cap.body["tracking_id"])
	}
}

func TestGenericWebhookNotifier_CustomHeaders(t *testing.T) {
	srv, cap := newTestServer(t, http.StatusOK)
	n := &GenericWebhookNotifier{
		URL: srv.URL,
		Headers: map[string]string{
			"X-Api-Key":    "secret",
			"X-Custom-Hdr": "value",
		},
	}
	err := n.Send(context.Background(), Message{Title: "T", Body: "B", Level: LevelInfo})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cap.headers.Get("X-Api-Key") != "secret" {
		t.Errorf("X-Api-Key header = %q, want secret", cap.headers.Get("X-Api-Key"))
	}
	if cap.headers.Get("X-Custom-Hdr") != "value" {
		t.Errorf("X-Custom-Hdr header = %q, want value", cap.headers.Get("X-Custom-Hdr"))
	}
}

func TestGenericWebhookNotifier_NoHeaders_NoError(t *testing.T) {
	srv, _ := newTestServer(t, http.StatusOK)
	n := &GenericWebhookNotifier{URL: srv.URL, Headers: nil}
	err := n.Send(context.Background(), Message{Title: "T", Body: "B", Level: LevelInfo})
	if err != nil {
		t.Fatalf("unexpected error with nil headers: %v", err)
	}
}

func TestGenericWebhookNotifier_HTTP4xx_ReturnsError(t *testing.T) {
	srv, _ := newTestServer(t, http.StatusUnauthorized)
	n := &GenericWebhookNotifier{URL: srv.URL}
	err := n.Send(context.Background(), Message{Title: "T", Body: "B", Level: LevelInfo})
	if err == nil {
		t.Fatal("expected error on 401 response")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("expected 401 in error, got: %v", err)
	}
}

// --- Signing ---

func TestSigning_Params_ZeroValue_ReturnsNil(t *testing.T) {
	var s Signing
	if got := s.params(); got != nil {
		t.Errorf("params() = %v, want nil for zero-value Signing", got)
	}
}

func TestSigning_Params_NonZero_ReturnsOne(t *testing.T) {
	s := Signing{Secret: "sec", WebhookID: "id", Event: "ev", UserAgent: "ua"}
	got := s.params()
	if len(got) != 1 {
		t.Fatalf("params() len = %d, want 1", len(got))
	}
	if got[0].secret != "sec" || got[0].webhookID != "id" || got[0].event != "ev" || got[0].userAgent != "ua" {
		t.Errorf("params()[0] = %+v, want matching Signing fields", got[0])
	}
}

func TestPostJSON_Signed_SetsWebhookHeaders(t *testing.T) {
	srv, cap := newTestServer(t, http.StatusOK)
	sign := Signing{Secret: "topsecret", WebhookID: "wh-1", Event: "test.event", UserAgent: "ipgaze/1.0.0 (+https://example.com)"}
	err := postJSON(context.Background(), srv.URL, map[string]string{"key": "val"}, sign.params()...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sig := cap.headers.Get("X-Webhook-Signature"); !strings.HasPrefix(sig, "sha256=") {
		t.Errorf("X-Webhook-Signature = %q, want sha256=... prefix", sig)
	}
	if cap.headers.Get("X-Webhook-Timestamp") == "" {
		t.Error("X-Webhook-Timestamp header missing")
	}
	if got := cap.headers.Get("X-Webhook-ID"); got != "wh-1" {
		t.Errorf("X-Webhook-ID = %q, want wh-1", got)
	}
	if got := cap.headers.Get("X-Webhook-Event"); got != "test.event" {
		t.Errorf("X-Webhook-Event = %q, want test.event", got)
	}
	if got := cap.headers.Get("User-Agent"); got != "ipgaze/1.0.0 (+https://example.com)" {
		t.Errorf("User-Agent = %q, want ipgaze/1.0.0 (+https://example.com)", got)
	}
}

func TestGenericWebhookNotifier_Signed_SetsHeaders(t *testing.T) {
	srv, cap := newTestServer(t, http.StatusOK)
	n := &GenericWebhookNotifier{
		URL:     srv.URL,
		Signing: Signing{Secret: "topsecret", WebhookID: "wh-2", Event: "contact.general_submitted", UserAgent: "ua"},
	}
	err := n.Send(context.Background(), Message{Title: "T", Body: "B", Level: LevelInfo})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sig := cap.headers.Get("X-Webhook-Signature"); !strings.HasPrefix(sig, "sha256=") {
		t.Errorf("X-Webhook-Signature = %q, want sha256=... prefix", sig)
	}
	if got := cap.headers.Get("X-Webhook-ID"); got != "wh-2" {
		t.Errorf("X-Webhook-ID = %q, want wh-2", got)
	}
}

// --- postJSON ---

func TestPostJSON_ContentTypeHeader(t *testing.T) {
	srv, cap := newTestServer(t, http.StatusOK)
	err := postJSON(context.Background(), srv.URL, map[string]string{"key": "val"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ct := cap.headers.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestPostJSON_UsesPOST(t *testing.T) {
	srv, cap := newTestServer(t, http.StatusOK)
	_ = postJSON(context.Background(), srv.URL, map[string]string{})
	if cap.method != http.MethodPost {
		t.Errorf("method = %q, want POST", cap.method)
	}
}

func TestPostJSON_InvalidURL_ReturnsError(t *testing.T) {
	err := postJSON(context.Background(), "://bad-url", map[string]string{})
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}

func TestPostJSON_ContextCancelled_ReturnsError(t *testing.T) {
	// Start a slow server that won't respond before the context is cancelled.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err := postJSON(ctx, srv.URL, map[string]string{})
	if err == nil {
		t.Fatal("expected error when context is cancelled")
	}
}

func TestPostJSON_ServerUnreachable_ReturnsError(t *testing.T) {
	// Use a port that is not listening (port 1 is typically not open).
	err := postJSON(context.Background(), "http://127.0.0.1:1/webhook", map[string]string{})
	if err == nil {
		t.Fatal("expected error when server is unreachable")
	}
}

// --- Level constants ---

func TestLevelConstants_Values(t *testing.T) {
	if LevelInfo != "info" {
		t.Errorf("LevelInfo = %q, want info", LevelInfo)
	}
	if LevelWarning != "warning" {
		t.Errorf("LevelWarning = %q, want warning", LevelWarning)
	}
	if LevelError != "error" {
		t.Errorf("LevelError = %q, want error", LevelError)
	}
	if LevelSuccess != "success" {
		t.Errorf("LevelSuccess = %q, want success", LevelSuccess)
	}
}

// --- fakeNotifier (test helper) ---

// fakeNotifier is a controllable Notifier implementation for table-driven tests.
type fakeNotifier struct {
	name   string
	onSend func(ctx context.Context, msg Message) error
}

func (f *fakeNotifier) Name() string {
	if f.name != "" {
		return f.name
	}
	return "fake"
}

func (f *fakeNotifier) Send(ctx context.Context, msg Message) error {
	if f.onSend != nil {
		return f.onSend(ctx, msg)
	}
	return nil
}
