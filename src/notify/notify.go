// Package notify provides webhook notification adapters for various services.
// Supports: telegram, discord, slack, mattermost, pushover, gotify, generic HTTP webhook.
package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// signParams carries the outbound webhook signing data for one request, per
// AI.md PART 12 → "Outbound webhook signing". Passed as an optional trailing
// arg to postJSON so unsigned call sites (tests, and any future internal
// use) keep working unchanged.
type signParams struct {
	secret    string
	event     string
	webhookID string
	userAgent string
}

// applySigningHeaders sets the X-Webhook-* headers (and User-Agent) on req.
// The signature always covers the exact bytes about to be sent; a request
// with an empty secret still gets a signature (HMAC with an empty key),
// since every real configured webhook has a non-empty auto-generated secret
// — only ad-hoc/test construction leaves it empty.
func applySigningHeaders(req *http.Request, sp signParams, body []byte) {
	mac := hmac.New(sha256.New, []byte(sp.secret))
	mac.Write(body)
	req.Header.Set("X-Webhook-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	req.Header.Set("X-Webhook-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	if sp.webhookID != "" {
		req.Header.Set("X-Webhook-ID", sp.webhookID)
	}
	if sp.event != "" {
		req.Header.Set("X-Webhook-Event", sp.event)
	}
	if sp.userAgent != "" {
		req.Header.Set("User-Agent", sp.userAgent)
	}
}

// Level represents the notification severity level.
type Level string

const (
	LevelInfo    Level = "info"
	LevelWarning Level = "warning"
	LevelError   Level = "error"
	LevelSuccess Level = "success"
)

// Message is a notification to send.
type Message struct {
	Title string
	Body  string
	Level Level
	URL   string

	// The fields below are additive and only consumed by
	// GenericWebhookNotifier, which sends the literal generic webhook body
	// shape from AI.md PART 12 (role/event/subject/body/severity/timestamp/
	// project_name/project_version/app_url/tracking_id). Other notifiers
	// ignore them.
	Role           string
	Event          string
	Timestamp      time.Time
	ProjectName    string
	ProjectVersion string
	AppURL         string
	TrackingID     string
}

// Notifier sends a notification message.
type Notifier interface {
	Send(ctx context.Context, msg Message) error
	Name() string
}

// Manager holds multiple notifiers and fans out messages.
type NotifyManager struct {
	notifiers []Notifier
}

// NewNotifyManager creates a new notification manager.
func NewNotifyManager() *NotifyManager {
	return &NotifyManager{}
}

// Register adds a notifier to the manager.
func (m *NotifyManager) Register(n Notifier) {
	m.notifiers = append(m.notifiers, n)
}

// Send fans out msg to all registered notifiers.
// Errors from individual notifiers are collected and returned as a combined error.
func (m *NotifyManager) Send(ctx context.Context, msg Message) error {
	var errs []string
	for _, n := range m.notifiers {
		if err := n.Send(ctx, msg); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", n.Name(), err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("notify errors: %s", strings.Join(errs, "; "))
	}
	return nil
}

// postJSON sends a JSON payload to a URL via HTTP POST. An optional sign
// param signs the request per AI.md PART 12 (X-Webhook-Signature/Timestamp/
// ID/Event headers); omitting it leaves the request unsigned, which existing
// call sites rely on.
func postJSON(ctx context.Context, url string, payload interface{}, sign ...signParams) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return postBytes(ctx, url, b, "application/json", sign...)
}

// postBytes POSTs a raw body to url, optionally signed. Shared by postJSON
// and any future non-JSON transport.
func postBytes(ctx context.Context, url string, b []byte, contentType string, sign ...signParams) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if len(sign) > 0 {
		applySigningHeaders(req, sign[0], b)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()
	// Drain the body so the connection can be reused; a drain error is not actionable here.
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

// Signing carries optional outbound-webhook signing data (AI.md PART 12).
// The zero value means the request is sent unsigned — used by direct/test
// construction that predates the signing feature; config-driven dispatch
// always sets it.
type Signing struct {
	Secret    string
	WebhookID string
	Event     string
	UserAgent string
}

// params converts s to the variadic sign argument postJSON expects: no
// elements when s is the zero value, one element otherwise.
func (s Signing) params() []signParams {
	if s == (Signing{}) {
		return nil
	}
	return []signParams{{secret: s.Secret, event: s.Event, webhookID: s.WebhookID, userAgent: s.UserAgent}}
}

// TelegramNotifier sends messages via the Telegram Bot API.
type TelegramNotifier struct {
	Token   string
	ChatID  string
	Signing Signing
}

// Name returns the notifier name.
func (t *TelegramNotifier) Name() string { return "telegram" }

// Send sends a message via Telegram.
func (t *TelegramNotifier) Send(ctx context.Context, msg Message) error {
	text := fmt.Sprintf("*%s*\n%s", msg.Title, msg.Body)
	if msg.URL != "" {
		text += "\n" + msg.URL
	}
	payload := map[string]interface{}{
		"chat_id":    t.ChatID,
		"text":       text,
		"parse_mode": "Markdown",
	}
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", t.Token)
	return postJSON(ctx, url, payload, t.Signing.params()...)
}

// DiscordNotifier sends messages via Discord webhooks.
type DiscordNotifier struct {
	WebhookURL string
	Signing    Signing
}

// Name returns the notifier name.
func (d *DiscordNotifier) Name() string { return "discord" }

// Send sends a message via Discord webhook.
func (d *DiscordNotifier) Send(ctx context.Context, msg Message) error {
	color := 0x3498db
	switch msg.Level {
	case LevelError:
		color = 0xe74c3c
	case LevelWarning:
		color = 0xf39c12
	case LevelSuccess:
		color = 0x2ecc71
	}
	payload := map[string]interface{}{
		"embeds": []map[string]interface{}{
			{
				"title":       msg.Title,
				"description": msg.Body,
				"color":       color,
				"url":         msg.URL,
			},
		},
	}
	return postJSON(ctx, d.WebhookURL, payload, d.Signing.params()...)
}

// SlackNotifier sends messages via Slack incoming webhooks.
type SlackNotifier struct {
	WebhookURL string
	Signing    Signing
}

// Name returns the notifier name.
func (s *SlackNotifier) Name() string { return "slack" }

// Send sends a message via Slack webhook.
func (s *SlackNotifier) Send(ctx context.Context, msg Message) error {
	text := fmt.Sprintf("*%s*\n%s", msg.Title, msg.Body)
	if msg.URL != "" {
		text += "\n" + msg.URL
	}
	payload := map[string]interface{}{
		"text": text,
	}
	return postJSON(ctx, s.WebhookURL, payload, s.Signing.params()...)
}

// MattermostNotifier sends messages via Mattermost incoming webhooks.
type MattermostNotifier struct {
	WebhookURL string
	Channel    string
	Signing    Signing
}

// Name returns the notifier name.
func (m *MattermostNotifier) Name() string { return "mattermost" }

// Send sends a message via Mattermost webhook.
func (m *MattermostNotifier) Send(ctx context.Context, msg Message) error {
	text := fmt.Sprintf("**%s**\n%s", msg.Title, msg.Body)
	if msg.URL != "" {
		text += "\n" + msg.URL
	}
	payload := map[string]interface{}{
		"text":    text,
		"channel": m.Channel,
	}
	return postJSON(ctx, m.WebhookURL, payload, m.Signing.params()...)
}

// PushoverNotifier sends messages via the Pushover API.
type PushoverNotifier struct {
	Token   string
	UserKey string
	Signing Signing
}

// Name returns the notifier name.
func (p *PushoverNotifier) Name() string { return "pushover" }

// Send sends a message via Pushover.
func (p *PushoverNotifier) Send(ctx context.Context, msg Message) error {
	payload := map[string]interface{}{
		"token":   p.Token,
		"user":    p.UserKey,
		"title":   msg.Title,
		"message": msg.Body,
		"url":     msg.URL,
	}
	return postJSON(ctx, "https://api.pushover.net/1/messages.json", payload, p.Signing.params()...)
}

// GotifyNotifier sends messages via a Gotify server.
type GotifyNotifier struct {
	ServerURL string
	Token     string
	Signing   Signing
}

// Name returns the notifier name.
func (g *GotifyNotifier) Name() string { return "gotify" }

// Send sends a message via Gotify.
func (g *GotifyNotifier) Send(ctx context.Context, msg Message) error {
	priority := 5
	if msg.Level == LevelError {
		priority = 9
	}
	payload := map[string]interface{}{
		"title":    msg.Title,
		"message":  msg.Body,
		"priority": priority,
	}
	url := strings.TrimRight(g.ServerURL, "/") + "/message?token=" + g.Token
	return postJSON(ctx, url, payload, g.Signing.params()...)
}

// GenericWebhookNotifier sends messages to a generic HTTP webhook.
type GenericWebhookNotifier struct {
	URL     string
	Headers map[string]string
	Signing Signing
}

// Name returns the notifier name.
func (g *GenericWebhookNotifier) Name() string { return "generic" }

// Send sends a message to the generic webhook endpoint. The body shape is
// the generic webhook payload from AI.md PART 12:
// {role,event,subject,body,severity,timestamp,project_name,project_version,
// app_url,tracking_id?}.
func (g *GenericWebhookNotifier) Send(ctx context.Context, msg Message) error {
	timestamp := msg.Timestamp
	if timestamp.IsZero() {
		timestamp = time.Now()
	}
	payload := map[string]interface{}{
		"role":            msg.Role,
		"event":           msg.Event,
		"subject":         msg.Title,
		"body":            msg.Body,
		"severity":        string(msg.Level),
		"timestamp":       timestamp.UTC().Format(time.RFC3339),
		"project_name":    msg.ProjectName,
		"project_version": msg.ProjectVersion,
		"app_url":         msg.AppURL,
	}
	if msg.TrackingID != "" {
		payload["tracking_id"] = msg.TrackingID
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.URL, bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range g.Headers {
		req.Header.Set(k, v)
	}
	if sp := g.Signing.params(); len(sp) > 0 {
		applySigningHeaders(req, sp[0], b)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()
	// Drain the body so the connection can be reused; a drain error is not actionable here.
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}
