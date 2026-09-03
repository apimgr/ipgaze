// Package notify — dispatch.go wires configured contact-role webhooks
// (AI.md PART 12) into concrete Notifier instances and sends events to them
// with HMAC signing and retry/backoff.
package notify

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// WebhookTarget is one configured outbound webhook: its destination URL (in
// the transport-specific format from AI.md PART 12's schema table) and the
// HMAC-SHA256 secret auto-generated for it when the URL was first saved.
type WebhookTarget struct {
	URL    string
	Secret string
}

// DispatchTargets holds the resolved webhook targets for one contact role.
// Callers build this from config.ResolveContactRole's ResolvedContact.
type DispatchTargets struct {
	Telegram   WebhookTarget
	Discord    WebhookTarget
	Slack      WebhookTarget
	Mattermost WebhookTarget
	Pushover   WebhookTarget
	Gotify     WebhookTarget
	Generic    WebhookTarget
}

// backoffSchedule is the retry delay sequence for a failed webhook send, per
// AI.md PART 12 → "Failure handling": 1m, 5m, 15m, 1h, 6h, 24h, then drop.
var backoffSchedule = []time.Duration{
	time.Minute, 5 * time.Minute, 15 * time.Minute,
	time.Hour, 6 * time.Hour, 24 * time.Hour,
}

var failureLog = struct {
	mu   sync.Mutex
	last map[string]time.Time
}{last: make(map[string]time.Time)}

// logWebhookFailure logs a notify.webhook_failed line, rate-limited to once
// per 5 minutes per transport name so a permanently-broken receiver can't
// flood the logs (AI.md PART 12).
func logWebhookFailure(name string, err error) {
	failureLog.mu.Lock()
	defer failureLog.mu.Unlock()
	if t, ok := failureLog.last[name]; ok && time.Since(t) < 5*time.Minute {
		return
	}
	failureLog.last[name] = time.Now()
	log.Printf("notify.webhook_failed: %s: %v", name, err)
}

// buildNotifier constructs the Notifier for a named transport from its
// configured URL, wiring in the signing secret, webhook ID, and event name.
// Returns nil for an unknown/unsupported transport name.
func buildNotifier(name, rawURL string, sign Signing) Notifier {
	switch name {
	case "telegram":
		token, chatID := parseTelegramURL(rawURL)
		return &TelegramNotifier{Token: token, ChatID: chatID, Signing: sign}
	case "discord":
		return &DiscordNotifier{WebhookURL: rawURL, Signing: sign}
	case "slack":
		return &SlackNotifier{WebhookURL: rawURL, Signing: sign}
	case "mattermost":
		return &MattermostNotifier{WebhookURL: rawURL, Signing: sign}
	case "pushover":
		token, user := parsePushoverURL(rawURL)
		return &PushoverNotifier{Token: token, UserKey: user, Signing: sign}
	case "gotify":
		server, token := parseGotifyURL(rawURL)
		return &GotifyNotifier{ServerURL: server, Token: token, Signing: sign}
	case "generic":
		return &GenericWebhookNotifier{URL: rawURL, Signing: sign}
	default:
		return nil
	}
}

// parseTelegramURL splits a configured Telegram Bot API URL
// (https://api.telegram.org/bot{TOKEN}/sendMessage?chat_id={CHAT}) into its
// token and chat_id parts. Returns empty strings if rawURL doesn't parse.
func parseTelegramURL(rawURL string) (token, chatID string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", ""
	}
	chatID = u.Query().Get("chat_id")
	// Path looks like /bot<TOKEN>/sendMessage.
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) > 0 && strings.HasPrefix(parts[0], "bot") {
		token = strings.TrimPrefix(parts[0], "bot")
	}
	return token, chatID
}

// parsePushoverURL extracts the user and token query params from a
// configured Pushover API URL (AI.md PART 12: "Pushover API URL with
// user/token").
func parsePushoverURL(rawURL string) (token, user string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", ""
	}
	q := u.Query()
	return q.Get("token"), q.Get("user")
}

// parseGotifyURL splits a configured Gotify URL (base server URL with a
// `token` query param) into the server base and the token, per AI.md PART 12
// ("Gotify URL" → `POST {url}/message?token={token}`).
func parseGotifyURL(rawURL string) (server, token string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL, ""
	}
	token = u.Query().Get("token")
	u.RawQuery = ""
	return strings.TrimRight(u.String(), "/"), token
}

// Event describes one notification to dispatch to a contact role's
// configured webhooks.
type Event struct {
	// Name is the event type, e.g. "contact.general_submitted".
	Name    string
	Subject string
	Body    string
	Level   Level
	URL     string
	// UserAgent is the outbound User-Agent header value:
	// "{project_name}/{project_version} (+{app_url})" per AI.md PART 12.
	UserAgent string
	// Role is the contact role this event was dispatched for (admin,
	// security, abuse, general), used by GenericWebhookNotifier's payload.
	Role           string
	ProjectName    string
	ProjectVersion string
	AppURL         string
	TrackingID     string
}

// Dispatch sends ev to every configured target in targets. Each target is
// attempted once synchronously by the caller's goroutine; a failed send is
// retried in the background on backoffSchedule, reusing the same
// X-Webhook-ID across retries so the receiver can dedupe (AI.md PART 12).
// Retries are in-process only (not persisted) — they do not survive a
// server restart, which is an accepted limitation until a durable queue
// exists.
func Dispatch(targets DispatchTargets, ev Event) {
	send := func(name string, t WebhookTarget) {
		if t.URL == "" {
			return
		}
		webhookID, err := uuid.NewV7()
		webhookIDStr := webhookID.String()
		if err != nil {
			webhookIDStr = uuid.NewString()
		}
		sign := Signing{Secret: t.Secret, WebhookID: webhookIDStr, Event: ev.Name, UserAgent: ev.UserAgent}
		n := buildNotifier(name, t.URL, sign)
		if n == nil {
			return
		}
		msg := Message{
			Title: ev.Subject, Body: ev.Body, Level: ev.Level, URL: ev.URL,
			Role: ev.Role, Event: ev.Name, Timestamp: time.Now(),
			ProjectName: ev.ProjectName, ProjectVersion: ev.ProjectVersion,
			AppURL: ev.AppURL, TrackingID: ev.TrackingID,
		}
		go dispatchWithRetry(name, n, msg)
	}
	send("telegram", targets.Telegram)
	send("discord", targets.Discord)
	send("slack", targets.Slack)
	send("mattermost", targets.Mattermost)
	send("pushover", targets.Pushover)
	send("gotify", targets.Gotify)
	send("generic", targets.Generic)
}

// dispatchWithRetry sends msg via n, retrying on backoffSchedule until it
// succeeds or the schedule is exhausted, at which point the failure is
// logged via logWebhookFailure.
func dispatchWithRetry(name string, n Notifier, msg Message) {
	ctx := context.Background()
	err := n.Send(ctx, msg)
	if err == nil {
		return
	}
	for _, delay := range backoffSchedule {
		time.Sleep(delay)
		if err = n.Send(ctx, msg); err == nil {
			return
		}
	}
	logWebhookFailure(name, fmt.Errorf("all retries exhausted: %w", err))
}
