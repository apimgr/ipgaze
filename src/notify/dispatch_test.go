package notify

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseTelegramURL(t *testing.T) {
	token, chatID := parseTelegramURL("https://api.telegram.org/bot123:ABC/sendMessage?chat_id=456")
	if token != "123:ABC" {
		t.Errorf("token = %q, want 123:ABC", token)
	}
	if chatID != "456" {
		t.Errorf("chatID = %q, want 456", chatID)
	}
}

func TestParseTelegramURL_Invalid(t *testing.T) {
	token, chatID := parseTelegramURL(":://bad-url")
	if token != "" || chatID != "" {
		t.Errorf("expected empty token/chatID for invalid URL, got %q/%q", token, chatID)
	}
}

func TestParsePushoverURL(t *testing.T) {
	token, user := parsePushoverURL("https://api.pushover.net/1/messages.json?token=T&user=U")
	if token != "T" {
		t.Errorf("token = %q, want T", token)
	}
	if user != "U" {
		t.Errorf("user = %q, want U", user)
	}
}

func TestParsePushoverURL_Invalid(t *testing.T) {
	token, user := parsePushoverURL(":://bad-url")
	if token != "" || user != "" {
		t.Errorf("expected empty token/user for invalid URL, got %q/%q", token, user)
	}
}

func TestParseGotifyURL(t *testing.T) {
	server, token := parseGotifyURL("https://gotify.example.com/?token=T")
	if server != "https://gotify.example.com" {
		t.Errorf("server = %q, want https://gotify.example.com", server)
	}
	if token != "T" {
		t.Errorf("token = %q, want T", token)
	}
}

func TestParseGotifyURL_Invalid(t *testing.T) {
	server, token := parseGotifyURL(":://bad-url")
	if server != ":://bad-url" || token != "" {
		t.Errorf("expected rawURL echoed back with empty token, got %q/%q", server, token)
	}
}

func TestBuildNotifier_AllTransports(t *testing.T) {
	sign := Signing{Secret: "s", WebhookID: "id", Event: "e", UserAgent: "ua"}
	cases := []struct {
		name string
		url  string
		want string
	}{
		{"telegram", "https://api.telegram.org/botT/sendMessage?chat_id=1", "telegram"},
		{"discord", "https://discord.example.com/hook", "discord"},
		{"slack", "https://slack.example.com/hook", "slack"},
		{"mattermost", "https://mattermost.example.com/hook", "mattermost"},
		{"pushover", "https://api.pushover.net/1/messages.json?token=T&user=U", "pushover"},
		{"gotify", "https://gotify.example.com/?token=T", "gotify"},
		{"generic", "https://generic.example.com/hook", "generic"},
	}
	for _, c := range cases {
		n := buildNotifier(c.name, c.url, sign)
		if n == nil {
			t.Errorf("buildNotifier(%q) = nil, want non-nil", c.name)
			continue
		}
		if n.Name() != c.want {
			t.Errorf("buildNotifier(%q).Name() = %q, want %q", c.name, n.Name(), c.want)
		}
	}
}

func TestBuildNotifier_Unknown(t *testing.T) {
	if n := buildNotifier("unknown-transport", "https://example.com", Signing{}); n != nil {
		t.Errorf("buildNotifier(unknown) = %v, want nil", n)
	}
}

func TestDispatch_SendsToConfiguredTargets(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	Dispatch(DispatchTargets{
		Discord: WebhookTarget{URL: srv.URL, Secret: "sec"},
		Slack:   WebhookTarget{URL: srv.URL, Secret: "sec"},
	}, Event{
		Name: "test.event", Subject: "S", Body: "B", Level: LevelInfo,
		Role: "general", ProjectName: "ipgaze", ProjectVersion: "1.0.0",
		AppURL: "https://example.com",
	})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&hits) >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := atomic.LoadInt32(&hits); got < 2 {
		t.Errorf("hits = %d, want >= 2", got)
	}
}

func TestDispatch_SkipsEmptyTargets(t *testing.T) {
	// No targets configured; Dispatch must return immediately without
	// spawning any goroutines or panicking.
	Dispatch(DispatchTargets{}, Event{Name: "test.event"})
}

func TestDispatchWithRetry_SucceedsOnFirstAttempt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := &GenericWebhookNotifier{URL: srv.URL}
	done := make(chan struct{})
	go func() {
		dispatchWithRetry("generic", n, Message{Title: "T", Body: "B"})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("dispatchWithRetry did not return promptly on success")
	}
}

func TestLogWebhookFailure_RateLimited(t *testing.T) {
	// First call logs, second call within the rate-limit window is a no-op;
	// this just exercises both branches without asserting on log output.
	logWebhookFailure("test-transport-ratelimit", errTest("boom"))
	logWebhookFailure("test-transport-ratelimit", errTest("boom again"))
}

type errTest string

func (e errTest) Error() string { return string(e) }
