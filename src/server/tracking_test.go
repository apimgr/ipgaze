package server

import (
	"html/template"
	"testing"

	"github.com/apimgr/ipgaze/src/config"
)

func TestTrackingScriptTemplateConsentGateAndEscaping(t *testing.T) {
	fn := templateFuncMap("build-123")["trackingScript"].(func(config.TrackingConfig, bool, string) template.HTML)
	tracking := config.TrackingConfig{Type: "cloudflare", ID: `token" onload="alert(1)`}
	if got := fn(tracking, false, "https://static.cloudflareinsights.com/beacon.min.js"); got != "" {
		t.Fatalf("tracking script emitted without consent: %s", got)
	}
	got := string(fn(tracking, true, "https://static.cloudflareinsights.com/beacon.min.js"))
	if got != `<script defer src="/server/tracking.js"></script>` {
		t.Fatalf("generated same-origin loader mismatch: %s", got)
	}
}
