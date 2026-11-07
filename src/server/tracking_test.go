package server

import (
	"html/template"
	"strings"
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
	if !strings.Contains(got, `/static/js/tracking.js?v=build-123`) {
		t.Fatalf("same-origin loader or asset stamp missing: %s", got)
	}
	if strings.Contains(got, `data-id="token" onload=`) || !strings.Contains(got, `data-id="token&#34; onload=&#34;alert(1)"`) {
		t.Fatalf("tracking attributes were not HTML escaped: %s", got)
	}
}
