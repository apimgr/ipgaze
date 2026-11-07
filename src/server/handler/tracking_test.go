package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/apimgr/ipgaze/src/config"
	"github.com/apimgr/ipgaze/src/netutil"
)

func analyticsTestHandler() *PagesHandler {
	cfg := config.DefaultConfig()
	cfg.Server.Tracking = config.TrackingConfig{Type: "simple"}
	cfg.Server.Privacy.Cookies.Analytics.Enabled = true
	cfg.Web.CSP.Enabled = true
	cfg.Web.CSP.Mode = "enforce"
	cfg.Web.CSP.ScriptSrcExtra = "https://scripts.simpleanalyticscdn.com"
	return &PagesHandler{Config: cfg, Trust: netutil.NewTrustResolver(config.TrustedProxiesConfig{}, "")}
}

func TestAnalyticsTrackingConsentAndPolicy(t *testing.T) {
	tests := []struct {
		name       string
		cookie     string
		ccpa       bool
		gpc        string
		wantEnable bool
	}{
		{name: "first visit waits for consent"},
		{name: "consent granted", cookie: `{"analytics":true}`, wantEnable: true},
		{name: "consent denied", cookie: `{"analytics":false}`},
		{name: "CCPA opt out", cookie: `{"analytics":true}`, ccpa: true},
		{name: "global privacy control", cookie: `{"analytics":true}`, gpc: "1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := analyticsTestHandler()
			r := httptest.NewRequest(http.MethodGet, "https://ipgaze.example/", nil)
			if tt.cookie != "" {
				r.AddCookie(&http.Cookie{Name: "cookie_consent", Value: url.QueryEscape(tt.cookie)})
			}
			if tt.ccpa {
				r.AddCookie(&http.Cookie{Name: "ccpa_opt_out", Value: "true"})
			}
			if tt.gpc != "" {
				r.Header.Set("Sec-GPC", tt.gpc)
			}
			gotEnabled, gotURL := h.analyticsTracking(r)
			if gotEnabled != tt.wantEnable {
				t.Fatalf("analyticsTracking enabled = %v, want %v", gotEnabled, tt.wantEnable)
			}
			if gotEnabled && gotURL != "https://scripts.simpleanalyticscdn.com/latest.js" {
				t.Fatalf("analyticsTracking URL = %q", gotURL)
			}
		})
	}
}

func TestGeneratedTrackingEndpointConsentAndOverlayGate(t *testing.T) {
	h := analyticsTestHandler()
	r := httptest.NewRequest(http.MethodGet, "https://ipgaze.example/server/tracking.js", nil)
	w := httptest.NewRecorder()
	h.ServerTrackingScript(w, r)
	if w.Code != http.StatusNotFound || !strings.Contains(w.Header().Get("Cache-Control"), "no-cache") {
		t.Fatalf("no-consent response = %d cache=%q", w.Code, w.Header().Get("Cache-Control"))
	}
	r = httptest.NewRequest(http.MethodGet, "https://ipgaze.example/server/tracking.js", nil)
	r.AddCookie(&http.Cookie{Name: "cookie_consent", Value: url.QueryEscape(`{"analytics":true}`)})
	w = httptest.NewRecorder()
	h.ServerTrackingScript(w, r)
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/javascript; charset=utf-8" {
		t.Fatalf("consented script response = %d content-type=%q", w.Code, w.Header().Get("Content-Type"))
	}
	if !strings.Contains(w.Body.String(), "scripts.simpleanalyticscdn.com/latest.js") {
		t.Fatalf("generated script omitted configured source: %s", w.Body.String())
	}
	h.Trust.OnionAddress = "ipgazeexample.onion"
	onion := httptest.NewRequest(http.MethodGet, "http://ipgazeexample.onion/server/tracking.js", nil)
	onion.AddCookie(&http.Cookie{Name: "cookie_consent", Value: url.QueryEscape(`{"analytics":true}`)})
	w = httptest.NewRecorder()
	h.ServerTrackingScript(w, onion)
	if w.Code != http.StatusNotFound {
		t.Fatalf("onion tracking response = %d, want 404", w.Code)
	}
}

func TestAnalyticsTrackingRequiresCSPSourceAndDisablesClearnetOnion(t *testing.T) {
	h := analyticsTestHandler()
	r := httptest.NewRequest(http.MethodGet, "https://ipgaze.example/", nil)
	h.Config.Web.CSP.ScriptSrcExtra = ""
	if enabled, _ := h.analyticsTracking(r); enabled {
		t.Fatal("analytics enabled without a matching enforced script-src source")
	}

	h.Config.Server.Tracking = config.TrackingConfig{Type: "fathom", ID: "ABCDEFGH"}
	h.Config.Web.CSP.ScriptSrcExtra = "https://cdn.usefathom.com"
	h.Trust.OnionAddress = "ipgazeexample.onion"
	onionRequest := httptest.NewRequest(http.MethodGet, "http://ipgazeexample.onion/", nil)
	if enabled, _ := h.analyticsTracking(onionRequest); enabled {
		t.Fatal("clearnet analytics provider enabled for onion request")
	}
}

func TestAnalyticsTrackingDisabledOnOnionEvenForSelfHostedProvider(t *testing.T) {
	h := analyticsTestHandler()
	h.Config.Server.Tracking = config.TrackingConfig{Type: "matomo", ID: "1", URL: "http://ipgazeexample.onion/matomo"}
	h.Config.Web.CSP.ScriptSrcExtra = ""
	h.Trust.OnionAddress = "ipgazeexample.onion"
	r := httptest.NewRequest(http.MethodGet, "http://ipgazeexample.onion/", nil)
	enabled, source := h.analyticsTracking(r)
	if enabled || source != "" {
		t.Fatalf("analytics should be disabled on onion, got enabled=%v source=%q", enabled, source)
	}
}

func TestSimpleAnalyticsNoScriptPixelHonorsConsentCSPAndTor(t *testing.T) {
	h := analyticsTestHandler()
	r := httptest.NewRequest(http.MethodGet, "https://ipgaze.example/", nil)
	if h.analyticsNoScriptAllowed(r) {
		t.Fatal("Simple Analytics pixel must wait for consent on first visit")
	}
	r.AddCookie(&http.Cookie{Name: "cookie_consent", Value: url.QueryEscape(`{"analytics":true}`)})
	if !h.analyticsNoScriptAllowed(r) {
		t.Fatal("default img-src should permit the consented Simple Analytics pixel")
	}
	h.Config.Web.CSP.ImgSrcOverride = "'self'"
	if h.analyticsNoScriptAllowed(r) {
		t.Fatal("img-src self must reject the external pixel")
	}
	h.Config.Web.CSP.ImgSrcOverride = "https://queue.simpleanalyticscdn.com"
	h.Trust.OnionAddress = "ipgazeexample.onion"
	onion := httptest.NewRequest(http.MethodGet, "http://ipgazeexample.onion/", nil)
	if h.analyticsNoScriptAllowed(onion) {
		t.Fatal("clearnet pixel must not load for an onion request")
	}
	r.Header.Set("Sec-GPC", "1")
	if enabled, _ := h.analyticsTracking(r); enabled {
		t.Fatal("global privacy control must disable tracking despite stored consent")
	}
}

func TestCSPHostSourceHonorsConfiguredPath(t *testing.T) {
	tests := []struct {
		name      string
		rule      string
		sourceURL string
		want      bool
	}{
		{name: "host-only rule", rule: "https://analytics.example", sourceURL: "https://analytics.example/private.js", want: true},
		{name: "matching path prefix", rule: "https://analytics.example/public/", sourceURL: "https://analytics.example/public/tracker.js", want: true},
		{name: "different path", rule: "https://analytics.example/public/", sourceURL: "https://analytics.example/private/tracker.js"},
		{name: "exact path", rule: "https://analytics.example/tracker.js", sourceURL: "https://analytics.example/tracker.js", want: true},
		{name: "exact path mismatch", rule: "https://analytics.example/tracker.js", sourceURL: "https://analytics.example/tracker-v2.js"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source, err := url.Parse(tt.sourceURL)
			if err != nil {
				t.Fatal(err)
			}
			if got := cspHostSourceMatches(tt.rule, source); got != tt.want {
				t.Fatalf("cspHostSourceMatches(%q, %q) = %v, want %v", tt.rule, tt.sourceURL, got, tt.want)
			}
		})
	}
}
