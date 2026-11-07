package config

import "testing"

func TestValidateTrackingProviders(t *testing.T) {
	tests := []struct {
		name    string
		config  TrackingConfig
		wantErr bool
	}{
		{"disabled", TrackingConfig{}, false},
		{"google ga4", TrackingConfig{Type: "google", ID: "G-AB12CD34"}, false},
		{"google legacy", TrackingConfig{Type: "google", ID: "UA-12345-6"}, false},
		{"matomo", TrackingConfig{Type: "matomo", ID: "1", URL: "https://analytics.example.com"}, false},
		{"piwik", TrackingConfig{Type: "piwik", ID: "2", URL: "https://analytics.example.com/piwik"}, false},
		{"owa", TrackingConfig{Type: "owa", ID: "site", URL: "https://owa.example.com"}, false},
		{"fathom cloud", TrackingConfig{Type: "fathom", ID: "ABCDEFGH"}, false},
		{"plausible self-hosted", TrackingConfig{Type: "plausible", ID: "example.com", URL: "https://analytics.example.com"}, false},
		{"plausible hyphenated domain", TrackingConfig{Type: "plausible", ID: "metrics.example-site.com"}, false},
		{"plausible underscore", TrackingConfig{Type: "plausible", ID: "bad_host.example"}, true},
		{"plausible empty label", TrackingConfig{Type: "plausible", ID: "invalid..example"}, true},
		{"plausible IP address", TrackingConfig{Type: "plausible", ID: "192.0.2.1"}, true},
		{"plausible single label", TrackingConfig{Type: "plausible", ID: "localhost"}, true},
		{"umami", TrackingConfig{Type: "umami", ID: "550e8400-e29b-41d4-a716-446655440000", URL: "https://analytics.example.com"}, false},
		{"simple", TrackingConfig{Type: "simple"}, false},
		{"cloudflare", TrackingConfig{Type: "cloudflare", ID: "beacon-token"}, false},
		{"unknown provider", TrackingConfig{Type: "unknown"}, true},
		{"invalid google id", TrackingConfig{Type: "google", ID: "G-\"><script>"}, true},
		{"matomo missing URL", TrackingConfig{Type: "matomo", ID: "1"}, true},
		{"invalid umami id", TrackingConfig{Type: "umami", ID: "not-a-uuid", URL: "https://analytics.example.com"}, true},
		{"unsafe URL", TrackingConfig{Type: "fathom", ID: "ABCDEFGH", URL: "javascript:alert(1)"}, true},
		{"URL credentials", TrackingConfig{Type: "fathom", ID: "ABCDEFGH", URL: "https://fixture@analytics.example.com"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config
			err := ValidateTracking(&got)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateTracking() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
