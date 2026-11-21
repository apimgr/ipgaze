package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestMigrateLegacyKeysMapsAndRemovesLegacySettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.yml")
	original := []byte(`server:
  logging:
    level: debug
    access_format: json
    access:
      filename: access.log
      rotate: daily
      keep: 7
  schedule:
    geoip_update: weekly
    timezone: UTC
  scheduler:
    enabled: false
  web:
    cors: https://old.example
    cookie_consent:
      message: old consent
      policy_url: https://example.com/privacy
      enabled: true
  security_headers:
    hsts: true
    hsts_max_age: 3600
    frame_options: DENY
  security:
    hsts:
      enabled: false
    nel:
      enabled: true
      max_age_seconds: 60
    headers:
      clear_site_data:
        on_consent_withdrawal: true
      permissions_policy: obsolete
    csrf:
      enabled: true
  title: Old title
  description: Old description
  port: "80"
  branding:
    logo_url: logo.svg
    favicon_url: icon.svg
    primary_color: '#123456'
    footer_text: <b>Legacy</b>
    theme_color: blue
    source_code_url: https://example.com/source
  pages:
    about:
      content: '# About'
    privacy:
      content: Privacy extension
    terms:
      content: Terms override
  privacy:
    content: {obsolete: true}
  admin:
    email: admin@example.com
    path: /private
    password: do-not-keep
    token: old-admin-token
    username: old-admin
    two_factor:
      enabled: true
  https_port: 8443
  ssl:
    dns01:
      provider: cloudflare
      credentials: old-dns-secret
    letsencrypt:
      provider: route53
      credentials_encrypted: encrypted-dns
      validated_at: old-time
      domain: example.com
      domains: [example.com]
  rate_limit:
    enabled: true
    requests: 99
    window: 1m
  maintenance_mode: true
  mcp: {}
  secret_key: obsolete-secret
  geoip:
    dir: /old/geoip
    databases: [old.mmdb]
    country_mode: allow
  database:
    sqlite: /old/db.sqlite
  metrics:
    endpoint: /old/metrics
  notifications:
    email_enabled: true
    webhook_enabled: true
  i18n:
    auto_detect: false
    rtl_languages: [ar]
    show_selector: false
    translations_dir: /old/translations
web:
  favicon_url: web-icon.svg
  ui:
    favicon: ui-icon.svg
    logo: ui-logo.svg
    accent: '#abcdef'
  footer:
    custom_html: '<p>Custom</p>'
  permissions_policy: obsolete
  honor_dnt: true
  robots:
    ai_bots: deny
  csrf:
    enabled: false
`)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	migrated := migrateLegacyKeys(path, original)
	var document yaml.Node
	if err := yaml.Unmarshal(migrated, &document); err != nil {
		t.Fatalf("parse migrated config: %v", err)
	}
	root := document.Content[0]
	if findConfigNode(root, "server.scheduler.enabled") != nil {
		t.Fatal("retired server.scheduler.enabled key was retained")
	}
	for _, test := range []struct {
		path string
		want string
	}{
		{"server.logs.level", "debug"},
		{"server.logs.access.format", "json"},
		{"server.logs.access.filename", "access.log"},
		{"server.logs.access.rotate", "daily"},
		{"server.logs.access.keep", "7"},
		{"server.scheduler.timezone", "UTC"},
		{"web.cors", "https://old.example"},
		{"server.privacy.consent.message", "old consent"},
		{"server.privacy.consent.policy.url", "https://example.com/privacy"},
		{"web.hsts.enabled", "true"},
		{"web.hsts.max_age_seconds", "3600"},
		{"web.headers.nel.enabled", "true"},
		{"web.headers.nel.max_age_seconds", "60"},
		{"web.headers.clear_site_data.on_consent_withdrawal", "true"},
		{"server.csrf.enabled", "true"},
		{"server.branding.title", "Old title"},
		{"server.branding.description", "Old description"},
		{"server.branding.logo", "logo.svg"},
		{"server.branding.favicon", "icon.svg"},
		{"web.ui.accent", "#abcdef"},
		{"server.branding.content.footer.format", "html"},
		{"server.branding.content.footer.body", "<p>&lt;b&gt;Legacy&lt;/b&gt;</p>"},
		{"server.branding.content.about.format", "md"},
		{"server.branding.content.about.body", "# About"},
		{"server.branding.content.privacy.body", "Privacy extension"},
		{"server.branding.content.terms.body", "Terms override"},
		{"server.contact.admin.email", "admin@example.com"},
		{"server.admin_path", "/private"},
		{"server.port", "80,8443"},
		{"server.ssl.letsencrypt.dns_provider", "cloudflare"},
		{"server.ssl.letsencrypt.dns_credentials", "old-dns-secret"},
	} {
		t.Run(test.path, func(t *testing.T) {
			node := findConfigNode(root, test.path)
			if node == nil || node.Value != test.want {
				t.Fatalf("%s = %v, want %q", test.path, node, test.want)
			}
		})
	}
	for _, path := range []string{
		"server.logging", "server.schedule.geoip_update", "server.web", "server.security_headers",
		"server.security.hsts", "server.security.nel", "server.security.headers", "server.security.csrf", "web.csrf",
		"server.title", "server.description", "server.branding.logo_url", "server.branding.favicon_url",
		"server.branding.primary_color", "server.branding.footer_text", "server.branding.theme_color",
		"server.branding.source_code_url", "web.favicon_url", "web.ui.favicon", "web.ui.logo",
		"web.footer.custom_html", "server.pages.about.content", "server.pages.privacy.content",
		"server.pages.terms.content", "server.admin.email", "server.admin.path", "server.admin.password",
		"server.admin.token", "server.admin.username", "server.admin.two_factor", "server.https_port",
		"server.ssl.dns01", "server.ssl.letsencrypt.provider", "server.ssl.letsencrypt.credentials_encrypted",
		"server.privacy.content",
		"server.ssl.letsencrypt.validated_at", "server.ssl.letsencrypt.domain", "server.ssl.letsencrypt.domains",
		"server.rate_limit.enabled", "server.rate_limit.requests", "server.rate_limit.window", "server.maintenance_mode",
		"server.mcp", "server.secret_key", "server.geoip.dir", "server.geoip.databases", "server.geoip.country_mode",
		"server.database.sqlite", "server.metrics.endpoint", "server.notifications.email_enabled",
		"server.notifications.webhook_enabled", "server.i18n.auto_detect", "server.i18n.rtl_languages",
		"server.i18n.show_selector", "server.i18n.translations_dir", "web.permissions_policy", "web.honor_dnt", "web.robots.ai_bots",
	} {
		if node := findConfigNode(root, path); node != nil {
			t.Errorf("legacy path %s remains in migrated config", path)
		}
	}
}

func TestMigrateLegacyTopLevelDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.yml")
	content := []byte("database:\n  type: libsql\n  primary:\n    url: libsql://db.example\n    token: legacy-token\n    pool:\n      max_open: 8\nserver:\n  database:\n    driver: sqlite\n    pool:\n      max_idle: 2\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	migrated := migrateLegacyKeys(path, content)
	var document yaml.Node
	if err := yaml.Unmarshal(migrated, &document); err != nil {
		t.Fatal(err)
	}
	root := document.Content[0]
	for key, want := range map[string]string{
		"server.database.driver":        "sqlite",
		"server.database.url":           "libsql://db.example",
		"server.database.token":         "legacy-token",
		"server.database.pool.max_open": "8",
		"server.database.pool.max_idle": "2",
	} {
		if got := findConfigNode(root, key); got == nil || got.Value != want {
			t.Errorf("%s = %v, want %q", key, got, want)
		}
	}
	if findConfigNode(root, "database") != nil {
		t.Fatal("legacy root database section was retained")
	}
}

func TestMigrateLegacyKeysDestinationWinsAndCreatesPrivateBackup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.yml")
	original := []byte(`server:
  logging:
    level: warn
  logs:
    level: error
    access:
      filename: modern.log
  branding:
    footer_text: old text
    content:
      footer:
        format: html
        body: modern footer
  port: "8080"
  https_port: 8443
`)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	migrated := migrateLegacyKeys(path, original)
	var document yaml.Node
	if err := yaml.Unmarshal(migrated, &document); err != nil {
		t.Fatalf("parse migrated config: %v", err)
	}
	root := document.Content[0]
	for path, want := range map[string]string{
		"server.logs.level":                   "error",
		"server.logs.access.filename":         "modern.log",
		"server.branding.content.footer.body": "modern footer",
		"server.port":                         "8080,8443",
	} {
		if got := findConfigNode(root, path); got == nil || got.Value != want {
			t.Errorf("%s = %v, want %q", path, got, want)
		}
	}
	backup, err := os.ReadFile(path + ".bak")
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if string(backup) != string(original) {
		t.Fatalf("backup differs from original: %q", backup)
	}
	info, err := os.Stat(path + ".bak")
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode = %#o, want 0600", info.Mode().Perm())
	}
	if strings.Contains(string(migrated), "old text") {
		t.Fatal("legacy footer replaced the current footer")
	}
}

func TestMigrateLegacyKeysConvertsCustomHTMLAndRemovesInvalidDNSMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.yml")
	content := []byte(`web:
  footer:
    custom_html: '<p>Keep <strong>markup</strong></p>'
server:
  ssl:
    letsencrypt:
      credentials_encrypted: legacy-credential
      validated_at: old-time
      domain: example.com
      domains: [example.com]
`)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	migrated := migrateLegacyKeys(path, content)
	var document yaml.Node
	if err := yaml.Unmarshal(migrated, &document); err != nil {
		t.Fatal(err)
	}
	root := document.Content[0]
	if got := findConfigNode(root, "server.branding.content.footer.format"); got == nil || got.Value != "html" {
		t.Fatalf("footer format = %v, want html", got)
	}
	if got := findConfigNode(root, "server.branding.content.footer.body"); got == nil || got.Value != "<p>Keep <strong>markup</strong></p>" {
		t.Fatalf("footer body = %v, want original HTML", got)
	}
	if got := findConfigNode(root, "server.ssl.letsencrypt.dns_credentials"); got == nil || got.Value != "legacy-credential" {
		t.Fatalf("DNS credentials = %v, want legacy credential", got)
	}
	for _, key := range []string{"validated_at", "domain", "domains"} {
		if findConfigNode(root, "server.ssl.letsencrypt."+key) != nil {
			t.Errorf("obsolete DNS field %s was retained", key)
		}
	}
}

func TestMigrateLegacyKeysPrimaryColorAndHTTPSWithoutPrimaryPort(t *testing.T) {
	root := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for path, value := range map[string]string{"server.branding.primary_color": "#123456"} {
		setConfigNode(root, path, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value})
	}
	setConfigNode(root, "server.https_port", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: "443"})
	content, err := yaml.Marshal(&yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{root}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "missing.yml")
	migrated := migrateLegacyKeys(path, content)
	var document yaml.Node
	if err := yaml.Unmarshal(migrated, &document); err != nil {
		t.Fatal(err)
	}
	if got := findConfigNode(document.Content[0], "web.ui.accent"); got == nil || got.Value != "#123456" {
		t.Fatalf("accent = %v, want #123456", got)
	}
	if got := findConfigNode(document.Content[0], "server.port"); got == nil || got.Value != ",443" {
		t.Fatalf("port = %v, want ,443", got)
	}
}

func TestMigrateLegacyKeysPrunesSchedulerTaskKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.yml")
	content := []byte(`server:
  scheduler:
    tasks:
      backup:
        enabled: true
        schedule: "0 2 * * *"
        retry_on_fail: true
        retry_delay: 30s
        retention: 7
        obsolete: true
      geoip_update:
        enabled: true
        schedule: weekly
        retention: 3
      blocklist_update:
        enabled: true
        schedule: "0 4 * * *"
        retry_on_fail: true
        retry_delay: 1h
`)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	migrated := migrateLegacyKeys(path, content)
	var document yaml.Node
	if err := yaml.Unmarshal(migrated, &document); err != nil {
		t.Fatal(err)
	}
	root := document.Content[0]
	for path, want := range map[string]string{
		"server.scheduler.tasks.backup.retry_on_fail":  "true",
		"server.scheduler.tasks.backup.retry_delay":    "30s",
		"server.scheduler.tasks.backup.retention":      "7",
		"server.scheduler.tasks.geoip_update.schedule": "weekly",
	} {
		if got := findConfigNode(root, path); got == nil || got.Value != want {
			t.Errorf("%s = %v, want %q", path, got, want)
		}
	}
	for _, path := range []string{
		"server.scheduler.tasks.backup.obsolete", "server.scheduler.tasks.geoip_update.retention",
		"server.scheduler.tasks.blocklist_update",
	} {
		if findConfigNode(root, path) != nil {
			t.Errorf("obsolete scheduler key %s was retained", path)
		}
	}
}
