package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestMigrateConfigAreasSplitsAndPreservesExistingValues(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.yml")
	original := []byte("server:\n  port: \"8080\"\n  database:\n    driver: sqlite\n  branding:\n    title: Old title\n    tagline: Example\n  metrics:\n    enabled: true\n  cache:\n    type: memory\n  unknown_project_setting:\n    feature: true\nweb:\n  ui:\n    theme: dark\n    accent: \"#123456\"\n  csrf:\n    enabled: true\ntor:\n  onion_address: example.onion\ndata:\n  cve:\n    source: https://example.test/cve.json\ncustom:\n  enabled: true\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	dropinDir := filepath.Join(dir, "yaml.d")
	if err := os.Mkdir(dropinDir, 0o700); err != nil {
		t.Fatal(err)
	}
	branding := []byte("server:\n  branding:\n    title: New title\n    description: Operator description\n")
	if err := os.WriteFile(filepath.Join(dropinDir, "branding.yml"), branding, 0o600); err != nil {
		t.Fatal(err)
	}
	migrated := migrateConfigAreas(path, original)
	if bytes.Equal(migrated, original) {
		t.Fatal("area migration did not rewrite server.yml")
	}
	if !strings.HasPrefix(string(migrated), areaConfigHeader) {
		t.Fatal("server.yml is missing the fixed area-file header")
	}
	var primary map[string]any
	if err := yaml.Unmarshal(migrated, &primary); err != nil {
		t.Fatalf("parse migrated server.yml: %v", err)
	}
	server := primary["server"].(map[string]any)
	if server["port"] != "8080" || server["database"] == nil || server["cache"] == nil {
		t.Fatalf("server-local fields were not retained: %#v", server)
	}
	if _, ok := server["branding"]; ok {
		t.Fatal("branding remained in server.yml")
	}
	brandingData, err := os.ReadFile(filepath.Join(dropinDir, "branding.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var brandingRoot map[string]any
	if err := yaml.Unmarshal(brandingData, &brandingRoot); err != nil {
		t.Fatalf("parse branding.yml: %v", err)
	}
	brandingConfig := brandingRoot["server"].(map[string]any)["branding"].(map[string]any)
	if brandingConfig["title"] != "New title" || brandingConfig["tagline"] != "Example" || brandingConfig["description"] != "Operator description" {
		t.Fatalf("branding migration lost precedence or values: %#v", brandingConfig)
	}
	for _, filename := range []string{"web.yml", "metrics.yml", "tor.yml", "security.yml", "app.yml"} {
		if _, err := os.Stat(filepath.Join(dropinDir, filename)); err != nil {
			t.Errorf("expected area file %s: %v", filename, err)
		}
	}
	backup, err := os.ReadFile(path + ".bak")
	if err != nil {
		t.Fatalf("read server.yml.bak: %v", err)
	}
	if !bytes.Equal(backup, original) {
		t.Fatalf("server.yml.bak = %q, want original %q", backup, original)
	}
	info, err := os.Stat(dropinDir)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("yaml.d mode = %#o, want 0700", got)
	}
}

func TestMigrateConfigAreasNoOpsWhenServerConfigIsAlreadySplit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.yml")
	original := []byte("server:\n  port: \"8080\"\n  database:\n    driver: sqlite\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if migrated := migrateConfigAreas(path, original); !bytes.Equal(migrated, original) {
		t.Fatalf("already split config changed: %q", migrated)
	}
	if _, err := os.Stat(filepath.Join(dir, "yaml.d")); !os.IsNotExist(err) {
		t.Fatalf("no-op migration created yaml.d: %v", err)
	}
	if _, err := os.Stat(path + ".bak"); !os.IsNotExist(err) {
		t.Fatalf("no-op migration created backup: %v", err)
	}
}

func TestMigrateConfigAreasMovesUserAndGroupOutOfServerYML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.yml")
	original := []byte("server:\n  user: ipgaze\n  group: ipgaze\n  port: \"8080\"\n")
	migrated := migrateConfigAreas(path, original)
	var primary map[string]any
	if err := yaml.Unmarshal(migrated, &primary); err != nil {
		t.Fatalf("parse migrated server.yml: %v", err)
	}
	server := primary["server"].(map[string]any)
	if _, ok := server["user"]; ok {
		t.Fatal("server.user remained in server.yml")
	}
	if _, ok := server["group"]; ok {
		t.Fatal("server.group remained in server.yml")
	}
	appData, err := os.ReadFile(filepath.Join(dir, "yaml.d", "app.yml"))
	if err != nil {
		t.Fatalf("read app.yml: %v", err)
	}
	var app map[string]any
	if err := yaml.Unmarshal(appData, &app); err != nil {
		t.Fatalf("parse app.yml: %v", err)
	}
	appServer := app["server"].(map[string]any)
	if appServer["user"] != "ipgaze" || appServer["group"] != "ipgaze" {
		t.Fatalf("server.user/group not moved intact: %#v", appServer)
	}
}
