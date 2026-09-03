package main

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/apimgr/ipgaze/src/client/api"
	paths "github.com/apimgr/ipgaze/src/client/path"
	"github.com/apimgr/ipgaze/src/client/setup"
)

func TestPersistCLIFlags_NilConfig_NoPanic(t *testing.T) {
	persistCLIFlags(nil, "https://example.com", "tok", paths.ConfigFile())
}

func TestPersistCLIFlags_NoFlags_NoChange(t *testing.T) {
	cfg := &setup.CLIConfig{}
	persistCLIFlags(cfg, "", "", paths.ConfigFile())
	if cfg.Server.Primary != "" || cfg.Auth.Token != "" {
		t.Errorf("expected no change, got %+v", cfg)
	}
}

func TestPersistCLIFlags_EmptyCurrent_FlagSaved(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	cfg := &setup.CLIConfig{}
	persistCLIFlags(cfg, "https://example.com", "mytoken", paths.ConfigFile())
	if cfg.Server.Primary != "https://example.com" {
		t.Errorf("Server.Primary = %q, want %q", cfg.Server.Primary, "https://example.com")
	}
	if cfg.Auth.Token != "mytoken" {
		t.Errorf("Auth.Token = %q, want %q", cfg.Auth.Token, "mytoken")
	}
}

func TestPersistCLIFlags_ValidCurrent_NotOverwritten(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	cfg := &setup.CLIConfig{
		Server: setup.ServerConfig{Primary: "https://existing.example.com"},
		Auth:   setup.AuthConfig{Token: "existing-token"},
	}
	persistCLIFlags(cfg, "https://flag.example.com", "flag-token", paths.ConfigFile())
	if cfg.Server.Primary != "https://existing.example.com" {
		t.Errorf("Server.Primary was overwritten: got %q", cfg.Server.Primary)
	}
	if cfg.Auth.Token != "existing-token" {
		t.Errorf("Auth.Token was overwritten: got %q", cfg.Auth.Token)
	}
}

func TestPersistCLIFlags_InvalidCurrent_FlagReplacesIt(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	cfg := &setup.CLIConfig{
		Server: setup.ServerConfig{Primary: "not-a-url"},
	}
	persistCLIFlags(cfg, "https://flag.example.com", "", paths.ConfigFile())
	if cfg.Server.Primary != "https://flag.example.com" {
		t.Errorf("Server.Primary = %q, want %q", cfg.Server.Primary, "https://flag.example.com")
	}
}

func TestPersistCLIFlags_InvalidFlag_NotSaved(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	cfg := &setup.CLIConfig{}
	persistCLIFlags(cfg, "not-a-valid-url", "", paths.ConfigFile())
	if cfg.Server.Primary != "" {
		t.Errorf("expected invalid flag not saved, got %q", cfg.Server.Primary)
	}
}

func TestPersistCLIFlags_WritesToExplicitConfigPath(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "work.yml")
	cfg := &setup.CLIConfig{}
	persistCLIFlags(cfg, "https://example.com", "", target)
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("expected config written to %s: %v", target, err)
	}
}

func TestExitCodeForError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"connection", &api.ConnectionError{URL: "https://x", Err: errors.New("dial")}, exitConnection},
		{"unauthorized", &api.APIError{StatusCode: http.StatusUnauthorized}, exitAuth},
		{"forbidden", &api.APIError{StatusCode: http.StatusForbidden}, exitAuth},
		{"not found", &api.APIError{StatusCode: http.StatusNotFound}, exitNotFound},
		{"server error", &api.APIError{StatusCode: http.StatusInternalServerError}, exitGeneral},
		{"token revoked", api.ErrTokenRevoked, exitAuth},
		{"plain", errors.New("boom"), exitGeneral},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := exitCodeForError(tc.err); got != tc.want {
				t.Errorf("exitCodeForError(%v) = %d, want %d", tc.err, got, tc.want)
			}
		})
	}
}

func TestExitCodeValues(t *testing.T) {
	want := map[string]int{
		"success": 0, "general": 1, "config": 2,
		"connection": 3, "auth": 4, "notfound": 5, "usage": 64,
	}
	got := map[string]int{
		"success": exitSuccess, "general": exitGeneral, "config": exitConfig,
		"connection": exitConnection, "auth": exitAuth,
		"notfound": exitNotFound, "usage": exitUsage,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("exit code %s = %d, want %d", k, got[k], v)
		}
	}
}

func TestTruthyFlag_LocaleForms(t *testing.T) {
	cases := map[string]bool{
		"true": true, "yes": true, "on": true, "1": true,
		"oui": true, "si": true, "da": true, "enabled": true,
		"false": false, "no": false, "off": false, "0": false,
		"non": false, "niet": false, "disabled": false,
	}
	for input, want := range cases {
		var f truthyFlag
		if err := f.Set(input); err != nil {
			t.Fatalf("Set(%q) returned error: %v", input, err)
		}
		if f.Bool() != want {
			t.Errorf("Set(%q).Bool() = %v, want %v", input, f.Bool(), want)
		}
		if !f.set {
			t.Errorf("Set(%q) did not mark the flag as set", input)
		}
	}
}

func TestTruthyFlag_IsBoolFlag(t *testing.T) {
	var f truthyFlag
	if !f.IsBoolFlag() {
		t.Error("truthyFlag must report IsBoolFlag so --debug works without a value")
	}
	if f.Bool() {
		t.Error("unset truthyFlag must be false")
	}
	if f.String() != "false" {
		t.Errorf("unset String() = %q, want \"false\"", f.String())
	}
}

func TestTruthyFlag_InvalidValueErrors(t *testing.T) {
	var f truthyFlag
	if err := f.Set("banana"); err == nil {
		t.Error("expected an error for a non-boolean value")
	}
}

func TestEnvOr(t *testing.T) {
	t.Setenv("IPGAZE_TEST_ENVOR", "from-env")
	if got := envOr("from-flag", "IPGAZE_TEST_ENVOR"); got != "from-flag" {
		t.Errorf("flag value must win, got %q", got)
	}
	if got := envOr("", "IPGAZE_TEST_ENVOR"); got != "from-env" {
		t.Errorf("env value must be used when flag empty, got %q", got)
	}
	if got := envOr("", "IPGAZE_TEST_ENVOR_UNSET"); got != "" {
		t.Errorf("unset env must yield empty, got %q", got)
	}
}

func TestResolveTimeout_EnvOverridesConfig(t *testing.T) {
	cfg := &setup.CLIConfig{Server: setup.ServerConfig{Timeout: "45s"}}
	if got := resolveTimeout(cfg); got != 45*time.Second {
		t.Errorf("config timeout = %v, want 45s", got)
	}
	t.Setenv("IPGAZE_SERVER_TIMEOUT", "5s")
	if got := resolveTimeout(cfg); got != 5*time.Second {
		t.Errorf("env timeout = %v, want 5s", got)
	}
	t.Setenv("IPGAZE_SERVER_TIMEOUT", "12")
	if got := resolveTimeout(cfg); got != 12*time.Second {
		t.Errorf("bare-seconds env timeout = %v, want 12s", got)
	}
	t.Setenv("IPGAZE_SERVER_TIMEOUT", "nonsense")
	if got := resolveTimeout(cfg); got != 45*time.Second {
		t.Errorf("invalid env must fall back to config, got %v", got)
	}
}

func TestResolveToken_Priority(t *testing.T) {
	dir := t.TempDir()
	flagFile := filepath.Join(dir, "flag-token")
	if err := os.WriteFile(flagFile, []byte("file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgFile := filepath.Join(dir, "cfg-token")
	if err := os.WriteFile(cfgFile, []byte("cfg-file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &setup.CLIConfig{Auth: setup.AuthConfig{Token: "cfg-token", TokenFile: cfgFile}}

	t.Setenv("IPGAZE_TOKEN", "env-token")

	if got := resolveToken("flag-token", flagFile, cfg); got != "flag-token" {
		t.Errorf("--token must win, got %q", got)
	}
	if got := resolveToken("", flagFile, cfg); got != "file-token" {
		t.Errorf("--token-file must beat env, got %q", got)
	}
	if got := resolveToken("", "", cfg); got != "env-token" {
		t.Errorf("env must beat auth.token, got %q", got)
	}

	t.Setenv("IPGAZE_TOKEN", "")
	if got := resolveToken("", "", cfg); got != "cfg-token" {
		t.Errorf("auth.token must be used, got %q", got)
	}

	cfg.Auth.Token = ""
	if got := resolveToken("", "", cfg); got != "cfg-file-token" {
		t.Errorf("auth.token_file must be the last tier, got %q", got)
	}
}

func TestResolveToken_NoSourcesReturnsEmpty(t *testing.T) {
	t.Setenv("IPGAZE_TOKEN", "")
	if got := resolveToken("", "", &setup.CLIConfig{}); got != "" {
		t.Errorf("expected empty token, got %q", got)
	}
}

func TestDetectMode_ValueFlagWithSpaceSyntax(t *testing.T) {
	args := []string{"ipgaze-cli", "--server", "https://example.com"}
	if got := detectMode(args, "tui"); got != "tui" {
		t.Errorf("--server URL must not be read as a positional arg, got %q", got)
	}
	args = []string{"ipgaze-cli", "--config", "work", "--token", "abc"}
	if got := detectMode(args, "tui"); got != "tui" {
		t.Errorf("config-only value flags must stay in TUI mode, got %q", got)
	}
}

func TestDetectMode_PositionalArgForcesCLI(t *testing.T) {
	args := []string{"ipgaze-cli", "--server", "https://example.com", "8.8.8.8"}
	if got := detectMode(args, "tui"); got != "cli" {
		t.Errorf("positional IP must force CLI mode, got %q", got)
	}
}

func TestDetectMode_ActionFlagForcesCLI(t *testing.T) {
	args := []string{"ipgaze-cli", "--field", "country"}
	if got := detectMode(args, "tui"); got != "cli" {
		t.Errorf("action flag must force CLI mode, got %q", got)
	}
}

func TestConfigLangDefault_AutoTreatedAsUnset(t *testing.T) {
	cfg := &setup.CLIConfig{Defaults: setup.DefaultsConfig{Lang: "auto"}}
	if got := configLangDefault(cfg); got != "" {
		t.Errorf("auto must resolve to empty, got %q", got)
	}
	cfg.Defaults.Lang = "fr"
	if got := configLangDefault(cfg); got != "fr" {
		t.Errorf("configured lang = %q, want fr", got)
	}
}

func TestBuildEpoch_DerivesBuildDate(t *testing.T) {
	if buildEpoch() != 0 {
		t.Errorf("default BuildEpoch must parse to 0, got %d", buildEpoch())
	}
	if BuildDate != "N/A" {
		t.Errorf("BuildDate = %q, want N/A for an unset BuildEpoch", BuildDate)
	}
	if Version != "devel" || CommitID != "N/A" {
		t.Errorf("build defaults = %q/%q, want devel/N/A", Version, CommitID)
	}
}
