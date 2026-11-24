package log

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewManager_CreatesFiles(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.Debug.Enabled = true

	m, err := NewManager(dir, cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer m.Close()

	// Write one line to each log type
	m.WriteAccess("127.0.0.1 - - [01/Jan/2025:00:00:00 +0000] \"GET / HTTP/1.1\" 200 512 \"-\" \"test\" req-1")
	m.WriteServer("INFO", "server started")
	m.WriteError("ERROR", "something failed")
	m.WriteApp("INFO", "user created", "id", "abc123", "ip", "1.2.3.4")
	m.WriteAuth("ipgaze", 1, "user", "bob", "result", "fail", "reason", "invalid_credentials")
	m.WriteAuditEvent("audit_001", "server.started", "server", "info", "success", "127.0.0.1", map[string]any{"version": "1.0.0"})
	m.WriteSecurity("Failed authentication attempt", "192.168.1.100")
	m.WriteDebug("debug detail")

	// Flush by closing
	m.Close()

	for _, name := range []string{"access.log", "server.log", "error.log", "app.log", "auth.log", "audit.log", "security.log", "debug.log"} {
		path := filepath.Join(dir, name)
		b, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("log file %s not created: %v", name, err)
			continue
		}
		if len(b) == 0 {
			t.Errorf("log file %s is empty", name)
		}
	}
}

func TestNewManager_MkdirFails(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.Access.Enabled = true

	_, err := NewManager(filepath.Join(blocker, "sub"), cfg)
	if err == nil {
		t.Error("NewManager: expected error when a path component is a regular file, got nil")
	}
}

func TestManager_NilSafe(t *testing.T) {
	var m *Manager
	// None of these must panic
	m.WriteAccess("line")
	m.WriteServer("INFO", "msg")
	m.WriteError("ERROR", "msg")
	m.WriteApp("INFO", "msg")
	m.WriteAuth("prog", 1)
	m.WriteAudit(AuditEvent{})
	m.WriteAuditEvent("id", "ev", "cat", "info", "success", "ip", nil)
	m.WriteSecurity("msg", "ip")
	m.WriteDebug("msg")
	m.Close()
}

func TestManager_AuditJSON(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultConfig()
	m, err := NewManager(dir, cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	m.WriteAuditEvent("audit_001", "config.updated", "config", "info", "success", "10.0.0.1",
		map[string]any{"changed_keys": []string{"server.port"}})
	m.Close()

	b, err := os.ReadFile(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatalf("read audit.log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 audit line, got %d", len(lines))
	}

	var evt AuditEvent
	if err := json.Unmarshal([]byte(lines[0]), &evt); err != nil {
		t.Fatalf("unmarshal audit event: %v", err)
	}
	if evt.Event != "config.updated" {
		t.Errorf("Event: got %q, want %q", evt.Event, "config.updated")
	}
	if evt.Category != "config" {
		t.Errorf("Category: got %q, want %q", evt.Category, "config")
	}
	if evt.Actor.IP != "10.0.0.1" {
		t.Errorf("Actor.IP: got %q, want %q", evt.Actor.IP, "10.0.0.1")
	}
	if evt.Actor.Type != "operator" {
		t.Errorf("Actor.Type: got %q, want operator", evt.Actor.Type)
	}
	if len(evt.ID) != 26 {
		t.Errorf("ID: got %q, want a canonical 26-character ULID", evt.ID)
	}
	if evt.Prev != emptyAuditHash {
		t.Errorf("Prev = %q, want the zero hash for the first entry", evt.Prev)
	}
	// Time must be valid RFC3339
	if _, err := time.Parse(time.RFC3339Nano, evt.Time); err != nil {
		t.Errorf("Time not valid RFC3339: %q", evt.Time)
	}
}

func TestAuditHashChainContinuesAcrossRotation(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.Audit.Keep = "forever"
	m, err := NewManager(dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	m.WriteAuditEvent("", "one", "server", "info", "success", "", nil)
	m.audit.mu.Lock()
	m.audit.opened = time.Now().Add(-48 * time.Hour)
	m.audit.mu.Unlock()
	m.WriteAuditEvent("", "two", "server", "info", "success", "", nil)
	m.Close()
	if broken := verifyAuditChainAt(dir, "audit.log"); broken != 0 {
		t.Fatalf("current audit chain broken at line %d", broken)
	}
	anchor, err := os.ReadFile(filepath.Join(dir, "audit.anchor"))
	if err != nil {
		t.Fatal(err)
	}
	if len(strings.TrimSpace(string(anchor))) != 64 {
		t.Fatalf("anchor = %q, want 64 lowercase hex characters", anchor)
	}
	info, err := os.Stat(filepath.Join(dir, "audit.anchor"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("anchor permissions = %04o, want 0600", info.Mode().Perm())
	}
}

func TestAuditRotationReportsTamperedClosedFile(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.Audit.Keep = "forever"
	m, err := NewManager(dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	m.WriteAuditEvent("", "before", "server", "info", "success", "", nil)
	activePath := filepath.Join(dir, "audit.log")
	line, err := os.ReadFile(activePath)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(line), `"event":"before"`, `"event":"changed"`, 1)
	if tampered == string(line) {
		t.Fatal("could not prepare audit tamper fixture")
	}
	if err := os.WriteFile(activePath, []byte(tampered), 0o640); err != nil {
		t.Fatal(err)
	}
	m.audit.mu.Lock()
	m.audit.opened = time.Now().Add(-48 * time.Hour)
	m.audit.mu.Unlock()
	m.WriteAuditEvent("", "after", "server", "info", "success", "", nil)
	m.Close()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	archive := ""
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "audit-") && strings.HasSuffix(entry.Name(), ".log") {
			archive = entry.Name()
			break
		}
	}
	if archive == "" {
		t.Fatal("audit rotation did not create an archive")
	}
	current, err := os.ReadFile(activePath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(current), `"event":"security.audit_chain_broken"`) || !strings.Contains(string(current), archive) {
		t.Fatalf("rotation did not report the tampered closed file: %s", current)
	}
	if broken := verifyAuditChainAt(dir, "audit.log"); broken != 0 {
		t.Fatalf("current chain broken at %d after rotation warning", broken)
	}
}

func TestNewManagerReportsBrokenAuditChainOnce(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "audit.log"), []byte(`{"event":"edited"}`+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	m, err := NewManager(dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	m.Close()
	first, err := os.ReadFile(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(first), `"event":"security.audit_chain_broken"`) {
		t.Fatalf("broken-chain event missing: %s", first)
	}
	m, err = NewManager(dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	m.Close()
	second, err := os.ReadFile(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(second), `"event":"security.audit_chain_broken"`) != 1 {
		t.Fatalf("broken-chain warning was repeated: %s", second)
	}
}

func TestManager_AuditSourceJSON(t *testing.T) {
	dir := t.TempDir()
	m, err := NewManager(dir, DefaultConfig())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	m.WriteAudit(AuditEvent{Event: "api.request", Source: "mcp", Category: "api", Severity: "info", Result: "success"})
	m.Close()

	b, err := os.ReadFile(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatalf("read audit.log: %v", err)
	}
	var evt AuditEvent
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(b))), &evt); err != nil {
		t.Fatalf("unmarshal audit event: %v", err)
	}
	if evt.Source != "mcp" {
		t.Errorf("Source: got %q, want mcp", evt.Source)
	}
}

func TestManager_ReconfigureSwitchesActiveWriter(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultConfig()
	manager, err := NewManager(dir, cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	manager.WriteServer("INFO", "before reload")
	cfg.Server.Filename = "server-renamed.log"
	if err := manager.Reconfigure(cfg); err != nil {
		t.Fatalf("Reconfigure: %v", err)
	}
	manager.WriteServer("INFO", "after reload")
	manager.Close()

	oldLog, err := os.ReadFile(filepath.Join(dir, "server.log"))
	if err != nil {
		t.Fatalf("read old server log: %v", err)
	}
	newLog, err := os.ReadFile(filepath.Join(dir, "server-renamed.log"))
	if err != nil {
		t.Fatalf("read replacement server log: %v", err)
	}
	if !strings.Contains(string(oldLog), "before reload") || strings.Contains(string(oldLog), "after reload") {
		t.Errorf("old server log has incorrect contents: %q", oldLog)
	}
	if !strings.Contains(string(newLog), "after reload") || strings.Contains(string(newLog), "before reload") {
		t.Errorf("replacement server log has incorrect contents: %q", newLog)
	}
}

func TestManager_AccessApache(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultConfig()
	m, err := NewManager(dir, cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	m.WriteAccessRequest(AccessEntry{
		IP: "1.2.3.4", Method: "GET", Path: "/api/v1/ip", Proto: "HTTP/1.1",
		Status: 200, Bytes: 42, Referer: "-", UserAgent: "curl/7.0", RequestID: "req-123",
	})
	m.Close()

	b, err := os.ReadFile(filepath.Join(dir, "access.log"))
	if err != nil {
		t.Fatalf("read access.log: %v", err)
	}
	line := strings.TrimSpace(string(b))
	if !strings.HasPrefix(line, "1.2.3.4") {
		t.Errorf("access line does not start with IP: %q", line)
	}
	if !strings.Contains(line, `"GET /api/v1/ip HTTP/1.1"`) {
		t.Errorf("access line missing request: %q", line)
	}
	if !strings.Contains(line, "200") {
		t.Errorf("access line missing status 200: %q", line)
	}
}

func TestManager_SecurityFail2ban(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultConfig()
	m, err := NewManager(dir, cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	m.WriteSecurity("Rate limit exceeded", "192.168.1.5")
	m.Close()

	b, err := os.ReadFile(filepath.Join(dir, "security.log"))
	if err != nil {
		t.Fatalf("read security.log: %v", err)
	}
	line := strings.TrimSpace(string(b))
	if !strings.Contains(line, "[security]") {
		t.Errorf("security line missing [security] tag: %q", line)
	}
	if !strings.Contains(line, "192.168.1.5") {
		t.Errorf("security line missing IP: %q", line)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Level != "warn" {
		t.Errorf("Level: got %q, want %q", cfg.Level, "warn")
	}
	if cfg.Access.Filename != "access.log" {
		t.Errorf("Access.Filename: got %q", cfg.Access.Filename)
	}
	if cfg.Audit.Format != "json" {
		t.Errorf("Audit.Format: got %q, want json", cfg.Audit.Format)
	}
	if !cfg.Audit.Enabled {
		t.Error("Audit.Enabled should be true by default")
	}
	if cfg.Debug.Enabled {
		t.Error("Debug.Enabled should be false by default")
	}
}
