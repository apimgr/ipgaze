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
	// Time must be valid RFC3339
	if _, err := time.Parse(time.RFC3339Nano, evt.Time); err != nil {
		t.Errorf("Time not valid RFC3339: %q", evt.Time)
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
