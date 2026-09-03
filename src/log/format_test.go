package log

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeAndRead builds a Manager whose config has been adjusted by mutate,
// runs emit against it, and returns the contents of the named log file.
func writeAndRead(t *testing.T, name string, mutate func(*Config), emit func(*Manager)) string {
	t.Helper()
	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.Version = "1.2.3"
	mutate(&cfg)
	m, err := NewManager(dir, cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	emit(m)
	m.Close()

	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return strings.TrimSpace(string(b))
}

func TestAccessFormats(t *testing.T) {
	entry := AccessEntry{
		IP: "1.2.3.4", Method: "GET", Path: "/api/v1/ip", Proto: "HTTP/1.1",
		Status: 200, Bytes: 42, Referer: "-", UserAgent: "curl/7.0", RequestID: "req-1",
	}
	emit := func(m *Manager) { m.WriteAccessRequest(entry) }

	t.Run("apache", func(t *testing.T) {
		line := writeAndRead(t, "access.log", func(c *Config) { c.Access.Format = "apache" }, emit)
		if !strings.Contains(line, `"GET /api/v1/ip HTTP/1.1" 200 42 "-" "curl/7.0" req-1`) {
			t.Errorf("apache line = %q", line)
		}
	})

	t.Run("nginx", func(t *testing.T) {
		line := writeAndRead(t, "access.log", func(c *Config) { c.Access.Format = "nginx" }, emit)
		if !strings.HasPrefix(line, "1.2.3.4 - - [") {
			t.Errorf("nginx line = %q", line)
		}
		if strings.Contains(line, "curl/7.0") {
			t.Errorf("nginx common format must not carry the user agent: %q", line)
		}
	})

	t.Run("json", func(t *testing.T) {
		line := writeAndRead(t, "access.log", func(c *Config) { c.Access.Format = "json" }, emit)
		var got map[string]any
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Fatalf("not JSON: %v (%q)", err, line)
		}
		for _, k := range []string{"ip", "time", "method", "path", "status", "size", "ua"} {
			if _, ok := got[k]; !ok {
				t.Errorf("json access line missing key %q", k)
			}
		}
	})
}

func TestLeveledFormats(t *testing.T) {
	emit := func(m *Manager) { m.WriteServer("INFO", "started") }

	t.Run("text", func(t *testing.T) {
		line := writeAndRead(t, "server.log", func(c *Config) { c.Server.Format = "text" }, emit)
		if !strings.Contains(line, "[INFO] started") {
			t.Errorf("text line = %q", line)
		}
	})

	t.Run("json", func(t *testing.T) {
		line := writeAndRead(t, "server.log", func(c *Config) { c.Server.Format = "json" }, emit)
		var got map[string]any
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Fatalf("not JSON: %v (%q)", err, line)
		}
		if got["level"] != "INFO" || got["msg"] != "started" {
			t.Errorf("json leveled line = %v", got)
		}
	})
}

func TestAppFormats(t *testing.T) {
	emit := func(m *Manager) { m.WriteApp("INFO", "cache warm", "items", "12") }

	t.Run("logfmt", func(t *testing.T) {
		line := writeAndRead(t, "app.log", func(c *Config) { c.App.Format = "logfmt" }, emit)
		if !strings.Contains(line, `level=INFO`) || !strings.Contains(line, `items=12`) {
			t.Errorf("logfmt line = %q", line)
		}
	})

	t.Run("json", func(t *testing.T) {
		line := writeAndRead(t, "app.log", func(c *Config) { c.App.Format = "json" }, emit)
		var got map[string]any
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Fatalf("not JSON: %v (%q)", err, line)
		}
		if got["items"] != "12" {
			t.Errorf("json app line = %v", got)
		}
	})
}

func TestAuthFormats(t *testing.T) {
	emit := func(m *Manager) { m.WriteAuthFailure("1.2.3.4", "/api/v1/server/config", "invalid_token") }

	t.Run("syslog", func(t *testing.T) {
		line := writeAndRead(t, "auth.log", func(c *Config) { c.Auth.Format = "syslog" }, emit)
		if !strings.Contains(line, "ipgaze[") || !strings.Contains(line, "result=fail") {
			t.Errorf("syslog auth line = %q", line)
		}
	})

	t.Run("json", func(t *testing.T) {
		line := writeAndRead(t, "auth.log", func(c *Config) { c.Auth.Format = "json" }, emit)
		var got map[string]any
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Fatalf("not JSON: %v (%q)", err, line)
		}
		if got["reason"] != "invalid_token" {
			t.Errorf("json auth line = %v", got)
		}
	})
}

func TestSecurityFormats(t *testing.T) {
	emit := func(m *Manager) { m.WriteSecurity("Rate limit exceeded", "1.2.3.4") }

	tests := []struct {
		format string
		want   string
	}{
		{"fail2ban", "[security] Rate limit exceeded from 1.2.3.4"},
		{"syslog", "<134>1 "},
		{"cef", "CEF:0|CasjaysDev|ipgaze|1.2.3|security|Rate limit exceeded|5|src=1.2.3.4"},
		{"text", "[SECURITY] Rate limit exceeded from 1.2.3.4"},
	}
	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			format := tt.format
			line := writeAndRead(t, "security.log", func(c *Config) { c.Security.Format = format }, emit)
			if !strings.Contains(line, tt.want) {
				t.Errorf("%s line = %q, want it to contain %q", format, line, tt.want)
			}
		})
	}

	t.Run("json", func(t *testing.T) {
		line := writeAndRead(t, "security.log", func(c *Config) { c.Security.Format = "json" }, emit)
		var got map[string]any
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Fatalf("not JSON: %v (%q)", err, line)
		}
		if got["ip"] != "1.2.3.4" || got["msg"] != "Rate limit exceeded" {
			t.Errorf("json security line = %v", got)
		}
	})
}

// TestSanitizeLineStripsCRLF proves a value carrying CRLF cannot forge a
// second log record (AI.md PART 11: raw text only, one event per line).
func TestSanitizeLineStripsCRLF(t *testing.T) {
	line := writeAndRead(t, "security.log",
		func(c *Config) { c.Security.Format = "fail2ban" },
		func(m *Manager) { m.WriteSecurity("Blocked", "1.2.3.4\r\nFAKE [security] injected from 9.9.9.9") })
	if strings.Count(line, "\n") != 0 {
		t.Errorf("sanitized line still spans multiple records: %q", line)
	}
}
