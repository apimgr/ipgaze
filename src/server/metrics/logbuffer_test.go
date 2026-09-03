package metrics

import (
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestLogBuffer_EvictsOldest(t *testing.T) {
	b := NewLogBuffer(3)
	now := time.Now()
	for _, line := range []string{"a", "b", "c", "d"} {
		b.Append(LogEntry{Time: now, Level: "info", Line: line})
	}
	if b.Len() != 3 {
		t.Fatalf("Len() = %d, want 3", b.Len())
	}
	entries := b.Recent(0, 0)
	want := []string{"b", "c", "d"}
	for i, e := range entries {
		if e.Line != want[i] {
			t.Errorf("entry %d = %q, want %q", i, e.Line, want[i])
		}
	}
}

func TestLogBuffer_RecentHonorsMaxAge(t *testing.T) {
	b := NewLogBuffer(10)
	b.Append(LogEntry{Time: time.Now().Add(-2 * time.Hour), Level: "info", Line: "old"})
	b.Append(LogEntry{Time: time.Now(), Level: "info", Line: "new"})

	entries := b.Recent(10, time.Hour)
	if len(entries) != 1 || entries[0].Line != "new" {
		t.Errorf("Recent = %v, want only the fresh entry", entries)
	}
}

func TestLogBuffer_RecentHonorsLimit(t *testing.T) {
	b := NewLogBuffer(10)
	now := time.Now()
	for _, line := range []string{"a", "b", "c"} {
		b.Append(LogEntry{Time: now, Level: "info", Line: line})
	}
	entries := b.Recent(2, time.Hour)
	if len(entries) != 2 || entries[0].Line != "b" || entries[1].Line != "c" {
		t.Errorf("Recent(2) = %v, want the two newest entries", entries)
	}
}

func TestLogBuffer_StreamsGroupedByLevel(t *testing.T) {
	b := NewLogBuffer(10)
	now := time.Now()
	b.Append(LogEntry{Time: now, Level: "info", Line: "one"})
	b.Append(LogEntry{Time: now, Level: "error", Line: "two"})
	b.Append(LogEntry{Time: now, Level: "info", Line: "three"})

	streams := b.Streams(b.Recent(0, 0), "ipgaze")
	if len(streams) != 2 {
		t.Fatalf("streams = %d, want 2", len(streams))
	}
	if streams[0].Stream["level"] != "error" {
		t.Errorf("first stream level = %q, want error (sorted)", streams[0].Stream["level"])
	}
	if streams[0].Stream["app"] != "ipgaze" {
		t.Errorf("app label = %q, want ipgaze", streams[0].Stream["app"])
	}
	if len(streams[1].Values) != 2 {
		t.Errorf("info stream values = %d, want 2", len(streams[1].Values))
	}
}

func TestRedactLine_MasksBearerCredentials(t *testing.T) {
	got := redactLine("upstream rejected Authorization: Bearer sk-abc123 request")
	if got != "upstream rejected Authorization: Bearer xxxxx request" {
		t.Errorf("redactLine = %q, want the bearer value masked", got)
	}
}

func TestIsSensitiveKey(t *testing.T) {
	sensitive := []string{"token", "api_key", "Password", "encryption_key", "authorization"}
	for _, key := range sensitive {
		if !isSensitiveKey(key) {
			t.Errorf("isSensitiveKey(%q) = false, want true", key)
		}
	}
	for _, key := range []string{"path", "status", "duration_ms"} {
		if isSensitiveKey(key) {
			t.Errorf("isSensitiveKey(%q) = true, want false", key)
		}
	}
}

func TestLogBuffer_RecordRedactsSensitiveAttrs(t *testing.T) {
	b := NewLogBuffer(10)
	b.Record("WARN", "auth failed for Bearer sk-secret", slog.String("token", "sk-abc"), slog.String("service", "loki"))

	entries := b.Recent(0, 0)
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	if entries[0].Level != "warn" {
		t.Errorf("level = %q, want warn", entries[0].Level)
	}
	if strings.Contains(entries[0].Line, "sk-abc") || strings.Contains(entries[0].Line, "sk-secret") {
		t.Errorf("line = %q, want credentials redacted", entries[0].Line)
	}
	if !strings.Contains(entries[0].Line, "service=loki") {
		t.Errorf("line = %q, want the non-sensitive attribute preserved", entries[0].Line)
	}
}

func TestDefaultLogBuffer_IsSingleton(t *testing.T) {
	if DefaultLogBuffer(5) != DefaultLogBuffer(500) {
		t.Error("DefaultLogBuffer returned different buffers, want one shared buffer")
	}
}
