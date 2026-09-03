package log

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseRotate(t *testing.T) {
	tests := []struct {
		in     string
		period string
		bytes  int64
	}{
		{"", "", 0},
		{"never", "", 0},
		{"daily", "daily", 0},
		{"weekly", "weekly", 0},
		{"monthly", "monthly", 0},
		{"yearly", "yearly", 0},
		{"50MB", "", 50 * 1024 * 1024},
		{"weekly,50MB", "weekly", 50 * 1024 * 1024},
		{"1GB", "", 1024 * 1024 * 1024},
		{"512KB", "", 512 * 1024},
		{"nonsense", "", 0},
	}
	for _, tt := range tests {
		got := parseRotate(tt.in)
		if got.period != tt.period || got.maxBytes != tt.bytes {
			t.Errorf("parseRotate(%q) = {%q,%d}, want {%q,%d}", tt.in, got.period, got.maxBytes, tt.period, tt.bytes)
		}
	}
}

func TestParseKeep(t *testing.T) {
	tests := []struct {
		in    string
		mode  string
		count int
		age   time.Duration
	}{
		{"", "none", 0, 0},
		{"none", "none", 0, 0},
		{"forever", "forever", 0, 0},
		{"5", "count", 5, 0},
		{"0", "none", 0, 0},
		{"7d", "age", 0, 7 * 24 * time.Hour},
		{"2w", "age", 0, 14 * 24 * time.Hour},
		{"3m", "age", 0, 90 * 24 * time.Hour},
		{"bogus", "none", 0, 0},
	}
	for _, tt := range tests {
		got := parseKeep(tt.in)
		if got.mode != tt.mode || got.count != tt.count || got.age != tt.age {
			t.Errorf("parseKeep(%q) = %+v, want {%s %d %v}", tt.in, got, tt.mode, tt.count, tt.age)
		}
	}
}

func TestPeriodKey(t *testing.T) {
	a := time.Date(2026, 1, 2, 23, 59, 0, 0, time.UTC)
	b := time.Date(2026, 1, 3, 0, 1, 0, 0, time.UTC)
	if periodKey("daily", a) == periodKey("daily", b) {
		t.Error("daily period key did not change across midnight")
	}
	if periodKey("monthly", a) != periodKey("monthly", b) {
		t.Error("monthly period key changed within the same month")
	}
	if periodKey("", a) != "" {
		t.Error("empty period must yield an empty key")
	}
}

// newTestWriter opens a writer directly so a test can drive rotation without
// standing up a whole Manager.
func newTestWriter(t *testing.T, dir, name, rotate, keep string, compress bool) *writer {
	t.Helper()
	w, err := openWriter(dir, LogFileConfig{
		Enabled:  true,
		Filename: name,
		Format:   "text",
		Rotate:   rotate,
		Keep:     keep,
	}, "text", compress)
	if err != nil {
		t.Fatalf("openWriter: %v", err)
	}
	return w
}

// archiveCount counts rotated files for base in dir.
func archiveCount(t *testing.T, dir, base string) int {
	t.Helper()
	prefix, suffix := archivePrefixSuffix(base)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	n := 0
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, prefix) && (strings.HasSuffix(name, suffix) || strings.HasSuffix(name, suffix+".gz")) {
			n++
		}
	}
	return n
}

func TestWriterRotatesBySize(t *testing.T) {
	dir := t.TempDir()
	w := newTestWriter(t, dir, "size.log", "200b", "forever", false)
	defer w.file.Close()

	line := strings.Repeat("x", 60)
	for i := 0; i < 12; i++ {
		w.write(line)
	}

	if got := archiveCount(t, dir, "size.log"); got == 0 {
		t.Fatal("expected at least one archive from size-based rotation")
	}
	info, err := os.Stat(filepath.Join(dir, "size.log"))
	if err != nil {
		t.Fatalf("stat active file: %v", err)
	}
	if info.Size() > 200 {
		t.Errorf("active file is %d bytes, above the 200-byte ceiling", info.Size())
	}
}

func TestWriterRotatesByDay(t *testing.T) {
	dir := t.TempDir()
	w := newTestWriter(t, dir, "daily.log", "daily", "forever", false)
	defer w.file.Close()

	w.write("first day")
	// Backdate the period anchor so the next write lands in a new day.
	w.mu.Lock()
	w.opened = w.opened.Add(-48 * time.Hour)
	w.mu.Unlock()
	w.write("second day")

	if got := archiveCount(t, dir, "daily.log"); got != 1 {
		t.Fatalf("archive count = %d, want 1", got)
	}
	active, err := os.ReadFile(filepath.Join(dir, "daily.log"))
	if err != nil {
		t.Fatalf("read active: %v", err)
	}
	if !strings.Contains(string(active), "second day") {
		t.Error("active file missing the post-rotation line")
	}
	if strings.Contains(string(active), "first day") {
		t.Error("active file still holds the pre-rotation line")
	}
}

func TestWriterPrunesToKeepCount(t *testing.T) {
	dir := t.TempDir()
	w := newTestWriter(t, dir, "keep.log", "daily", "2", false)
	defer w.file.Close()

	// Each pass backdates the anchor by a day and rotates at a distinct second,
	// so five iterations produce five differently-named archives.
	for i := 0; i < 5; i++ {
		w.write("entry")
		w.mu.Lock()
		w.opened = w.opened.Add(-24 * time.Hour)
		w.mu.Unlock()
		if err := w.rotateIfDue(time.Now().Add(time.Duration(i+1) * time.Second)); err != nil {
			t.Fatalf("rotateIfDue: %v", err)
		}
	}

	if got := archiveCount(t, dir, "keep.log"); got > 2 {
		t.Errorf("archive count = %d, want at most 2 after keep=2 pruning", got)
	}
}

func TestWriterKeepNoneDropsArchives(t *testing.T) {
	dir := t.TempDir()
	w := newTestWriter(t, dir, "drop.log", "daily", "none", false)
	defer w.file.Close()

	w.write("entry")
	w.mu.Lock()
	w.opened = w.opened.Add(-24 * time.Hour)
	w.mu.Unlock()
	w.write("next")

	if got := archiveCount(t, dir, "drop.log"); got != 0 {
		t.Errorf("archive count = %d, want 0 with keep=none", got)
	}
}

func TestWriterCompressesArchive(t *testing.T) {
	dir := t.TempDir()
	w := newTestWriter(t, dir, "gz.log", "daily", "forever", true)
	defer w.file.Close()

	w.write("entry")
	w.mu.Lock()
	w.opened = w.opened.Add(-24 * time.Hour)
	w.mu.Unlock()
	w.write("next")

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	found := false
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".gz") {
			found = true
		}
	}
	if !found {
		t.Error("expected a gzipped archive")
	}
}

// TestManagerRotate exercises the scheduler-facing entry point.
func TestManagerRotate(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultConfig()
	m, err := NewManager(dir, cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer m.Close()

	m.WriteServer("INFO", "hello")
	if err := m.Rotate(); err != nil {
		t.Errorf("Rotate: %v", err)
	}
}
