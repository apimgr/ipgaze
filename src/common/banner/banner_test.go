package banner

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/apimgr/ipgaze/src/common/terminal"
)

// makeSize builds a terminal.TerminalSize with the given cols/rows.
// The SizeMode is inferred from the same thresholds as terminal.GetTerminalSize().
func makeSize(cols, rows int) terminal.TerminalSize {
	var mode terminal.SizeMode
	switch {
	case cols < 40 || rows < 10:
		mode = terminal.SizeModeMicro
	case cols < 60 || rows < 16:
		mode = terminal.SizeModeMinimal
	case cols < 80 || rows < 24:
		mode = terminal.SizeModeCompact
	case cols < 120 || rows < 40:
		mode = terminal.SizeModeStandard
	case cols < 200 || rows < 60:
		mode = terminal.SizeModeWide
	case cols < 400 || rows < 80:
		mode = terminal.SizeModeUltrawide
	default:
		mode = terminal.SizeModeMassive
	}
	return terminal.TerminalSize{Cols: cols, Rows: rows, Mode: mode}
}

// captureStdout redirects os.Stdout for the duration of fn and returns whatever
// was written to it. This is safe for single-threaded test use only.
func captureStdout(fn func()) string {
	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w

	fn()

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	r.Close()
	return buf.String()
}

// minimalConfig returns a BannerPrintConfig suitable for basic tests.
func minimalConfig() BannerPrintConfig {
	return BannerPrintConfig{
		AppName:   "testapp",
		Version:   "1.2.3",
		AppMode:   "production",
		Debug:     false,
		URLs:      []string{"http://0.0.0.0:8080"},
		ColorFlag: "never",
	}
}

// ─────────────────────── printMicro ──────────────────────────────────────────

// printMicro must always print AppName and Version — it is the smallest mode.
func TestPrintMicro_ContainsNameAndVersion(t *testing.T) {
	cfg := minimalConfig()
	out := captureStdout(func() { printMicro(cfg) })
	if !strings.Contains(out, "testapp") {
		t.Errorf("printMicro: AppName missing from output:\n%s", out)
	}
	if !strings.Contains(out, "1.2.3") {
		t.Errorf("printMicro: Version missing from output:\n%s", out)
	}
}

// ─────────────────────── printMinimal ────────────────────────────────────────

// printMinimal must include AppName, Version, and AppMode.
func TestPrintMinimal_ContainsNameVersionMode(t *testing.T) {
	cfg := minimalConfig()
	out := captureStdout(func() { printMinimal(cfg, true) })
	if !strings.Contains(strings.ToLower(out), "testapp") {
		t.Errorf("printMinimal: AppName missing:\n%s", out)
	}
	if !strings.Contains(out, "1.2.3") {
		t.Errorf("printMinimal: Version missing:\n%s", out)
	}
	if !strings.Contains(out, "production") {
		t.Errorf("printMinimal: AppMode missing:\n%s", out)
	}
}

// emoji=false must suppress all emoji characters (NO_COLOR / TERM=dumb path)
// while still including AppName, Version, and AppMode text.
func TestPrintMinimal_EmojiDisabled_NoEmoji(t *testing.T) {
	cfg := minimalConfig()
	out := captureStdout(func() { printMinimal(cfg, false) })
	for _, e := range []string{"🚀", "📦", "🔧", "🔒", "✅"} {
		if strings.Contains(out, e) {
			t.Errorf("printMinimal emoji=false: unexpected %q in output:\n%s", e, out)
		}
	}
	if !strings.Contains(strings.ToLower(out), "testapp") {
		t.Errorf("printMinimal emoji=false: AppName missing:\n%s", out)
	}
}

// ─────────────────────── printCompact ────────────────────────────────────────

// printCompact without color must print name, version, mode, and the URL.
func TestPrintCompact_NoColor_ContainsAllFields(t *testing.T) {
	cfg := minimalConfig()
	out := captureStdout(func() { printCompact(cfg, false, true) })
	if !strings.Contains(strings.ToLower(out), "testapp") {
		t.Errorf("printCompact no-color: AppName missing:\n%s", out)
	}
	if !strings.Contains(out, "1.2.3") {
		t.Errorf("printCompact no-color: Version missing:\n%s", out)
	}
	if !strings.Contains(out, "production") {
		t.Errorf("printCompact no-color: AppMode missing:\n%s", out)
	}
	if !strings.Contains(out, "http://0.0.0.0:8080") {
		t.Errorf("printCompact no-color: URL missing:\n%s", out)
	}
}

// printCompact with color must still contain readable text (despite ANSI codes).
func TestPrintCompact_WithColor_ContainsAppName(t *testing.T) {
	cfg := minimalConfig()
	out := captureStdout(func() { printCompact(cfg, true, true) })
	if !strings.Contains(strings.ToLower(out), "testapp") {
		t.Errorf("printCompact color: AppName missing:\n%s", out)
	}
	if !strings.Contains(out, "http://0.0.0.0:8080") {
		t.Errorf("printCompact color: URL missing:\n%s", out)
	}
}

// printCompact must list all provided URLs.
func TestPrintCompact_MultipleURLs(t *testing.T) {
	cfg := minimalConfig()
	cfg.URLs = []string{"http://0.0.0.0:8080", "http://abc.onion"}
	out := captureStdout(func() { printCompact(cfg, false, true) })
	for _, u := range cfg.URLs {
		if !strings.Contains(out, u) {
			t.Errorf("printCompact multi-URL: %q missing from output:\n%s", u, out)
		}
	}
}

// ─────────────────────── printFull ───────────────────────────────────────────

// printFull without color must not emit ANSI escape codes.
func TestPrintFull_NoColor_NoANSI(t *testing.T) {
	cfg := minimalConfig()
	size := makeSize(80, 24)
	out := captureStdout(func() { printFull(cfg, size, false, true) })
	if strings.Contains(out, "\033[") {
		t.Errorf("printFull no-color: unexpected ANSI escape sequences in output:\n%s", out)
	}
	if !strings.Contains(strings.ToLower(out), "testapp") {
		t.Errorf("printFull no-color: AppName missing:\n%s", out)
	}
	if !strings.Contains(out, "1.2.3") {
		t.Errorf("printFull no-color: Version missing:\n%s", out)
	}
}

// printFull with color must include ANSI escape sequences.
func TestPrintFull_WithColor_ContainsANSI(t *testing.T) {
	cfg := minimalConfig()
	size := makeSize(80, 24)
	out := captureStdout(func() { printFull(cfg, size, true, true) })
	if !strings.Contains(out, "\033[") {
		t.Errorf("printFull with-color: expected ANSI escape sequences, got:\n%s", out)
	}
}

// printFull must include a "Debug: enabled" line when Debug=true.
func TestPrintFull_DebugLine_WhenDebugTrue(t *testing.T) {
	cfg := minimalConfig()
	cfg.Debug = true
	size := makeSize(80, 24)
	out := captureStdout(func() { printFull(cfg, size, false, true) })
	if !strings.Contains(out, "Debug") {
		t.Errorf("printFull debug=true: 'Debug' line missing from output:\n%s", out)
	}
}

// printFull must NOT include "Debug: enabled" when Debug=false.
func TestPrintFull_NoDebugLine_WhenDebugFalse(t *testing.T) {
	cfg := minimalConfig()
	cfg.Debug = false
	size := makeSize(80, 24)
	out := captureStdout(func() { printFull(cfg, size, false, true) })
	if strings.Contains(out, "Debug: enabled") {
		t.Errorf("printFull debug=false: unexpected 'Debug: enabled' in output:\n%s", out)
	}
}

// printFull must print every URL in cfg.URLs.
func TestPrintFull_MultipleURLs(t *testing.T) {
	cfg := minimalConfig()
	cfg.URLs = []string{"http://0.0.0.0:8080", "http://example.onion"}
	size := makeSize(80, 24)
	out := captureStdout(func() { printFull(cfg, size, false, true) })
	for _, u := range cfg.URLs {
		if !strings.Contains(out, u) {
			t.Errorf("printFull multiple URLs: %q missing from output:\n%s", u, out)
		}
	}
}

// printFull with cols > 100 must cap the effective width at 100 so no single
// printed line exceeds 100 visible characters (box borders included).
// Measurement uses rune count, not byte count — box-drawing chars (─ │ ┌ ┐ └ ┘)
// are 3 bytes each in UTF-8 but count as one visual column.
func TestPrintFull_WidthCappedAt100(t *testing.T) {
	cfg := minimalConfig()
	size := makeSize(200, 50)
	out := captureStdout(func() { printFull(cfg, size, false, true) })
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		if w := utf8.RuneCountInString(line); w > 100 {
			t.Errorf("printFull cap-at-100: line too wide (%d runes): %q", w, line)
		}
	}
}

// printFull with no URLs must not panic.
func TestPrintFull_NoURLs_NoPanic(t *testing.T) {
	cfg := minimalConfig()
	cfg.URLs = nil
	size := makeSize(80, 24)
	captureStdout(func() { printFull(cfg, size, false, true) })
}

// ─────────────────────── CachedSize race safety ──────────────────────────────

// Concurrent reads and writes to CachedSize through cacheMu must not data-race.
// Run the test suite with -race to verify.
func TestCachedSize_ConcurrentAccess(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cacheMu.Lock()
			CachedSize.Cols = i * 10
			cacheMu.Unlock()

			cacheMu.RLock()
			_ = CachedSize.Cols
			cacheMu.RUnlock()
		}(i)
	}
	wg.Wait()
}

// ─────────────────────── WatchTerminalSize ────────────────────────────────────

// WatchTerminalSize must return promptly when the context is cancelled.
func TestWatchTerminalSize_ExitsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		WatchTerminalSize(ctx)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("WatchTerminalSize: did not exit after context cancellation within 2s")
	}
}
