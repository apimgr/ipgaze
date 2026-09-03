//go:build windows

// Package banner — Windows resize watcher: polls terminal size every 500ms
// because Windows has no SIGWINCH equivalent.
package banner

import (
	"context"
	"os"
	"time"

	"github.com/apimgr/ipgaze/src/common/terminal"
	"golang.org/x/term"
)

// WatchTerminalSize polls the terminal size every 500ms and refreshes
// CachedSize when it changes. Call it in a goroutine at startup if the
// process needs to react to terminal resize (server banner re-print,
// TUI reflow, etc.).
func WatchTerminalSize(ctx context.Context) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	var lastCols, lastRows int

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cols, rows, err := term.GetSize(int(os.Stdout.Fd()))
			if err != nil {
				continue
			}
			if cols == 0 {
				cols = 80
			}
			if rows == 0 {
				rows = 24
			}
			if cols == lastCols && rows == lastRows {
				continue
			}
			lastCols, lastRows = cols, rows
			cacheMu.Lock()
			CachedSize = terminal.TerminalSize{
				Cols: cols,
				Rows: rows,
				Mode: terminal.GetTerminalSize().Mode,
			}
			cacheMu.Unlock()
		}
	}
}
