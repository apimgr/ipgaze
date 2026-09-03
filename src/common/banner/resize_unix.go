//go:build !windows

// Package banner — Unix resize watcher: reacts to SIGWINCH to keep
// CachedSize current so long-running processes (server, TUI) can reflow
// output without querying the OS on every render.
package banner

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/apimgr/ipgaze/src/common/terminal"
	"golang.org/x/term"
)

// WatchTerminalSize listens for SIGWINCH and refreshes CachedSize until ctx
// is cancelled. Call it in a goroutine at startup if the process needs to
// react to terminal resize (server banner re-print, TUI reflow, etc.).
func WatchTerminalSize(ctx context.Context) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGWINCH)
	defer signal.Stop(sigCh)

	for {
		select {
		case <-ctx.Done():
			return
		case <-sigCh:
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
