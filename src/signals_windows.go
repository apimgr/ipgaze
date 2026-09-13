//go:build windows

package main

import (
	"os"
	"os/signal"
)

// notifyServerSignals registers the Windows signal set from AI.md PART 8's
// Windows signal table (11132-11138): only os.Interrupt (Ctrl+C / Ctrl+Break)
// is deliverable, and it means graceful shutdown. Service control stops arrive
// through the SCM handler, not through this channel.
//
// AI.md 11140: Windows does NOT support SIGHUP, SIGUSR1, SIGUSR2 or SIGQUIT,
// so there is nothing to ignore and no log-reopen/status-dump signal to watch.
func notifyServerSignals(ch chan<- os.Signal) {
	signal.Notify(ch, os.Interrupt)
}

// isLogReopenSignal always reports false on Windows — SIGUSR1 does not exist.
func isLogReopenSignal(os.Signal) bool { return false }

// isStatusDumpSignal always reports false on Windows — SIGUSR2 does not exist.
func isStatusDumpSignal(os.Signal) bool { return false }
