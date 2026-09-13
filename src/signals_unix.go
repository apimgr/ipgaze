//go:build !windows

package main

import (
	"os"
	"os/signal"
	"syscall"
)

// notifyServerSignals registers the Unix signal set from AI.md PART 8's signal
// table (11120-11130) on ch: SIGTERM/SIGINT/SIGQUIT/SIGRTMIN+3 for graceful
// shutdown, SIGUSR1 for log reopen, SIGUSR2 for status dump. SIGHUP is
// explicitly ignored — config auto-reloads via the ConfigManager file watcher.
//
// AI.md 11140 requires build tags to separate platform signal code: Windows has
// no SIGHUP/SIGUSR1/SIGUSR2/SIGQUIT, so those constants must not appear in a
// file compiled for it.
func notifyServerSignals(ch chan<- os.Signal) {
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT, syscall.Signal(37),
		syscall.SIGUSR1, syscall.SIGUSR2)
	signal.Ignore(syscall.SIGHUP)
}

// isLogReopenSignal reports whether sig is the reopen-logs signal (SIGUSR1).
func isLogReopenSignal(sig os.Signal) bool {
	return sig == syscall.SIGUSR1
}

// isStatusDumpSignal reports whether sig is the status-dump signal (SIGUSR2).
func isStatusDumpSignal(sig os.Signal) bool {
	return sig == syscall.SIGUSR2
}
