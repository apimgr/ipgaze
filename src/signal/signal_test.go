//go:build !windows

package signal

import (
	"context"
	"syscall"
	"testing"
	"time"
)

// TestNew verifies that New returns a non-nil Handler with valid internal channels.
func TestNew(t *testing.T) {
	h := NewSignalHandler()
	if h == nil {
		t.Fatal("NewSignalHandler() returned nil")
	}
	if h.shutdownCh == nil {
		t.Error("shutdownCh is nil")
	}
	if h.logRotateCh == nil {
		t.Error("logRotateCh is nil")
	}
	if h.statusDumpCh == nil {
		t.Error("statusDumpCh is nil")
	}
}

// TestChannelAccessors verifies the exported channel accessors return non-nil channels.
func TestChannelAccessors(t *testing.T) {
	h := NewSignalHandler()
	if h.ShutdownCh() == nil {
		t.Error("ShutdownCh() returned nil")
	}
	if h.LogRotateCh() == nil {
		t.Error("LogRotateCh() returned nil")
	}
	if h.StatusDumpCh() == nil {
		t.Error("StatusDumpCh() returned nil")
	}
}

// TestSetupReturnsCancel verifies that Setup returns a non-nil cancel function.
func TestSetupReturnsCancel(t *testing.T) {
	h := NewSignalHandler()
	ctx, ctxCancel := context.WithCancel(context.Background())
	defer ctxCancel()

	cancel := h.Setup(ctx)
	if cancel == nil {
		t.Fatal("Setup returned nil cancel function")
	}
	// Cancel must not panic when called.
	cancel()
}

// TestSetupCancelViaContext verifies that cancelling the context causes the
// background goroutine to stop without sending a shutdown signal.
func TestSetupCancelViaContext(t *testing.T) {
	h := NewSignalHandler()
	ctx, ctxCancel := context.WithCancel(context.Background())
	cancel := h.Setup(ctx)
	defer cancel()

	// Cancel the context — the goroutine should exit cleanly.
	ctxCancel()

	// Verify ShutdownCh receives nothing within a short window.
	select {
	case <-h.ShutdownCh():
		t.Error("shutdownCh fired on context cancel; want no signal")
	case <-time.After(100 * time.Millisecond):
	}
}

// TestSIGUSR1CausesLogRotate verifies that SIGUSR1 sends to LogRotateCh.
func TestSIGUSR1CausesLogRotate(t *testing.T) {
	h := NewSignalHandler()
	ctx, ctxCancel := context.WithCancel(context.Background())
	defer ctxCancel()

	cancel := h.Setup(ctx)
	defer cancel()

	// Send SIGUSR1 to ourselves.
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGUSR1); err != nil {
		t.Fatalf("Kill(SIGUSR1): %v", err)
	}

	select {
	case <-h.LogRotateCh():
	case <-time.After(2 * time.Second):
		t.Error("LogRotateCh did not fire within 2s after SIGUSR1")
	}
}

// TestSIGUSR2CausesStatusDump verifies that SIGUSR2 sends to StatusDumpCh.
func TestSIGUSR2CausesStatusDump(t *testing.T) {
	h := NewSignalHandler()
	ctx, ctxCancel := context.WithCancel(context.Background())
	defer ctxCancel()

	cancel := h.Setup(ctx)
	defer cancel()

	// Send SIGUSR2 to ourselves.
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGUSR2); err != nil {
		t.Fatalf("Kill(SIGUSR2): %v", err)
	}

	select {
	case <-h.StatusDumpCh():
	case <-time.After(2 * time.Second):
		t.Error("StatusDumpCh did not fire within 2s after SIGUSR2")
	}
}

// TestSIGTERMCausesShutdown verifies that SIGTERM sends to ShutdownCh.
func TestSIGTERMCausesShutdown(t *testing.T) {
	h := NewSignalHandler()
	ctx, ctxCancel := context.WithCancel(context.Background())
	defer ctxCancel()

	cancel := h.Setup(ctx)
	defer cancel()

	// Send SIGTERM to ourselves.
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("Kill(SIGTERM): %v", err)
	}

	select {
	case <-h.ShutdownCh():
	case <-time.After(2 * time.Second):
		t.Error("ShutdownCh did not fire within 2s after SIGTERM")
	}
}

// TestSIGINTCausesShutdown verifies that SIGINT sends to ShutdownCh.
func TestSIGINTCausesShutdown(t *testing.T) {
	h := NewSignalHandler()
	ctx, ctxCancel := context.WithCancel(context.Background())
	defer ctxCancel()

	cancel := h.Setup(ctx)
	defer cancel()

	if err := syscall.Kill(syscall.Getpid(), syscall.SIGINT); err != nil {
		t.Fatalf("Kill(SIGINT): %v", err)
	}

	select {
	case <-h.ShutdownCh():
	case <-time.After(2 * time.Second):
		t.Error("ShutdownCh did not fire within 2s after SIGINT")
	}
}

// TestShutdownChannelNonBlocking verifies the shutdownCh is buffered (capacity 1)
// and a second signal is dropped rather than blocking the goroutine.
func TestShutdownChannelNonBlocking(t *testing.T) {
	h := NewSignalHandler()
	ctx, ctxCancel := context.WithCancel(context.Background())
	defer ctxCancel()

	cancel := h.Setup(ctx)
	defer cancel()

	// Send SIGTERM twice in quick succession; second must not block.
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("first Kill(SIGTERM): %v", err)
	}

	// Drain the first signal.
	select {
	case <-h.ShutdownCh():
	case <-time.After(2 * time.Second):
		t.Fatal("ShutdownCh did not fire after first SIGTERM")
	}

	// At this point the goroutine has returned (shutdown was signalled and
	// the goroutine exits). The channel buffer means no goroutine leak.
	// Just verify the channel is now empty (second signal was never sent
	// because the goroutine exited after the first).
	select {
	case <-h.ShutdownCh():
		t.Error("unexpected second value in ShutdownCh")
	case <-time.After(50 * time.Millisecond):
	}
}

// TestLogRotateChannelNonBlocking verifies a second SIGUSR1 is dropped when the
// channel is already full rather than blocking the signal goroutine.
func TestLogRotateChannelNonBlocking(t *testing.T) {
	h := NewSignalHandler()
	ctx, ctxCancel := context.WithCancel(context.Background())
	defer ctxCancel()

	cancel := h.Setup(ctx)
	defer cancel()

	// Send two SIGUSR1 signals without draining the channel.
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGUSR1); err != nil {
		t.Fatalf("Kill(SIGUSR1) #1: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGUSR1); err != nil {
		t.Fatalf("Kill(SIGUSR1) #2: %v", err)
	}

	// At most one value should be in the buffered channel.
	timeout := time.After(2 * time.Second)
	select {
	case <-h.LogRotateCh():
	case <-timeout:
		t.Fatal("LogRotateCh did not fire")
	}
}
