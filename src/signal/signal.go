package signal

import (
	"context"
)

// Handler holds the signal handling context and callbacks.
type SignalHandler struct {
	shutdownCh   chan struct{}
	logRotateCh  chan struct{}
	statusDumpCh chan struct{}
}

// NewSignalHandler creates a new signal Handler.
func NewSignalHandler() *SignalHandler {
	return &SignalHandler{
		shutdownCh:   make(chan struct{}, 1),
		logRotateCh:  make(chan struct{}, 1),
		statusDumpCh: make(chan struct{}, 1),
	}
}

// ShutdownCh returns a channel that receives when shutdown is requested.
func (h *SignalHandler) ShutdownCh() <-chan struct{} { return h.shutdownCh }

// LogRotateCh returns a channel that receives on SIGUSR1 (log rotation).
func (h *SignalHandler) LogRotateCh() <-chan struct{} { return h.logRotateCh }

// StatusDumpCh returns a channel that receives on SIGUSR2 (status dump).
func (h *SignalHandler) StatusDumpCh() <-chan struct{} { return h.statusDumpCh }

// Setup registers OS signal handlers. Must be called from main.
// Returns a cancel function to stop listening.
func (h *SignalHandler) Setup(ctx context.Context) (cancel func()) {
	return h.setupPlatform(ctx)
}
