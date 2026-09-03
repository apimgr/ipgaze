//go:build windows

package signal

import (
	"context"
	"os"
	"os/signal"
)

func (h *SignalHandler) setupPlatform(ctx context.Context) func() {
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt)

	go func() {
		select {
		case <-sigCh:
			select {
			case h.shutdownCh <- struct{}{}:
			default:
			}
		case <-ctx.Done():
			signal.Stop(sigCh)
		}
	}()

	return func() {
		signal.Stop(sigCh)
	}
}
