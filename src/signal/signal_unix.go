//go:build !windows

package signal

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func (h *SignalHandler) setupPlatform(ctx context.Context) func() {
	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh,
		syscall.SIGTERM,
		syscall.SIGINT,
		syscall.SIGQUIT,
		syscall.SIGUSR1,
		syscall.SIGUSR2,
		// SIGRTMIN+3: sent by Docker on graceful stop
		syscall.Signal(37),
	)
	// Ignore SIGHUP — config auto-reloads via file watcher
	signal.Ignore(syscall.SIGHUP)

	go func() {
		for {
			select {
			case sig := <-sigCh:
				switch sig {
				case syscall.SIGUSR1:
					select {
					case h.logRotateCh <- struct{}{}:
					default:
					}
				case syscall.SIGUSR2:
					select {
					case h.statusDumpCh <- struct{}{}:
					default:
					}
				default:
					// SIGTERM, SIGINT, SIGQUIT, SIGRTMIN+3 → shutdown
					select {
					case h.shutdownCh <- struct{}{}:
					default:
					}
					return
				}
			case <-ctx.Done():
				signal.Stop(sigCh)
				return
			}
		}
	}()

	return func() {
		signal.Stop(sigCh)
	}
}
