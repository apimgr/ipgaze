//go:build windows

package run

import (
	"context"
	"fmt"
	"os"

	"golang.org/x/sys/windows/svc"
)

const windowsServiceExitFailure = 1

func runPlatform(ctx context.Context, cfg *Config) error {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return fmt.Errorf("detect Windows service context: %w", err)
	}
	if !isService {
		return runMain(ctx, cfg)
	}
	if err := svc.Run("ipgaze", &windowsService{cfg: cfg}); err != nil {
		return fmt.Errorf("run Windows service: %w", err)
	}
	return nil
}

type windowsService struct {
	cfg *Config
}

func (s *windowsService) Execute(_ []string, requests <-chan svc.ChangeRequest, statuses chan<- svc.Status) (bool, uint32) {
	statuses <- svc.Status{State: svc.StartPending}
	done := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		defer close(done)
		result <- runMain(context.Background(), s.cfg)
	}()

	status := svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	statuses <- status
	for {
		select {
		case <-done:
			statuses <- svc.Status{State: svc.Stopped}
			if err := <-result; err != nil {
				return false, windowsServiceExitFailure
			}
			return false, 0
		case request, ok := <-requests:
			if !ok {
				return false, 0
			}
			switch request.Cmd {
			case svc.Interrogate:
				statuses <- status
			case svc.Stop, svc.Shutdown:
				statuses <- svc.Status{State: svc.StopPending}
				WindowsServiceStopSignal <- os.Interrupt
				<-done
				statuses <- svc.Status{State: svc.Stopped}
				if err := <-result; err != nil {
					return false, windowsServiceExitFailure
				}
				return false, 0
			}
		}
	}
}
