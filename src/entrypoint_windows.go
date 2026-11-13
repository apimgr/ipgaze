//go:build windows

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows/svc"
)

func main() {
	isService, err := svc.IsWindowsService()
	if err != nil {
		fmt.Fprintf(os.Stderr, "detect Windows service context: %v\n", err)
		os.Exit(exGeneral)
	}
	if !isService {
		runMain()
		return
	}
	if err := svc.Run("ipgaze", &windowsService{}); err != nil {
		fmt.Fprintf(os.Stderr, "run Windows service: %v\n", err)
		os.Exit(exGeneral)
	}
}

type windowsService struct{}

func (*windowsService) Execute(_ []string, requests <-chan svc.ChangeRequest, statuses chan<- svc.Status) (bool, uint32) {
	statuses <- svc.Status{State: svc.StartPending}
	done := make(chan struct{})
	go func() {
		defer close(done)
		runMain()
	}()

	status := svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	statuses <- status
	for {
		select {
		case <-done:
			statuses <- svc.Status{State: svc.Stopped}
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
				windowsServiceStopSignal <- os.Interrupt
				<-done
				statuses <- svc.Status{State: svc.Stopped}
				return false, 0
			}
		}
	}
}
