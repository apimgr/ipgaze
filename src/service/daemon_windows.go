//go:build windows

package service

import (
	"fmt"
	"os"
)

// Daemonize is a no-op on Windows. Traditional Unix daemonization (fork+setsid)
// is not supported. Use --service install && --service start for a Windows Service.
func Daemonize(lang string) error {
	fmt.Fprintln(os.Stderr, "Warning: --daemon is not supported on Windows")
	fmt.Fprintln(os.Stderr, "Use --service install && --service start for Windows Service")
	return nil
}
