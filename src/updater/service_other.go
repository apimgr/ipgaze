//go:build !linux && !darwin && !windows && !freebsd && !openbsd && !netbsd
// +build !linux,!darwin,!windows,!freebsd,!openbsd,!netbsd

package updater

import (
	"fmt"
	"runtime"
)

// restartService is a stub for unsupported platforms.
func restartService() error {
	return fmt.Errorf("service restart not supported on %s", runtime.GOOS)
}
