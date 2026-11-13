//go:build !windows

package service

import (
	"os"

	"github.com/apimgr/ipgaze/src/paths"
)

// IsRunningAsService reports whether the current process was launched by an
// OS service manager. It avoids treating containers and explicitly daemonized
// child processes as managed services.
func IsRunningAsService() bool {
	if paths.IsRunningInContainer() || os.Getenv("_DAEMON_CHILD") != "" {
		return false
	}
	if os.Getenv("INVOCATION_ID") != "" || os.Getenv("NOTIFY_SOCKET") != "" ||
		os.Getenv("SVDIR") != "" || os.Getenv("S6_LOGGING") != "" {
		return true
	}
	return os.Getppid() == 1
}

func prepareServiceDirectories(paths.Directories, string) error { return nil }
