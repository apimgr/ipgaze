package service

import (
	"os"
	"runtime"

	paths "github.com/apimgr/ipgaze/src/path"
)

// daemonServiceManagerString returns the active service manager as a short
// string used by shouldDaemonize to decide whether daemonization is needed.
// Container environments are detected first to ensure they always stay foreground.
func daemonServiceManagerString() string {
	if paths.IsRunningInContainer() {
		return "container"
	}

	ppid := os.Getppid()

	if ppid == 1 {
		if _, err := os.Stat("/run/systemd/system"); err == nil {
			return "systemd"
		}
	}
	if os.Getenv("INVOCATION_ID") != "" {
		return "systemd"
	}

	if runtime.GOOS == "darwin" && ppid == 1 {
		return "launchd"
	}

	if os.Getenv("SVDIR") != "" {
		return "runit"
	}

	if os.Getenv("S6_LOGGING") != "" {
		return "s6"
	}

	if ppid == 1 {
		if _, err := os.Stat("/etc/init.d"); err == nil {
			if _, err2 := os.Stat("/run/systemd/system"); os.IsNotExist(err2) {
				return "sysv"
			}
		}
	}

	if _, err := os.Stat("/etc/rc.subr"); err == nil {
		return "rcd"
	}

	return "manual"
}

// ShouldDaemonize determines if the process should daemonize based on context.
// When isServiceStart is true the decision is forced by the detected service manager.
// Otherwise daemonFlag takes priority, then configDaemonize, then false.
func ShouldDaemonize(isServiceStart bool, daemonFlag bool, configDaemonize bool) bool {
	if isServiceStart {
		switch daemonServiceManagerString() {
		case "systemd", "launchd", "runit", "s6", "container":
			return false
		case "sysv", "rcd":
			return true
		default:
			return false
		}
	}

	if daemonFlag {
		return true
	}
	return configDaemonize
}

// filterDaemonFlag removes --daemon/-d from args to prevent an infinite
// re-exec loop when the child process inherits the same argument list.
func filterDaemonFlag(args []string) []string {
	filtered := make([]string, 0, len(args))
	for _, arg := range args {
		if arg != "--daemon" && arg != "-d" {
			filtered = append(filtered, arg)
		}
	}
	return filtered
}
