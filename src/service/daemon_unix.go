//go:build !windows

package service

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"

	"github.com/apimgr/ipgaze/src/common/i18n"
)

// Daemonize forks the process and detaches from the controlling terminal.
//
// Behaviour:
//   - If already reparented to init (PPID == 1) → no-op, returns nil.
//   - If _DAEMON_CHILD env var is set → we are the re-exec'd child, returns nil
//     so normal startup continues.
//   - Otherwise → re-exec self with _DAEMON_CHILD=1 and Setsid=true, print the
//     child PID using the caller's language, then exit 0 from the parent.
//
// Call only when daemonization has been requested (--daemon flag or config).
func Daemonize(lang string) error {
	// Already reparented to init — we are already a daemon.
	if os.Getppid() == 1 {
		return nil
	}

	// We are the re-exec'd daemon child — continue normal startup.
	if os.Getenv("_DAEMON_CHILD") != "" {
		return nil
	}

	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("getting executable path: %w", err)
	}

	args := filterDaemonFlag(os.Args[1:])
	cmd := exec.Command(execPath, args...)
	cmd.Env = append(os.Environ(), "_DAEMON_CHILD=1")
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{
		// Create a new session to detach from the controlling terminal.
		Setsid: true,
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting daemon: %w", err)
	}

	mgr := i18n.NewTranslationManager()
	fmt.Printf("%s\n", mgr.Tf(lang, "daemon_started", strconv.Itoa(cmd.Process.Pid)))
	os.Exit(0)
	return nil
}
