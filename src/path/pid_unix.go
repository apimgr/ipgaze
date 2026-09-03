//go:build !windows

package path

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// isProcessRunning returns true if a process with the given PID is running on Unix.
// Uses signal 0 which checks process existence without sending a real signal.
func isProcessRunning(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = p.Signal(syscall.Signal(0))
	return err == nil
}

// isOurProcess verifies the process with the given PID is actually our binary (Unix).
// Checks /proc/{pid}/exe on Linux; falls back to ps on macOS/BSD.
func isOurProcess(pid int) bool {
	exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		// macOS/BSD: use ps command
		return isOurProcessDarwin(pid)
	}
	// Exact match: substring matching would also match ipgaze-cli.
	return filepath.Base(exePath) == "ipgaze"
}

// isOurProcessDarwin checks the process name on macOS/BSD using the ps command.
func isOurProcessDarwin(pid int) bool {
	cmd := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "comm=")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	// Exact match: substring matching would also match ipgaze-cli.
	return strings.TrimSpace(string(output)) == "ipgaze"
}
