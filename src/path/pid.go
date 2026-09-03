// Package paths PID file management — cross-platform process ID tracking.
package path

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// CheckPIDFile checks if a PID file exists and if the process is still running.
// Returns: (isRunning bool, pid int, err error)
// Returns (false, 0, nil) when no PID file exists or the process is stale (stale file removed).
// Returns (true, pid, nil) when the process is running and is our binary.
// Returns (false, 0, err) on read errors.
func CheckPIDFile(pidPath string) (bool, int, error) {
	data, err := os.ReadFile(pidPath)
	if os.IsNotExist(err) {
		return false, 0, nil
	}
	if err != nil {
		return false, 0, fmt.Errorf("reading pid file: %w", err)
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		// Corrupt PID file — remove it and continue
		os.Remove(pidPath)
		return false, 0, nil
	}

	if !isProcessRunning(pid) {
		// Stale PID file — remove it
		os.Remove(pidPath)
		return false, 0, nil
	}

	// Process exists — verify it is actually our binary (not PID reuse)
	if !isOurProcess(pid) {
		// PID was reused by another process — remove stale file
		os.Remove(pidPath)
		return false, 0, nil
	}

	return true, pid, nil
}

// WritePIDFile writes the current process PID to the given file.
// Returns an error if another instance is already running.
// Creates parent directories if they don't exist, using the permissions
// mandated by AI.md PART 8 for the locked-at-startup elevation state:
// 0755 dir / 0644 file in system mode, 0700 dir / 0600 file in user mode.
func WritePIDFile(pidPath string) error {
	running, existingPID, err := CheckPIDFile(pidPath)
	if err != nil {
		return err
	}
	if running {
		return fmt.Errorf("already running (pid %d)", existingPID)
	}

	isRoot := isElevated()
	if err := EnsureDir(dirOf(pidPath), isRoot); err != nil {
		return fmt.Errorf("create pid dir: %w", err)
	}

	pid := os.Getpid()
	return os.WriteFile(pidPath, []byte(strconv.Itoa(pid)+"\n"), filePermFor(isRoot))
}

// RemovePIDFile removes the PID file if it belongs to the current process.
func RemovePIDFile(pidPath string) error {
	data, err := os.ReadFile(pidPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid != os.Getpid() {
		return nil
	}
	return os.Remove(pidPath)
}

// dirOf returns the directory part of a file path.
func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return path[:i]
		}
	}
	return "."
}
