//go:build windows

package updater

import (
	"fmt"
	"os"
	"os/exec"
	"time"
)

// replaceBinary replaces the running binary on Windows.
// Windows cannot delete/rename a running executable, so we rename
// the current binary to .old, move the new binary to the current path,
// and schedule the .old file for deletion on reboot.
func replaceBinary(currentPath, newBinaryPath string) error {
	oldPath := currentPath + ".old"

	// Remove any .old left over from a previous update
	os.Remove(oldPath)

	// Rename running binary to .old (allowed on Windows)
	if err := os.Rename(currentPath, oldPath); err != nil {
		return fmt.Errorf("rename current binary: %w", err)
	}

	// Move new binary into place
	if err := os.Rename(newBinaryPath, currentPath); err != nil {
		// Attempt to restore the original
		os.Rename(oldPath, currentPath)
		return fmt.Errorf("move new binary: %w", err)
	}

	return nil
}

// restartSelf starts a new instance of the binary and exits (Windows).
// Windows does not support exec() replacement.
func restartSelf() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}

	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start new process: %w", err)
	}

	// Give the new process a moment to start
	time.Sleep(100 * time.Millisecond)

	os.Exit(0)
	return nil
}
