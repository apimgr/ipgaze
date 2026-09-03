//go:build !windows

package updater

import (
	"fmt"
	"os"
	"syscall"
)

// replaceBinary atomically replaces the running binary on Unix.
// Unix allows renaming over a running executable — the old binary stays in memory
// until the process exits, then the new one takes over on next start.
func replaceBinary(currentPath, newBinaryPath string) error {
	info, err := os.Stat(currentPath)
	if err != nil {
		return fmt.Errorf("stat current binary: %w", err)
	}

	if err := os.Rename(newBinaryPath, currentPath); err != nil {
		return fmt.Errorf("rename binary: %w", err)
	}

	if err := os.Chmod(currentPath, info.Mode()); err != nil {
		return fmt.Errorf("restore permissions: %w", err)
	}

	return nil
}

// restartSelf re-execs the current process with the original argv (Unix).
// syscall.Exec replaces the current process image.
func restartSelf() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return syscall.Exec(exe, os.Args, os.Environ())
}
