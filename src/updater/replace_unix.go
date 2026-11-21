//go:build !windows
// +build !windows

package updater

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// replaceBinary atomically replaces the running binary on Unix.
// Unix allows renaming over a running executable; the in-memory image is
// unaffected until the process exits.
func replaceBinary(currentPath, newBinaryPath string) error {
	info, err := os.Stat(currentPath)
	if err != nil {
		return fmt.Errorf("failed to stat current binary: %w", err)
	}

	if err := os.Rename(newBinaryPath, currentPath); err != nil {
		return fmt.Errorf("failed to replace binary: %w", err)
	}

	if err := os.Chmod(currentPath, info.Mode()); err != nil {
		return fmt.Errorf("failed to restore permissions: %w", err)
	}

	return nil
}

// createProtectedReplacementDir creates the verified update copy beside the
// installed binary so the final rename stays on one filesystem. Automatic
// replacement is allowed only in a root-owned, non-writable install directory.
func createProtectedReplacementDir(currentPath string) (string, error) {
	installDir := filepath.Dir(currentPath)
	info, err := os.Stat(installDir)
	if err != nil {
		return "", err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || !ok || owner.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
		return "", fmt.Errorf("automatic update requires a root-owned, non-writable install directory")
	}
	tempDir, err := os.MkdirTemp(installDir, ".ipgaze-update-")
	if err != nil {
		return "", err
	}
	return tempDir, nil
}

// restartSelf re-executes the current process via syscall.Exec (Unix).
// The current process image is replaced; no new PID is created.
func restartSelf() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return syscall.Exec(exe, os.Args, os.Environ())
}
