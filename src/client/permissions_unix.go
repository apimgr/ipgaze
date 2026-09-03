//go:build !windows

// Package main unix permission helpers for the ipgaze CLI client.
package main

import (
	"fmt"
	"os"
)

// checkFilePermissions verifies that a file has secure (0600) permissions on Unix.
func checkFilePermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s has insecure permissions %s — run: chmod 0600 %s", path, info.Mode().Perm(), path)
	}
	return nil
}

// setDirPermissions enforces 0700 (user-only access) on an existing directory.
// MkdirAll applies the mode only to directories it creates, so a pre-existing
// directory with looser permissions must be tightened explicitly.
func setDirPermissions(dir string) error {
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("set permissions on %s: %w", dir, err)
	}
	return nil
}

// setFilePermissions enforces 0600 (user-only read/write) on an existing file.
func setFilePermissions(path string) error {
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("set permissions on %s: %w", path, err)
	}
	return nil
}
