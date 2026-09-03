// Package main client initialization helpers.
package main

import (
	"fmt"
	"os"

	paths "github.com/apimgr/ipgaze/src/client/path"
)

// ensureDirectories creates all required client directories on startup and
// enforces user-only permissions on them, including on directories that
// already existed with looser modes (AI.md PART 32 "Set correct permissions").
func ensureDirectories() error {
	dirs := []string{
		paths.ConfigDir(),
		paths.DataDir(),
		paths.CacheDir(),
		paths.LogDir(),
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create dir %s: %w", dir, err)
		}
		if err := setDirPermissions(dir); err != nil {
			return err
		}
	}
	return nil
}
