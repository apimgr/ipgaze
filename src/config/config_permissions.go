package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/apimgr/ipgaze/src/paths"
)

func ensureConfigDirectory(dir string) error {
	mode := os.FileMode(0o700)
	if paths.StartedElevated() {
		mode = 0o755
	}
	if err := os.MkdirAll(dir, mode); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	if filepath.Clean(dir) == filepath.Clean(paths.GetDirectories().Config) && paths.StartedElevated() {
		parent := filepath.Dir(dir)
		if parent != string(os.PathSeparator) {
			if err := os.Chmod(parent, 0o755); err != nil {
				return fmt.Errorf("set config parent permissions: %w", err)
			}
		}
	}
	if err := os.Chmod(dir, mode); err != nil {
		return fmt.Errorf("set config directory permissions: %w", err)
	}
	return nil
}

func ensureConfigFileDirectory(dir string) error {
	if filepath.Base(dir) != "yaml.d" {
		return ensureConfigDirectory(dir)
	}
	if err := ensureConfigDirectory(filepath.Dir(dir)); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create private config area directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("secure private config area directory: %w", err)
	}
	return nil
}
