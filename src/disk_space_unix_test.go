//go:build linux || darwin || freebsd

package main

import "testing"

func TestDiskFreeAndUsedPercent(t *testing.T) {
	dir := t.TempDir()
	free, usedPercent, err := diskFreeAndUsedPercent(dir)
	if err != nil {
		t.Fatalf("diskFreeAndUsedPercent: %v", err)
	}
	if free == 0 {
		t.Error("expected nonzero free bytes on real filesystem")
	}
	if usedPercent < 0 || usedPercent > 100 {
		t.Errorf("usedPercent out of range: %d", usedPercent)
	}
}

func TestDiskFreeAndUsedPercent_InvalidPath(t *testing.T) {
	if _, _, err := diskFreeAndUsedPercent("/nonexistent/path/that/does/not/exist"); err == nil {
		t.Error("expected error for nonexistent path")
	}
}
