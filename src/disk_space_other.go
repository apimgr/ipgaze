//go:build !linux && !darwin && !freebsd

package main

import "fmt"

// diskFreeAndUsedPercent is unavailable on this platform (e.g. windows); the
// backup disk-space pre-check degrades gracefully and never blocks backups.
func diskFreeAndUsedPercent(path string) (freeBytes uint64, usedPercent int, err error) {
	return 0, 0, fmt.Errorf("disk space check unsupported on this platform")
}
