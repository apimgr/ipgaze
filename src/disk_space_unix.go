//go:build linux || darwin || freebsd

package main

import (
	"golang.org/x/sys/unix"
)

// diskFreeAndUsedPercent returns the free bytes and used-percentage of the
// filesystem containing path, via unix.Statfs. Used by the backup disk-space
// pre-check (AI.md PART 21 Backup Creation Flow step 2).
func diskFreeAndUsedPercent(path string) (freeBytes uint64, usedPercent int, err error) {
	var stat unix.Statfs_t
	if statErr := unix.Statfs(path, &stat); statErr != nil {
		return 0, 0, statErr
	}
	blockSize := uint64(stat.Bsize)
	total := uint64(stat.Blocks) * blockSize
	free := uint64(stat.Bavail) * blockSize
	if total == 0 {
		return free, 0, nil
	}
	used := total - free
	return free, int(used * 100 / total), nil
}
