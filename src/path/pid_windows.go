//go:build windows

package path

import (
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// isProcessRunning returns true if a process with the given PID is running on Windows.
// Uses OpenProcess + GetExitCodeProcess to check if the process is still active.
func isProcessRunning(pid int) bool {
	if pid <= 0 {
		return false
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(handle)
	var exitCode uint32
	err = windows.GetExitCodeProcess(handle, &exitCode)
	// STILL_ACTIVE (259 / 0x103) means the process is still running
	return err == nil && exitCode == 259
}

// isOurProcess verifies the process with the given PID is actually our binary (Windows).
// Uses QueryFullProcessImageName to retrieve the executable path.
func isOurProcess(pid int) bool {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(handle)

	var buf [windows.MAX_PATH]uint16
	var size uint32 = windows.MAX_PATH
	err = windows.QueryFullProcessImageName(handle, 0, &buf[0], &size)
	if err != nil {
		return false
	}
	exePath := windows.UTF16ToString(buf[:size])
	// Exact match: substring matching would also match ipgaze-cli.exe.
	base := filepath.Base(exePath)
	return strings.EqualFold(base, "ipgaze.exe") || strings.EqualFold(base, "ipgaze")
}
