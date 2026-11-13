//go:build !windows

package paths

func isRunningAsWindowsService() bool { return false }

func isWindowsAdministrator() bool { return false }
