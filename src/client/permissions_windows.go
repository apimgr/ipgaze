//go:build windows

// Package main windows permission helpers for the ipgaze CLI client.
package main

// checkFilePermissions is a no-op on Windows (ACLs handle security).
func checkFilePermissions(_ string) error {
	return nil
}

// setDirPermissions is a no-op on Windows: directories under %APPDATA% and
// %LOCALAPPDATA% already grant user-only access and inherit their ACLs.
func setDirPermissions(_ string) error {
	return nil
}

// setFilePermissions is a no-op on Windows: files inherit the ACLs of the
// user-only directory they are created in.
func setFilePermissions(_ string) error {
	return nil
}
