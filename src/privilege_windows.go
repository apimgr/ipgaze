//go:build windows

package main

import (
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

// isElevated returns true if the process is running as Administrator (Windows).
func isElevated() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	token := windows.Token(0)
	member, err := token.IsMember(sid)
	return err == nil && member
}

// canEscalate checks if the current user can escalate via UAC (Windows).
func canEscalate() bool {
	if isElevated() {
		return true
	}
	return isInAdminGroup()
}

// isInAdminGroup checks if the current user is a member of the Administrators group.
func isInAdminGroup() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	token := windows.Token(0)
	groups, err := token.GetTokenGroups()
	if err != nil {
		return false
	}
	for _, g := range groups.AllGroups() {
		if windows.EqualSid(g.Sid, sid) {
			return true
		}
	}
	return false
}

// execElevated re-executes the current process with elevated privileges via UAC (Windows).
func execElevated(args []string) error {
	verb := "runas"
	exe, _ := os.Executable()
	cwd, _ := os.Getwd()
	argStr := strings.Join(args[1:], " ")
	return windows.ShellExecute(
		0,
		windows.StringToUTF16Ptr(verb),
		windows.StringToUTF16Ptr(exe),
		windows.StringToUTF16Ptr(argStr),
		windows.StringToUTF16Ptr(cwd),
		windows.SW_NORMAL,
	)
}

// dropPrivileges is a no-op on Windows — the Virtual Service Account (VSA) handles
// minimal-privilege isolation without explicit privilege dropping.
func dropPrivileges(_ string) error {
	return nil
}

// ensureSystemUser is a no-op on Windows — the Virtual Service Account (VSA)
// is provisioned by the Windows Service Manager, not the binary.
func ensureSystemUser(_, _ string) (uid, gid int, err error) {
	return 0, 0, nil
}

// chownRecursive is a no-op on Windows — ownership is governed by NTFS ACLs
// under the Virtual Service Account, not POSIX uid/gid.
func chownRecursive(_ string, _, _ int) error {
	return nil
}
