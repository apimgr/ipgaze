//go:build windows

package paths

import (
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

func isRunningAsWindowsService() bool {
	isService, err := svc.IsWindowsService()
	return err == nil && isService
}

func isWindowsAdministrator() bool {
	var sid *windows.SID
	if err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid,
	); err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	member, err := windows.Token(0).IsMember(sid)
	return err == nil && member
}
