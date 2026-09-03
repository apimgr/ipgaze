//go:build freebsd || openbsd || netbsd
// +build freebsd openbsd netbsd

package updater

import "os/exec"

// restartService restarts the ipgaze rc.d service on BSD systems.
func restartService() error {
	return exec.Command("service", "ipgaze", "restart").Run()
}
