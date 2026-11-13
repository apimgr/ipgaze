//go:build freebsd || openbsd || netbsd
// +build freebsd openbsd netbsd

package updater

import "os/exec"

// restartService restarts the ipgaze rc.d service on BSD systems.
func restartService() error {
	return exec.Command("service", "ipgaze", "restart").Run()
}

func restartServiceDeferred(bool) error {
	return startDetachedServiceRestart(exec.Command("service", "ipgaze", "restart"))
}

func startDetachedServiceRestart(cmd *exec.Cmd) error {
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}
