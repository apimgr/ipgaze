//go:build linux
// +build linux

package updater

import "os/exec"

// restartService restarts the ipgaze system service on Linux.
// Tries systemd first; falls back to the generic service(8) command.
func restartService() error {
	if _, err := exec.LookPath("systemctl"); err == nil {
		return exec.Command("systemctl", "restart", "ipgaze").Run()
	}
	return exec.Command("service", "ipgaze", "restart").Run()
}
