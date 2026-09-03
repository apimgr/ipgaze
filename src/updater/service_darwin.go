//go:build darwin
// +build darwin

package updater

import "os/exec"

// restartService restarts the ipgaze LaunchAgent on macOS via launchctl.
// kickstart -k kills the existing instance and starts a fresh one.
func restartService() error {
	const label = "io.github.apimgr.ipgaze"
	return exec.Command("launchctl", "kickstart", "-k", "system/"+label).Run()
}
