//go:build darwin
// +build darwin

package updater

import (
	"os"
	"os/exec"
	"strconv"
)

// restartService restarts the ipgaze LaunchAgent on macOS via launchctl.
// kickstart -k kills the existing instance and starts a fresh one.
func restartService() error {
	const label = "io.github.apimgr.ipgaze"
	return exec.Command("launchctl", "kickstart", "-k", "system/"+label).Run()
}

func restartServiceDeferred(userService bool) error {
	const label = "io.github.apimgr.ipgaze"
	domain := "system"
	if userService {
		domain = "gui/" + strconv.Itoa(os.Getuid())
	}
	return startDetachedServiceRestart(exec.Command("launchctl", "kickstart", "-k", domain+"/"+label))
}

func startDetachedServiceRestart(cmd *exec.Cmd) error {
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}
