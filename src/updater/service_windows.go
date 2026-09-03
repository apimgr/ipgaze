//go:build windows
// +build windows

package updater

import (
	"os/exec"
	"time"
)

// restartService stops and starts the ipgaze Windows service via sc.exe.
func restartService() error {
	exec.Command("sc", "stop", "ipgaze").Run()
	time.Sleep(2 * time.Second)
	return exec.Command("sc", "start", "ipgaze").Run()
}
