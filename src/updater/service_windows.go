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

func restartServiceDeferred(bool) error {
	cmd := exec.Command("cmd.exe", "/C", "sc.exe stop ipgaze && timeout /t 2 /nobreak >NUL && sc.exe start ipgaze")
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}
