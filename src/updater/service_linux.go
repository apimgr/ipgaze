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

func restartServiceDeferred(userService bool) error {
	if _, err := exec.LookPath("systemctl"); err == nil {
		args := make([]string, 0, 5)
		if userService {
			args = append(args, "--user")
		}
		args = append(args, "--no-block", "restart", "ipgaze")
		return exec.Command("systemctl", args...).Run()
	}
	return startDetachedServiceRestart(exec.Command("service", "ipgaze", "restart"))
}

func startDetachedServiceRestart(cmd *exec.Cmd) error {
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}
