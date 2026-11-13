//go:build windows

package i2p

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func setParentDeathSignal(cmd *exec.Cmd) {}

func signalI2PD(proc *os.Process) error { return proc.Signal(os.Interrupt) }

func terminateStaleI2PD(pid int, binary, pidPath string) error {
	pidText := strconv.Itoa(pid)
	out, err := exec.Command("tasklist", "/FI", "PID eq "+pidText, "/FO", "CSV", "/NH").Output()
	if err != nil || !strings.Contains(strings.ToLower(string(out)), strings.ToLower(filepath.Base(binary))) {
		return nil
	}
	if err := exec.Command("taskkill", "/PID", pidText, "/T").Run(); err != nil {
		return fmt.Errorf("terminate stale i2pd PID %d from %s: %w", pid, pidPath, err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		out, err := exec.Command("tasklist", "/FI", "PID eq "+pidText, "/FO", "CSV", "/NH").Output()
		if err != nil || !strings.Contains(string(out), pidText) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return exec.Command("taskkill", "/F", "/PID", pidText, "/T").Run()
}
