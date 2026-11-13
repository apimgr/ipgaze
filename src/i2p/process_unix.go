//go:build !linux && !windows

package i2p

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func setParentDeathSignal(cmd *exec.Cmd) {}

func signalI2PD(proc *os.Process) error { return proc.Signal(syscall.SIGTERM) }

func terminateStaleI2PD(pid int, binary, pidPath string) error {
	// ps is available on supported BSD and macOS systems and lets us verify
	// ownership before acting on a persisted PID.
	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "comm=").Output()
	if err != nil {
		return nil
	}
	if !strings.Contains(string(out), binary) {
		return fmt.Errorf("refusing to terminate PID %d from %s because it is not verifiably i2pd", pid, pidPath)
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return nil
	}
	_ = proc.Signal(syscall.SIGTERM)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if err := proc.Signal(syscall.Signal(0)); err != nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return proc.Kill()
}
