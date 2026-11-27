//go:build linux

package i2p

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const parentDeathHelperEnv = "IPGAZE_I2P_PARENT_DEATH_HELPER"

func TestI2PParentDeathCleanupHelper(t *testing.T) {
	if os.Getenv(parentDeathHelperEnv) != "1" {
		return
	}
	pidPath := os.Getenv("IPGAZE_I2P_CHILD_PID_FILE")
	child := exec.Command("sleep", "30")
	setParentDeathSignal(child)
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pidPath, []byte(strconv.Itoa(child.Process.Pid)), 0o600); err != nil {
		_ = child.Process.Kill()
		t.Fatal(err)
	}
	select {}
}

func TestI2PDChildExitsWhenServerProcessIsKilled(t *testing.T) {
	pidPath := filepath.Join(t.TempDir(), "i2pd.pid")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	parent := exec.Command(executable, "-test.run=^TestI2PParentDeathCleanupHelper$")
	parent.Env = append(os.Environ(), parentDeathHelperEnv+"=1", "IPGAZE_I2P_CHILD_PID_FILE="+pidPath)
	if err := parent.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if parent.Process != nil {
			_ = parent.Process.Kill()
			_ = parent.Wait()
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	var childPID int
	for time.Now().Before(deadline) {
		data, readErr := os.ReadFile(pidPath)
		if readErr == nil {
			childPID, err = strconv.Atoi(strings.TrimSpace(string(data)))
			if err == nil {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if childPID <= 0 {
		t.Fatal("helper did not report its child process")
	}
	child, err := os.FindProcess(childPID)
	if err != nil {
		t.Fatalf("find child process: %v", err)
	}
	if err := parent.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatalf("kill helper server process: %v", err)
	}
	_ = parent.Wait()
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if childProcessExited(childPID, child) {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	_ = child.Kill()
	t.Fatal("i2pd child remained alive after its server process was killed")
}

func childProcessExited(pid int, process *os.Process) bool {
	if err := process.Signal(syscall.Signal(0)); err != nil {
		return true
	}
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return true
	}
	closeParen := strings.LastIndexByte(string(stat), ')')
	return closeParen >= 0 && len(stat) > closeParen+2 && stat[closeParen+2] == 'Z'
}
