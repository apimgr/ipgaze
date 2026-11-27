//go:build linux

package tor

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const torOwnerHelperEnv = "IPGAZE_TOR_OWNER_HELPER"

func TestTorProcessOwnershipCleanupHelper(t *testing.T) {
	if os.Getenv(torOwnerHelperEnv) != "1" {
		return
	}
	torBinary := os.Getenv("IPGAZE_TOR_FAKE_BINARY")
	torrcPath := os.Getenv("IPGAZE_TOR_FAKE_CONFIG")
	pidPath := os.Getenv("IPGAZE_TOR_FAKE_PID_FILE")
	torrc := "DataDirectory " + filepath.Dir(pidPath) + "\n" + "__OwningControllerProcess " + strconv.Itoa(os.Getpid()) + "\n"
	if err := os.WriteFile(torrcPath, []byte(torrc), 0o600); err != nil {
		t.Fatal(err)
	}
	child, err := spawnTor(context.Background(), torBinary, torrcPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pidPath, []byte(strconv.Itoa(child.cmd.Process.Pid)), 0o600); err != nil {
		_ = child.cmd.Process.Kill()
		t.Fatal(err)
	}
	select {}
}

func TestTorOwnedChildExitsWhenServerProcessIsKilled(t *testing.T) {
	base := t.TempDir()
	pidPath := filepath.Join(base, "tor.pid")
	configPath := filepath.Join(base, "torrc")
	torBinary := filepath.Join(base, "fake-tor")
	script := "#!/bin/sh\n" +
		"torrc=\"$2\"\n" +
		"owner=$(sed -n 's/^__OwningControllerProcess //p' \"$torrc\")\n" +
		"while kill -0 \"$owner\" 2>/dev/null; do sleep 0.05; done\n"
	if err := os.WriteFile(torBinary, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	parent := exec.Command(executable, "-test.run=^TestTorProcessOwnershipCleanupHelper$")
	parent.Env = append(os.Environ(), torOwnerHelperEnv+"=1", "IPGAZE_TOR_FAKE_BINARY="+torBinary, "IPGAZE_TOR_FAKE_CONFIG="+configPath, "IPGAZE_TOR_FAKE_PID_FILE="+pidPath)
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
		t.Fatal("helper did not report the managed Tor child PID")
	}
	child, err := os.FindProcess(childPID)
	if err != nil {
		t.Fatalf("find Tor child process: %v", err)
	}
	if err := parent.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatalf("kill server helper process: %v", err)
	}
	_ = parent.Wait()
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if torChildExited(childPID, child) {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	_ = child.Kill()
	t.Fatal("managed Tor child remained alive after its owner process was killed")
}

func torChildExited(pid int, process *os.Process) bool {
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
