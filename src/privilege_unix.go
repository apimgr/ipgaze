//go:build !windows

package main

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// reservedSystemIDs are well-known UIDs/GIDs used by services across distros,
// per AI.md PART 23 "Reserved/Well-Known UIDs" — never allocated even if free.
var reservedSystemIDs = map[int]bool{
	65534: true,
	999:   true, 998: true, 997: true, 996: true, 995: true,
	994: true, 993: true, 992: true, 991: true, 990: true,
	989: true, 988: true, 987: true, 986: true, 985: true,
	984: true, 983: true, 982: true, 981: true, 980: true,
	101: true, 102: true, 103: true, 104: true, 105: true,
	106: true, 107: true, 108: true, 109: true, 110: true,
	170: true, 171: true, 172: true, 173: true, 174: true,
	175: true, 176: true, 177: true, 178: true, 179: true,
}

// findAvailableSystemID finds an unused ID where both UID and GID are free
// and not reserved, per AI.md PART 23 "UID/GID Selection Logic" (safe range
// 200-899, searched top-down).
func findAvailableSystemID() (int, error) {
	for id := 899; id >= 200; id-- {
		if reservedSystemIDs[id] {
			continue
		}
		if _, err := user.LookupId(strconv.Itoa(id)); err == nil {
			continue
		}
		if _, err := user.LookupGroupId(strconv.Itoa(id)); err == nil {
			continue
		}
		return id, nil
	}
	return 0, fmt.Errorf("no available UID/GID in safe range 200-899")
}

// ensureSystemUser creates the dedicated {internal_name} system user/group if
// it does not already exist, per AI.md PART 23 "System User Requirements" and
// the Server Startup Sequence step 8a ("Server binary handles user/group
// creation ... during NORMAL STARTUP"). Returns the user's uid/gid either way.
// Must be called while still root.
func ensureSystemUser(username, homeDir string) (uid, gid int, err error) {
	if u, lookErr := user.Lookup(username); lookErr == nil {
		uid, _ = strconv.Atoi(u.Uid)
		gid, _ = strconv.Atoi(u.Gid)
		return uid, gid, nil
	}

	id, err := findAvailableSystemID()
	if err != nil {
		return 0, 0, err
	}

	gecos := username + " service account"
	if _, lookErr := exec.LookPath("groupadd"); lookErr == nil {
		if out, cmdErr := exec.Command("groupadd", "--system", "--gid", strconv.Itoa(id), username).CombinedOutput(); cmdErr != nil {
			return 0, 0, fmt.Errorf("groupadd: %w: %s", cmdErr, out)
		}
		if out, cmdErr := exec.Command("useradd", "--system", "--uid", strconv.Itoa(id), "--gid", strconv.Itoa(id),
			"--home-dir", homeDir, "--shell", "/sbin/nologin", "--comment", gecos, username).CombinedOutput(); cmdErr != nil {
			return 0, 0, fmt.Errorf("useradd: %w: %s", cmdErr, out)
		}
	} else if _, lookErr := exec.LookPath("addgroup"); lookErr == nil {
		// Alpine/busybox fallback (no shadow-utils installed).
		if out, cmdErr := exec.Command("addgroup", "-S", "-g", strconv.Itoa(id), username).CombinedOutput(); cmdErr != nil {
			return 0, 0, fmt.Errorf("addgroup: %w: %s", cmdErr, out)
		}
		if out, cmdErr := exec.Command("adduser", "-S", "-D", "-H", "-u", strconv.Itoa(id), "-G", username,
			"-s", "/sbin/nologin", "-g", gecos, username).CombinedOutput(); cmdErr != nil {
			return 0, 0, fmt.Errorf("adduser: %w: %s", cmdErr, out)
		}
	} else {
		return 0, 0, fmt.Errorf("no user management tool found (groupadd/useradd or addgroup/adduser)")
	}

	return id, id, nil
}

// chownRecursive sets ownership on path and everything beneath it, per AI.md
// PART 23 Server Startup Sequence step 8c ("Only root can chown to another
// user"). Enforced unconditionally, even if ownership already matches.
func chownRecursive(path string, uid, gid int) error {
	if path == "" {
		return nil
	}
	return filepath.WalkDir(path, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Chown(p, uid, gid)
	})
}

// isElevated returns true if the process is running as root (Unix).
func isElevated() bool {
	return os.Geteuid() == 0
}

// canEscalate checks if the current user can escalate privileges (Unix).
// Checks for passwordless sudo first, then group membership.
func canEscalate() bool {
	cmd := exec.Command("sudo", "-n", "true")
	if cmd.Run() == nil {
		return true
	}

	u, err := user.Current()
	if err != nil {
		return false
	}
	groups, err := u.GroupIds()
	if err != nil {
		return false
	}
	for _, gid := range groups {
		g, err := user.LookupGroupId(gid)
		if err != nil {
			continue
		}
		if g.Name == "sudo" || g.Name == "wheel" || g.Name == "admin" {
			return true
		}
	}
	return false
}

// escalationMethods returns the ordered list of escalation mechanisms to try
// for the current GOOS, per AI.md PART 23 "Escalation Detection by OS".
func escalationMethods() []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{"sudo", "osascript"}
	case "freebsd", "netbsd", "openbsd", "dragonfly":
		return []string{"doas", "sudo", "su"}
	default:
		// Linux and other Unix variants.
		return []string{"sudo", "su", "pkexec", "doas"}
	}
}

// buildElevationCmd constructs the *exec.Cmd for the given escalation
// mechanism re-executing the current process with args.
func buildElevationCmd(method string, args []string) *exec.Cmd {
	switch method {
	case "su":
		// su re-executes the command through the target user's shell, so the
		// argv must be joined into a single shell-quoted command string.
		return exec.Command("su", "-c", shellJoin(args))
	case "osascript":
		script := fmt.Sprintf("do shell script %s with administrator privileges", osaQuote(shellJoin(args)))
		return exec.Command("osascript", "-e", script)
	default:
		// sudo, pkexec, doas all accept the target command as argv directly.
		elevatedArgs := append([]string{}, args...)
		return exec.Command(method, elevatedArgs...)
	}
}

// shellJoin quotes each argument for safe inclusion in a POSIX shell command
// string, as required by su -c.
func shellJoin(args []string) string {
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
	}
	return strings.Join(quoted, " ")
}

// osaQuote quotes a string for embedding as an AppleScript string literal.
func osaQuote(s string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`) + `"`
}

// execElevated re-executes the current process with elevated privileges
// (Unix). It walks the OS-specific fallback chain from AI.md PART 23,
// trying each mechanism in order and falling through when a mechanism is
// unavailable (exec.LookPath fails) or the attempt itself fails.
func execElevated(args []string) error {
	methods := escalationMethods()
	var attempted []string
	var lastErr error

	for _, method := range methods {
		if _, err := exec.LookPath(method); err != nil {
			continue
		}
		attempted = append(attempted, method)

		cmd := buildElevationCmd(method, args)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			lastErr = fmt.Errorf("%s: %w", method, err)
			continue
		}
		return nil
	}

	if len(attempted) == 0 {
		return fmt.Errorf("no privilege escalation method available (tried: %s)", strings.Join(methods, ", "))
	}
	return fmt.Errorf("privilege escalation failed via all available methods (%s): %w", strings.Join(attempted, ", "), lastErr)
}

// dropPrivileges drops root privileges and switches to the named system user.
// Must be called after binding privileged ports and before any other work.
func dropPrivileges(username string) error {
	u, err := user.Lookup(username)
	if err != nil {
		return fmt.Errorf("user %s not found: %w", username, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return fmt.Errorf("invalid uid %s: %w", u.Uid, err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return fmt.Errorf("invalid gid %s: %w", u.Gid, err)
	}
	// Clear supplementary groups before dropping uid/gid — otherwise any
	// groups inherited from the root process (e.g. "root", "docker") stay
	// attached to the service-account process after the drop. Must run
	// while still privileged: only root can call setgroups(2).
	if err := syscall.Setgroups([]int{}); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}
	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("setgid %d: %w", gid, err)
	}
	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("setuid %d: %w", uid, err)
	}
	if os.Geteuid() == 0 {
		return fmt.Errorf("privilege drop failed: still running as root")
	}
	return nil
}
