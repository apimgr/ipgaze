// Package updater implements CLI auto-update per AI.md PART 32.
// Flow: autodiscover → version check → download from server → SHA-256 verify → atomic swap → re-exec.
package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/apimgr/ipgaze/src/client/api"
)

// PlatformKey returns the os-arch key used in the cli_versions map (e.g. "linux-amd64").
func PlatformKey() string {
	return runtime.GOOS + "-" + runtime.GOARCH
}

// BinaryFilename returns the expected CLI binary filename for this platform.
func BinaryFilename(projectName string) string {
	name := projectName + "-cli-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return name
}

// CheckResult holds the result of an update check.
type CheckResult struct {
	// Current is the version currently running.
	Current string
	// Available is the version available on the server (empty if none).
	Available string
	// SHA256 is the expected checksum of the available binary.
	SHA256 string
	// BelowMin is true when Current < CLIMinVersion (server refuses old CLIs).
	BelowMin bool
	// MinVersion is the server-required minimum CLI version.
	MinVersion string
}

// NeedsUpdate returns true when an update is available.
func (r *CheckResult) NeedsUpdate() bool {
	return r.Available != "" && r.Current != r.Available
}

// CheckForUpdates queries /api/autodiscover and returns whether an update is available.
// It logs cli.update_forced when the running version is below cli_min_version.
func CheckForUpdates(ctx context.Context, client *api.APIClient, currentVersion string) (*CheckResult, error) {
	disc, err := client.Autodiscover(ctx)
	if err != nil {
		return nil, fmt.Errorf("autodiscover: %w", err)
	}

	result := &CheckResult{
		Current:    currentVersion,
		MinVersion: disc.CLIMinVersion,
	}

	entry, ok := disc.CLIVersions[PlatformKey()]
	if ok {
		result.Available = entry.Version
		result.SHA256 = entry.SHA256
	}

	// cli_min_version enforcement (AI.md PART 32)
	if disc.CLIMinVersion != "" && isOlderVersion(currentVersion, disc.CLIMinVersion) {
		result.BelowMin = true
		// Audit event: cli.update_forced
		fmt.Fprintf(os.Stderr, "audit: cli.update_forced current=%s min_required=%s\n",
			currentVersion, disc.CLIMinVersion)
	}

	return result, nil
}

// Do downloads, verifies, and installs the update. Calls re-exec on success.
// Emits audit events to stderr per AI.md PART 32.
func Do(ctx context.Context, client *api.APIClient, projectName, serverBase, currentVersion string) error {
	// Audit event: cli.update_started
	fmt.Fprintf(os.Stderr, "audit: cli.update_started from=%s\n", currentVersion)

	result, err := CheckForUpdates(ctx, client, currentVersion)
	if err != nil {
		return err
	}

	if !result.NeedsUpdate() {
		fmt.Println("Already up to date.")
		return nil
	}

	fmt.Printf("Updating %s-cli from %s to %s...\n", projectName, result.Current, result.Available)

	// Temp directory per spec tmp-dir rules
	tmpDir := filepath.Join(os.TempDir(), projectName+"-update")
	if err := os.MkdirAll(tmpDir, 0700); err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}

	tmpPath := filepath.Join(tmpDir, "cli.update.tmp")

	filename := BinaryFilename(projectName)
	_, err = client.DownloadBinary(ctx, filename, tmpPath)
	if err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("download: %w", err)
	}

	// Verify SHA-256 per AI.md PART 32 (same verifyChecksum pattern as PART 22).
	// A missing checksum is fatal: never install an unverified binary — mirrors
	// the hard-abort in the server-side updater (src/updater/update.go).
	if result.SHA256 == "" {
		os.Remove(tmpPath)
		fmt.Fprintln(os.Stderr, "audit: cli.update_checksum_invalid expected=(none)")
		return fmt.Errorf("checksum not available for this platform — aborting update")
	}
	if err := verifyChecksum(tmpPath, result.SHA256); err != nil {
		os.Remove(tmpPath)
		// Audit event: cli.update_checksum_invalid
		fmt.Fprintf(os.Stderr, "audit: cli.update_checksum_invalid expected=%s\n", result.SHA256)
		return fmt.Errorf("checksum mismatch: %w", err)
	}

	// Make executable on Unix
	if runtime.GOOS != "windows" {
		if err := os.Chmod(tmpPath, 0755); err != nil {
			os.Remove(tmpPath)
			return fmt.Errorf("chmod: %w", err)
		}
	}

	// Resolve current binary path
	currentPath, err := os.Executable()
	if err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("resolve binary path: %w", err)
	}
	currentPath, err = filepath.EvalSymlinks(currentPath)
	if err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("eval symlinks: %w", err)
	}

	// Check write permission on install path
	if err := checkWritable(currentPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("you do not have permission to update %s; ask your admin or move the binary to a writable path", currentPath)
	}

	// Atomic swap (platform-specific)
	if err := replaceBinary(currentPath, tmpPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("replace binary: %w", err)
	}

	// Audit event: cli.update_completed
	fmt.Fprintf(os.Stderr, "audit: cli.update_completed version=%s\n", result.Available)
	fmt.Printf("Update complete. Restarting...\n")

	// Re-exec with original argv to continue the in-progress command
	return restartSelf()
}

// verifyChecksum checks that the file at path has the expected SHA-256 hex digest.
func verifyChecksum(path, expected string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != expected {
		return fmt.Errorf("got %s, want %s", got, expected)
	}
	return nil
}

// checkWritable returns an error if the file is not writable by the current user.
func checkWritable(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	f.Close()
	return nil
}

// isOlderVersion returns true when a is strictly older than b, comparing
// dotted numeric semver components (so "1.9.0" < "1.10.0"). A leading "v"
// and any pre-release/build suffix on a component are ignored for the
// numeric comparison; equal numeric prefixes fall back to string order.
func isOlderVersion(a, b string) bool {
	pa := parseVersionParts(a)
	pb := parseVersionParts(b)
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			return x < y
		}
	}
	return a != b && a < b
}

// parseVersionParts splits a version string into leading numeric components.
func parseVersionParts(v string) []int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	fields := strings.Split(v, ".")
	parts := make([]int, 0, len(fields))
	for _, f := range fields {
		num := 0
		for _, r := range f {
			if r < '0' || r > '9' {
				break
			}
			num = num*10 + int(r-'0')
		}
		parts = append(parts, num)
	}
	return parts
}
