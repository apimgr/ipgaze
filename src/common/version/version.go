// Package version provides build-time version constants and helpers.
// Variables are set via -ldflags at build time per AI.md PART 7.
package version

import "runtime"

var (
	// Version is the semver string, e.g. "1.0.0". Set via ldflags.
	Version = "dev"

	// Commit is the short git commit hash (7 chars). Set via ldflags.
	Commit = "unknown"

	// Date is the ISO 8601 build timestamp. Set via ldflags.
	Date = "unknown"

	// OfficialSite is the canonical project URL. Set via ldflags.
	OfficialSite = ""
)

// GoVersion returns the Go runtime version string.
func GoVersion() string {
	return runtime.Version()
}

// UserAgent returns the standard User-Agent string for the CLI client.
// Format: ipgaze-cli/{version} (go/{go_version}; {os}/{arch})
func UserAgent() string {
	return "ipgaze-cli/" + Version + " (go/" + runtime.Version() + "; " + runtime.GOOS + "/" + runtime.GOARCH + ")"
}

// IsRelease returns true if this is a proper release build (not dev/unknown).
func IsRelease() bool {
	return Version != "dev" && Commit != "unknown"
}
