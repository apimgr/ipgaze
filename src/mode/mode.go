// Package mode parses the application mode string used by the `--mode`
// CLI flag and `MODE` environment variable (AI.md PART 6). It intentionally
// holds no package-level state — the resolved mode lives in
// config.AppConfig.Server.Mode, and debug gating lives in
// config.AppConfig.IsDebug() (reads the DEBUG env var directly). A previous
// version of this package duplicated that state behind an init()-populated
// global, which raced with the --debug flag (set inside main(), after
// init() already ran) and was never actually read by the server or config
// packages — removed rather than wired in, since nothing in AI.md mandates
// this specific package, only the mode/debug behavior it now only parses.
package mode

import (
	"fmt"
	"strings"
)

// AppMode represents the application execution mode.
type AppMode string

const (
	// AppModeProduction is the production application mode.
	AppModeProduction AppMode = "production"
	// AppModeDevelopment is the development application mode.
	AppModeDevelopment AppMode = "development"
	// AppModeDebug is the distinct debug application mode (AI.md PART 6
	// "Six Operational States" table): entered only via `--mode debug` /
	// `MODE=debug`, never a development alias. Its own row governs the
	// Debug and Debug+Endpoints states; everything not called out there
	// falls back to development-mode behavior.
	AppModeDebug AppMode = "debug"
)

// ParseMode parses a mode string and returns the corresponding AppMode.
// Accepts: "dev", "devel", "development", "prod", "production" (case-insensitive).
func ParseMode(s string) (AppMode, error) {
	normalized := strings.ToLower(strings.TrimSpace(s))
	switch normalized {
	case "dev", "devel", "development":
		return AppModeDevelopment, nil
	case "prod", "production":
		return AppModeProduction, nil
	default:
		return AppModeProduction, fmt.Errorf("invalid mode: %s (expected: dev, devel, development, prod, or production)", s)
	}
}

// ParseModeWithDebugAlias parses a mode string that may additionally be the
// special value "debug" (per AI.md PART 6 "Six Operational States"): its own
// distinct AppMode, not a development alias. Selecting it defaults the debug
// flag on (Debug+Endpoints is the default when MODE=debug and DEBUG is
// unset); an explicitly set DEBUG env var or --debug flag still wins over
// that implied default. Unlike ParseMode, this accepts "debug" successfully.
func ParseModeWithDebugAlias(s string) (m AppMode, impliedDebug bool, err error) {
	if strings.ToLower(strings.TrimSpace(s)) == "debug" {
		return AppModeDebug, true, nil
	}
	m, err = ParseMode(s)
	return m, false, err
}

// String returns the string representation of the mode.
func (m AppMode) String() string {
	return string(m)
}
