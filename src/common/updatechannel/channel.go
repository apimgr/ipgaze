// Package updatechannel defines canonical update-channel names.
package updatechannel

import "strings"

// Normalize converts accepted rolling-channel aliases to the canonical name.
func Normalize(value string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "stable":
		return "stable", true
	case "beta":
		return "beta", true
	case "devel", "daily", "rolling", "dev", "development":
		return "devel", true
	default:
		return "", false
	}
}
