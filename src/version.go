package main

import (
	"strconv"
	"time"
)

// Build info - BuildEpoch is set via -ldflags at build time; BuildDate is derived from it.
var (
	Version      = "devel"
	CommitID     = "N/A"
	BuildDate    = "N/A"
	BuildEpoch   = "0"
	OfficialSite = ""
)

// buildEpoch returns the embedded Unix build timestamp, or zero when unset or invalid.
func buildEpoch() int64 {
	n, err := strconv.ParseInt(BuildEpoch, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// init derives the RFC 3339 UTC build date from the embedded build epoch.
func init() {
	if n := buildEpoch(); n > 0 {
		BuildDate = time.Unix(n, 0).UTC().Format("2006-01-02T15:04:05Z")
	}
}
