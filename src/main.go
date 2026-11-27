package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/apimgr/ipgaze/src/run"
)

func main() {
	run.ConfigureBuildInfo(Version, CommitID, BuildDate, BuildEpoch, OfficialSite)
	run.RegisterFlags(flag.CommandLine)
	args := run.RewriteBareUpdateArgs(os.Args[1:])
	if err := flag.CommandLine.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "invalid command line: %v\n", err)
		os.Exit(64)
	}
	if run.HandleEarlyFlags(filepath.Base(os.Args[0])) {
		return
	}
	cfg, err := run.BuildConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "load configuration: %v\n", err)
		os.Exit(78)
	}
	// Copy linker-provided values into the runtime config before startup.
	cfg.Version = Version
	cfg.CommitID = CommitID
	cfg.BuildDate = BuildDate
	cfg.BuildEpoch = BuildEpoch
	cfg.OfficialSite = OfficialSite
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := run.Run(ctx, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "ipgaze: %v\n", err)
		os.Exit(run.ExitCode(err, 1))
	}
}
