//go:build !windows

package run

import "context"

func runPlatform(ctx context.Context, cfg *Config) error {
	return runMain(ctx, cfg)
}
