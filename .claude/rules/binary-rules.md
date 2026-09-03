# Binary Rules (PART 7, 8, 32)

⚠️ **These rules are NON-NEGOTIABLE. Violations are bugs.** ⚠️

## CRITICAL - NEVER DO
- Never build with `go` directly on the host — all builds go through Docker (`casjaysdev/go:latest`) or the Makefile targets
- Never guess CLI flag names, binary output paths, or client behavior — read AI.md PART 7/8/32 before touching `src/client/` or binary entrypoints
- Never skip `--help`/`--version` verification after a CLI change

## CRITICAL - ALWAYS DO
- Use `make dev` / `make local` / `make build` for binary builds, never a raw `go build`
- Keep `src/client/` present for all projects (client scope is mandatory per PART 32)
- Verify CLI changes by building and exercising the binary (flags, exit codes, stdout/stderr) before reporting done

## Key Rules Summary
- **NOT YET FULLY POPULATED**: PARTs 7 (Binary Requirements), 8 (Server Binary CLI), and 32 (Client) have not been read in this pass — only PART 0/1 general rules above are included. Read AI.md PART 7, 8, 32 directly before doing binary/CLI-specific work.

For complete details, see AI.md PART 7, PART 8, PART 32.
