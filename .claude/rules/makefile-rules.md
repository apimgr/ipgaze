# Makefile Rules (PART 25)

⚠️ **These rules are NON-NEGOTIABLE. Violations are bugs.** ⚠️

> Synced against AI.md revision `fbd22cdebc89` (2026-11-24). AI.md remains authoritative for complete requirements.

## CRITICAL - NEVER DO
- **PART 25:** *Six core targets. DO NOT ADD MORE.** The only other permitted target is `clean`, a housekeeping target that removes `binaries/` and `releases/` and builds nothing. There is no `all` target and none is required.
- **PART 25:** **NEVER guess or assume** - must be explicitly created by user
- **PART 25:** *CRITICAL: Only add `v` prefix to NUMERIC semantic versions, NEVER to text versions.**
- **PART 25:** *Rule: Add `v` prefix ONLY if tag is a NUMBER (semantic version X.Y.Z), NEVER if it's TEXT.**
- **PART 25:** ✗ NEVER create: `git tag vdev`, `git tag vbeta` (wrong!)
- **PART 25:** ❌ `vdev` - NEVER add v to text
- **PART 25:** ❌ `vbeta` - NEVER add v to text
- **PART 25:** ❌ `v20251218` - NEVER add v to timestamps
- **PART 25:** ❌ `vv0.3.0` - NEVER double the v prefix
- **PART 25:** *Binaries are NEVER copied or symlinked. They stay in `binaries/` until explicitly moved for release.**
- **PART 25:** | Action | Example | Why Prohibited |
- **PART 25:** | Tag name | `devel` (single rolling tag — never a timestamp) |
- **PART 25:** *NEVER:**
- **PART 25:** ❌ `vdev`, `vbeta`, `vdevel` (text versions never get v)
- **PART 25:** ❌ `v20251218` (timestamps never get v)

## CRITICAL - ALWAYS DO
- **PART 25:** If not present, CLI/Agent users must always specify `--server` flag
- **PART 25:** Every binary MUST have these values embedded at build time:
- **PART 25:** *OfficialSite usage:** If set, CLI uses this as default `--server` value. If empty, users must provide `--server` flag or configure in cli.yml.
- **PART 25:** *Every GitHub release MUST include these files:**
- **PART 25:** | Release name | `v{version}` (always with v: `v1.2.3`, `v0.2.0`) |
- **PART 25:** | Max releases | **1** (always overwrites previous devel) |

## AI.md 2026-11-24 Updates

- The six core targets remain fixed; `clean`, internal `release-check`, and housekeeping are the only documented exceptions. `release-check` is a prerequisite, not a workflow entry point.
- `make release` accepts stable `X.Y.Z` versions only; beta and devel releases come from CI.
- `IDEA.md` `official_site` is documentation metadata only. Operational CLI defaults come from `site.txt`, `OFFICIAL_SITE`, or CI configuration.
- Batch Go work should share one bounded Docker toolchain run; use named containers, resource limits, and the project-scoped Go build cache.

## Key Rules Summary

### PART 25 — MAKEFILE
- Targets
- Versioning
- Binary Naming
- Build Matrix
- Makefile Implementation
- Embedded Build Info
- Go Module Caching
- Target Details
- Directory Rules
- NEVER Copy or Symlink Binaries
- Release Artifacts
- Release Types
- Version Tag Summary (Quick Reference)
- Version Files
- Release Summary

For complete details, see AI.md PART 25.

<!-- AI.md source: fbd22cdebc89 -->
