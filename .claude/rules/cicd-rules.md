# CI/CD Rules (PART 27)

⚠️ **These rules are NON-NEGOTIABLE. Violations are bugs.** ⚠️

## CRITICAL - NEVER DO
- Never pin third-party GitHub Actions to a tag — pin to a full commit SHA only
- Never expose secrets/write tokens to fork PRs; never use unsafe `pull_request_target` on build/test/publish paths

## CRITICAL - ALWAYS DO
- Give workflows least-privilege `permissions:` blocks
- Verify workflow changes with `act --list -W {file}` (or equivalent dry-run) before considering them done; check post-push CI status
- Pin commit SHAs to 7 chars explicitly: `git rev-parse --short=7 HEAD`
  (never bare `--short`), `${CI_COMMIT_SHA:0:7}` on GitLab (never
  `CI_COMMIT_SHORT_SHA`)
- Registry/repo-path identifiers (image tags, OCI labels' url/source/
  documentation) key off `INTERNAL_NAME`, never `PROJECT_NAME` — a later
  rename must not orphan them. Display-only labels (`image.title`,
  `image.base.name`) still use `PROJECT_NAME`
- Doc-table placeholder casing is lowercase: `{commit_id}`, `{yymm}`,
  `{version}` — the underlying shell/env vars stay `${COMMIT_ID}`, etc.

## Key Rules Summary
- **NOT YET FULLY POPULATED**: PART 27 (CI/CD Workflows) has not been read in this pass — only PART 0/1 general rules above are included. Read AI.md PART 27 directly before doing CI/CD-specific work.

For complete details, see AI.md PART 27.
