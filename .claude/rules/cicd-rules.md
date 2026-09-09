# CI/CD Rules (PART 27)

⚠️ **These rules are NON-NEGOTIABLE. Violations are bugs.** ⚠️

## CRITICAL - NEVER DO
- Never mix local-dev and CI/CD build styles — CI/CD workflows NEVER use Makefile targets (commands must be
  explicit `go build ...` with every flag visible), NEVER reference local host cache paths
  (`~/.local/share/go`, `GO_CACHE`/`GO_BUILD` bind mounts), and NEVER depend on local Docker containers for
  the build itself (GitHub/Gitea/Forgejo Actions use the `casjaysdev/go:latest` job container directly)
- Never pin a third-party Action to a tag — pin to a full 40-char commit SHA only; `workflow-policy` enforces
  this by grepping every `uses:` line across `.github/`, `.gitea/`, `.forgejo/` for a non-SHA reference and
  failing the build if one is found
- Never omit `options: "--user 0:0"` on a `container:` job — without it, numeric-UID-less exec steps (OS
  diagnostics, checkout post-job cleanup) can fail or flake after all real work already passed
- Never cross-cancel different release refs — a concurrency group may only cancel an older run for the exact
  same branch or exact same tag; a newer `v1.2.4` run must never cancel an in-flight `v1.2.3` run
- Never apply OCI labels via Dockerfile `LABEL` in CI-built images — apply via `--label`/`--annotation`
  build args or the `docker/metadata-action` `annotations:` output, and set `labels: ""` on
  `build-push-action` so per-platform labels don't diverge from the manifest annotations
- Never use `github.event.repository.default_branch` to compute a secret-scan range — after a push it
  resolves to the same commit as HEAD and silently skips the scan; derive the range explicitly instead
  (`before`/`sha` on push, PR base/head on pull_request, empty/full-history on schedule)
- Never expose secrets or write tokens to fork PRs; never use `pull_request_target` unsafely on
  build/test/publish paths
- Never use `github.*` context/env vars in a Gitea or Forgejo workflow — use `gitea.*`/`GITEA_*` (Forgejo
  workflows may use `forgejo.*`/`FORGEJO_*` but remain backwards-compatible with `gitea.*`/`GITEA_*` and the
  `.gitea/workflows/` directory, since Forgejo Actions is a Gitea Actions fork)

## CRITICAL - ALWAYS DO
- Give every job least-privilege `permissions:` (e.g. `contents: read` unless a job specifically needs more)
- Set `VERSION`, `COMMIT_ID`, `BUILD_EPOCH` explicitly in a "Set build info" step in every workflow, deriving
  `BUILD_DATE` from `BUILD_EPOCH` (used only for Docker OCI labels, never embedded via ldflags):
  `VERSION` from `release.txt` if present else the tag with `v` stripped; `COMMIT_ID` via
  `git rev-parse --short=7 HEAD` (GitLab: `${CI_COMMIT_SHA:0:7}`, never `CI_COMMIT_SHORT_SHA`)
- Use workflow concurrency with `cancel-in-progress: true` for every branch-push workflow targeting `main`,
  `master`, `devel`, `dev`, or `beta` (group keyed by workflow+ref), and for tag-only release workflows keyed
  by the exact tag ref
- Route every project to the correct provider directory and config: GitHub → `.github/workflows/*.yml`
  (github.com only, no self-hosted); Gitea → `.gitea/workflows/*.yml`; Forgejo → `.forgejo/workflows/*.yml`
  (self-hosted only, compatible with `.gitea/workflows/` too); GitLab → `.gitlab-ci.yml`; Jenkins →
  `Jenkinsfile`
- Require `ci.yml` and `release.yml` on every project; treat `beta.yml`/`daily.yml`/`docker.yml` as optional,
  project-specific additions; never add `build-toolchain.yml` for Go — `casjaysdev/go:latest` is externally
  maintained
- Run every toolchain job (lint/test/build/vuln-scan) inside `container: image: casjaysdev/go:latest` with
  `options: "--user 0:0"`; scanner jobs that use pinned third-party actions (trufflehog, trivy) run directly
  on the runner, not inside that container
- Skip non-security jobs on the weekly schedule trigger with `if: github.event_name != 'schedule'` — leave
  `secret-scan`, `workflow-policy`, `vuln-scan`, `image-scan` running on push, PR, and the weekly cron
- Enforce a coverage threshold (60% in the reference `ci.yml`) via `go tool cover -func` after
  `go test -cover -coverprofile=...`, writing coverage to a per-owner/per-repo tempdir under `/tmp`, never a
  project-tree or fixed shared path
- Build the full 8-platform release matrix (linux/darwin/windows/freebsd × amd64/arm64, `.exe` suffix for
  windows) in `release.yml`, triggered on `v*`/`[0-9]*.[0-9]*.[0-9]*` tag pushes
- Only build/scan a Docker image when the project actually ships one — gate image-build/scan steps on
  `hashFiles('docker/Dockerfile') != ''`
- Check post-push CI status after every push and treat a red or still-running build as a bug to fix
  immediately, not something to report done

## Key Rules Summary
CI/CD is explicit and provider-native — never a Makefile call, never a local host path, never a local
Docker-for-build dependency. Every third-party Action is SHA-pinned, every container job pins
`--user 0:0`, every job carries least-privilege permissions, and concurrency cancellation is scoped exactly
to same-ref branch pushes or same-exact-tag releases. Build info (`VERSION`/`COMMIT_ID`/`BUILD_EPOCH`) is
always set explicitly per run rather than inherited from local Makefile variables. Gitea and Forgejo share
one Actions engine — use `gitea.*`/`GITEA_*` (or Forgejo's own `forgejo.*`/`FORGEJO_*`, kept backwards
compatible), never GitHub's `github.*`/`GITHUB_*`, in any `.gitea/workflows/` or `.forgejo/workflows/` file.
OCI image metadata is always CI-applied (labels + manifest annotations), never a Dockerfile `LABEL`.

For complete details, see AI.md PART 27.
