# CI/CD Rules (PART 27)

⚠️ **These rules are NON-NEGOTIABLE. Violations are bugs.** ⚠️

## CRITICAL - NEVER DO
- **PART 27:** *CI/CD workflows are DIFFERENT from local development. Do NOT mix them.**
- **PART 27:** | **Makefile** | ALWAYS use Makefile targets | NEVER use Makefile (explicit commands) |
- **PART 27:** *CI/CD workflows MUST NOT:**
- **PART 27:** > **Note:** `ci.yml` and `release.yml` are required on every project. Go projects never have `build-toolchain.yml` — `casjaysdev/go:latest` is maintained externally. `beta.yml`, `devel.yml`, and `docker.yml` are project-specific optional workflows — include only when the project requires them.
- **PART 27:** *Tag release auto-cancel policy:** Tag-only release workflows like `release.yml` MUST also use workflow concurrency, but only per exact tag ref. A newer run for `refs/tags/v1.2.3` should cancel the older `refs/tags/v1.2.3` run. A run for `v1.2.4` must NOT cancel `v1.2.3`.
- **PART 27:** Runs on push and pull requests; security jobs (`secret-scan`, `workflow-policy`, `vuln-scan`, `image-scan`) also run on the weekly schedule. All toolchain jobs run inside `container: image: casjaysdev/go:latest` — never installs tools inline (scanner jobs use their pinned actions directly on the runner). No `ensure-build-image` gate, no `build-toolchain.yml`.
- **PART 27:** > **Note:** Security jobs (`secret-scan`, `workflow-policy`, `vuln-scan`, `image-scan`) are defined within `ci.yml`. They run on push, PR, and weekly schedule (`cron: '0 6 * * 1'`). Add `if: github.event_name != 'schedule'` to build/test/coverage/artifact jobs to skip non-security work on scheduled runs. Secret scanning is mandatory on every public repo via truffleHog (Apache-2.0). Derive the scan range in a dedicated step: `github.event.before`/`github.sha` on push (empty when `before` is all-zeros, i.e. a new branch), PR base/head on pull requests, and empty (full-history scan) on schedule — never `default_branch`, which after a push resolves to the same commit as HEAD and silently skips the scan.
- **PART 27:** [ ] Binary naming: NEVER include -musl suffix

## CRITICAL - ALWAYS DO
- **PART 27:** *All projects MUST have CI/CD workflows appropriate for their git hosting platform.**
- **PART 27:** *CI/CD workflows MUST:**
- **PART 27:** Use Makefile targets (commands must be explicit for visibility)
- **PART 27:** *Container-job user rule:** every `container:` job MUST set `options: "--user 0:0"`. The runner (and actions/checkout's post-job cleanup) execs into the job container — e.g. `cat /etc/*release` for OS diagnostics — as a user the image's `/etc/passwd` may not define, which fails or flakes the job after all real work already passed, wasting the entire run. Numeric `0:0` needs no `/etc/passwd` lookup at all, so it is immune regardless of the image's user table.
- **PART 27:** *Branch push auto-cancel policy:** Any workflow triggered by pushes to `main`, `master`, `devel`, `dev`, or `beta` MUST use workflow concurrency to cancel older in-progress runs for the same ref. This applies to branch-based CI (for example `beta.yml`, `devel.yml`, `docker.yml`, and any project-specific branch-push workflow).
- **PART 27:** All workflows MUST set these environment variables:
- **PART 27:** | Agents | `arm64`, `amd64` (both required) |
- **PART 27:** All projects MUST have a `Jenkinsfile` in the repository root.
- **PART 27:** | Agent labels | `amd64` and `arm64` MUST be available |
- **PART 27:** | Docker | Required for builds (casjaysdev/go:latest) |
- **PART 27:** | Docker buildx | Required on amd64 runner for multi-arch builds |
- **PART 27:** *Required Token Permissions:**
- **PART 27:** | Docker | `docker.yml` (all branches) | Docker stage (always runs) |
- **PART 27:** | Docker devel | `docker.yml` `build-devel` job (all branches + daily schedule) | "Docker: Devel" stage (always runs) + 4am cron |
- **PART 27:** [ ] All 8 platform builds required (4 OS x 2 arch)

## Key Rules Summary

### PART 27 — CI/CD WORKFLOWS
- CI/CD vs Local Development (IMPORTANT)
- Workflow Files (GitHub Actions)
- Build Info Variables
- CI Workflow (GitHub Actions)
- Release Workflow — Stable (GitHub Actions)
- Beta Workflow (GitHub Actions)
- Devel Workflow (GitHub Actions)
- Docker Workflow (GitHub Actions)
- Self-Hosted Configuration (Gitea/Forgejo Actions)
- Workflow Files (Gitea/Forgejo Actions)
- Release Workflow — Stable (Gitea/Forgejo Actions)
- Beta Workflow (Gitea/Forgejo Actions)
- Devel Workflow (Gitea/Forgejo Actions)
- Docker Workflow (Gitea/Forgejo Actions)
- Variable Mapping (GitHub → Gitea → Forgejo)
- Self-Hosted Configuration (GitLab CI)
- Key Differences from GitHub/Gitea Actions
- GitLab CI Configuration
- GitLab CI Variables
- GitLab Scheduled Pipelines (for Devel Builds)
- Variable Mapping
- Configuration
- Triggers (Matching GitHub Actions)
- Jenkinsfile
- Jenkins Configuration

For complete details, see AI.md PART 27.

<!-- AI.md source: 03cc45ec58df -->
