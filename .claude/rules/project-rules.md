# Project Rules (PART 2, PART 3, PART 4)

⚠️ **These rules are NON-NEGOTIABLE. Violations are bugs.** ⚠️

## CRITICAL - NEVER DO
- **PART 2:** | **GPL/AGPL/LGPL** | ⚠️ AVOID | Copyleft licenses - do not use |
- **PART 2:** *NEVER use GPL/AGPL/LGPL licensed dependencies** - they require derivative works to be open-sourced under the same license.
- **PART 3:** *NEVER hardcode `{project_name}` or `{project_org}` - always infer from git remote or directory path.**
- **PART 3:** *Note:** `docker/rootfs/` (build-time container overlay) is COMMITTED, never gitignored.
- **PART 3:** Line 1: literal `# gitignore created on ` followed by the creation timestamp in `MM/DD/YY at HH:MM` format (24-hour clock). Generated once on creation; never updated on edit.
- **PART 3:** Line 2: the literal string `ignoredirmessage` — this is the magic token that tells the project tooling to suppress the "directory ignored" reminder in the shell prompt. Do not rename, do not translate, do not prefix with `#`.
- **PART 3:** *What .dockerignore MUST NOT include:**
- **PART 3:** *ALL paths are ALWAYS relative to PROJECT ROOT, never the current working directory.**
- **PART 3:** NEVER assume current directory is project root
- **PART 3:** **NEVER mix purposes** - don't put user config in data_dir or vice versa
- **PART 3:** | **Always Latest Stable** | Use latest stable Go version (NEVER hardcode specific versions) |
- **PART 3:** | **CI/CD** | Build/test inside `casjaysdev/go:latest` jobs or `docker run ... casjaysdev/go:latest` (never `setup-go`, never pinned tags) |
- **PART 3:** *MUST use `modernc.org/sqlite`. NEVER use `github.com/mattn/go-sqlite3`.**
- **PART 3:** | `github.com/mattn/go-sqlite3` | YES | **NEVER USE** |
- **PART 3:** **NEVER run `go` directly - always use Makefile targets (`make dev`, `make test`, etc.)**

## CRITICAL - ALWAYS DO
- **PART 2:** *All projects MUST use the MIT License.**
- **PART 2:** | License file | `LICENSE.md` (REQUIRED in project root) |
- **PART 2:** *All third-party dependencies MUST have their licenses attributed in LICENSE.md.**
- **PART 2:** | License Type | Attribution Required | Example Libraries |
- **PART 2:** *When full text is required:**
- **PART 2:** | License | Full Text Required | Reason |
- **PART 2:** | BSD-3-Clause | YES (brief) | Non-endorsement clause must be visible |
- **PART 2:** | Apache 2.0 | Only NOTICE file | Must include NOTICE if library has one |
- **PART 2:** | Event | Action Required |
- **PART 2:** *Every README.md MUST include a license badge:**
- **PART 2:** 1. `LICENSE.md` file (REQUIRED)
- **PART 2:** 2. README.md badge (REQUIRED)
- **PART 2:** | No LICENSE.md file | Legally ambiguous | Always include LICENSE.md |
- **PART 2:** *License Rules:** LICENSE.md required in root. Embed third-party licenses. No GPL/AGPL/LGPL. Update when deps change. Automate checking in CI/CD.
- **PART 3:** *Note:** When using path-based inference, `PROJECT_ORG` will be the parent directory name, which may not match the git organization unless you follow the recommended `~/Projects/{gitprovider}/{project_org}/{internal_name}` structure. Git remote inference is always more reliable.
- **PART 3:** | `{plist_name}` | derived | macOS LaunchAgent/LaunchDaemon Bundle ID — always `io.github.{project_org}.{internal_name}` | `io.github.casjay.jokes` |
- **PART 3:** **No VCS required** - May not have git initialized
- **PART 3:** *Required header format — every `.gitignore` MUST start with these two lines, in this order:**
- **PART 3:** *What .dockerignore MUST include:**
- **PART 3:** | `src/` | Source code - required for build |
- **PART 3:** | `go.mod`, `go.sum` | Go module files - required |
- **PART 3:** | `docker/` | Dockerfile and compose files - required |
- **PART 3:** *Rule: ALL file paths in code, documentation, and scripts MUST be relative to THIS project root, regardless of where it's located.**
- **PART 3:** Commands MUST be run from project root, OR
- **PART 3:** Commands MUST use absolute paths, OR
- **PART 3:** Commands MUST `cd` to project root first
- **PART 3:** | OS | Required |
- **PART 3:** | Architecture | Required |
- **PART 3:** *IMPORTANT: Be smart about implementations - code must work on ALL platforms.**
- **PART 3:** | **Docker** | Use `casjaysdev/go:latest` for builds (always use this exact unpinned image) |
- **PART 3:** *All libraries MUST be pure Go and work with `CGO_ENABLED=0`.**
- **PART 3:** | Driver | CGO Required | Use |
- **PART 3:** | `modernc.org/sqlite` | NO | **ALWAYS USE THIS** |
- **PART 3:** *CGO_ENABLED=0 Rule:** All libraries must work with `CGO_ENABLED=0`. If a library requires CGO, find a pure Go alternative or don't use it.
- **PART 3:** Version numbers are examples - always use latest stable versions
- **PART 3:** [ ] All 4 OSes must be supported
- **PART 3:** [ ] Both AMD64 and ARM64 must be supported
- **PART 3:** [ ] Always use latest stable Go
- **PART 4:** [ ] Config file is ALWAYS `server.yml` (not .yaml)

## Key Rules Summary

### PART 2 — LICENSE & ATTRIBUTION
- Project License
- LICENSE.md Structure
- Embedded Licenses
- Embedded License Attribution
- Third-Party Licenses
- Maintenance Requirements
- README.md License Badge (REQUIRED)
- Docker Annotations (REQUIRED)
- Go Module License Field
- Common Mistakes (AVOID)
- License Compatibility Matrix
- Resources

### PART 3 — PROJECT STRUCTURE
- Project Information
- Project Description
- Project-Specific Features
- Variables
- Local Project Path Structure (RECOMMENDED)
- Directory Structure
- Path Convention
- Runtime Directory Usage
- Platform Support
- Go Version
- Required Go Libraries

### PART 4 — OS-SPECIFIC PATHS
- Linux
- macOS
- BSD (FreeBSD, OpenBSD, NetBSD)
- Windows
- Docker/Container

For complete details, see AI.md PART 2, PART 3, PART 4.

<!-- AI.md source: 03cc45ec58df -->
