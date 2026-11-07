# Project Alignment Audit

Updated: 2026-11-06
Source of truth: `AI.md` (read-only)

## Completed during this alignment

- Corrected public help examples, request-aware URLs, MCP help page and JSON endpoint, OpenAPI entries, and setup documentation.
- Added the HTML and enveloped JSON security overview, policy, acknowledgments, and researcher report-status routes. Added the coordinated disclosure form mode, rotating `security_id`, CAPTCHA, encrypted report storage, notifications, acknowledgment, and one-shot daily status access.
- Added PGP report encryption and AES-256-GCM fallback delivery as an encrypted attachment. Encryption-key rotation now re-encrypts AES-encrypted report rows in a transaction.
- Added the authorized `--maintenance security-report list|set` workflow so operators can update the documented researcher-visible triage states without a web admin route. Listing exposes non-identifying metadata only; updates are audit-logged.
- Removed obsolete 2024 terms-page dates, standardized page/contact JSON envelopes, and updated README and docs for current routes and behavior.
- Updated `.github/SECURITY.md` and `docs/security.md` to make GitHub private reporting primary for repository vulnerabilities, state the in-scope targets and exclusions, provide conservative safe-harbor terms, and document the official service's 90-day disclosure policy. Corrected the MCP authentication guidance in configuration docs.
- Updated Docker/Incus smoke checks and the SSR test for canonical security.txt behavior; `/security.txt` is checked as a 404.
- Removed the unsupported `/security.txt` alias; `/.well-known/security.txt` remains canonical.
- Corrected IDEA.md's duplicate MCP entry and documented that reporter details can persist only inside encrypted security reports.
- Searched `/root/Projects/github/apimgr/TODO.API.md` before adding each confirmed AI.md conflict or underspecified requirement found during the segmented review. AI.md remains unchanged.
- Added PGP rotation archives retained for the 30-day grace window, re-encrypted them when the installation secret rotates, and made PGP deletion remove active and archived key material.
- Added `--maintenance backup test` as a dry-run archive extraction and private-key decryption check using the installation secret from the extracted database. Restore now consumes keyserver publish state and republishes the restored public key when configured.
- Redacted sensitive query values from access and debug logs. Added a separate researcher handle field for handle-based credit.
- Bounded encryption-key rotation's database transaction to AI.md's 30-second transaction deadline.
- Updated third-party license versions to match go.mod and added the MCP SDK attribution from its module license.
- Added individual compliance-standard settings and report output; an enabled standard now requires encrypted backups, and report generation is audit-logged.
- Corrected CLI, Tor, and I2P integration documentation to match actual command and feature behavior.
- Updated ReadTheDocs to its current supported Ubuntu LTS and Python version.
- Made service uninstall remove the OS-specific paths resolved for the current command, including CLI directory overrides.

## Remaining confirmed alignment gaps

- AI.md PART 11 lines 14966 and 14972 conflict: the policy is described as API-editable, while server security is also declared file-configured with no administration routes. The policy uses the user-approved conservative default with read-only HTML/JSON routes; the conflict is logged in `/root/Projects/github/apimgr/TODO.API.md`.
- AI.md PART 12 lists `recaptcha`, `hcaptcha`, and `simple` CAPTCHA choices without defining provider credentials or verification protocols. The implementation provides the built-in `simple` challenge; the missing provider contract is logged in `/root/Projects/github/apimgr/TODO.API.md`.
- AI.md conflicts on the default tracking consent model and whether supplied invalid `security_id` values must be logged. The implementation requires affirmative consent and does not log the secret token; both conflicts are logged in `/root/Projects/github/apimgr/TODO.API.md`.
- Daily backup archives are still full archives rather than deltas. AI.md does not define the delta format or restore/apply contract, so this is logged for specification clarification before implementing incremental restore.
- AI.md also leaves notification language selection and the startup/shutdown email event behavior undefined; these questions are in `/root/Projects/github/apimgr/TODO.API.md`.
- AI.md also conflicts about whether `docker/rootfs/` is committed, whether README's Development section is absolutely last, whether configuration may be database-backed, and whether path environment variables are init-only. These are listed in `/root/Projects/github/apimgr/TODO.API.md`.
- AI.md PART 8 gives conflicting help syntax (`--service help`/`<command> help` versus `--service --help`); the runtime help follows the explicit server command/startup examples, and the mismatch is logged in `/root/Projects/github/apimgr/TODO.API.md`.
- PART 11 still requires configured permanent IP blocks, abuse-triggered temporary blocking/alerting, and a `/server/dpo` contact route. The blocked-IP YAML schema, auto-block threshold semantics, and DPO contact source are underspecified and logged in `/root/Projects/github/apimgr/TODO.API.md`.
- Fixed the concrete allowlist rate-limit bypass gap. The automatic flood-blocking trigger remains unspecified (window, threshold basis, persistence) and is logged in `/root/Projects/github/apimgr/TODO.API.md`.
- PART 11's per-standard flags now exist, but its detailed behaviors (including breach workflows, retention, and organization-specific controls) are not fully implemented. Do not treat the flags or report as certification.
- PART 31.2 has inconsistent I2P configuration names (`features.i2p.enabled` versus `server.i2p.enabled` and other interfaces); this is recorded in `/root/Projects/github/apimgr/TODO.API.md`.
- The `go-licenses` scan identifies `modernc.org/mathutil` as unknown because its module archive lacks a recognized license filename. Upstream identifies it as BSD-3-Clause; the attribution is in `LICENSE.md`. The scan did not complete successfully.
- Segmented reviews covered PARTS 1–7 and focused portions of PARTS 8–33; they were not exhaustive line-by-line walks of every PART. Full-project compliance is not claimed.

## Verification status

- `bash "$HOME/.codex/hooks/test-lint-run.sh" test -- make test` — passed with 60.1% statement coverage after the latest code changes.
- `shellcheck tests/docker.sh tests/incus.sh` — passed through the lint gate.
- `mkdocs build --strict --site-dir <project-scoped temp directory>` — passed in Python 3.14; output stayed inside the disposable container.
- `git diff --check` — passed.
- `go vet ./...` and `GOTOOLCHAIN=go1.26.4 staticcheck ./...` — passed in the Go container through the lint gate.
- Remaining AI.md questions are listed in `/root/Projects/github/apimgr/TODO.API.md`; the exhaustive checklist audit is not yet complete.
