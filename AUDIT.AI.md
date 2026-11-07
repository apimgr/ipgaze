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
- Searched `/root/Projects/github/apimgr/TODO.API.md` before appending four newly confirmed AI.md conflicts or underspecified requirements; it now has eight entries. AI.md remains unchanged.
- Added PGP rotation archives retained for the 30-day grace window, re-encrypted them when the installation secret rotates, and made PGP deletion remove active and archived key material.
- Added `--maintenance backup test` as a dry-run archive extraction and private-key decryption check using the installation secret from the extracted database. Restore now consumes keyserver publish state and republishes the restored public key when configured.
- Redacted sensitive query values from access and debug logs. Added a separate researcher handle field for handle-based credit.

## Remaining confirmed alignment gaps

- AI.md PART 11 lines 14966 and 14972 conflict: the policy is described as API-editable, while server security is also declared file-configured with no administration routes. The policy uses the user-approved conservative default with read-only HTML/JSON routes; the conflict is logged in `/root/Projects/github/apimgr/TODO.API.md`.
- AI.md PART 12 lists `recaptcha`, `hcaptcha`, and `simple` CAPTCHA choices without defining provider credentials or verification protocols. The implementation provides the built-in `simple` challenge; the missing provider contract is logged in `/root/Projects/github/apimgr/TODO.API.md`.
- AI.md conflicts on the default tracking consent model and whether supplied invalid `security_id` values must be logged. The implementation requires affirmative consent and does not log the secret token; both conflicts are logged in `/root/Projects/github/apimgr/TODO.API.md`.
- Daily backup archives are still full archives rather than deltas. AI.md does not define the delta format or restore/apply contract, so this is logged for specification clarification before implementing incremental restore.
- AI.md also leaves notification language selection and the startup/shutdown email event behavior undefined; these questions are in `/root/Projects/github/apimgr/TODO.API.md`.
- The AI.md checklist has not been audited line by line. The focused review covered the completed changes, update-channel rules, documentation configuration, and public security policy; it found no additional mismatch in those areas. Full-project compliance is not claimed.

## Verification status

- `bash "$HOME/.codex/hooks/test-lint-run.sh" test -- make test` — passed with 60.1% statement coverage.
- `go vet ./...` — passed through the Docker Go image and lint gate.
- `shellcheck tests/docker.sh tests/incus.sh` — passed through the lint gate.
- `mkdocs build --strict --site-dir /tmp/ipgaze-site` — passed in Docker; generated site output stayed inside the disposable container.
- `git diff --check` — passed.
- Remaining AI.md questions are listed in `/root/Projects/github/apimgr/TODO.API.md`; the exhaustive checklist audit is not yet complete.
