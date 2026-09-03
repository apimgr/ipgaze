# AI Assistant Rules (PART 0, 1)

⚠️ **These rules are NON-NEGOTIABLE. Violations are bugs.** ⚠️

## CRITICAL - NEVER DO
- Never guess or assume a requirement, file location, or design choice — STOP and ASK
- Never edit AI.md — it is the read-only source-of-truth template (project overrides go in SPEC.md)
- Never claim "done" without reading, searching, testing, and verifying first
- Never create report/analysis files (AUDIT.md, COMPLIANCE.md, SUMMARY.md); temporary `AUDIT.AI.md` only during an explicit audit with >5 issues, deleted when resolved
- Never rely on memory for spec content — read the relevant AI.md PART before implementing
- Never add unrequested features or "improve"/"optimize" the spec
- Never attribute any output to an AI tool anywhere (code, comments, commit trailers, PRs, docs) — output must read as human-authored
- Never run plain `git commit` / `git push` — use the `gitcommit` wrapper only
- Subagents never write `.git/COMMIT_MESS` or call `gitcommit` — they edit and report back to the parent
- Never read an image >1000×1000 directly — resize to a tempdir copy first
- Never treat a non-conforming IDEA.md as authoritative without running the migration procedure

## CRITICAL - ALWAYS DO
- Read only the AI.md PART(s) relevant to the current task, on demand — never pre-load speculatively
- Session start: check `.claude/rules/` exists and is newer than AI.md; regenerate all 13 files if missing/outdated
- Ask when unsure — asking (~100 tokens) is far cheaper than a wrong implementation + redo (~5000+ tokens)
- Read before edit; search before create; verify before claim; test before commit
- Every 3-5 changes: stop and check for drift against the spec
- Update IDEA.md when features change; update TODO.AI.md/TODO.md as tasks progress (never delete/empty human-owned TODO.md, only mark done)
- Translate all new user-facing text (`t(r, "errors.*")`, `i18n.T`, `{{t .Lang "key"}}`) — add keys to `en.json` plus note for all other locale files
- Full Web Application Architecture: every feature works via Browser (HTML), PWA, API/automation (JSON), and CLI client — one endpoint pattern for all (`/x` web ⇄ `/api/{api_version}/x` JSON)
- Security-first, secure-by-default: never weaken authn/authz, TLS, CSRF/CSP/CORS, rate limiting, or input validation to "improve" usability
- Parameterized queries only; never `SELECT *`; never string-concatenate SQL
- Use intent-revealing names — never generic `Mode`, `Type`, `Status`, `Config`, `Get()`, `Init()` etc. without a qualifying subject
- Verify every change with a real tool appropriate to its type (tests, curl, build+run, browser, etc.) before reporting done

## Key Rules Summary
- AI.md PARTS 0-33 = HOW (read-only); IDEA.md = WHAT (editable); SPEC.md = project-specific overrides (SPEC.md > AI.md > global CLAUDE.md)
- Golden rule ordering: Correct > Verified > Fast
- Red-flag self-talk ("probably what they meant", "should work", "I'll fix later") means STOP
- Audit is explicit-command-only ("audit" / "check compliance" / "verify project") — normal work is not an audit
- All commits go through `gitcommit --dir {dir} all`, message written to `.git/COMMIT_MESS` first and re-read to verify

For complete details, see AI.md PART 0, PART 1.
