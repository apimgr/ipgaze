# Testing Rules (PART 28, 29, 30)

⚠️ **These rules are NON-NEGOTIABLE. Violations are bugs.** ⚠️

## CRITICAL - NEVER DO
- Never run `go test` or any build tooling directly on the host — use Docker (`casjaysdev/go:latest`) or Incus (`debian:latest`)
- Never commit with a failing test; never skip tests to save time

## CRITICAL - ALWAYS DO
- Run `make test` (Docker) for unit tests; use `./tests/run_tests.sh` / `./tests/incus.sh` for integration tests
- Keep ReadTheDocs (`docs/`, `mkdocs.yml`, `.readthedocs.yaml`) and i18n locale files in sync with the code

## Key Rules Summary
- **NOT YET FULLY POPULATED**: PARTs 28 (Testing & Development), 29 (ReadTheDocs Documentation), and 30 (I18N & A11Y) have not been read in full detail in this pass beyond PART 1's container-only build/test summary. Read AI.md PART 28, 29, 30 directly before doing testing/docs/i18n-specific work.

For complete details, see AI.md PART 28, PART 29, PART 30.
