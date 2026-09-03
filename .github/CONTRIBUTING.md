# Contributing to ipgaze

Thank you for your interest in contributing to ipgaze, a public IP lookup service with an echoip-compatible API.

## Local Setup

All builds run inside Docker — no local Go installation required.

```bash
git clone https://github.com/apimgr/ipgaze.git
cd ipgaze

# Build both server and client binaries for all 8 platforms
make build

# Start development server (hot rebuild)
make dev

# Run unit tests inside Docker
make test

# Run integration tests (auto-detects Incus or Docker)
./tests/run_tests.sh

# Build and serve documentation
pip install mkdocs-material
mkdocs serve
```

## Branch and PR Workflow

- `main` — stable, protected branch; all changes require a pull request
- Feature branches: `feat/short-description`
- Bug fix branches: `fix/short-description`
- All PRs must pass build, test, lint, and security checks before merge
- Direct pushes to `main` are not permitted except for emergency maintainer bypasses

## What Needs Tests and Docs

Every code change must:
- Include or update `*_test.go` tests alongside changed source files
- Update `docs/` pages when any user-facing, admin-facing, operator-facing, or API-facing behavior changes
- Update `IDEA.md` when features or data models change
- Keep `README.md` current with usage/installation changes

## Security Vulnerabilities

**Do not open a public GitHub issue for security vulnerabilities.**

Report security issues to: apimgr@casjay.pro

See [`.github/SECURITY.md`](SECURITY.md) and [`/.well-known/security.txt`](https://ifcfg.us/.well-known/security.txt) for the full disclosure process.
