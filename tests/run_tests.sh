#!/usr/bin/env bash
# @@License : WTFPL
# tests/run_tests.sh — Automatic test runner (PART 28)
set -eo pipefail

# The basic integration tier is Docker-only. Full systemd testing is explicit
# through tests/incus.sh and must never be selected by this automatic runner.
if command -v docker &>/dev/null; then
    echo "Docker detected - running container tests..."
    exec "$(dirname "$0")/docker.sh"
else
    echo "ERROR: Docker is required for the basic integration tests"
    echo "Install Docker: https://docker.com/"
    exit 1
fi
