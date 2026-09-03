#!/usr/bin/env bash
# @@License : WTFPL
# tests/run_tests.sh — Automatic test runner (PART 28)
set -eo pipefail

# Detect available container runtime and run appropriate test
if command -v incus &>/dev/null; then
    echo "Incus detected - running full systemd tests..."
    exec "$(dirname "$0")/incus.sh"
elif command -v docker &>/dev/null; then
    echo "Docker detected - running container tests..."
    exec "$(dirname "$0")/docker.sh"
else
    echo "ERROR: Neither incus nor docker found"
    echo "Please install one of the following:"
    echo "  - Incus (preferred): https://linuxcontainers.org/incus/"
    echo "  - Docker (fallback): https://docker.com/"
    exit 1
fi
