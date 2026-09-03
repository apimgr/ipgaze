#!/bin/bash
# scripts/verify-licenses.sh — check all deps are MIT-compatible (AI.md PART 2)
# ver: 2026.06.09

set -eo pipefail

VERIFY_LICENSES_SCRIPTDIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
VERIFY_LICENSES_PROJECTDIR="$(cd -- "${VERIFY_LICENSES_SCRIPTDIR}/.." && pwd)"

cd -- "${VERIFY_LICENSES_PROJECTDIR}"

echo "Checking for incompatible licenses..."

# Require go-licenses — never install inline.
# Pre-install in the build image or via: go install github.com/google/go-licenses@latest
command -v go-licenses >/dev/null 2>&1 || {
    echo "ERROR: go-licenses not found — run inside the project build image (docker/Dockerfile.build)"
    exit 1
}

# Check for copyleft licenses
echo "Scanning dependencies..."
if go-licenses csv ./... | grep -iE -- 'GPL|AGPL|LGPL'; then
    echo "ERROR: Copyleft license detected!"
    echo "Remove the dependency or find an alternative."
    exit 1
fi

echo "✓ All licenses are compatible"

# Generate license report
# --ignore modernc.org/mathutil: go-licenses' classifier reports this
# package's LICENSE as "Unknown" (low-confidence match on a BSD-3-Clause
# variant header) even though the file is a verbatim BSD-3-Clause text,
# manually verified and attributed in LICENSE.md. Ignoring it here only
# skips copying its license text into third_party_licenses/ — the GPL/
# AGPL/LGPL grep check above still covers it via `go-licenses csv`.
echo "Generating license report..."
go-licenses csv ./... > licenses.csv
go-licenses save ./... --save_path=third_party_licenses --ignore modernc.org/mathutil

echo "✓ License report saved to licenses.csv and third_party_licenses/"
