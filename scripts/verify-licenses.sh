#!/bin/bash
# scripts/verify-licenses.sh — check shipped dependencies against approved licenses (AI.md PART 2)
# ver: 2026.11.26

set -eo pipefail

VERIFY_LICENSES_SCRIPTDIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
VERIFY_LICENSES_PROJECTDIR="$(cd -- "${VERIFY_LICENSES_SCRIPTDIR}/.." && pwd)"

cd -- "${VERIFY_LICENSES_PROJECTDIR}"

echo "Checking for incompatible licenses..."

# Require go-licenses — it is pre-installed in casjaysdev/go:latest; never install inline.
command -v go-licenses >/dev/null 2>&1 || {
    echo "ERROR: go-licenses not found — run inside casjaysdev/go:latest" >&2
    exit 69
}

# Build scanner ignores from reviewed overrides. The scanner reads module and
# SPDX fields; the review note remains in the committed override file.
VERIFY_LICENSES_IGNORE=()
while read -r module _; do
    [ -n "${module}" ] || continue
    [[ "${module}" == \#* ]] && continue
    VERIFY_LICENSES_IGNORE+=(--ignore "${module}")
done < .github/license-overrides.txt

# Capture scanner output first so scanner failures fail closed under set -e.
echo "Scanning shipped dependencies..."
VERIFY_LICENSES_REPORT="$(go-licenses csv ./src/... "${VERIFY_LICENSES_IGNORE[@]}")"
VERIFY_LICENSES_REPORT="${VERIFY_LICENSES_REPORT}"$'\n'"$(awk 'NF && $1 !~ /^#/ { print $1 "," $2 }' .github/license-overrides.txt 2>/dev/null || true)"
if echo "${VERIFY_LICENSES_REPORT}" | grep -iE -- 'GPL|AGPL|LGPL'; then
    echo "ERROR: Copyleft license detected!" >&2
    echo "Remove the dependency or find an alternative." >&2
    exit 1
fi

echo "✓ All licenses are compatible"

# Keep generated reports outside the repository and remove them on exit.
echo "Generating license report..."
mkdir -p "${TMPDIR:-/tmp}/apimgr"
VERIFY_LICENSES_LICDIR="$(mktemp -d "${TMPDIR:-/tmp}/apimgr/ipgaze-XXXXXX")"
trap 'rm -rf -- "${VERIFY_LICENSES_LICDIR}"' EXIT
printf '%s\n' "${VERIFY_LICENSES_REPORT}" > "${VERIFY_LICENSES_LICDIR}/licenses.csv"
go-licenses save ./src/... "${VERIFY_LICENSES_IGNORE[@]}" --save_path="${VERIFY_LICENSES_LICDIR}/third_party_licenses"

echo "✓ License report generated in ${VERIFY_LICENSES_LICDIR}:"
cat "${VERIFY_LICENSES_LICDIR}/licenses.csv"
