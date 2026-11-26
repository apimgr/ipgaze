#!/usr/bin/env bash
# @@License : WTFPL
# tests/image.sh — Validate a shipped image's runtime contract and Tor health (PART 26)
set -euo pipefail

IMAGE_TEST_ROOT="$(cd -- "${BASH_SOURCE[0]%/*}/.." && pwd)"
cd "$IMAGE_TEST_ROOT"

__idea_value() {
	awk -v key="$1:" '$1 == key { $1 = ""; sub(/^[[:space:]]+/, ""); print; exit }' IDEA.md
}

PROJECT_NAME="$(__idea_value project_name)"
PROJECT_ORG="$(__idea_value project_org)"
INTERNAL_NAME="$(__idea_value internal_name)"
IMAGE_TEST_TIMEOUT="${IMAGE_TEST_TIMEOUT:-3600}"
TOR_BOOTSTRAP_TIMEOUT="${TOR_BOOTSTRAP_TIMEOUT:-180}"
REQUIRE_OVERLAY="${REQUIRE_OVERLAY:-0}"
IMAGE_TEST_CONTAINER="${PROJECT_NAME}-$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
IMAGE_TEST_SERVER="${PROJECT_NAME}-$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
IMAGE_TEST_TEMP=""

# shellcheck disable=SC2329
__cleanup() {
	local status=$?
	set +e
	if [ -n "$IMAGE_TEST_SERVER" ]; then
		docker rm -f "$IMAGE_TEST_SERVER" >/dev/null 2>&1
	fi
	if [ -n "$IMAGE_TEST_TEMP" ] && [ -d "$IMAGE_TEST_TEMP" ] && [ ! -L "$IMAGE_TEST_TEMP" ]; then
		case "$IMAGE_TEST_TEMP" in
			"${TMPDIR:-/tmp}/${PROJECT_ORG}/${INTERNAL_NAME}-"*) rm -rf -- "$IMAGE_TEST_TEMP" ;;
		esac
	fi
	exit "$status"
}

trap __cleanup EXIT INT TERM
trap 'exit 130' INT
trap 'exit 143' TERM

if [ -z "$PROJECT_NAME" ] || [ -z "$PROJECT_ORG" ] || [ -z "$INTERNAL_NAME" ]; then
	printf 'ERROR: IDEA.md must define project_name, project_org, and internal_name\n' >&2
	exit 78
fi

if [ "$#" -ne 1 ]; then
	printf 'Usage: %s IMAGE[:TAG]\n' "${BASH_SOURCE[0]}" >&2
	exit 2
fi
IMAGE="$1"

case "$IMAGE_TEST_TIMEOUT:$TOR_BOOTSTRAP_TIMEOUT:$REQUIRE_OVERLAY" in
	*[!0-9:]*|:*|*:) printf 'ERROR: timeout values must be integers and REQUIRE_OVERLAY must be 0 or 1\n' >&2; exit 2 ;;
esac
if [ "$IMAGE_TEST_TIMEOUT" -le 0 ] || [ "$TOR_BOOTSTRAP_TIMEOUT" -le 0 ] || { [ "$REQUIRE_OVERLAY" != 0 ] && [ "$REQUIRE_OVERLAY" != 1 ]; }; then
	printf 'ERROR: timeout values must be positive and REQUIRE_OVERLAY must be 0 or 1\n' >&2
	exit 2
fi

for command_name in docker timeout curl python3; do
	if ! command -v "$command_name" >/dev/null 2>&1; then
		printf 'ERROR: %s is required for image checks\n' "$command_name" >&2
		exit 69
	fi
done

IMAGE_TEST_TEMP_BASE="${TMPDIR:-/tmp}/${PROJECT_ORG}"
mkdir -p "$IMAGE_TEST_TEMP_BASE"
IMAGE_TEST_TEMP="$(mktemp -d "$IMAGE_TEST_TEMP_BASE/${INTERNAL_NAME}-XXXXXX")"
chmod 0700 "$IMAGE_TEST_TEMP"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
	timeout -k 30 "$IMAGE_TEST_TIMEOUT" docker pull "$IMAGE"
fi
timeout -k 30 "$IMAGE_TEST_TIMEOUT" docker run --rm --no-healthcheck \
	--name "$IMAGE_TEST_CONTAINER" --memory=512m --cpus=1 --cpu-shares=256 \
	--entrypoint sh "$IMAGE" -c "for c in bash curl tor i2pd tini; do command -v \"\$c\" || exit 1; done"

timeout -k 30 "$IMAGE_TEST_TIMEOUT" docker run -d --rm --no-healthcheck \
	--name "$IMAGE_TEST_SERVER" --memory=512m --cpus=1 --cpu-shares=256 \
	-p 127.0.0.1::80 "$IMAGE"
IMAGE_TEST_PORT="$(timeout -k 30 "$IMAGE_TEST_TIMEOUT" docker port "$IMAGE_TEST_SERVER" 80/tcp | awk -F: 'NR == 1 { print $NF }')"
if [ -z "$IMAGE_TEST_PORT" ]; then
	printf 'ERROR: could not determine the image health endpoint port\n' >&2
	exit 1
fi
IMAGE_TEST_HEALTH_URL="http://127.0.0.1:${IMAGE_TEST_PORT}/server/healthz"

IMAGE_TEST_LAST_STATUS=""
IMAGE_TEST_STARTED=$SECONDS
while [ "$((SECONDS - IMAGE_TEST_STARTED))" -lt "$TOR_BOOTSTRAP_TIMEOUT" ]; do
	if curl -q -LSsf --connect-timeout 2 --max-time 5 -H 'Accept: application/json' \
		"$IMAGE_TEST_HEALTH_URL" -o "$IMAGE_TEST_TEMP/health.json"; then
		IMAGE_TEST_LAST_STATUS="$(python3 -c 'import json,sys
try:
 with open(sys.argv[1],encoding="utf-8") as response: status=json.load(response)["features"]["tor"]["status"]
 print(status if status in {"healthy","starting","unavailable","error"} else "invalid")
except (OSError,ValueError,KeyError,TypeError,json.JSONDecodeError): print("invalid")' "$IMAGE_TEST_TEMP/health.json")"
		case "$IMAGE_TEST_LAST_STATUS" in
			healthy)
				printf 'OK: image Tor health is healthy\n'
				exit 0
				;;
			starting|unavailable) ;;
			error)
				printf 'ERROR: image reports features.tor.status=error\n' >&2
				exit 1
				;;
			*)
				printf 'ERROR: /server/healthz returned invalid Tor health data\n' >&2
				exit 1
				;;
		esac
	fi
	sleep 1
done

if [ "$REQUIRE_OVERLAY" = 0 ] && { [ "$IMAGE_TEST_LAST_STATUS" = starting ] || [ "$IMAGE_TEST_LAST_STATUS" = unavailable ]; }; then
	if ! curl -q -LSsf --connect-timeout 3 --max-time 5 https://check.torproject.org/ -o /dev/null; then
		printf 'SKIP: no outbound network\n' >&2
		exit 0
	fi
fi

printf 'ERROR: Tor did not become healthy within %s seconds (last status: %s)\n' \
	"$TOR_BOOTSTRAP_TIMEOUT" "${IMAGE_TEST_LAST_STATUS:-no health response}" >&2
exit 1
