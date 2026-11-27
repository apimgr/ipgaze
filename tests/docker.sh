#!/usr/bin/env bash
# @@License : WTFPL
# tests/docker.sh — Basic binary and API tests in an isolated Alpine container (PART 28)
set -eo pipefail
umask 077

DOCKER_TEST_ROOT="$(cd -- "${BASH_SOURCE[0]%/*}/.." && pwd)"
cd "$DOCKER_TEST_ROOT"

__idea_value() {
	awk -v key="$1:" '$1 == key { $1 = ""; sub(/^[[:space:]]+/, ""); print; exit }' IDEA.md
}

DOCKER_TEST_PROJECT_NAME="$(__idea_value project_name)"
DOCKER_TEST_PROJECT_ORG="$(__idea_value project_org)"
DOCKER_TEST_INTERNAL_NAME="$(__idea_value internal_name)"
DOCKER_TEST_BIN_DIR=""
DOCKER_TEST_REL_DIR=""
DOCKER_TEST_BIN_ABS=""
DOCKER_TEST_TIMEOUT="${DOCKER_TIMEOUT:-3600}"
DOCKER_TEST_MEM="${DOCKER_MEM:-2g}"
DOCKER_TEST_CPUS="${DOCKER_CPUS:-2}"
DOCKER_TEST_CPU_SHARES="${DOCKER_CPU_SHARES:-256}"
DOCKER_TEST_TOR_WAIT="${TOR_WAIT:-300}"
DOCKER_TEST_I2P_WAIT="${I2P_WAIT:-600}"
DOCKER_TEST_REQUIRE_OVERLAY="${REQUIRE_OVERLAY:-0}"
DOCKER_TEST_CONTAINER=""
DOCKER_TEST_TEMP=""

__cleanup() {
	local status=$?
	set +e
	if [ -n "$DOCKER_TEST_CONTAINER" ]; then
		docker rm -f "$DOCKER_TEST_CONTAINER" >/dev/null 2>&1
	fi
	if [ -n "$DOCKER_TEST_TEMP" ] && [ -d "$DOCKER_TEST_TEMP" ] && [ ! -L "$DOCKER_TEST_TEMP" ]; then
		case "$DOCKER_TEST_TEMP" in
			"${TMPDIR:-/tmp}/${DOCKER_TEST_PROJECT_ORG}/${DOCKER_TEST_INTERNAL_NAME}-"*) rm -rf -- "$DOCKER_TEST_TEMP" ;;
		esac
	fi
	exit "$status"
}

trap __cleanup EXIT INT TERM
trap 'exit 130' INT
trap 'exit 143' TERM

if [ -z "$DOCKER_TEST_PROJECT_NAME" ] || [ -z "$DOCKER_TEST_PROJECT_ORG" ] || [ -z "$DOCKER_TEST_INTERNAL_NAME" ]; then
	printf 'ERROR: IDEA.md must define project_name, project_org, and internal_name\n' >&2
	exit 78
fi

if [ "$#" -ne 0 ]; then
	printf 'Usage: %s\n' "${BASH_SOURCE[0]}" >&2
	exit 2
fi

if ! command -v docker >/dev/null 2>&1; then
	printf 'ERROR: docker is required for the basic tests\n' >&2
	exit 69
fi

if [ ! -f Makefile ]; then
	printf 'ERROR: Makefile is required to build the project test binaries\n' >&2
	exit 69
fi

DOCKER_TEST_TEMP_BASE="${TMPDIR:-/tmp}/${DOCKER_TEST_PROJECT_ORG}"
mkdir -p "$DOCKER_TEST_TEMP_BASE"
DOCKER_TEST_TEMP="$(mktemp -d "$DOCKER_TEST_TEMP_BASE/${DOCKER_TEST_INTERNAL_NAME}-XXXXXX")"
chmod 0700 "$DOCKER_TEST_TEMP"
DOCKER_TEST_BIN_DIR="$DOCKER_TEST_TEMP/binaries"
DOCKER_TEST_REL_DIR="$DOCKER_TEST_TEMP/releases"
DOCKER_TEST_BIN_ABS="$DOCKER_TEST_BIN_DIR"
DOCKER_TEST_CONTAINER="${DOCKER_TEST_PROJECT_NAME}-$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"

echo "Building server and client with make local..."
make local BINDIR="$DOCKER_TEST_BIN_DIR" RELDIR="$DOCKER_TEST_REL_DIR"

if [ ! -x "$DOCKER_TEST_BIN_DIR/$DOCKER_TEST_PROJECT_NAME" ]; then
	printf 'ERROR: build did not produce the server binary\n' >&2
	exit 1
fi
if [ -d src/client ] && [ ! -x "$DOCKER_TEST_BIN_DIR/$DOCKER_TEST_PROJECT_NAME-cli" ]; then
	printf 'ERROR: build did not produce the client binary\n' >&2
	exit 1
fi

mkdir -p "$DOCKER_TEST_TEMP/config" "$DOCKER_TEST_TEMP/data" \
	"$DOCKER_TEST_TEMP/cache" "$DOCKER_TEST_TEMP/logs" "$DOCKER_TEST_TEMP/backup"
chmod 0700 "$DOCKER_TEST_TEMP/config" "$DOCKER_TEST_TEMP/data" \
	"$DOCKER_TEST_TEMP/cache" "$DOCKER_TEST_TEMP/logs" "$DOCKER_TEST_TEMP/backup"

echo "Running binary and API checks in Alpine..."
timeout -k 30 "$DOCKER_TEST_TIMEOUT" docker run --rm -i --no-healthcheck \
	--name "$DOCKER_TEST_CONTAINER" \
	--memory="$DOCKER_TEST_MEM" --cpus="$DOCKER_TEST_CPUS" --cpu-shares="$DOCKER_TEST_CPU_SHARES" \
	-v "$DOCKER_TEST_BIN_ABS:/app:ro" \
	-v "$DOCKER_TEST_TEMP/config:/testdata/config" \
	-v "$DOCKER_TEST_TEMP/data:/testdata/data" \
	-v "$DOCKER_TEST_TEMP/cache:/testdata/cache" \
	-v "$DOCKER_TEST_TEMP/logs:/testdata/logs" \
	-v "$DOCKER_TEST_TEMP/backup:/testdata/backup" \
	-e DATABASE_DIR=/testdata/data/db/sqlite \
	-e "DOCKER_TEST_PROJECT_NAME=$DOCKER_TEST_PROJECT_NAME" \
	-e "DOCKER_TEST_INTERNAL_NAME=$DOCKER_TEST_INTERNAL_NAME" \
	-e "DOCKER_TEST_TOR_WAIT=$DOCKER_TEST_TOR_WAIT" \
	-e "DOCKER_TEST_I2P_WAIT=$DOCKER_TEST_I2P_WAIT" \
    -e "DOCKER_TEST_REQUIRE_OVERLAY=$DOCKER_TEST_REQUIRE_OVERLAY" \
	alpine:latest sh -s <<'CONTAINER_SCRIPT'
set -e
umask 077

DOCKER_TEST_FAILURES=0
DOCKER_TEST_URL="http://127.0.0.1:64580"
DOCKER_TEST_ROOT=/testdata
DOCKER_TEST_RESPONSE="$DOCKER_TEST_ROOT/response.json"
DOCKER_TEST_SERVER_PID=""
DOCKER_TEST_SERVER="$DOCKER_TEST_ROOT/bin/$DOCKER_TEST_PROJECT_NAME"
DOCKER_TEST_CLIENT="$DOCKER_TEST_ROOT/bin/$DOCKER_TEST_PROJECT_NAME-cli"

__fail() {
	printf 'FAILED: %s\n' "$1" >&2
	DOCKER_TEST_FAILURES=$((DOCKER_TEST_FAILURES + 1))
}

__check() {
	local description="$1"
	shift
	if "$@"; then
		printf 'PASS: %s\n' "$description"
	else
		__fail "$description"
	fi
}

__request() {
	local status
	status="$(curl -q -sS --max-time 20 -o "$DOCKER_TEST_RESPONSE" -w '%{http_code}' "$@")" || return 1
	DOCKER_TEST_LAST_STATUS="$status"
}

__expect_status() {
	local expected="$1"
	shift
	__request "$@" || return 1
	if [ "$DOCKER_TEST_LAST_STATUS" = "$expected" ]; then
		return 0
	fi
	printf 'Expected HTTP %s, got %s for %s\n' "$expected" "$DOCKER_TEST_LAST_STATUS" "$1" >&2
	if jq -e 'type == "object" and has("status")' "$DOCKER_TEST_RESPONSE" >/dev/null 2>&1; then
		jq -c '{status, checks}' "$DOCKER_TEST_RESPONSE" >&2
	fi
	return 1
}

__body_has() {
	local pattern="$1"
	shift
	__request "$@" || return 1
	grep -Ei -- "$pattern" "$DOCKER_TEST_RESPONSE" >/dev/null
}

__content_type_is() {
	local expected="$1" content_type
	shift
	content_type="$(curl -q -sS --max-time 20 -o "$DOCKER_TEST_RESPONSE" -w '%{content_type}' "$@")" || return 1
	case "$content_type" in
		"$expected"*) return 0 ;;
		*) return 1 ;;
	esac
}

__health_json() {
	curl -q -sS --max-time 20 -H 'Accept: application/json' \
		-o "$DOCKER_TEST_ROOT/health.json" "$DOCKER_TEST_URL/server/healthz"
}

__health_value() {
	local expression="$1"
	__health_json >/dev/null 2>&1 || return 1
	jq -er "$expression" "$DOCKER_TEST_ROOT/health.json"
}

__issue_owner_token() {
	local status
	status="$(curl -q -sS --max-time 20 -X POST -H 'Content-Type: application/json' \
		-o "$DOCKER_TEST_RESPONSE" -w '%{http_code}' \
		"$DOCKER_TEST_URL/api/v1/server/preferences/tokens/primary")" || return 1
	if [ "$status" != 201 ]; then
		printf 'Owner-token API returned HTTP %s (%s)\n' "$status" \
			"$(jq -r '[(.error // "unknown"), (.message // "no message")] | join(": ")' "$DOCKER_TEST_RESPONSE" 2>/dev/null || printf 'non-JSON response')" >&2
		grep -F 'owner token issuance failed' "$DOCKER_TEST_ROOT/server.log" | tail -n1 >&2 || true
		return 1
	fi
	DOCKER_TEST_OWNER_TOKEN="$(jq -er '.data.owner_token' "$DOCKER_TEST_RESPONSE")"
	[ -n "$DOCKER_TEST_OWNER_TOKEN" ]
}

__create_linked_token() {
	local primary_token="$1" status
	status="$(curl -q -sS --max-time 20 -X POST \
		-H "Authorization: Bearer $primary_token" \
		-H 'Content-Type: application/json' \
	-d '{"name":"docker-test","expires":"never"}' \
		-o "$DOCKER_TEST_RESPONSE" -w '%{http_code}' \
		"$DOCKER_TEST_URL/api/v1/server/preferences/tokens")" || return 1
	[ "$status" = 201 ] || return 1
	DOCKER_TEST_LINKED_TOKEN="$(jq -er '.data.linked_token' "$DOCKER_TEST_RESPONSE")"
	[ -n "$DOCKER_TEST_LINKED_TOKEN" ]
}

__auth_kind_is() {
	local expected_kind="$1" token="$2"
	if [ "$expected_kind" = owner ]; then
		local status
		status="$(curl -q -sS --max-time 20 -H "Authorization: Bearer $token" \
			-o "$DOCKER_TEST_RESPONSE" -w '%{http_code}' "$DOCKER_TEST_URL/api/v1/server/preferences/tokens")" || return 1
		if [ "$status" != 200 ] || ! jq -e '.ok == true and .data.primary.kind == "primary" and (.data.linked | type) == "array"' "$DOCKER_TEST_RESPONSE" >/dev/null; then
			printf 'Owner token list returned HTTP %s: %s\n' "$status" \
				"$(jq -c '{ok, error, data: {primary: .data.primary, linked_count: (.data.linked | length), max_linked: .data.max_linked}}' "$DOCKER_TEST_RESPONSE" 2>/dev/null || printf 'non-JSON response')" >&2
			return 1
		fi
		return
	fi
	curl -q -sS --max-time 20 -H "Authorization: Bearer $token" \
		-o "$DOCKER_TEST_RESPONSE" "$DOCKER_TEST_URL/api/v1/server/auth/check" || return 1
	jq -e --arg expected "$expected_kind" '.data.kind == $expected' "$DOCKER_TEST_RESPONSE" >/dev/null
}

__valid_tor_hostname() {
	local hostname="$1" label
	case "$hostname" in
		*.onion) label="${hostname%.onion}" ;;
		*) return 1 ;;
	esac
	[ "${#label}" -eq 56 ] || return 1
	case "$label" in *[!a-z2-7]*) return 1 ;; esac
}

__valid_i2p_hostname() {
	local hostname="$1" label
	case "$hostname" in
		*.b32.i2p) label="${hostname%.b32.i2p}" ;;
		*) return 1 ;;
	esac
	[ "${#label}" -eq 52 ] || return 1
	case "$label" in *[!a-z2-7]*) return 1 ;; esac
}

__rename_check() {
	"$1" --help >"$DOCKER_TEST_ROOT/rename-help.out" 2>&1 || return 1
	grep -F -- "$2" "$DOCKER_TEST_ROOT/rename-help.out" >/dev/null
}

__has_nonempty_file() {
	[ -n "$(find "$1" -type f -size +0 -print -quit)" ]
}

__stop_server() {
	if [ -n "$DOCKER_TEST_SERVER_PID" ]; then
		kill -TERM "$DOCKER_TEST_SERVER_PID" 2>/dev/null || true
		wait "$DOCKER_TEST_SERVER_PID" 2>/dev/null || true
		DOCKER_TEST_SERVER_PID=""
	fi
}

__container_cleanup() {
	local status=$?
	set +e
	__stop_server
	exit "$status"
}

trap __container_cleanup EXIT INT TERM
trap 'exit 130' INT
trap 'exit 143' TERM

apk add --no-cache curl bash file jq tor i2pd tzdata ca-certificates >/dev/null
mkdir -p "$DOCKER_TEST_ROOT/bin" "$DOCKER_TEST_ROOT/config" "$DOCKER_TEST_ROOT/data" \
	"$DOCKER_TEST_ROOT/cache" "$DOCKER_TEST_ROOT/logs" "$DOCKER_TEST_ROOT/backup"
chmod 0700 "$DOCKER_TEST_ROOT/config" "$DOCKER_TEST_ROOT/data"
cp "/app/$DOCKER_TEST_PROJECT_NAME" "$DOCKER_TEST_SERVER"
chmod 0700 "$DOCKER_TEST_SERVER"
if [ -f "/app/$DOCKER_TEST_PROJECT_NAME-cli" ]; then
	cp "/app/$DOCKER_TEST_PROJECT_NAME-cli" "$DOCKER_TEST_CLIENT"
	chmod 0700 "$DOCKER_TEST_CLIENT"
fi

printf 'server:\n  cli:\n    binary_download:\n      require_auth: true\n' >"$DOCKER_TEST_ROOT/config/server.yml"
chmod 0600 "$DOCKER_TEST_ROOT/config/server.yml"
__check 'server.yml has private permissions' test "$(stat -c %a "$DOCKER_TEST_ROOT/config/server.yml")" = 600
if [ -x "$DOCKER_TEST_CLIENT" ]; then
	mkdir -p "$DOCKER_TEST_ROOT/data/cli"
	DOCKER_TEST_CLI_RELEASE="$DOCKER_TEST_ROOT/data/cli/$DOCKER_TEST_PROJECT_NAME-cli-linux-amd64"
	cp "$DOCKER_TEST_CLIENT" "$DOCKER_TEST_CLI_RELEASE"
	chmod 0600 "$DOCKER_TEST_CLI_RELEASE"
	printf 'integration-test\n' >"$DOCKER_TEST_ROOT/data/cli/version.txt"
	(cd "$DOCKER_TEST_ROOT/data/cli" && sha256sum "$(basename "$DOCKER_TEST_CLI_RELEASE")" >sha256.txt)
	chmod 0600 "$DOCKER_TEST_ROOT/data/cli/version.txt" "$DOCKER_TEST_ROOT/data/cli/sha256.txt"
fi

echo '=== Binary checks ==='
__check 'server --version' "$DOCKER_TEST_SERVER" --version
__check 'server --help' "$DOCKER_TEST_SERVER" --help
__check 'server binary metadata' file "$DOCKER_TEST_SERVER"
if [ -x "$DOCKER_TEST_CLIENT" ]; then
	__check 'client --version' "$DOCKER_TEST_CLIENT" --version
	__check 'client --help' "$DOCKER_TEST_CLIENT" --help
fi

cp "$DOCKER_TEST_SERVER" "$DOCKER_TEST_ROOT/bin/renamed-server"
chmod 0700 "$DOCKER_TEST_ROOT/bin/renamed-server"
__check 'renamed server reports its current name' __rename_check "$DOCKER_TEST_ROOT/bin/renamed-server" renamed-server
if [ -x "$DOCKER_TEST_CLIENT" ]; then
	cp "$DOCKER_TEST_CLIENT" "$DOCKER_TEST_ROOT/bin/renamed-cli"
	chmod 0700 "$DOCKER_TEST_ROOT/bin/renamed-cli"
	__check 'renamed client reports its current name' __rename_check "$DOCKER_TEST_ROOT/bin/renamed-cli" renamed-cli
fi

echo '=== Server startup ==='
"$DOCKER_TEST_SERVER" --config "$DOCKER_TEST_ROOT/config" --data "$DOCKER_TEST_ROOT/data" \
	--cache "$DOCKER_TEST_ROOT/cache" --log "$DOCKER_TEST_ROOT/logs" --backup "$DOCKER_TEST_ROOT/backup" \
	--port 64580 --debug >"$DOCKER_TEST_ROOT/server.log" 2>&1 &
DOCKER_TEST_SERVER_PID=$!
DOCKER_TEST_READY=0
for attempt in $(seq 1 60); do
	if curl -q -sS --max-time 2 "$DOCKER_TEST_URL/server/healthz" >/dev/null 2>&1; then
		DOCKER_TEST_READY=1
		break
	fi
	sleep 1
done
__check 'server becomes healthy' test "$DOCKER_TEST_READY" = 1

echo '=== Health, metadata, and content negotiation ==='
__check 'health route' __expect_status 200 "$DOCKER_TEST_URL/server/healthz"
__check 'versioned health route' __expect_status 200 "$DOCKER_TEST_URL/api/v1/server/healthz"
__check 'plain-text health extension' __content_type_is text/plain "$DOCKER_TEST_URL/api/v1/server/healthz.txt"
__check 'JSON Accept on API health route' __content_type_is application/json -H 'Accept: application/json' "$DOCKER_TEST_URL/api/v1/server/healthz"
__check 'text Accept on API health route' __content_type_is text/plain -H 'Accept: text/plain' "$DOCKER_TEST_URL/api/v1/server/healthz"
__check 'robots.txt' __body_has 'user-agent' "$DOCKER_TEST_URL/robots.txt"
__check 'well-known security.txt' __body_has 'contact' "$DOCKER_TEST_URL/.well-known/security.txt"
__check 'legacy security.txt is absent' __expect_status 404 "$DOCKER_TEST_URL/security.txt"
__check 'autodiscover response' sh -c 'curl -q -sS --max-time 20 "$1/api/autodiscover" -o "$2" && jq -e ".ok == true and (.data.name | length > 0) and (.data.version | length > 0) and (.data.api.current_version | length > 0) and (.data.cli_min_version != null)" "$2" >/dev/null' sh "$DOCKER_TEST_URL" "$DOCKER_TEST_RESPONSE"

__check 'root HTML negotiation' __content_type_is text/html -H 'Accept: text/html' "$DOCKER_TEST_URL/"
__check 'root plain-text negotiation' sh -c 'curl -q -sS --max-time 20 -H "Accept: text/plain" "$1/" -o "$2" && ! grep -Eiq "<html" "$2"' sh "$DOCKER_TEST_URL" "$DOCKER_TEST_RESPONSE"
__check 'root JSON negotiation' sh -c 'curl -q -sS --max-time 20 -H "Accept: application/json" "$1/" -o "$2" && jq -e ".ip != null" "$2" >/dev/null' sh "$DOCKER_TEST_URL" "$DOCKER_TEST_RESPONSE"
__check 'curl user-agent gets plain text' sh -c 'curl -q -sS --max-time 20 -A "curl/8.0.0" "$1/" -o "$2" && ! grep -Eiq "<html" "$2"' sh "$DOCKER_TEST_URL" "$DOCKER_TEST_RESPONSE"
__check 'CLI user-agent gets plain text' sh -c 'curl -q -sS --max-time 20 -A "ipgaze-cli/1.0.0" "$1/" -o "$2" && ! grep -Eiq "<html" "$2"' sh "$DOCKER_TEST_URL" "$DOCKER_TEST_RESPONSE"

echo '=== Project lookup routes from IDEA.md ==='
for route in / /json /ip /8.8.8.8 /port/80 /api/v1 /api/v1/json /api/v1/ip \
	/api/v1/ip/8.8.8.8 /api/v1/port/80; do
	__check "GET $route" __expect_status 200 "$DOCKER_TEST_URL$route"
done
DOCKER_TEST_GEOIP_COUNTRY_STATUS="$(__health_value '.checks.geoip_country' 2>/dev/null || true)"
if [ "$DOCKER_TEST_GEOIP_COUNTRY_STATUS" = error ]; then
	for route in /country /country-iso /city /coordinates /asn /asn-org \
		/api/v1/country /api/v1/country-iso /api/v1/city /api/v1/coordinates /api/v1/asn /api/v1/asn-org; do
		__check "GET $route without GeoIP data" __expect_status 404 "$DOCKER_TEST_URL$route"
	done
else
	for route in /country /country-iso /city /coordinates /asn /asn-org \
		/api/v1/country /api/v1/country-iso /api/v1/city /api/v1/coordinates /api/v1/asn /api/v1/asn-org; do
		__check "GET $route" __expect_status 200 "$DOCKER_TEST_URL$route"
	done
fi
for route in /api/v1/server/about /api/v1/server/help /api/v1/server/privacy /api/v1/server/terms \
	/api/v1/server/contact /api/v1/server/security /api/v1/server/dpo \
	/api/v1/server/security/policy /api/v1/server/security/thanks; do
	__check "GET $route" __expect_status 200 "$DOCKER_TEST_URL$route"
done

echo '=== Operator-token route checks ==='
DOCKER_TEST_OPERATOR_TOKEN="$(awk '$1 == "server:" { in_server=1; next } in_server && /^[^[:space:]]/ { exit } in_server && $1 == "token:" { print $2; exit }' "$DOCKER_TEST_ROOT/config/secrets.yml" 2>/dev/null || true)"
DOCKER_TEST_OWNER_TOKEN=""
DOCKER_TEST_LINKED_TOKEN=""
if [ -n "$DOCKER_TEST_OPERATOR_TOKEN" ]; then
	__check 'secrets.yml has private permissions' test "$(stat -c %a "$DOCKER_TEST_ROOT/config/secrets.yml")" = 600
	__check 'issue owner token' __issue_owner_token
	if [ -n "$DOCKER_TEST_OWNER_TOKEN" ]; then
		__check 'operator route rejects missing credentials' __expect_status 401 "$DOCKER_TEST_URL/cli/binaries/$DOCKER_TEST_PROJECT_NAME-cli-linux-amd64"
		__check 'operator route rejects wrong credentials' __expect_status 401 -H 'Authorization: Bearer invalid-test-token' "$DOCKER_TEST_URL/cli/binaries/$DOCKER_TEST_PROJECT_NAME-cli-linux-amd64"
		__check 'operator route rejects owner credentials' __expect_status 401 -H "Authorization: Bearer $DOCKER_TEST_OWNER_TOKEN" "$DOCKER_TEST_URL/cli/binaries/$DOCKER_TEST_PROJECT_NAME-cli-linux-amd64"
		__check 'operator route accepts server.token' __expect_status 200 -H "Authorization: Bearer $DOCKER_TEST_OPERATOR_TOKEN" "$DOCKER_TEST_URL/cli/binaries/$DOCKER_TEST_PROJECT_NAME-cli-linux-amd64"
		__check 'operator route ignores query-string token' __expect_status 401 -G --data-urlencode "token=$DOCKER_TEST_OPERATOR_TOKEN" "$DOCKER_TEST_URL/cli/binaries/$DOCKER_TEST_PROJECT_NAME-cli-linux-amd64"
		__check 'auth check identifies operator token' __auth_kind_is operator "$DOCKER_TEST_OPERATOR_TOKEN"
		if [ -n "$DOCKER_TEST_OWNER_TOKEN" ]; then
			__check 'owner token is accepted as owner identity' __auth_kind_is owner "$DOCKER_TEST_OWNER_TOKEN"
		fi
		__check 'create linked API token' __create_linked_token "$DOCKER_TEST_OWNER_TOKEN"
	else
		__fail 'owner-token issuance did not return a token'
	fi
else
	__fail 'server.token was not generated in secrets.yml'
fi

echo '=== Client functionality ==='
if [ -x "$DOCKER_TEST_CLIENT" ]; then
	if [ -n "$DOCKER_TEST_LINKED_TOKEN" ]; then
		__check 'client performs an authenticated lookup' "$DOCKER_TEST_CLIENT" --server "$DOCKER_TEST_URL" --token "$DOCKER_TEST_LINKED_TOKEN" --output json
		__check 'client performs a specific-IP lookup' "$DOCKER_TEST_CLIENT" --server "$DOCKER_TEST_URL" --token "$DOCKER_TEST_LINKED_TOKEN" --field ip 8.8.8.8
		__check 'owner API rejects an invalid token' __expect_status 401 -H 'Authorization: Bearer invalid-test-token' "$DOCKER_TEST_URL/api/v1/server/preferences/tokens"
	else
		__fail 'client authenticated lookup was skipped because linked-token creation failed'
	fi
else
	printf 'SKIP: client binary is not part of this project\n' >&2
fi

echo '=== Tor and I2P health ==='
__check 'Tor binary installed' command -v tor
__check 'I2P binary installed' command -v i2pd
__check 'health response is valid JSON' __health_json
__check 'Tor is enabled in the application container' test "$(__health_value '.features.tor.enabled' 2>/dev/null || true)" = true
case "$(__health_value '.features.tor.status' 2>/dev/null || true)" in
	disabled|starting|healthy|unavailable) printf 'PASS: Tor status uses a contract value\n' ;;
	*) __fail 'Tor status uses a contract value' ;;
esac
DOCKER_TEST_TOR_STATUS="$(__health_value '.features.tor.status' 2>/dev/null || true)"
if [ "$DOCKER_TEST_TOR_STATUS" != healthy ]; then
	DOCKER_TEST_ATTEMPT=0
	while [ "$DOCKER_TEST_ATTEMPT" -lt "$DOCKER_TEST_TOR_WAIT" ]; do
		[ "$(__health_value '.features.tor.status' 2>/dev/null || true)" = healthy ] && break
		DOCKER_TEST_ATTEMPT=$((DOCKER_TEST_ATTEMPT + 1))
		sleep 1
	done
	DOCKER_TEST_TOR_STATUS="$(__health_value '.features.tor.status' 2>/dev/null || true)"
fi
if [ "$DOCKER_TEST_TOR_STATUS" = healthy ]; then
	__check 'Tor hostname is a v3 onion address' __valid_tor_hostname "$(__health_value '.features.tor.hostname' 2>/dev/null || true)"
	__check 'Tor check is healthy' test "$(jq -r '.checks.tor' "$DOCKER_TEST_ROOT/health.json" 2>/dev/null || true)" = ok
	for path in "$DOCKER_TEST_ROOT/config/tor" "$DOCKER_TEST_ROOT/data/tor" "$DOCKER_TEST_ROOT/data/tor/site"; do
		__check "private Tor directory permissions: $path" test "$(stat -c %a "$path" 2>/dev/null || true)" = 700
	done
elif [ "$DOCKER_TEST_REQUIRE_OVERLAY" = 1 ]; then
	__fail "Tor did not become healthy within ${DOCKER_TEST_TOR_WAIT}s"
else
	printf 'SKIP: Tor did not bootstrap within %ss (outbound network may be unavailable)\n' "$DOCKER_TEST_TOR_WAIT" >&2
	case "$DOCKER_TEST_TOR_STATUS" in
		starting) __check 'starting Tor maps to checks.tor=ok' test "$(jq -r '.checks.tor' "$DOCKER_TEST_ROOT/health.json" 2>/dev/null || true)" = ok ;;
		unavailable) __check 'unavailable Tor maps to checks.tor=degraded' test "$(jq -r '.checks.tor' "$DOCKER_TEST_ROOT/health.json" 2>/dev/null || true)" = degraded ;;
		*) __fail 'Tor remains enabled when bootstrap is unavailable' ;;
	esac
fi

__check 'I2P is enabled in the application container' test "$( __health_value '.features.i2p.enabled' 2>/dev/null || true)" = true
DOCKER_TEST_I2P_PROVIDER="$( __health_value '.features.i2p.provider' 2>/dev/null || true)"
DOCKER_TEST_ATTEMPT=0
while [ "$DOCKER_TEST_I2P_PROVIDER" != i2pd ] && [ "$DOCKER_TEST_ATTEMPT" -lt 30 ]; do
	DOCKER_TEST_ATTEMPT=$((DOCKER_TEST_ATTEMPT + 1))
	sleep 1
	DOCKER_TEST_I2P_PROVIDER="$( __health_value '.features.i2p.provider' 2>/dev/null || true)"
done
__check 'I2P provider is i2pd' test "$( __health_value '.features.i2p.provider' 2>/dev/null || true)" = i2pd
DOCKER_TEST_I2P_STATUS="$(__health_value '.features.i2p.status' 2>/dev/null || true)"
DOCKER_TEST_ATTEMPT=0
while [ "$DOCKER_TEST_I2P_STATUS" != healthy ] && [ "$DOCKER_TEST_ATTEMPT" -lt "$DOCKER_TEST_I2P_WAIT" ]; do
	DOCKER_TEST_ATTEMPT=$((DOCKER_TEST_ATTEMPT + 1))
	sleep 1
	DOCKER_TEST_I2P_STATUS="$(__health_value '.features.i2p.status' 2>/dev/null || true)"
done
if [ "$DOCKER_TEST_I2P_STATUS" = healthy ]; then
	__check 'I2P hostname is a b32.i2p address' __valid_i2p_hostname "$(__health_value '.features.i2p.hostname' 2>/dev/null || true)"
	__check 'I2P check is healthy' test "$(jq -r '.checks.i2p' "$DOCKER_TEST_ROOT/health.json" 2>/dev/null || true)" = ok
	__check 'I2P destination key is persisted' __has_nonempty_file "$DOCKER_TEST_ROOT/data/i2p/site"
elif [ "$DOCKER_TEST_REQUIRE_OVERLAY" = 1 ]; then
	__fail "I2P did not become healthy within ${DOCKER_TEST_I2P_WAIT}s"
else
	printf 'SKIP: I2P did not build tunnels within %ss (outbound network may be unavailable)\n' "$DOCKER_TEST_I2P_WAIT" >&2
	case "$DOCKER_TEST_I2P_STATUS" in
		starting|unavailable) : ;;
		*) __fail 'I2P reports a valid enabled-network status' ;;
	esac
fi

__stop_server
if [ "$DOCKER_TEST_FAILURES" -gt 0 ]; then
	printf 'ERROR: %s check(s) failed\n' "$DOCKER_TEST_FAILURES" >&2
	grep -Ei 'failed to open .* database|owner token issuance failed|I2P eepsite unavailable' "$DOCKER_TEST_ROOT/server.log" | tail -n 30 >&2 || true
	exit 1
fi
echo 'All Docker tests passed.'
CONTAINER_SCRIPT

echo 'Docker tests completed successfully.'
