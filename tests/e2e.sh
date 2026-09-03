#!/usr/bin/env bash
# @@License : WTFPL
# tests/e2e.sh — Browser E2E beta testing, all three tiers (PART 28)
set -eo pipefail

# Everything below runs in Docker: a chromedp/headless-shell sidecar provides
# Chromium over CDP and casjaysdev/go:latest runs `go test -tags e2e`. The two
# containers share one network namespace so 127.0.0.1 means the same thing to
# the test process and to the browser.

IPGAZE_E2E_ROOT="${IPGAZE_E2E_ROOT:-$(cd -- "${BASH_SOURCE[0]%/*}/.." && pwd)}"
IPGAZE_E2E_PROJECT="${IPGAZE_E2E_ROOT##*/}"
IPGAZE_E2E_GO_IMAGE="${IPGAZE_E2E_GO_IMAGE:-casjaysdev/go:latest}"
IPGAZE_E2E_BROWSER_IMAGE="${IPGAZE_E2E_BROWSER_IMAGE:-chromedp/headless-shell:latest}"
IPGAZE_E2E_GO_CACHE="${IPGAZE_E2E_GO_CACHE:-$HOME/go/pkg/mod}"
IPGAZE_E2E_GO_BUILD="${IPGAZE_E2E_GO_BUILD:-$HOME/.cache/go-build/${IPGAZE_E2E_PROJECT}}"
IPGAZE_E2E_BINARY="${IPGAZE_E2E_BINARY:-binaries/${IPGAZE_E2E_PROJECT}}"
IPGAZE_E2E_TIMEOUT="${IPGAZE_E2E_TIMEOUT:-20m}"
IPGAZE_E2E_SKIP_BUILD="${IPGAZE_E2E_SKIP_BUILD:-false}"
IPGAZE_E2E_VERBOSE="${IPGAZE_E2E_VERBOSE:-true}"
IPGAZE_E2E_RUN="${IPGAZE_E2E_RUN:-}"

IPGAZE_E2E_TAG="$(od -An -tx1 -N4 /dev/urandom | tr -d ' \n')"
IPGAZE_E2E_BROWSER_CONTAINER="${IPGAZE_E2E_PROJECT}-e2e-browser-${IPGAZE_E2E_TAG}"
IPGAZE_E2E_TEST_CONTAINER="${IPGAZE_E2E_PROJECT}-e2e-tests-${IPGAZE_E2E_TAG}"
IPGAZE_E2E_BUILD_CONTAINER="${IPGAZE_E2E_PROJECT}-e2e-build-${IPGAZE_E2E_TAG}"
IPGAZE_E2E_ARTIFACTS=""
IPGAZE_E2E_BROWSER_HOST_PORT=""

__log() {
  echo "==> $*"
}

__die() {
  echo "ERROR: $*" >&2
  exit 1
}

__usage() {
  cat <<EOF
Usage: tests/e2e.sh [options]

Runs the three-tier browser E2E suite (AI.md PART 28) inside Docker.

Options:
  -h, --help        Show this help and exit
  -s, --skip-build  Reuse the existing ${IPGAZE_E2E_BINARY} instead of rebuilding
  -q, --quiet       Do not pass -v to go test
  -r, --run REGEX   Only run tests whose name matches REGEX

Environment overrides:
  IPGAZE_E2E_GO_IMAGE       Go toolchain image (default ${IPGAZE_E2E_GO_IMAGE})
  IPGAZE_E2E_BROWSER_IMAGE  Chromium image (default ${IPGAZE_E2E_BROWSER_IMAGE})
  IPGAZE_E2E_TIMEOUT        go test timeout (default ${IPGAZE_E2E_TIMEOUT})
EOF
}

# __cleanup removes every container this script started. It runs on success,
# on failure and on interrupt, so nothing is ever left behind.
__cleanup() {
  local status=$?
  set +e
  docker rm -f "$IPGAZE_E2E_BUILD_CONTAINER" >/dev/null 2>&1
  docker rm -f "$IPGAZE_E2E_TEST_CONTAINER" >/dev/null 2>&1
  if docker inspect "$IPGAZE_E2E_BROWSER_CONTAINER" >/dev/null 2>&1; then
    if [ -n "$IPGAZE_E2E_ARTIFACTS" ]; then
      docker logs "$IPGAZE_E2E_BROWSER_CONTAINER" >"${IPGAZE_E2E_ARTIFACTS}/chromium.log" 2>&1
    fi
    docker rm -f "$IPGAZE_E2E_BROWSER_CONTAINER" >/dev/null 2>&1
    __log "Removed Chromium sidecar ${IPGAZE_E2E_BROWSER_CONTAINER}"
  fi
  if [ -n "$IPGAZE_E2E_ARTIFACTS" ]; then
    __log "Artifacts and server log: ${IPGAZE_E2E_ARTIFACTS}"
  fi
  exit "$status"
}

# __wait_for_port polls a TCP port on the host until it accepts a connection.
__wait_for_port() {
  local port="$1" attempt=0
  while [ "$attempt" -lt 60 ]; do
    if (exec 3<>"/dev/tcp/127.0.0.1/${port}") 2>/dev/null; then
      exec 3>&- 2>/dev/null
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 1
  done
  return 1
}

# __build compiles the server the suite drives. The E2E harness launches this
# binary itself so the tests exercise the real application, not a test double.
__build() {
  if [ "$IPGAZE_E2E_SKIP_BUILD" = "true" ] && [ -x "${IPGAZE_E2E_ROOT}/${IPGAZE_E2E_BINARY}" ]; then
    __log "Reusing existing ${IPGAZE_E2E_BINARY}"
    return 0
  fi
  __log "Building ${IPGAZE_E2E_BINARY} in ${IPGAZE_E2E_GO_IMAGE}"
  docker run --rm \
    --name "$IPGAZE_E2E_BUILD_CONTAINER" \
    -v "${IPGAZE_E2E_ROOT}:/app" \
    -v "${IPGAZE_E2E_GO_CACHE}:/usr/local/share/go/pkg/mod" \
    -v "${IPGAZE_E2E_GO_BUILD}:/usr/local/share/go/cache" \
    -w /app \
    -e CGO_ENABLED=0 \
    -e GOFLAGS=-buildvcs=false \
    "$IPGAZE_E2E_GO_IMAGE" \
    go build -buildvcs=false -trimpath -o "/app/${IPGAZE_E2E_BINARY}" ./src
}

# __start_browser launches the Chromium sidecar and waits for its DevTools
# endpoint to answer before any test opens a tab. The port is published on
# loopback purely so this script can probe readiness from the host. The image
# is started with its own default command on purpose: its entrypoint runs
# Chromium on 9223 behind a socat proxy on 9222, and overriding the port flags
# breaks that proxy.
__start_browser() {
  __log "Starting Chromium sidecar ${IPGAZE_E2E_BROWSER_CONTAINER}"
  docker run -d --rm \
    --name "$IPGAZE_E2E_BROWSER_CONTAINER" \
    --shm-size=1g \
    -p 127.0.0.1::9222 \
    "$IPGAZE_E2E_BROWSER_IMAGE" >/dev/null

  IPGAZE_E2E_BROWSER_HOST_PORT="$(docker port "$IPGAZE_E2E_BROWSER_CONTAINER" 9222/tcp | head -n1)"
  IPGAZE_E2E_BROWSER_HOST_PORT="${IPGAZE_E2E_BROWSER_HOST_PORT##*:}"
  [ -n "$IPGAZE_E2E_BROWSER_HOST_PORT" ] || __die "Chromium sidecar published no DevTools port"

  if __wait_for_port "$IPGAZE_E2E_BROWSER_HOST_PORT"; then
    __log "Chromium DevTools endpoint is up on host port ${IPGAZE_E2E_BROWSER_HOST_PORT}"
    return 0
  fi
  __die "Chromium sidecar never opened its DevTools port"
}

# __run_tests executes the tagged suite in the Go image, joined to the
# browser's network namespace so both see the same 127.0.0.1.
__run_tests() {
  local args=(go test -tags e2e -count=1 -timeout "$IPGAZE_E2E_TIMEOUT")
  if [ "$IPGAZE_E2E_VERBOSE" = "true" ]; then
    args+=(-v)
  fi
  if [ -n "$IPGAZE_E2E_RUN" ]; then
    args+=(-run "$IPGAZE_E2E_RUN")
  fi
  args+=(./tests/e2e/...)

  __log "Running the three-tier suite"
  docker run --rm \
    --name "$IPGAZE_E2E_TEST_CONTAINER" \
    --network "container:${IPGAZE_E2E_BROWSER_CONTAINER}" \
    -v "${IPGAZE_E2E_ROOT}:/app" \
    -v "${IPGAZE_E2E_GO_CACHE}:/usr/local/share/go/pkg/mod" \
    -v "${IPGAZE_E2E_GO_BUILD}:/usr/local/share/go/cache" \
    -v "${IPGAZE_E2E_ARTIFACTS}:/e2e-tmp" \
    -w /app \
    -e CGO_ENABLED=0 \
    -e GOFLAGS=-buildvcs=false \
    -e NO_COLOR=1 \
    -e "IPGAZE_E2E_BINARY=/app/${IPGAZE_E2E_BINARY}" \
    -e "IPGAZE_E2E_BROWSER=http://127.0.0.1:9222" \
    -e IPGAZE_E2E_TMPDIR=/e2e-tmp \
    "$IPGAZE_E2E_GO_IMAGE" \
    "${args[@]}"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    -h | --help)
      __usage
      exit 0
      ;;
    -s | --skip-build)
      IPGAZE_E2E_SKIP_BUILD=true
      shift
      ;;
    -q | --quiet)
      IPGAZE_E2E_VERBOSE=false
      shift
      ;;
    -r | --run)
      [ -n "$2" ] || __die "--run needs a regex"
      IPGAZE_E2E_RUN="$2"
      shift 2
      ;;
    *)
      __usage >&2
      __die "unknown option: $1"
      ;;
  esac
done

command -v docker >/dev/null 2>&1 || __die "docker is required — every test runs in a container"
[ -d "${IPGAZE_E2E_ROOT}/tests/e2e" ] || __die "tests/e2e is missing from ${IPGAZE_E2E_ROOT}"

mkdir -p "$IPGAZE_E2E_GO_CACHE" "$IPGAZE_E2E_GO_BUILD" "${IPGAZE_E2E_ROOT}/binaries" "${TMPDIR:-/tmp}/apimgr"
IPGAZE_E2E_ARTIFACTS="$(mktemp -d "${TMPDIR:-/tmp}/apimgr/${IPGAZE_E2E_PROJECT}-e2e-XXXXXX")"

trap __cleanup EXIT INT TERM

__build
__start_browser
__run_tests

__log "E2E suite completed successfully"
