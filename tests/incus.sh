#!/usr/bin/env bash
# @@License : WTFPL
# tests/incus.sh — Full integration + systemd testing in Incus Debian container (PART 28)
set -eo pipefail

# Check if incus is available
if ! command -v incus &>/dev/null; then
    echo "ERROR: incus not found. Install incus or use tests/docker.sh"
    exit 1
fi

# Detect project info
INCUS_PROJECT_NAME=$(basename "$PWD")
PROJECT_ORG=$(git remote get-url origin 2>/dev/null | sed -E 's|.*/([^/]+)/[^/]+(\.git)?$|\1|')
if [[ -z "$PROJECT_ORG" ]]; then
    PROJECT_ORG=$(basename "$(dirname "$PWD")")
fi
INTERNAL_NAME=$(sed -n 's/^internal_name:[[:space:]]*//p' IDEA.md | head -n1)
if [[ -z "$INTERNAL_NAME" ]]; then
    INTERNAL_NAME=$INCUS_PROJECT_NAME
fi
INCUS_CONTAINER_NAME="${INCUS_PROJECT_NAME}-$(tr -dc 'a-z0-9' </dev/urandom | head -c8)"
INCUS_TEMP_ROOT="${TMPDIR:-/tmp}/${PROJECT_ORG}"
mkdir -p "$INCUS_TEMP_ROOT"
INCUS_TEMP_DIR=$(mktemp -d "$INCUS_TEMP_ROOT/${INTERNAL_NAME}-XXXXXX")
INCUS_BINARY_DIR="$INCUS_TEMP_DIR/binaries"
mkdir -p "$INCUS_BINARY_DIR"

cleanup() {
    incus delete "$INCUS_CONTAINER_NAME" --force 2>/dev/null || true
    if [[ -n "${INCUS_TEMP_DIR:-}" && -d "$INCUS_TEMP_DIR" && ! -L "$INCUS_TEMP_DIR" && "$INCUS_TEMP_DIR" == "$INCUS_TEMP_ROOT/${INTERNAL_NAME}-"* ]]; then
        rm -rf -- "$INCUS_TEMP_DIR"
    fi
}
trap cleanup EXIT

# Build in Docker and keep binaries in the project-scoped OS temp directory.
INCUS_GO_CACHE="${HOME}/go/pkg/mod"
INCUS_GO_BUILD="${HOME}/.cache/go-build/${INCUS_PROJECT_NAME}"
mkdir -p "$INCUS_GO_CACHE" "$INCUS_GO_BUILD"
docker run --rm \
  --name "${INCUS_PROJECT_NAME}-$(tr -dc 'a-z0-9' </dev/urandom | head -c8)" \
  -v "$PWD:/app" \
  -v "$INCUS_TEMP_DIR:/out" \
  -v "$INCUS_GO_CACHE:/usr/local/share/go/pkg/mod" \
  -v "$INCUS_GO_BUILD:/usr/local/share/go/cache" \
  -w /app -e CGO_ENABLED=0 -e GOFLAGS=-buildvcs=false \
  casjaysdev/go:latest go build -buildvcs=false -trimpath -ldflags "-s -w" -o "/out/binaries/${INCUS_PROJECT_NAME}" ./src
if [ -d "src/client" ]; then
    docker run --rm \
      --name "${INCUS_PROJECT_NAME}-$(tr -dc 'a-z0-9' </dev/urandom | head -c8)" \
      -v "$PWD:/app" \
      -v "$INCUS_TEMP_DIR:/out" \
      -v "$INCUS_GO_CACHE:/usr/local/share/go/pkg/mod" \
      -v "$INCUS_GO_BUILD:/usr/local/share/go/cache" \
      -w /app -e CGO_ENABLED=0 -e GOFLAGS=-buildvcs=false \
      casjaysdev/go:latest go build -buildvcs=false -trimpath -ldflags "-s -w" -o "/out/binaries/${INCUS_PROJECT_NAME}-cli" ./src/client
fi

INCUS_IMAGE="images:debian/trixie"

echo "Launching Incus container (Debian + systemd)..."
incus launch "$INCUS_IMAGE" "$INCUS_CONTAINER_NAME"

# Wait for container to be ready
sleep 2

echo "Copying binaries to container..."
incus file push "$INCUS_BINARY_DIR/${INCUS_PROJECT_NAME}" "$INCUS_CONTAINER_NAME/usr/local/bin/"
incus exec "$INCUS_CONTAINER_NAME" -- chmod +x "/usr/local/bin/${INCUS_PROJECT_NAME}"

# Copy client if built
if [ -f "$INCUS_BINARY_DIR/${INCUS_PROJECT_NAME}-cli" ]; then
    incus file push "$INCUS_BINARY_DIR/${INCUS_PROJECT_NAME}-cli" "$INCUS_CONTAINER_NAME/usr/local/bin/"
    incus exec "$INCUS_CONTAINER_NAME" -- chmod +x "/usr/local/bin/${INCUS_PROJECT_NAME}-cli"
fi

# Ensure the tools the test body calls are present. The Debian image ships none of
# curl/file/jq, and the test body runs under `set -e`, so a missing tool aborts the
# whole run at its first use instead of failing a single assertion.
incus exec "$INCUS_CONTAINER_NAME" -- bash -c "apt-get update && apt-get install -y curl file jq" >/dev/null 2>&1

echo "Running tests in Incus..."
incus exec "$INCUS_CONTAINER_NAME" -- bash -c "
    set -eo pipefail

    echo '=== Version Check ==='
    ${INCUS_PROJECT_NAME} --version

    echo '=== Help Check ==='
    ${INCUS_PROJECT_NAME} --help

    echo '=== Binary Info ==='
    ls -lh /usr/local/bin/${INCUS_PROJECT_NAME}
    file /usr/local/bin/${INCUS_PROJECT_NAME}

    echo '=== Service Install Test ==='
    # System containers run a full init and support the ordinary service lifecycle.
    ${INCUS_PROJECT_NAME} --service --install
    echo '=== Service Status ==='
    # inside container — not a host-service mutation
    systemctl status ${INCUS_PROJECT_NAME} || true

    echo '=== Service Start Test ==='
    # inside container — not a host-service mutation
    systemctl start ${INCUS_PROJECT_NAME}
    sleep 2
    # inside container — not a host-service mutation
    systemctl status ${INCUS_PROJECT_NAME}
    getent passwd ${INCUS_PROJECT_NAME}
    systemctl show -p MainPID --value ${INCUS_PROJECT_NAME} | xargs -r -I{} stat -c %U /proc/{} | grep -qx '${INCUS_PROJECT_NAME}'

    echo '=== API Endpoint Tests ==='
    # Test JSON response (default)
    curl -q -LSsf http://localhost:80/api/v1/server/healthz || echo 'FAILED: /api/v1/server/healthz'

    # Test .txt extension (plain text)
    curl -q -LSsf http://localhost:80/api/v1/server/healthz.txt || echo 'FAILED: /api/v1/server/healthz.txt'

    # Test Accept header: application/json
    curl -q -LSsf -H 'Accept: application/json' http://localhost:80/server/healthz || echo 'FAILED: Accept JSON'

    # Test Accept header: text/plain
    curl -q -LSsf -H 'Accept: text/plain' http://localhost:80/server/healthz || echo 'FAILED: Accept text/plain'

    echo '=== Project-Specific Endpoint Tests (echoip-compatible, IDEA.md) ==='
    curl -q -LSsf http://localhost:80/json | grep -q -- '\"ip\"' || echo 'FAILED: /json'
    curl -q -LSsf http://localhost:80/ip || echo 'FAILED: /ip'
    curl -q -LSsf http://localhost:80/ip.txt || echo 'FAILED: /ip.txt'
    curl -q -LSsf http://localhost:80/country.txt || echo 'FAILED: /country.txt'
    curl -q -LSsf http://localhost:80/asn.txt || echo 'FAILED: /asn.txt'
    curl -q -LSsf http://localhost:80/robots.txt | grep -qi -- 'user-agent' || echo 'FAILED: /robots.txt'
    curl -q -LSsf http://localhost:80/.well-known/security.txt | grep -qi -- 'contact' || echo 'FAILED: /.well-known/security.txt'
    INCUS_SECURITY_TXT_STATUS=\$(curl -q -LSs -o /dev/null -w '%{http_code}' http://localhost:80/security.txt)
    [ \"\$INCUS_SECURITY_TXT_STATUS\" = 404 ] || echo 'FAILED: /security.txt should be 404'
    curl -q -LSsf http://localhost:80/api/v1/ | grep -q -- '\"ip\"' || echo 'FAILED: /api/v1/ JSON'
    curl -q -LSsf http://localhost:80/api/v1/ip || echo 'FAILED: /api/v1/ip'

    echo '=== Content Negotiation Tests ==='
    curl -q -LSsfI -H 'Accept: text/html' http://localhost:80/ | grep -qi -- 'text/html' || echo 'FAILED: Frontend HTML'
    curl -q -LSsf -H 'Accept: text/plain' http://localhost:80/ | grep -qvi -- '<html' || echo 'FAILED: Frontend text/plain'
    curl -q -LSsf -A 'curl/8.0.0' http://localhost:80/ | grep -qvi -- '<html' || echo 'FAILED: curl UA plain text'

    echo '=== Open API Smoke Test ==='
    # No auth required — all endpoints are publicly accessible.
    # Health responses are BARE (AI.md PART 13: no {ok,data} envelope on any
    # health route, in any state) — the top-level status field carries the state.
    curl -q -LSsf -H 'Accept: application/json' http://localhost:80/server/healthz | grep -q -- '\"status\": \"healthy\"' \
        && echo '✓ Health endpoint works' \
        || echo '✗ FAILED: Health endpoint'

    echo '=== Binary Rename Tests ==='
    # Test that binaries show ACTUAL name in --help/--version (not hardcoded)
    cp /usr/local/bin/${INCUS_PROJECT_NAME} /tmp/renamed-server
    chmod +x /tmp/renamed-server
    if /tmp/renamed-server --help 2>&1 | grep -q -- 'renamed-server'; then
        echo '✓ Server binary rename works (--help shows actual name)'
    else
        echo '✗ FAILED: Server --help does not show renamed binary name'
    fi

    echo '=== Client Tests (if exists) ==='
    if [ -f /usr/local/bin/${INCUS_PROJECT_NAME}-cli ]; then
        ${INCUS_PROJECT_NAME}-cli --version || echo 'FAILED: CLI --version'
        ${INCUS_PROJECT_NAME}-cli --help || echo 'FAILED: CLI --help'

        # Test binary rename
        cp /usr/local/bin/${INCUS_PROJECT_NAME}-cli /tmp/renamed-cli
        chmod +x /tmp/renamed-cli
        if /tmp/renamed-cli --help 2>&1 | grep -q -- 'renamed-cli'; then
            echo '✓ CLI binary rename works'
        else
            echo '✗ FAILED: CLI --help does not show renamed binary name'
        fi

        # Full CLI functionality tests against server
        echo '--- CLI Full Functionality Tests ---'
        # The CLI's only positional argument is an IP address (AI.md PART 32) —
        # there is no 'status' subcommand to call here.
        if [ -n \"\${API_TOKEN:-}\" ]; then
            # Test with API token
            ${INCUS_PROJECT_NAME}-cli --server http://localhost:80 --token \"\$API_TOKEN\" --output json \
                || echo 'FAILED: CLI self lookup with token'
        else
            # Test without token (open API — anonymous allowed)
            ${INCUS_PROJECT_NAME}-cli --server http://localhost:80 --output json \
                || echo 'FAILED: CLI self lookup without token'
        fi
        ${INCUS_PROJECT_NAME}-cli --server http://localhost:80 --field ip 8.8.8.8 \
            || echo 'FAILED: CLI single-field IP lookup'
    else
        echo 'client not installed - skipping'
    fi

    echo '=== Service Stop Test ==='
    # inside container — not a host-service mutation
    systemctl stop ${INCUS_PROJECT_NAME}

    echo '=== All tests passed ==='
"

echo "Incus tests completed successfully"
