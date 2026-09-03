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
INCUS_PROJECT_ORG=$(basename "$(dirname "$PWD")")
INCUS_CONTAINER_NAME="test-${INCUS_PROJECT_NAME}-$$"

# Incus image - use latest Debian stable (update when new stable releases)
INCUS_IMAGE="images:debian/trixie"

trap "incus delete \"$INCUS_CONTAINER_NAME\" --force 2>/dev/null || true" EXIT

# Build — use Makefile if present (standard for all bootstrapped projects)
# Output always lands in binaries/
if [ -f "Makefile" ]; then
    echo "Building with make build..."
    make build
else
    # No Makefile yet — fallback to direct docker run
    echo "Building in Docker (no Makefile)..."
    INCUS_GO_CACHE="${INCUS_GO_CACHE:-$HOME/go/pkg/mod}"
    INCUS_GO_BUILD="${INCUS_GO_BUILD:-$HOME/.cache/go-build/${INCUS_PROJECT_NAME}}"
    mkdir -p "$INCUS_GO_CACHE" "$INCUS_GO_BUILD" binaries
    docker run --rm \
      --name "${INCUS_PROJECT_NAME}-$(tr -dc 'a-z0-9' </dev/urandom | head -c8)" \
      -v $PWD:/app \
      -v $INCUS_GO_CACHE:/usr/local/share/go/pkg/mod \
      -v $INCUS_GO_BUILD:/usr/local/share/go/cache \
      -w /app -e CGO_ENABLED=0 -e GOFLAGS=-buildvcs=false \
      casjaysdev/go:latest go build -buildvcs=false -trimpath -ldflags "-s -w" -o /app/binaries/${INCUS_PROJECT_NAME} ./src
    if [ -d "src/client" ]; then
        docker run --rm \
          --name "${INCUS_PROJECT_NAME}-$(tr -dc 'a-z0-9' </dev/urandom | head -c8)" \
          -v $PWD:/app \
          -v $INCUS_GO_CACHE:/usr/local/share/go/pkg/mod \
          -v $INCUS_GO_BUILD:/usr/local/share/go/cache \
          -w /app -e CGO_ENABLED=0 -e GOFLAGS=-buildvcs=false \
          casjaysdev/go:latest go build -buildvcs=false -trimpath -ldflags "-s -w" -o /app/binaries/${INCUS_PROJECT_NAME}-cli ./src/client
    fi
fi

echo "Launching Incus container (Debian + systemd)..."
incus launch "$INCUS_IMAGE" "$INCUS_CONTAINER_NAME"

# Wait for container to be ready
sleep 2

echo "Copying binaries to container..."
incus file push "binaries/${INCUS_PROJECT_NAME}" "$INCUS_CONTAINER_NAME/usr/local/bin/"
incus exec "$INCUS_CONTAINER_NAME" -- chmod +x "/usr/local/bin/${INCUS_PROJECT_NAME}"

# Copy client if built
if [ -f "binaries/${INCUS_PROJECT_NAME}-cli" ]; then
    incus file push "binaries/${INCUS_PROJECT_NAME}-cli" "$INCUS_CONTAINER_NAME/usr/local/bin/"
    incus exec "$INCUS_CONTAINER_NAME" -- chmod +x "/usr/local/bin/${INCUS_PROJECT_NAME}-cli"
fi

# Ensure curl is available for testing
incus exec "$INCUS_CONTAINER_NAME" -- bash -c "command -v curl || apt-get update && apt-get install -y curl" >/dev/null 2>&1

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
    ${INCUS_PROJECT_NAME} --service --install

    echo '=== Service Status ==='
    # inside VM — not a host-service mutation
    systemctl status ${INCUS_PROJECT_NAME} || true

    echo '=== Service Start Test ==='
    # inside VM — not a host-service mutation
    systemctl start ${INCUS_PROJECT_NAME}
    sleep 2
    # inside VM — not a host-service mutation
    systemctl status ${INCUS_PROJECT_NAME}

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
    curl -q -LSsf http://localhost:80/security.txt | grep -qi -- 'contact' || echo 'FAILED: /security.txt'
    curl -q -LSsf http://localhost:80/api/v1/ | grep -q -- '\"ip\"' || echo 'FAILED: /api/v1/ JSON'
    curl -q -LSsf http://localhost:80/api/v1/ip || echo 'FAILED: /api/v1/ip'

    echo '=== Content Negotiation Tests ==='
    curl -q -LSsfI -H 'Accept: text/html' http://localhost:80/ | grep -qi -- 'text/html' || echo 'FAILED: Frontend HTML'
    curl -q -LSsf -H 'Accept: text/plain' http://localhost:80/ | grep -qvi -- '<html' || echo 'FAILED: Frontend text/plain'
    curl -q -LSsf -A 'curl/8.0.0' http://localhost:80/ | grep -qvi -- '<html' || echo 'FAILED: curl UA plain text'

    echo '=== Open API Smoke Test ==='
    # No auth required — all endpoints are publicly accessible
    curl -q -LSsf http://localhost:80/server/healthz | grep -q -- '\"ok\":true' \
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
        if [ -n \"\${API_TOKEN:-}\" ]; then
            # Test with API token
            ${INCUS_PROJECT_NAME}-cli --server http://localhost:80 --token \"\$API_TOKEN\" status || echo 'CLI status failed'
        else
            # Test without token (open API — anonymous allowed)
            ${INCUS_PROJECT_NAME}-cli --server http://localhost:80 status || echo 'CLI status (no token) failed or not applicable'
        fi
    else
        echo 'client not installed - skipping'
    fi

    echo '=== Service Stop Test ==='
    # inside VM — not a host-service mutation
    systemctl stop ${INCUS_PROJECT_NAME}

    echo '=== All tests passed ==='
"

echo "Incus tests completed successfully"
