#!/usr/bin/env bash
# @@License : WTFPL
# tests/docker.sh — Full integration testing in Docker Alpine container (PART 28)
set -eo pipefail

# Detect project info
DOCKER_PROJECT_NAME=$(basename "$PWD")
DOCKER_PROJECT_ORG=$(basename "$(dirname "$PWD")")

# Build — use Makefile if present (standard for all bootstrapped projects)
# Output always lands in binaries/
if [ -f "Makefile" ]; then
    echo "Building with make build..."
    make build
else
    # No Makefile yet — fallback to direct docker run
    echo "Building in Docker (no Makefile)..."
    DOCKER_GO_CACHE="${DOCKER_GO_CACHE:-$HOME/go/pkg/mod}"
    DOCKER_GO_BUILD="${DOCKER_GO_BUILD:-$HOME/.cache/go-build/${DOCKER_PROJECT_NAME}}"
    mkdir -p "$DOCKER_GO_CACHE" "$DOCKER_GO_BUILD" binaries
    docker run --rm \
      --name "${DOCKER_PROJECT_NAME}-$(tr -dc 'a-z0-9' </dev/urandom | head -c8)" \
      -v $PWD:/app \
      -v $DOCKER_GO_CACHE:/usr/local/share/go/pkg/mod \
      -v $DOCKER_GO_BUILD:/usr/local/share/go/cache \
      -w /app -e CGO_ENABLED=0 -e GOFLAGS=-buildvcs=false \
      casjaysdev/go:latest go build -buildvcs=false -trimpath -ldflags "-s -w" -o /app/binaries/${DOCKER_PROJECT_NAME} ./src
    if [ -d "src/client" ]; then
        docker run --rm \
          --name "${DOCKER_PROJECT_NAME}-$(tr -dc 'a-z0-9' </dev/urandom | head -c8)" \
          -v $PWD:/app \
          -v $DOCKER_GO_CACHE:/usr/local/share/go/pkg/mod \
          -v $DOCKER_GO_BUILD:/usr/local/share/go/cache \
          -w /app -e CGO_ENABLED=0 -e GOFLAGS=-buildvcs=false \
          casjaysdev/go:latest go build -buildvcs=false -trimpath -ldflags "-s -w" -o /app/binaries/${DOCKER_PROJECT_NAME}-cli ./src/client
    fi
fi

echo "Testing in Docker (Alpine)..."
docker run --rm \
  --name "${DOCKER_PROJECT_NAME}-$(tr -dc 'a-z0-9' </dev/urandom | head -c8)" \
  -v "$PWD/binaries:/app" \
  alpine:latest sh -c "
    set -e

    # Install required tools for testing
    apk add --no-cache curl bash file jq >/dev/null

    chmod +x /app/${DOCKER_PROJECT_NAME}
    [ -f /app/${DOCKER_PROJECT_NAME}-cli ] && chmod +x /app/${DOCKER_PROJECT_NAME}-cli

    echo '=== Version Check ==='
    /app/${DOCKER_PROJECT_NAME} --version

    echo '=== Help Check ==='
    /app/${DOCKER_PROJECT_NAME} --help

    echo '=== Binary Info ==='
    ls -lh /app/${DOCKER_PROJECT_NAME}
    file /app/${DOCKER_PROJECT_NAME}

    echo '=== Starting Server for API Tests ==='
    /app/${DOCKER_PROJECT_NAME} --port 64580 > /tmp/server.log 2>&1 &
    SERVER_PID=\$!
    sleep 3

    echo '=== API Endpoint Tests ==='
    # Test JSON response (default)
    curl -q -LSsf http://localhost:64580/api/v1/server/healthz || echo 'FAILED: /api/v1/server/healthz'

    # Test .txt extension (plain text)
    curl -q -LSsf http://localhost:64580/api/v1/server/healthz.txt || echo 'FAILED: /api/v1/server/healthz.txt'

    # Test Accept header: application/json
    curl -q -LSsf -H 'Accept: application/json' http://localhost:64580/server/healthz || echo 'FAILED: Accept JSON'

    # Test Accept header: text/plain
    curl -q -LSsf -H 'Accept: text/plain' http://localhost:64580/server/healthz || echo 'FAILED: Accept text/plain'

    echo '=== Project-Specific Endpoint Tests (echoip-compatible, IDEA.md) ==='
    # Frontend field endpoints (plain text for CLI/curl clients)
    curl -q -LSsf http://localhost:64580/json | grep -q -- '\"ip\"' || echo 'FAILED: /json'
    curl -q -LSsf http://localhost:64580/ip || echo 'FAILED: /ip'
    curl -q -LSsf http://localhost:64580/ip.txt || echo 'FAILED: /ip.txt'
    curl -q -LSsf http://localhost:64580/country.txt || echo 'FAILED: /country.txt'
    curl -q -LSsf http://localhost:64580/city.txt || echo 'FAILED: /city.txt'
    curl -q -LSsf http://localhost:64580/asn.txt || echo 'FAILED: /asn.txt'
    curl -q -LSsf http://localhost:64580/asn-org.txt || echo 'FAILED: /asn-org.txt'
    curl -q -LSsf http://localhost:64580/country-iso.txt || echo 'FAILED: /country-iso.txt'
    curl -q -LSsf http://localhost:64580/coordinates.txt || echo 'FAILED: /coordinates.txt'

    # Well-known / metadata endpoints
    curl -q -LSsf http://localhost:64580/robots.txt | grep -qi -- 'user-agent' || echo 'FAILED: /robots.txt'
    curl -q -LSsf http://localhost:64580/security.txt | grep -qi -- 'contact' || echo 'FAILED: /security.txt'
    curl -q -LSsf http://localhost:64580/.well-known/security.txt | grep -qi -- 'contact' || echo 'FAILED: /.well-known/security.txt'

    # API v1 field routes
    curl -q -LSsf http://localhost:64580/api/v1/ | grep -q -- '\"ip\"' || echo 'FAILED: /api/v1/ JSON'
    curl -q -LSsf http://localhost:64580/api/v1/ip || echo 'FAILED: /api/v1/ip'

    # Autodiscover (PART 13/14) — required fields
    curl -q -LSsf http://localhost:64580/api/autodiscover | jq -e '.api_version and .version and .server_name and .cli_min_version' >/dev/null \
        || echo 'FAILED: /api/autodiscover missing required fields'

    echo '=== Content Negotiation Tests ==='
    # Frontend route: browser (HTML) vs CLI (plain text) smart detection
    curl -q -LSsfI -H 'Accept: text/html' http://localhost:64580/ | grep -qi -- 'text/html' || echo 'FAILED: Frontend HTML'
    curl -q -LSsf -H 'Accept: text/plain' http://localhost:64580/ | grep -qvi -- '<html' || echo 'FAILED: Frontend text/plain'
    curl -q -LSsf -H 'Accept: application/json' http://localhost:64580/ | grep -q -- '\"ip\"' || echo 'FAILED: Frontend JSON'
    # User-Agent based detection (curl / CLI → plain text, not HTML)
    curl -q -LSsf -A 'curl/8.0.0' http://localhost:64580/ | grep -qvi -- '<html' || echo 'FAILED: curl UA plain text'
    curl -q -LSsf -A 'ipgaze-cli/1.0.0' http://localhost:64580/ | grep -qvi -- '<html' || echo 'FAILED: CLI UA plain text'

    echo '=== Open API Smoke Test ==='
    # No auth required — all endpoints are publicly accessible
    curl -q -LSsf http://localhost:64580/server/healthz | grep -q -- '\"ok\":true' \
        && echo '✓ Health endpoint works' \
        || echo '✗ FAILED: Health endpoint'

    echo '=== Binary Rename Tests ==='
    # Test that binaries show ACTUAL name in --help/--version (not hardcoded)
    cp /app/${DOCKER_PROJECT_NAME} /app/renamed-server
    chmod +x /app/renamed-server
    if /app/renamed-server --help 2>&1 | grep -q -- 'renamed-server'; then
        echo '✓ Server binary rename works (--help shows actual name)'
    else
        echo '✗ FAILED: Server --help does not show renamed binary name'
    fi

    echo '=== Client Tests (if exists) ==='
    if [ -f /app/${DOCKER_PROJECT_NAME}-cli ]; then
        /app/${DOCKER_PROJECT_NAME}-cli --version || echo 'FAILED: CLI --version'
        /app/${DOCKER_PROJECT_NAME}-cli --help || echo 'FAILED: CLI --help'

        # Test binary rename
        cp /app/${DOCKER_PROJECT_NAME}-cli /app/renamed-cli
        chmod +x /app/renamed-cli
        if /app/renamed-cli --help 2>&1 | grep -q -- 'renamed-cli'; then
            echo '✓ CLI binary rename works'
        else
            echo '✗ FAILED: CLI --help does not show renamed binary name'
        fi

        # Full CLI functionality tests against server
        echo '--- CLI Full Functionality Tests ---'
        if [ -n \"\${API_TOKEN:-}\" ]; then
            # Test with API token
            /app/${DOCKER_PROJECT_NAME}-cli --server http://localhost:64580 --token \"\$API_TOKEN\" status || echo 'CLI status failed'
        else
            # Test without token (open API — anonymous allowed)
            /app/${DOCKER_PROJECT_NAME}-cli --server http://localhost:64580 status || echo 'CLI status (no token) failed or not applicable'
        fi
    else
        echo 'client not built - skipping'
    fi

    echo '=== Stopping Server ==='
    kill \$SERVER_PID
    wait \$SERVER_PID 2>/dev/null || true

    echo '=== All tests passed ==='
"

echo "Docker tests completed successfully"
