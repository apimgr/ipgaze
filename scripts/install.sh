#!/bin/bash
# ipgaze installation script
# Supports Linux (systemd)

set -e

BINARY_URL="https://github.com/apimgr/ipgaze/releases/latest/download"
INSTALL_DIR="/usr/local/bin"

PROJECT_REPO="${BINARY_URL%/releases/latest/download}"
PROJECTNAME="${PROJECT_REPO##*/}"
PROJECT_ORG="${PROJECT_REPO%/*}"
PROJECT_ORG="${PROJECT_ORG##*/}"
# Keep this stable identity aligned with IDEA.md; it must not follow PROJECTNAME.
INTERNAL_NAME="ipgaze"

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)
        BINARY="ipgaze-linux-amd64"
        ;;
    aarch64|arm64)
        BINARY="ipgaze-linux-arm64"
        ;;
    *)
        echo "❌ Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

echo "🚀 Installing ipgaze..."
echo "   Architecture: $ARCH"
echo "   Binary: $BINARY"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Please run as root (use sudo)"
    exit 1
fi

# Download binary and its published checksum to a private tempdir (no fixed
# /tmp path, no symlink race), then verify SHA-256 before installing.
mkdir -p "${TMPDIR:-/tmp}/${PROJECT_ORG}"
TEMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/${PROJECT_ORG}/${INTERNAL_NAME}-XXXXXX")

__cleanup() {
    if [[ -n "${TEMP_DIR:-}" && -d "$TEMP_DIR" && ! -L "$TEMP_DIR" && \
        "$TEMP_DIR" == "${TMPDIR:-/tmp}/${PROJECT_ORG}/${INTERNAL_NAME}-"* ]]; then
        rm -rf -- "$TEMP_DIR"
    fi
}

trap __cleanup EXIT

echo "📥 Downloading binary..."
curl -q -LSsf -o "$TEMP_DIR/$PROJECTNAME" "$BINARY_URL/$BINARY"

echo "🔐 Verifying checksum..."
curl -q -LSsf -o "$TEMP_DIR/checksums.txt" "$BINARY_URL/checksums.txt"
EXPECTED_SHA=$(grep -- " $BINARY\$" "$TEMP_DIR/checksums.txt" | awk '{print $1}')
if [ -z "$EXPECTED_SHA" ]; then
    echo "❌ No checksum entry found for $BINARY in checksums.txt"
    exit 1
fi
ACTUAL_SHA=$(sha256sum "$TEMP_DIR/$PROJECTNAME" | awk '{print $1}')
if [ "$EXPECTED_SHA" != "$ACTUAL_SHA" ]; then
    echo "❌ Checksum mismatch: expected $EXPECTED_SHA, got $ACTUAL_SHA"
    exit 1
fi

chmod +x "$TEMP_DIR/$PROJECTNAME"

# Install binary
echo "📦 Installing binary to $INSTALL_DIR..."
mv "$TEMP_DIR/$PROJECTNAME" "$INSTALL_DIR/$PROJECTNAME"

# The binary handles platform/init-system detection, service file creation,
# enabling, starting, and user/directory setup on first run — this script
# never duplicates that logic (see AI.md "Service Install Logic").
echo "⚙️  Installing and starting service..."
"$INSTALL_DIR/$PROJECTNAME" --service --install

# Check status
if "$INSTALL_DIR/$PROJECTNAME" --service status; then
    echo ""
    echo "✅ ipgaze installed successfully!"
else
    echo "❌ Service failed to start"
    echo "Check status: sudo $INSTALL_DIR/$PROJECTNAME --service status"
    exit 1
fi
