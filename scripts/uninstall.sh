#!/bin/bash
# ipgaze uninstallation script

set -e

BINARY_PATH="/usr/local/bin/ipgaze"

echo "🗑️  Uninstalling ipgaze..."

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Please run as root (use sudo)"
    exit 1
fi

# The binary handles stopping, disabling, removing the service file, and
# deleting config/data/cache/log/backup directories and the system user —
# it also prompts for confirmation before the destructive parts (see AI.md
# "Service Uninstall Logic"). This script never duplicates that logic.
if [ -x "$BINARY_PATH" ]; then
    "$BINARY_PATH" --service --uninstall
else
    echo "❌ $BINARY_PATH not found or not executable"
    exit 1
fi

# Remove binary (the service uninstall keeps it per spec)
echo "🗑️  Removing binary..."
rm -f "$BINARY_PATH"

echo ""
echo "✅ ipgaze uninstalled successfully!"
