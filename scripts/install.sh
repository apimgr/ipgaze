#!/bin/bash
# ipgaze installation script
# Supports Linux (systemd)

set -e

PROJECTNAME="ipgaze"
BINARY_URL="https://github.com/apimgr/ipgaze/releases/latest/download"
INSTALL_DIR="/usr/local/bin"
SERVICE_USER="ipgaze"
DATA_DIR="/var/lib/ipgaze"
LOG_DIR="/var/log/ipgaze"
CONFIG_DIR="/etc/ipgaze"

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
TMPDIR=$(mktemp -d "/tmp/${PROJECTNAME}.XXXXXX")
trap 'rm -rf "$TMPDIR"' EXIT

echo "📥 Downloading binary..."
curl -q -LSsf -o "$TMPDIR/$PROJECTNAME" "$BINARY_URL/$BINARY"

echo "🔐 Verifying checksum..."
curl -q -LSsf -o "$TMPDIR/checksums.txt" "$BINARY_URL/checksums.txt"
EXPECTED_SHA=$(grep -- " $BINARY\$" "$TMPDIR/checksums.txt" | awk '{print $1}')
if [ -z "$EXPECTED_SHA" ]; then
    echo "❌ No checksum entry found for $BINARY in checksums.txt"
    exit 1
fi
ACTUAL_SHA=$(sha256sum "$TMPDIR/$PROJECTNAME" | awk '{print $1}')
if [ "$EXPECTED_SHA" != "$ACTUAL_SHA" ]; then
    echo "❌ Checksum mismatch: expected $EXPECTED_SHA, got $ACTUAL_SHA"
    exit 1
fi

chmod +x "$TMPDIR/$PROJECTNAME"

# Install binary
echo "📦 Installing binary to $INSTALL_DIR..."
mv "$TMPDIR/$PROJECTNAME" "$INSTALL_DIR/$PROJECTNAME"

# Create user
if ! id "$SERVICE_USER" &>/dev/null; then
    echo "👤 Creating user $SERVICE_USER..."
    useradd -r -s /bin/false "$SERVICE_USER"
fi

# Create directories
echo "📁 Creating directories..."
mkdir -p "$DATA_DIR" "$LOG_DIR" "$CONFIG_DIR"
chown "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR" "$LOG_DIR" "$CONFIG_DIR"

# Create systemd service
echo "⚙️  Creating systemd service..."
cat > "/etc/systemd/system/$PROJECTNAME.service" <<EOF
[Unit]
Description=ipgaze - IP address lookup service
After=network.target
Documentation=https://github.com/apimgr/ipgaze

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
ExecStart=$INSTALL_DIR/$PROJECTNAME -l :8080 -d $DATA_DIR -r -s
Restart=on-failure
RestartSec=5s

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATA_DIR $LOG_DIR

# Environment
Environment="CONFIG_DIR=$CONFIG_DIR"
Environment="DATA_DIR=$DATA_DIR"
Environment="LOGS_DIR=$LOG_DIR"

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
echo "🔄 Reloading systemd..."
systemctl daemon-reload

# Enable service
echo "✅ Enabling service..."
systemctl enable "$PROJECTNAME"

# Start service
echo "▶️  Starting service..."
systemctl start "$PROJECTNAME"

# Check status
sleep 2
if systemctl is-active --quiet "$PROJECTNAME"; then
    echo ""
    echo "✅ ipgaze installed successfully!"
    echo ""
    echo "Service status:"
    systemctl status "$PROJECTNAME" --no-pager
    echo ""
    echo "Access: curl -q -LSsf http://localhost:8080/"
    echo "Logs:   sudo journalctl -u $PROJECTNAME -f"
else
    echo "❌ Service failed to start"
    echo "Check logs: sudo journalctl -u $PROJECTNAME -n 50"
    exit 1
fi
