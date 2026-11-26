#!/bin/bash
# ipgaze backup script

set -euo pipefail
umask 077

PROJECTNAME="ipgaze"
DATA_DIR="/var/lib/ipgaze"
CONFIG_DIR="/etc/ipgaze"
BACKUP_DIR="${BACKUP_DIR:-/var/backups}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/${PROJECTNAME}_${TIMESTAMP}.tar.gz"

echo "📦 Backing up ipgaze..."

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Please run as root (use sudo)" >&2
    exit 1
fi

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Create backup
echo "📁 Creating backup archive..."
if ! tar -czf "$BACKUP_FILE" \
    -C / \
    --exclude='*.log' \
    "${DATA_DIR#/}" \
    "${CONFIG_DIR#/}" \
    2>/dev/null; then
    echo "ERROR: Backup archive creation failed" >&2
    rm -f -- "$BACKUP_FILE"
    exit 1
fi

# Check if backup was created
if [ -f "$BACKUP_FILE" ]; then
    SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
    echo "✅ Backup created: $BACKUP_FILE ($SIZE)"

    # Keep only last 7 backups
    echo "🧹 Cleaning old backups (keeping last 7)..."
    mapfile -d '' -t backups < <(find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type f -name "${PROJECTNAME}_*.tar.gz" -printf '%T@ %f\0' | sort -zrn)
    for ((index = 7; index < ${#backups[@]}; index++)); do
        rm -f -- "$BACKUP_DIR/${backups[index]#* }"
    done

    echo "✅ Backup complete!"
    find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type f -name "${PROJECTNAME}_*.tar.gz" -printf '%TY-%Tm-%Td %TH:%TM %s %p\n' | sort -r
else
    echo "ERROR: Backup failed" >&2
    exit 1
fi
