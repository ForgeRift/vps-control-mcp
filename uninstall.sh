#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# vps-control-mcp  —  Uninstall Script
# Run on your VPS:  chmod +x uninstall.sh && ./uninstall.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

PM2_NAME="vps-mcp"
INSTALL_DIR="$(cd "$(dirname "$0")" && pwd)"

echo ""
echo "=== vps-control-mcp Uninstall ==="
echo ""

# ── 1. Stop and remove PM2 process ──────────────────────────────────────────

if command -v pm2 &>/dev/null; then
  if pm2 describe "$PM2_NAME" &>/dev/null; then
    echo "Stopping $PM2_NAME..."
    pm2 stop "$PM2_NAME" 2>/dev/null || true
    pm2 delete "$PM2_NAME" 2>/dev/null || true
    pm2 save
    echo "✓ PM2 process removed"
  else
    echo "PM2 process $PM2_NAME not found — skipping."
  fi
else
  echo "PM2 not installed — skipping process cleanup."
fi

# ── 2. Remove files ─────────────────────────────────────────────────────────

echo ""
read -rp "Delete the install directory ($INSTALL_DIR)? [y/N] " confirm
if [[ "$confirm" =~ ^[Yy]$ ]]; then
  # Safety: refuse to delete if path is / or /root
  if [ "$INSTALL_DIR" = "/" ] || [ "$INSTALL_DIR" = "/root" ]; then
    echo "ERROR: Refusing to delete $INSTALL_DIR — safety check."
    exit 1
  fi
  rm -rf "$INSTALL_DIR"
  echo "✓ Install directory removed"
else
  echo "Keeping files in $INSTALL_DIR"
  echo "  To clean up manually: rm -rf $INSTALL_DIR"
fi

# ── 3. Reminder ─────────────────────────────────────────────────────────────

echo ""
echo "=== Uninstall Complete ==="
echo ""
echo "Don't forget to remove the vps-control entry from your"
echo "claude_desktop_config.json on your local machine."
echo ""
