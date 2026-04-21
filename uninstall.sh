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

# ── 3. Revoke OAuth client registration ─────────────────────────────────────
# ToS §14.2: ForgeRift deactivates all OAuth client registrations within 24h
# of cancellation/termination. This script handles the client-side cleanup.

echo ""
echo "=== OAuth Client Cleanup ==="
echo ""

OAUTH_CONFIG_FILE="$INSTALL_DIR/.oauth-client.json"
OAUTH_ENDPOINT="${OAUTH_REVOCATION_ENDPOINT:-}"

if [ -f "$OAUTH_CONFIG_FILE" ]; then
  echo "Found OAuth client config at: $OAUTH_CONFIG_FILE"

  # Extract client_id for logging (never log the secret)
  CLIENT_ID=$(grep -o '"client_id"[[:space:]]*:[[:space:]]*"[^"]*"' "$OAUTH_CONFIG_FILE" 2>/dev/null | grep -o '"[^"]*"$' | tr -d '"' || echo "unknown")
  echo "OAuth client_id: $CLIENT_ID"

  if [ -n "$OAUTH_ENDPOINT" ]; then
    echo "Sending revocation request to: $OAUTH_ENDPOINT"
    # Best-effort revocation -- failure is non-fatal but should be investigated
    curl -sf -X POST "$OAUTH_ENDPOINT/revoke" \
      -H "Content-Type: application/json" \
      -d "{\"client_id\": \"$CLIENT_ID\"}" \
      && echo "OK OAuth client revocation request sent" \
      || echo "WARN Revocation request failed -- contact support@forgerift.io to confirm deactivation"
  else
    echo "WARN OAUTH_REVOCATION_ENDPOINT not set."
    echo "   The OAuth client registration ($CLIENT_ID) must be deactivated manually."
    echo "   Contact support@forgerift.io or log in to your ForgeRift account to revoke it."
    echo "   ToS 14.2 guarantees deactivation within 24 hours of account cancellation."
  fi

  # Remove the local OAuth config file
  rm -f "$OAUTH_CONFIG_FILE" 2>/dev/null && echo "OK Local OAuth config removed" || true
else
  echo "No local OAuth client config found -- skipping client-side revocation."
  echo "If you had OAuth configured, contact support@forgerift.io to confirm server-side deactivation."
fi

# ── 4. DNS / sslip.io reminder ───────────────────────────────────────────────

echo ""
echo "=== DNS Cleanup (Manual) ==="
echo ""
echo "The sslip.io DNS entry (e.g. <your-ip>.sslip.io) is NOT removed automatically."
echo "DNS entries via sslip.io are ephemeral -- they expire when the IP is no longer"
echo "reachable. No action required unless you configured a custom domain."
echo "See ToS 14 for the full deactivation and data-deletion timeline."
echo ""

# ── 5. Reminder ─────────────────────────────────────────────────────────────

echo ""
echo "=== Uninstall Complete ==="
echo ""
echo "Don't forget to remove the vps-control entry from your"
echo "claude_desktop_config.json on your local machine."
echo ""
