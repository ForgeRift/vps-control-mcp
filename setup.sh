#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# vps-control-mcp  —  Setup Script
# Run on your VPS:  chmod +x setup.sh && ./setup.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

INSTALL_DIR="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="$INSTALL_DIR/.env"
ECOSYSTEM="$INSTALL_DIR/ecosystem.config.cjs"
PM2_NAME="vps-mcp"

echo ""
echo "=== vps-control-mcp Setup ==="
echo ""

# ── 1. Check prerequisites ──────────────────────────────────────────────────

if ! command -v node &>/dev/null; then
  echo "ERROR: Node.js not found. Install Node 18+ first."
  echo "  curl -fsSL https://deb.nodesource.com/setup_18.x | bash -"
  echo "  apt-get install -y nodejs"
  exit 1
fi
echo "✓ Node.js $(node -v)"

if ! command -v npm &>/dev/null; then
  echo "ERROR: npm not found."
  exit 1
fi
echo "✓ npm $(npm -v)"

if ! command -v pm2 &>/dev/null; then
  echo "Installing PM2 globally..."
  npm install -g pm2
fi
echo "✓ PM2 $(pm2 -v)"

# ── 2. Install dependencies + build ─────────────────────────────────────────

echo ""
echo "Installing dependencies..."
cd "$INSTALL_DIR"
npm install --include=dev

echo "Building TypeScript..."
npm run build

if [ ! -f "$INSTALL_DIR/dist/index.js" ]; then
  echo "ERROR: Build failed — dist/index.js not found."
  exit 1
fi
echo "✓ Build complete"

# ── 3. Generate .env ────────────────────────────────────────────────────────

if [ -f "$ENV_FILE" ]; then
  echo ""
  echo "Existing .env found — using current configuration."
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  TOKEN="${MCP_AUTH_TOKEN:-}"
else
  echo ""
  echo "Generating auth token..."
  TOKEN=$(openssl rand -hex 32)

  cat > "$ENV_FILE" <<ENVEOF
# ── Required ──────────────────────────────────────────────────────────────────
MCP_AUTH_TOKEN=$TOKEN

# ── Optional (defaults shown) ─────────────────────────────────────────────────
PORT=3001
# APP_DIR=/root/sharpedge
# PM2_LOG_DIR=/root/.pm2/logs
# AUDIT_LOG_PATH=/root/mcp-audit.log
# ALLOWED_PROCESSES=my-api,my-worker
# MAX_CUSTOM_COMMANDS_PER_SESSION=10
ENVEOF

  echo "✓ Auth token generated and saved to .env"
fi

# ── 4. Configure PM2 ───────────────────────────────────────────────────────

echo ""

# Stop existing instance if running
if pm2 describe "$PM2_NAME" &>/dev/null; then
  echo "Stopping existing $PM2_NAME process..."
  pm2 stop "$PM2_NAME" 2>/dev/null || true
  pm2 delete "$PM2_NAME" 2>/dev/null || true
fi

echo "Starting $PM2_NAME via PM2..."
pm2 start "$ECOSYSTEM"

# Save PM2 process list so it survives reboot
pm2 save

# Set up PM2 startup script (survives server reboot)
echo ""
echo "Configuring PM2 startup (auto-start on reboot)..."
pm2 startup 2>/dev/null || echo "  (pm2 startup may require manual step — see output above)"

echo ""
echo "✓ PM2 process running"

# ── 5. Verify ───────────────────────────────────────────────────────────────

sleep 2
PORT_VAL=$(grep -oP 'PORT=\K[0-9]+' "$ENV_FILE" 2>/dev/null || echo "3001")

if pm2 describe "$PM2_NAME" 2>/dev/null | grep -q "online"; then
  echo ""
  echo "=== Setup Complete ==="
  echo "Server running at http://$(hostname -I | awk '{print $1}'):$PORT_VAL"
  echo ""
  echo "Add this to your claude_desktop_config.json:"
  echo ""
  echo "{"
  echo "  \"mcpServers\": {"
  echo "    \"vps-control\": {"
  echo "      \"command\": \"mcp-remote\","
  echo "      \"args\": ["
  echo "        \"http://YOUR_VPS_IP:$PORT_VAL/sse\","
  echo "        \"--allow-http\","
  echo "        \"--header\","
  echo "        \"Authorization: Bearer $TOKEN\""
  echo "      ]"
  echo "    }"
  echo "  }"
  echo "}"
  echo ""
  echo "Replace YOUR_VPS_IP with your server's public IP address."
else
  echo ""
  echo "WARNING: Process may not have started correctly."
  echo "Check logs: pm2 logs $PM2_NAME --lines 20"
fi
