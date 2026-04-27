#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# vps-control-mcp  —  Setup Script
# Run on your VPS as root:  chmod +x setup.sh && ./setup.sh
#
# What this does:
#   1. Validates your ForgeRift subscription key
#   2. Installs Node.js, PM2 if missing
#   3. Builds the MCP server
#   4. Saves your ForgeRift key as the auth token in .env
#   5. Installs nginx + certbot, configures TLS via sslip.io
#   6. Starts the MCP via PM2 (auto-restarts on crash + reboot)
#   7. Hardens the firewall (port 3001 localhost-only)
#   8. Prints your Cowork connect URL and step-by-step connection instructions
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

INSTALL_DIR="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="$INSTALL_DIR/.env"
ECOSYSTEM="$INSTALL_DIR/ecosystem.config.cjs"
PM2_NAME="vps-mcp"
MCP_PORT=3001

echo ""
echo "======================================================"
echo "  vps-control-mcp  Setup"
echo "======================================================"
echo ""

# ── 0. Must run as root ────────────────────────────────────────────────────

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: This script must be run as root."
  echo "  sudo ./setup.sh"
  exit 1
fi

# ── 1. Validate ForgeRift subscription ───────────────────────────────────────

echo "Enter your ForgeRift License Key"
echo "(from your welcome email — subscribe at forgerift.io if you haven't yet):"
echo ""
read -rsp "License key: " FORGERIFT_KEY
echo ""

if [ -z "$FORGERIFT_KEY" ]; then
  echo "ERROR: A ForgeRift License Key is required."
  echo "  Subscribe at forgerift.io to get one."
  exit 1
fi

echo "Validating subscription..."
VALIDATE_RESPONSE=$(curl -fsSL \
  "https://payments.104-131-74-82.sslip.io/validate?token=${FORGERIFT_KEY}" \
  2>/dev/null || echo '{"valid":false,"reason":"Network error — check internet connectivity"}')

if echo "$VALIDATE_RESPONSE" | grep -q '"valid":true'; then
  echo "✓ Subscription confirmed"
else
  REASON=$(echo "$VALIDATE_RESPONSE" | grep -o '"reason":"[^"]*"' | head -1 | sed 's/"reason":"//;s/"$//')
  echo "ERROR: Subscription validation failed."
  [ -n "$REASON" ] && echo "  Reason: $REASON"
  echo "  Check your key or visit forgerift.io to manage your subscription."
  echo "  Support: support@forgerift.io"
  exit 1
fi
echo ""

# ── 2. Detect public IP ────────────────────────────────────────────────────

echo "Detecting public IP..."
PUBLIC_IP=$(curl -4 -fsSL https://icanhazip.com 2>/dev/null || \
            curl -4 -fsSL https://ifconfig.me 2>/dev/null || \
            hostname -I | awk '{print $1}')
PUBLIC_IP="${PUBLIC_IP//[[:space:]]/}"

if [ -z "$PUBLIC_IP" ]; then
  echo "ERROR: Could not detect public IP. Set PUBLIC_IP manually and re-run."
  exit 1
fi

# Convert IP dots to dashes for sslip.io domain (e.g. 1.2.3.4 → 1-2-3-4.sslip.io)
SSLIP_DOMAIN="${PUBLIC_IP//./-}.sslip.io"
MCP_URL="https://${SSLIP_DOMAIN}/mcp"

echo "✓ Public IP:   $PUBLIC_IP"
echo "✓ TLS domain:  $SSLIP_DOMAIN"
echo "✓ MCP URL:     $MCP_URL"
echo ""

# ── 3. Check / install Node.js ────────────────────────────────────────────

if ! command -v node &>/dev/null; then
  echo "Installing Node.js 20..."
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash - >/dev/null 2>&1
  apt-get install -y nodejs >/dev/null 2>&1
fi
echo "✓ Node.js $(node -v)"

if ! command -v npm &>/dev/null; then
  echo "ERROR: npm not found after Node install."
  exit 1
fi
echo "✓ npm $(npm -v)"

# ── 4. Install PM2 ────────────────────────────────────────────────────────

if ! command -v pm2 &>/dev/null; then
  echo "Installing PM2 globally..."
  npm install -g pm2 >/dev/null 2>&1
fi
echo "✓ PM2 $(pm2 -v)"

# ── 5. Install dependencies + build ──────────────────────────────────────

echo ""
echo "Installing dependencies..."
cd "$INSTALL_DIR"
npm install --include=dev >/dev/null 2>&1

echo "Building TypeScript..."
npm run build >/dev/null 2>&1

if [ ! -f "$INSTALL_DIR/dist/index.js" ]; then
  echo "ERROR: Build failed — dist/index.js not found."
  exit 1
fi
echo "✓ Build complete"

# ── 6. Generate .env ──────────────────────────────────────────────────────

TOKEN="$FORGERIFT_KEY"

if [ -f "$ENV_FILE" ]; then
  echo ""
  echo "Existing .env found — updating auth token with validated ForgeRift key."
  while IFS='=' read -r k v; do
    [[ "$k" =~ ^[A-Z_]+$ ]] && export "$k=$v"
  done < "$ENV_FILE"

  # Update or insert MCP_AUTH_TOKEN
  if grep -q "^MCP_AUTH_TOKEN=" "$ENV_FILE"; then
    sed -i "s|^MCP_AUTH_TOKEN=.*|MCP_AUTH_TOKEN=$TOKEN|" "$ENV_FILE"
  else
    echo "MCP_AUTH_TOKEN=$TOKEN" >> "$ENV_FILE"
  fi

  # Ensure PUBLIC_URL is set (added in v1.2.0 — may be missing in older .env files)
  if ! grep -q "^PUBLIC_URL=" "$ENV_FILE" 2>/dev/null; then
    echo "PUBLIC_URL=https://${SSLIP_DOMAIN}" >> "$ENV_FILE"
    echo "✓ Added PUBLIC_URL to existing .env"
  fi

  # Ensure RATE_LIMIT_PER_MIN is set (added in v1.2.0)
  if ! grep -q "^RATE_LIMIT_PER_MIN=" "$ENV_FILE" 2>/dev/null; then
    echo "# RATE_LIMIT_PER_MIN=60" >> "$ENV_FILE"
  fi

  echo "✓ Auth token updated in .env"
  echo ""
  echo "  -> If you previously configured a Cowork or Claude Desktop connector"
  echo "     with an old token, update it now to the token printed below."
  echo ""
else
  echo ""
  cat > "$ENV_FILE" <<ENVEOF
# ── Required ──────────────────────────────────────────────────────────────────
MCP_AUTH_TOKEN=$TOKEN

# ── Auto-detected (used by OAuth discovery endpoints) ─────────────────────────
PUBLIC_URL=https://${SSLIP_DOMAIN}

# ── Optional (defaults shown) ─────────────────────────────────────────────────
PORT=$MCP_PORT
# APP_DIR=/root/myapp
# PM2_LOG_DIR=/root/.pm2/logs
# AUDIT_LOG_PATH=/root/mcp-audit.log
# ALLOWED_PROCESSES=my-api,my-worker
# MAX_CUSTOM_COMMANDS_PER_SESSION=10
# MAX_LOG_LINES=50
# MAX_OUTPUT_CHARS=3000
# MAX_FILE_LINES=100
# ALLOWED_READ_DIRS=/root/myapp,/root/.pm2/logs
# ALLOWED_REDIRECT_HOSTS=my-custom-domain.com
# RATE_LIMIT_PER_MIN=60
# AUDIT_MAX_SIZE_MB=10
ENVEOF

  echo "✓ ForgeRift key saved as auth token in .env"
fi

# ── 7. Install nginx + certbot ────────────────────────────────────────────

echo ""
echo "Installing nginx and certbot..."
apt-get update -qq >/dev/null 2>&1
apt-get install -y nginx certbot python3-certbot-nginx >/dev/null 2>&1
echo "✓ nginx + certbot installed"

# Write nginx config for the sslip.io domain
NGINX_CONF="/etc/nginx/sites-available/vps-mcp"
cat > "$NGINX_CONF" <<NGINXEOF
server {
    listen 80;
    server_name $SSLIP_DOMAIN;

    location / {
        proxy_pass         http://127.0.0.1:$MCP_PORT;
        proxy_http_version 1.1;
        proxy_set_header   Upgrade \$http_upgrade;
        proxy_set_header   Connection 'upgrade';
        proxy_set_header   Host \$host;
        proxy_set_header   X-Real-IP \$remote_addr;
        proxy_cache_bypass \$http_upgrade;

        # Streamable HTTP / SSE — do not buffer
        proxy_buffering    off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        chunked_transfer_encoding on;
    }
}
NGINXEOF

ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/vps-mcp 2>/dev/null || true
rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true
nginx -t >/dev/null 2>&1 && systemctl reload nginx >/dev/null 2>&1
echo "✓ nginx configured for $SSLIP_DOMAIN"

# Obtain Let's Encrypt certificate
echo "Obtaining TLS certificate (Let's Encrypt)..."
echo "  This may take 30–60 seconds..."
if certbot --nginx -d "$SSLIP_DOMAIN" \
     --non-interactive --agree-tos \
     --email "admin@${SSLIP_DOMAIN}" \
     --redirect \
     >/dev/null 2>&1; then
  echo "✓ TLS certificate issued for $SSLIP_DOMAIN"
else
  echo "WARNING: certbot failed. TLS cert not issued."
  echo "  Ensure port 80 is open and $SSLIP_DOMAIN resolves to $PUBLIC_IP."
  echo "  After fixing, run: certbot --nginx -d $SSLIP_DOMAIN"
  echo "  Continuing setup without TLS — MCP will not be reachable from Cowork."
fi

# ── 8. Configure PM2 + startup persistence ────────────────────────────────

echo ""

if pm2 describe "$PM2_NAME" &>/dev/null; then
  echo "Restarting existing $PM2_NAME process..."
  pm2 restart "$PM2_NAME" >/dev/null 2>&1
else
  echo "Starting $PM2_NAME via PM2..."
  pm2 start "$ECOSYSTEM" >/dev/null 2>&1
fi

pm2 save >/dev/null 2>&1
pm2 startup systemd -u root --hp /root >/dev/null 2>&1 \
  && systemctl enable pm2-root >/dev/null 2>&1 \
  || true
echo "✓ PM2 running + auto-start on reboot configured"

# ── 9. Firewall: lock port 3001 to localhost ──────────────────────────────

echo ""
echo "Hardening firewall..."

# Remove any existing rule for this port, then re-add clean
iptables -D INPUT -p tcp --dport "$MCP_PORT" -j DROP 2>/dev/null || true
iptables -I INPUT 1 -p tcp --dport "$MCP_PORT" -j DROP

# Persist across reboots
if command -v netfilter-persistent &>/dev/null; then
  netfilter-persistent save >/dev/null 2>&1
elif command -v iptables-save &>/dev/null; then
  apt-get install -y iptables-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null 2>&1 || true
fi

echo "✓ Port $MCP_PORT locked to localhost (nginx proxies TLS → localhost)"

# ── 10. Verify + print connect instructions ────────────────────────────────

sleep 2

echo ""
echo "======================================================"
echo "  Setup Complete"
echo "======================================================"
echo ""

if pm2 describe "$PM2_NAME" 2>/dev/null | grep -q "online"; then
  echo "✓ $PM2_NAME is running"
else
  echo "WARNING: Process may not have started."
  echo "  Check: pm2 logs $PM2_NAME --lines 30"
fi

echo ""
echo "Your MCP endpoint:"
echo ""
echo "  $MCP_URL"
echo ""
echo "Your auth token (this is your ForgeRift License Key — keep it secret):"
echo ""
echo "  $TOKEN"
echo ""
echo "────────────────────────────────────────────────────────"
echo "  How to connect in Cowork"
echo "────────────────────────────────────────────────────────"
echo ""
echo "  1. Open Cowork → Settings → MCP Connectors"
echo "  2. Click 'Add connector' and enter:"
echo "       URL:   $MCP_URL"
echo "       Token: $TOKEN  (same as your ForgeRift License Key)"
echo "  3. Click Connect."
echo "  4. Done — ask Claude 'Check my VPS health' to verify."
echo ""
echo "  Advanced: Claude Desktop config (claude_desktop_config.json):"
echo "    Add this to your mcpServers section:"
echo ""
echo '    "vps-control": {'
echo '      "command": "mcp-remote",'
echo '      "args": ['
echo "        \"$MCP_URL\","
echo '        "--header",'
echo "        \"Authorization: Bearer $TOKEN\""
echo '      ]'
echo '    }'
echo ""
echo "────────────────────────────────────────────────────────"
echo "  Support"
echo "────────────────────────────────────────────────────────"
echo ""
echo "  Docs:     https://github.com/ForgeRift/vps-control-mcp"
echo "  Support:  support@forgerift.io"
echo ""
