# Getting Started with vps-control-mcp

Welcome. This guide walks you through connecting Claude to your VPS (Virtual Private Server) so you can manage it through conversation — deploy code, check logs, restart services, and more — without logging into the server yourself.

**Not sure if this is the right plugin?** If you want to control your Windows PC rather than a remote Linux server, see [local-terminal-mcp](https://github.com/ForgeRift/local-terminal-mcp) instead.

---

## What Does This Actually Do?

vps-control-mcp gives Claude a secure connection to your Linux VPS. Once connected, you can say things like:

- *"Check if my Node app is running and show me the last 50 lines of logs"*
- *"Deploy the latest version of my backend from the main branch"*
- *"Restart nginx and verify the site is responding"*
- *"How much disk space is left and which directories are biggest?"*
- *"Show me any errors in the last hour from my app logs"*

Claude runs commands on your server, reads the output, and responds in plain English. You stay in Claude — no SSH client required.

---

## What You'll Need Before Starting

Before you install anything, make sure you have:

1. **A Linux VPS** — Any Ubuntu 20.04+ or Debian 11+ server works. DigitalOcean, Linode, Vultr, Hetzner, AWS EC2, etc. all work. You need root or sudo access. If you don't have a VPS yet, DigitalOcean's $6/mo Droplet is a good starting point.

2. **A Claude account** — Claude Pro, Team, or Enterprise plan. The free plan doesn't support plugins. If you're not sure which plan you have, check at [claude.ai](https://claude.ai).

3. **A ForgeRift subscription token** — You get this when you subscribe at [forgerift.io](https://forgerift.io). It looks like a long string of letters and numbers. Keep it handy.

4. **SSH access to your server** — You need to be able to SSH in at least once to run the setup script. If you're currently using a password to SSH in, that's fine. You don't need an SSH key set up yet — the installer can help with that.

5. **Node.js on your VPS** — The plugin runs as a Node.js process on your server. The setup script checks for this and installs it if missing.

---

## Step 1: Run the Server-Side Setup Script

SSH into your VPS:

```
ssh root@your-server-ip
```

Then run the ForgeRift setup script:

```
curl -fsSL https://forgerift.io/install/vps-control.sh | bash
```

This script:
- Checks for Node.js 18+ and installs it if missing
- Clones the vps-control-mcp repository
- Creates a `.env` file for your configuration
- Sets up the plugin as a PM2 process (so it restarts if the server reboots)
- Configures nginx to proxy HTTPS traffic to the plugin

When the script finishes, it prints your **plugin URL** — something like `https://vps-control.104-131-74-82.sslip.io`. Write this down.

---

## Step 2: Configure Your Environment

The setup script creates a `.env` file at `/root/vps-control-mcp/.env`. Open it:

```
nano /root/vps-control-mcp/.env
```

You'll see:

```
MCP_AUTH_TOKEN=          # Required — set this first
ANTHROPIC_API_KEY=       # Required for AI safety review (Layer 3)
PORT=3010
AUDIT_LOG_PATH=/root/vps-control-mcp/audit.log
APP_DIR=/root/vps-control-mcp
```

**Fill in the required values:**

- **MCP_AUTH_TOKEN** — Make up a strong secret here (like a random 32-character string). This is the password Claude uses to connect to your plugin. Keep it secret — anyone with this token can run commands on your server.

  To generate one: `openssl rand -hex 16`

- **ANTHROPIC_API_KEY** — Your Anthropic API key from [console.anthropic.com](https://console.anthropic.com). This is separate from your Claude account — it's used by the plugin's AI safety layer to review potentially risky commands before running them. The key needs enough credits to run occasional reviews; typical usage costs pennies per day.

Save the file (`Ctrl+X`, then `Y`, then Enter) and restart the plugin:

```
pm2 restart vps-mcp
```

---

## Step 3: Add the Plugin to Claude Desktop

Open Claude Desktop on your computer. Go to **Settings → Plugins → Add Plugin**.

Enter:
- **Plugin URL:** The URL from Step 1 (e.g., `https://vps-control.104-131-74-82.sslip.io`)
- **Auth token:** The `MCP_AUTH_TOKEN` value you set in Step 2

Click **Connect**. If everything worked, you'll see vps-control-mcp appear in your active plugins list.

---

## Step 4: Verify the Connection

Start a new conversation in Claude and type:

```
Check my VPS health
```

Claude should respond with your server's CPU, memory, disk usage, and the status of any PM2 processes. If you see a connection error instead, see [Troubleshooting](#troubleshooting) below.

---

## Step 5: Your First 5 Minutes

Here are some things to try right away to get comfortable with how the plugin works:

**Check what's running:**
> *"What processes are running under PM2? Show me their status and memory usage."*

**Look at your app logs:**
> *"Show me the last 100 lines of logs from my main app."*

**Check disk usage:**
> *"How much disk space am I using? Break it down by directory under /var."*

**Check a service:**
> *"Is nginx running? Show me its status."*

**See recent errors:**
> *"Were there any errors in the last hour? Check PM2 logs and nginx error logs."*

---

## What Claude Can Do on Your Server

### Reading and Monitoring (always available)
- View running processes, PM2 status, system resource usage
- Read log files and filter by time range or keyword
- Check service status (nginx, postgresql, redis, etc.)
- View file contents, directory listings, disk usage
- Inspect git status and recent commits
- Check open ports and network connections
- Read your audit log (every command Claude runs is logged)

### Deployments (AMBER — AI-reviewed)
- Pull latest code from GitHub
- Run build commands (`npm run build`, `go build`, etc.)
- Restart PM2 processes or nginx
- Run database migrations
- Check deployment health after a deploy

### Configuration Changes (AMBER — AI-reviewed)
- Edit configuration files
- Set environment variables
- Modify nginx config and reload
- Manage cron jobs

### What's Blocked (see [COMMANDS.md](COMMANDS.md) for the full list)
Anything that could cause irreversible damage to your server is blocked at the code level — no AI review, no exceptions. This includes things like wiping databases, modifying the firewall, rewriting git history on pushed branches, and deleting system files. See COMMANDS.md for the complete breakdown.

---

## Realistic Workflow Examples

### Deploying a new version of your app
> *"Deploy the latest from the main branch. Pull the new code, rebuild, and restart the app. Let me know when it's back up and healthy."*

Claude will: `git pull`, run your build command, restart the PM2 process, wait a moment, then check that the process is running and (if you have a health endpoint) that it's responding.

### Debugging a crash
> *"My app crashed at around 2pm today. Show me what happened."*

Claude will check PM2 logs around that time, look for error messages, check if the process restarted itself, and summarize what it found.

### Monitoring a deploy you already did
> *"I just deployed 10 minutes ago. Is everything healthy? Any errors since then?"*

Claude checks PM2 status, recent error logs, and system resources — then gives you a quick verdict.

### Cleaning up disk space
> *"I'm running low on disk. Find the biggest directories and suggest what's safe to clean up."*

Claude runs `du` to identify large directories, then suggests candidates (old logs, build artifacts, node_modules, Docker images) while being cautious about anything that might be needed.

### Setting up a new service
> *"I want to add Redis to this server. Walk me through installing and configuring it for my Node app."*

Claude will check if Redis is already installed, install it if not, start the service, add it to PM2's startup config, and then help you add the connection string to your app's environment.

---

## Security Model in Plain English

Every command Claude tries to run goes through three layers of review:

1. **Pattern scanner (Layer 2)** — A list of 275+ patterns built into the plugin code. Anything matching a HARD_BLOCKED pattern is rejected immediately without running. Anything matching a BLOCKED pattern goes to Layer 3 for review.

2. **AI safety board (Layer 3)** — For AMBER-tier commands, the plugin sends the command and your full conversation context to a separate Anthropic API call. The safety board decides whether the command makes sense given what you're actually trying to do. If it approves, the command runs. If not, it's blocked.

3. **Audit log** — Every command attempt — approved or blocked — is written to `audit.log` on your server with a timestamp. You can ask Claude to show it to you at any time: *"Show me the audit log from today."*

Your MCP_AUTH_TOKEN is the key to all of this. Keep it secret. Rotate it if you think it was exposed. Don't commit it to GitHub.

---

## Troubleshooting

### "Connection refused" or Claude can't reach the plugin

1. Check that PM2 is running: SSH into your server and run `pm2 status`. Look for `vps-mcp` with status `online`.
2. Check that nginx is running: `systemctl status nginx`
3. Check that port 443 is open in your server's firewall. In your hosting provider's control panel, make sure inbound TCP 443 is allowed.
4. Test the URL directly: `curl https://your-plugin-url/health` — should return `{"status":"ok"}`.

### "Auth token invalid"

The token Claude is using doesn't match `MCP_AUTH_TOKEN` in your `.env`. Double-check both:
- The token in Claude Desktop's plugin settings
- The `MCP_AUTH_TOKEN` value in `/root/vps-control-mcp/.env`

They must match exactly — no extra spaces, no missing characters.

### "Layer 3 timed out" or safety review errors

The plugin's AI safety review uses `ANTHROPIC_API_KEY` to make API calls. Check:
- The key in `.env` is valid and not expired
- Your Anthropic account has remaining credits
- Test the key: `curl https://api.anthropic.com/v1/messages -H "x-api-key: YOUR_KEY" -H "anthropic-version: 2023-06-01" -H "content-type: application/json" -d '{"model":"claude-haiku-4-5-20251001","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}'`

### Plugin isn't running after a server reboot

PM2 should auto-restart the plugin. If it didn't: `pm2 resurrect`. If PM2 itself isn't starting: `pm2 startup` and follow the printed instructions to enable PM2's systemd service.

### Commands are unexpectedly blocked

See [COMMANDS.md](COMMANDS.md) for the full breakdown of AMBER and RED categories. If a legitimate operation is being blocked and you think it shouldn't be, contact support@forgerift.io with the specific command and context.

---

## Updating the Plugin

```
cd /root/vps-control-mcp
git pull
npm install
npm run build
pm2 restart vps-mcp
```

Or ask Claude: *"Update the vps-control plugin to the latest version."* — it can run this sequence for you.

---

## Uninstalling

```
pm2 stop vps-mcp
pm2 delete vps-mcp
pm2 save
cd /root && rm -rf vps-control-mcp
```

Then remove the nginx configuration for the plugin (`/etc/nginx/sites-enabled/vps-control`) and reload nginx.

---

---

## Step 6: Set Up Claude as Your Plugin Expert (Recommended)

Claude works even better when it already knows how vps-control-mcp works — which tools are available, what commands are blocked, and how to interpret what it sees on your server. This step primes Claude with that knowledge so it can self-diagnose common issues and give you accurate guidance without you having to explain the plugin each time.

**Pick one option:**

### Option A: Claude Project (best for ongoing use)
1. In Claude, go to **Projects** and open or create a project for your VPS work
2. Add **[CLAUDE_CONTEXT.md](CLAUDE_CONTEXT.md)** as a project file
3. Every conversation in that project automatically has full plugin context

### Option B: Add to Claude Memory
Start a new Claude conversation and paste:

> *"Please remember the following about my vps-control-mcp setup: [paste the contents of CLAUDE_CONTEXT.md]. Reference this any time I ask about my server, deployments, logs, or my ForgeRift plugin."*

### Option C: Paste at Session Start
Paste the contents of [CLAUDE_CONTEXT.md](CLAUDE_CONTEXT.md) at the start of any troubleshooting session. Claude will use it for that conversation.

---

**What CLAUDE_CONTEXT.md contains:** all 17 tools and what they do, the full RED/AMBER/GREEN security model with command examples, common gotchas, configuration reference, and diagnostic prompts.

Once loaded, try:
> *"I’m having trouble with [describe issue]. What’s the most likely cause given how vps-control-mcp works?"*

## Getting Help

- **Documentation:** [COMMANDS.md](COMMANDS.md) | [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | [SECURITY.md](SECURITY.md)
- **Support:** support@forgerift.io
- **Security issues:** security@forgerift.io (do not post publicly)
- **GitHub:** [github.com/ForgeRift/vps-control-mcp](https://github.com/ForgeRift/vps-control-mcp)

When contacting support, include your plugin version (`pm2 info vps-mcp | grep version`) and the relevant portion of your audit log.

---

*Next: See [COMMANDS.md](COMMANDS.md) for a full breakdown of what's allowed, reviewed, and blocked.*
