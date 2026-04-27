> **Tip:** For faster diagnosis, load [CLAUDE_CONTEXT.md](CLAUDE_CONTEXT.md) into your Claude Project or paste it at the start of your session. It primes Claude with full plugin knowledge so it can help you self-diagnose most issues.

# Troubleshooting — VPS Control MCP

## "Click to Reconnect" Prompt

You will occasionally see a **"click to reconnect"** prompt in Claude Desktop or Cowork. This is expected and not a sign anything is broken.

**Why it happens:** vps-control-mcp runs as a persistent process on your VPS. When it restarts — during an update, after a server reboot, or if PM2 autorestarted it after a crash — the active connection drops and your Claude client detects the gap. vps-control-mcp now restores the session transparently when a Cowork SSE client reconnects after a restart (a GET on an unknown session ID recreates the server+transport under the original session ID — see CHANGELOG 1.10.7). The "click to reconnect" prompt only appears when the client cannot reach the server at all (TLS expiry, nginx down, port held by a stale process).

**What to do:** Click the reconnect button. The session restores instantly — no reconfiguration, no lost context. The first tool call after reconnect will include a brief note confirming the restart happened.

**What you don't need to do:** You do not need to re-enter your auth token, re-add the connector, or restart Claude Desktop.

**How often it happens:** Roughly once per deploy (updates are pushed periodically). Unexpected restarts outside of deploys usually mean PM2 restarted the process after a transient error — check `get_recent_errors` for vps-mcp if you want to investigate.

---

## Common Issues

**Cowork says "Couldn't reach the MCP server"**
Check that the MCP process is running: SSH to VPS and run `pm2 status vps-mcp`. If it shows "errored" or "stopped", check logs with `pm2 logs vps-mcp --lines 50`. Common causes: TLS certificate expired (re-run certbot renewal), port not open (check `ufw status`), or process crashed after a bad deploy.

**OAuth handshake fails or loops**
Disconnect the connector in Cowork settings, wait 10 seconds, then reconnect. The "server disconnected" flash during reconnection is normal — it's the OAuth handshake completing. If it persists, check that the OAuth discovery endpoint is reachable at your VPS domain.

**Commands blocked unexpectedly**
The three-tier security model (RED/AMBER/GREEN) blocks 275+ dangerous patterns server-side. Check the error message for the category. Common false positives: `&&` and `;` in awk/sed expressions trigger the chaining block. Workaround: use `git -C <path>` instead of `cd <path> && git ...`, or use separate tool calls.

**Git commit message gets mangled**
The VPS MCP strips quotes from git commit messages when they contain spaces. Workaround: use hyphenated-no-space commit messages (e.g., `security-hardening-v1.2.0` instead of `"security hardening v1.2.0"`).

**Deploy job status shows "running" forever**
The deploy process restarts the MCP server mid-deploy, which wipes the in-memory job store. Job state is persisted to `deploy-jobs.json` — check that file for the actual status. If the file is missing, the deploy likely completed but the status wasn't persisted. Check `pm2 status` and `git log` to verify.

**Background command timeout**
Commands that take longer than 30 seconds should use `run_in_background=true`. This returns a job ID immediately — poll with `get_job_status` to check completion. Without this flag, long commands will time out and return an error.

---

## Known Issues

- **Command chaining blocked:** `&&`, `;`, backticks, `node -e`, `npx` are all blocked by the security model. Use separate tool calls or `git -C` workaround for multi-step operations.
- **Commit message quote stripping:** Spaces in git commit messages cause issues when passed through the MCP. Use hyphenated messages without quotes.
- **read_file_section path restriction:** File reads are restricted to `ALLOWED_READ_DIRS` (set in `.env`, defaults to your `APP_DIR` and `PM2_LOG_DIR`). Files outside these directories must be accessed via `run_approved_command` with `cat` or `head`.
- **`.env` file access blocked:** Reading `.env` files is blocked by the sensitive file guard (info-leak category). This is correct security behavior — environment variables should not be exposed via MCP.
- **High restart count in PM2:** A large restart count on `vps-mcp` is expected — each `deploy_vps_mcp` call restarts the process. This is not indicative of instability. Concern only if the process is in a crash loop (restart count climbing in real-time with no deploys in progress).
- **Reconnect prompt after deploy:** Each deploy restarts vps-mcp, which drops the active connection. vps-control-mcp transparently restores the session when a Cowork SSE client reconnects (see CHANGELOG 1.10.7). The "click to reconnect" prompt is a fallback for edge cases where the server cannot be reached at all (TLS expiry, nginx down, port held by a stale process). See the "Click to Reconnect" section at the top of this file for full details.

## Support

- **GitHub Issues:** [github.com/ForgeRift/vps-control-mcp/issues](https://github.com/ForgeRift/vps-control-mcp/issues)
- **Email:** support@forgerift.io
- **Security vulnerabilities:** security@forgerift.io (90-day responsible disclosure)
