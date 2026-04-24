# Troubleshooting — VPS Control MCP

## Common Issues

**Cowork says "Couldn't reach the MCP server"**
Check that the MCP process is running: SSH to VPS and run `pm2 status vps-mcp`. If it shows "errored" or "stopped", check logs with `pm2 logs vps-mcp --lines 50`. Common causes: TLS certificate expired (re-run certbot renewal), port not open (check `ufw status`), or process crashed after a bad deploy.

**OAuth handshake fails or loops**
Disconnect the connector in Cowork settings, wait 10 seconds, then reconnect. The "server disconnected" flash during reconnection is normal — it's the OAuth handshake completing. If it persists, check that the OAuth discovery endpoint is reachable at your VPS domain.

**Commands blocked unexpectedly**
The three-tier security model (RED/AMBER/GREEN) blocks 100+ dangerous patterns server-side. Check the error message for the category. Common false positives: `&&` and `;` in awk/sed expressions trigger the chaining block. Workaround: use `git -C <path>` instead of `cd <path> && git ...`, or use separate tool calls.

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
- **72 restarts since last deploy:** The high restart count on `vps-mcp` in PM2 is expected — each deploy_vps_mcp call restarts the process. This is not indicative of instability.
