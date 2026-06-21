# Claude Context — vps-control-mcp
*Add this file to your Claude Project, paste it into Claude memory, or include it at the start of any session where you want Claude to act as a knowledgeable expert on this plugin.*

---

## How to Use This Context

When this document is loaded, treat yourself as the user's expert assistant for vps-control-mcp. Default behaviors:

- **Use the MCP tools directly** to verify state. Don't ask the user to paste output you can fetch yourself — `get_pm2_status`, `get_recent_errors`, `read_audit_log`, `get_system_health` exist for exactly this.
- **When a command is blocked**, tell the user the tier (GREEN/AMBER/RED), which category triggered it, and offer the exact manual SSH equivalent.
- **For deploys**, monitor via `get_deploy_status` or poll `get_job_status`. Don't wait silently.
- **Lead any diagnosis** with `get_pm2_status` + `get_recent_errors` + `read_audit_log` before guessing.
- **When uncertain about a command's tier**, assume AMBER and ask the user for context before running it — Layer 3 gives better results with more context.

---

## What This Plugin Is

**vps-control-mcp** gives Claude a secure, audited connection to a Linux VPS. It runs as a Node.js process on your server, exposes 18 structured tools over HTTPS, and enforces a three-tier security model that hard-blocks dangerous operations at the code level — before any AI review.

**Built by:** ForgeRift LLC  
**Version:** 1.13.2  
**License:** BUSL 1.1 (converts to MIT 4 years from each version's release date; see CHANGELOG.md)  
**Docs:** github.com/ForgeRift/vps-control-mcp

### Architecture & Transport

vps-control-mcp uses **StreamableHTTP over HTTPS**. Default: port 3001 on the VPS, fronted by nginx + Let's Encrypt (sslip.io pattern, no custom domain required). Bearer token auth via `MCP_AUTH_TOKEN`. OAuth 2.0 discovery + dynamic client registration also supported for Cowork compatibility.

Every command passes through three security layers before executing:
- **Layer 1:** Hard-coded RED block list — regex + path checks in source code. Instant rejection, no AI consulted.
- **Layer 2:** Claude Haiku BLOCKED-tier pre-classifier (deterministic pattern match → Haiku AI check). Layer 3: multi-persona BLOCKED-tier board (Sonnet). AMBER is a separate tier that warns but does not invoke AI — AMBER commands proceed after dry-run confirmation. If Layer 2/3 is unreachable (missing API key, no credits, network failure), behavior is controlled by `LAYER_STRICT_MODE` (default: block / fail-closed; set `LAYER_STRICT_MODE=false` to allow pass-through).
- **Layer 3:** Multi-persona safety board (Sonnet) for BLOCKED-tier commands requiring deeper context review.

---

## What This Plugin Cannot Do

- **Edit files** — file access is read-only (`read_file_section`, `search_file`). Writes go through `run_approved_command` and hit AMBER review.
- **Run interactive commands** — no TTY. Commands that expect stdin input will hang or error.
- **Persist environment changes** — each `run_approved_command` call is a fresh shell. `export VAR=x` in one call won't carry over to the next.
- **Access files outside ALLOWED_READ_DIRS** — unless via `run_approved_command` with `cat`.
- **Read sensitive files** — `.env`, SSH keys, `/etc/shadow`, cloud credentials are blocked even inside allowed dirs.
- **Execute RED-tier commands** — ever. No override, no context that unlocks them.

---

## The 18 Available Tools

### Monitoring (read-only, always GREEN)
- `get_pm2_status` — all PM2 processes: name, status, memory, CPU, uptime, restart count
- `get_recent_errors` — tail stderr log for a named PM2 process
- `get_recent_output` — tail stdout log for a named PM2 process
- `get_system_health` — disk usage, memory, uptime
- `read_audit_log` — immutable log of every tool call made through this plugin

### File Access (read-only, always GREEN)
- `read_file_section` — read a line range from a file inside ALLOWED_READ_DIRS
- `search_file` — regex search within an allowed file

### Git Operations
- `git_status` — working tree status (GREEN)
- `git_log` — recent commits (GREEN)
- `git_pull` — fetch + merge from origin (AMBER)
- `git_push` — push to origin (AMBER)

### Deployment
- `deploy` — full pipeline: pull → install → build → restart → health check (AMBER)
- `deploy_vps_mcp` — specialized deploy of the vps-control-mcp process itself (AMBER)
- `deploy_client` — build the client container + publish its `dist/` to the fixed `CLIENT_WEB_ROOT` nginx web root (AMBER; opt-in, disabled until `CLIENT_WEB_ROOT` is set; requires `confirm:true`; destination never caller-supplied)
- `get_deploy_status` — poll a background deploy job (GREEN)

### Process Control
- `restart_process` — gracefully restart a named PM2 process (AMBER)

### Escape Hatch
- `run_approved_command` — arbitrary shell with RED-tier blocking, rate limiting, and audit logging (AMBER/RED depending on command)
- `get_job_status` — poll output of a background command (GREEN)

---

## Security Model — Three Tiers

### ✅ GREEN — Runs Immediately
Read-only and low-risk operations. No AI review required. Examples:
- `ls`, `cat`, `du`, `df`, `free`, `uptime`
- `ps`, `top`, `netstat`, `ss`
- `git status`, `git log`
- `pm2 status`, `systemctl status`
- `dig`, `nslookup`, `host`
- `crontab -l` (read-only)
- Any `get_*` or `read_*` tool

**Rule:** If it reads, lists, searches, or reports without changing state → GREEN.

### ⚠️ AMBER — AI Safety Board Reviews Before Running
Legitimate but potentially dangerous. Layer 3 reads the full conversation context and decides. The more context the user provides, the more accurately Layer 3 assesses intent.

| Category | What It Covers | Usually Approved | May Be Blocked |
|----------|---------------|-----------------|----------------|
| Command chaining | `&&`, `;`, `\|` | `git pull && npm run build` during a deploy | Chains mixing read + destructive ops without context |
| Code execution | `python3 -c`, `node -e` | Simple one-liners | Obfuscated or remote-loading code |
| File write | `>`, `tee`, `echo >>` | Writing to project directory | Writing to system paths |
| File deletion | `rm`, `rmdir` | Deleting build artifacts | Deleting outside project dir |
| Service management | `systemctl start/stop/restart/enable` | Restarting nginx after config change | Disabling security services |
| Package install | `apt install`, `npm install -g` | Package for active setup task | Unrelated or attack-adjacent packages |
| Data exfiltration | `curl` posting data out, `scp` | Posting to own API endpoint | Unexplained outbound transfers |
| Privilege escalation | `sudo su`, `su -` | `sudo` for a specific named command | Switching to root and staying |
| Persistence | `crontab`, `systemd` units | Backup cron job you designed | Hidden or root tasks without context |
| Direct DB access | `psql`, `mysql` write ops | `SELECT` queries for debugging | `DROP`/`DELETE` without clear dev/staging context |
| git pull / git push | Fetch/push to origin | All standard usage | Force push → RED |
| Environment vars | `export`, `.env` edits | Adding a var for an active setup | Modifying system-wide PATH or security config |

**How to help Layer 3 approve:** Give context before the command. "I'm deploying v1.2 of my API and need to restart nginx" works far better than issuing a cold restart.

### RED â€” Always Blocked Without an Audited Opt-Out
Hard-coded in source. The AI safety layer is never consulted. Offer to write the manual SSH equivalent and walk the user through it step by step. (Operators with a justified workflow can demote a specific binary via the `BYPASS_BINARIES` env var; every use is logged as `[SECURITY-BYPASS]`.)

**Permanently blocked:**
- `rm -rf /` or recursive deletion targeting home/root/system paths
- `curl ... | bash` or `wget ... | sh` (download-and-execute)
- `git push --force` to a remote (destructive history rewrite)
- `dd if=... of=/dev/sda` or raw disk writes
- `insmod`, `modprobe` with custom modules (kernel probe insertion)
- `chmod -R 777 /` or mass OS permission destruction
- `shutdown`, `reboot`, `halt`, `init 0`
- Deleting or truncating the audit log
- `docker system prune -af` or mass container destruction
- `DROP DATABASE`, `DROP TABLE` in production context
- Writing to `/etc/`, `/bin/`, `/sbin/`, `/usr/bin/`, `/lib/`
- `iptables -F` or disabling `ufw`
- Reading SSH private keys, `/etc/shadow`, cloud credential directories
- Obfuscated root-level cron jobs (hard-blocked persistence variant)
- `eval` piped from untrusted sources, remote-loading exec variants

---

## Common Gotchas

**"Click to Reconnect" prompt (Cowork)**
Expected after any vps-mcp restart: every `deploy_vps_mcp`, sometimes `deploy` of other processes, manual `pm2 restart vps-mcp`, or the 256MB heap cap forcing a restart. One click within 5–10 seconds of the prompt appearing is normal. No reconfiguration needed.

*Not normal:* the click does nothing, the prompt reappears every few minutes, or appears with no recent deploy. Likely causes:
- vps-mcp crash-looping — SSH in, run `pm2 status vps-mcp`. If `errored` or the restart count is climbing, check `pm2 logs vps-mcp --lines 100`.
- TLS cert expired — check nginx error log.
- `MCP_AUTH_TOKEN` mismatch after a recent `.env` edit.
- Port 3001 held by a stale process.

*Important:* After `deploy_vps_mcp` specifically (deploying the MCP onto itself), reconnect may require a click *and* sometimes a second click after PM2 finishes restarting. If two clicks fail, SSH in and verify `pm2 status vps-mcp` shows `online`.

*Also important:* Reconnecting does **not** restore in-memory job state. Any in-flight `get_deploy_status` poll loses its job ID on restart. After reconnect, verify deploy success via `pm2 status` + `git log` instead.

---

**Commit message quote stripping**
Spaces in git commit messages get mangled through the MCP. Use hyphenated-no-space messages: `security-fix-v1.2` not `"security fix v1.2"`.

**Deploy job status "running" forever**
The deploy restarts vps-mcp mid-process, wiping the in-memory job store. Check `deploy-jobs.json` on the server for actual status. Then verify with `pm2 status` + `git log`.

**Background command timeout**
Commands over 30 seconds need `run_in_background=true`. Returns a job ID; poll with `get_job_status`. Without this flag, long commands time out and return an error.

**`&&` chaining blocked**
Use `git -C /path/to/repo` instead of `cd /path && git ...`. Or break into separate tool calls.

**`read_file_section` path restriction**
Only reads from `ALLOWED_READ_DIRS` (set in `.env`). Files outside this require `run_approved_command` with `cat`.

**`.env` file reads are blocked**
Intentional sensitive file guard. Don't try to work around it.

**`ALLOWED_PROCESSES` restricts restarts**
If a PM2 process restart is blocked even though the process exists, check `ALLOWED_PROCESSES` in `.env`. The process name must be on this allowlist for `restart_process` to act on it.

**High PM2 restart count**
Each `deploy_vps_mcp` restarts the process — the counter climbs. Only a concern if restarting in real-time with no deploys in progress (crash loop).

**`BYPASS_BINARIES` usage**
Format: `processname:category-name` (comma-separated for multiple). Example: `nginx:service-mgmt,myapp:file-write`. Every bypass is logged as `[SECURITY-BYPASS]` in the audit trail. Use only for legitimate recurring workflows that consistently over-block.

**Layer 3 timeout**
If the AI safety review fails, check `ANTHROPIC_API_KEY` in `.env` is valid and has credits. Quick test:
```
curl https://api.anthropic.com/v1/messages \
  -H "x-api-key: YOUR_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{"model":"claude-haiku-4-5-20251001","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}'
```

**Rate limit on `run_approved_command`**
`MAX_CUSTOM_COMMANDS_PER_SESSION` (default: 10) counts per MCP connection session. When hit, calls return a rate-limit error. Counter resets when the vps-mcp process restarts.

---

## Incident Response

If the audit log shows activity you didn't authorize:
1. Rotate `MCP_AUTH_TOKEN` immediately in `.env`, then `pm2 restart vps-mcp`.
2. Ask Claude to `read_audit_log` — review entries for the suspicious time window, especially any `[SECURITY-BYPASS]` tags.
3. Check `BYPASS_BINARIES` in `.env` for unexpected entries.
4. Check nginx access logs for requests from unexpected IPs.
5. Consider opening a GitHub Issue or emailing security@forgerift.io.

---

## Key Configuration Variables

| Variable | What It Does |
|----------|-------------|
| `MCP_AUTH_TOKEN` | Auth token — required, keep secret, rotate if exposed |
| `ANTHROPIC_API_KEY` | Powers Layer 3 AI safety review |
| `APP_DIR` | Root dir for allowed file reads and git ops |
| `ALLOWED_READ_DIRS` | Comma-separated dirs Claude can read |
| `ALLOWED_PROCESSES` | PM2 process names Claude can restart |
| `CLIENT_WEB_ROOT` | Enables `deploy_client`; fixed nginx web root the client `dist/` is published to (empty = disabled; validated absolute) |
| `CLIENT_COMPOSE_FILE` / `CLIENT_SERVICE` / `CLIENT_DIST_PATH` | `deploy_client` compose file / service / in-container dist path (defaults: `/root/ServiceCycle/docker-compose.yml`, `client`, `/app/dist`) |
| `PM2_LOG_DIR` | Where PM2 writes logs |
| `AUDIT_LOG_PATH` | Immutable audit trail location |
| `BYPASS_BINARIES` | `process:category` pairs exempt from blocking (logged as `[SECURITY-BYPASS]`) |
| `MAX_CUSTOM_COMMANDS_PER_SESSION` | Rate limit on `run_approved_command` (default: 10, resets on process restart) |
| `MAX_LOG_LINES` | Lines returned by log tools (default: 50) |
| `LAYER_STRICT_MODE` | Default `true` (fail-closed). Set `false` to allow pass-through when Layer 2/3 is unreachable. |
| `RATE_LIMIT_PER_MIN` | Requests per minute per token (default: 60) |
| `AUDIT_MAX_SIZE_MB` | Audit log rotation threshold (default: 10MB) |

---

## Audit Log

Every tool call is logged with: timestamp, tool name, security tier (GREEN/AMBER/RED), command or args (secrets auto-redacted), Layer 1/2/3 decision source, and `[SECURITY-BYPASS]` tag when `BYPASS_BINARIES` matched. Ask Claude: *"Show me the audit log from today"* — or check the file at `AUDIT_LOG_PATH` directly via SSH.

---

## Useful Diagnostic Prompts

```
Check my VPS health — CPU, memory, disk, PM2 processes
```
```
Show me the last 50 lines of errors from [process-name]
```
```
Show me the audit log from today — what commands were run?
```
```
What's the git status of [app directory]?
```
```
Is nginx running? Check its status.
```

---

## Support

- **GitHub Issues:** github.com/ForgeRift/vps-control-mcp/issues
- **Email:** support@forgerift.io
- **Security:** security@forgerift.io

---

## Memory Prompt

*Paste this into Claude to save this context as a memory (best used with Claude Projects):*

> "Please remember the following about my vps-control-mcp setup so you can help me manage my VPS and troubleshoot issues without me having to re-explain it: [paste this entire document]. Reference this any time I ask about my server, VPS commands, deployments, logs, or anything related to my ForgeRift plugin. Note: add this to a Claude Project for persistent context — standard memory may not retain the full document across sessions."
