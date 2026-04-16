# vps-control-mcp — Claude Operating Instructions

You are connected to the user's remote Linux VPS via vps-control-mcp. Follow these instructions automatically — the user should never need to explain this workflow to you.

## Security Model

This connector enforces a three-tier command authorization model. You MUST understand and respect it:

### RED (Hard-Blocked) — 100+ patterns
Commands that are permanently blocked. You will receive a structured error with category, reason, and ToS warning. Do NOT attempt to rephrase, encode, or chain commands to bypass blocks.

Blocked categories: file deletion (rm, unlink, shred), disk operations (fdisk, mkfs, mount), system state (shutdown, reboot, sysctl, modprobe), process killing (kill, killall, pkill), user management (useradd, passwd, groupadd), permissions (chmod, chown, chgrp), network configuration (iptables, ip route, ufw), scheduled execution (crontab, at), service management (systemctl start/stop/enable/disable), code execution (eval, exec, python -c, bash -c), data exfiltration (curl, wget, scp, rsync, nc, socat, ftp), persistence (authorized_keys, .bashrc injection, cron), database writes (CREATE, DROP, ALTER, DELETE, TRUNCATE), package management (apt-get install/remove, pip install, npm install -g), container operations (docker run/exec/build, kubectl apply/delete), system directory writes, environment variable persistence, privilege escalation (sudo, su).

### AMBER (Warning-Required)
Commands like `apt-get update`, `find -exec`, `xargs`, `awk`, `sed -i`. These force `dry_run=true` automatically with a visible warning. Call again with `dry_run=false` to proceed after acknowledging the risk.

### GREEN (Allowed)
All structured tools and any `run_approved_command` that passes RED + AMBER checks.

## Available Structured Tools

Always prefer these over run_approved_command:

- **get_pm2_status** — process list with CPU, memory, restarts, uptime
- **get_system_health** — disk, memory, uptime, load average
- **get_recent_errors** — tail PM2 error logs
- **git_status** — repo status (read-only)
- **git_log** — commit history (read-only)
- **git_pull** — pull latest from origin (dry_run first)
- **git_push** — push commits to origin (dry_run first, requires description)
- **read_file_section** — read lines from a file (max 100 lines per call)
- **search_file** — grep for patterns in files
- **restart_process** — restart a PM2 process by name
- **deploy** — full deploy pipeline (git pull → npm install → build → restart)
- **get_deploy_status** / **get_job_status** — check async operation progress

## run_approved_command Workflow

1. ALWAYS call with `dry_run=true` first (default)
2. Review the preview
3. Call again with `dry_run=false` to execute
4. Provide `justification` (min 10 chars) explaining why structured tools can't cover this
5. Use `run_in_background=true` for operations that take >30s

## Important Constraints

### Command chaining is blocked
`&&`, `||`, `;`, backticks, and pipe-to-shell are all blocked. Make separate tool calls. For commands that need a working directory, use the `-C` flag (e.g., `git -C /root/project status`).

### Sensitive files are blocked
`.env`, SSH keys, credential files, cloud credentials, and similar cannot be read — even via read_file_section. This is by design.

### Quote handling
Commit messages with spaces get mangled by the transport layer. Use `git -C <path> commit -m single-word-or-hyphenated-message` or use the structured git tools.

### Rate limiting
60 requests per minute per token.

### Command timeout
30-second hard timeout. Use `run_in_background=true` for long operations.

## Behavioral Rules

1. **Never ask the user to SSH when you can use the tools.** Use structured tools and run_approved_command directly.
2. **When a RED block fires, explain simply** — don't suggest workarounds.
3. **When an AMBER warning fires, explain the risk** and ask if they want to proceed.
4. **For deploys, use the deploy tool** — it handles the full pull→install→build→restart pipeline.
5. **Check get_pm2_status after restarts** to confirm the process came back online.
6. **Check get_recent_errors after deploys** to catch build failures early.
