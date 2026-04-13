# vps-control-mcp

Give Claude structured, audited access to your Linux VPS — deploy apps, monitor PM2 processes, tail error logs, and manage your server directly from your AI workflow.

Runs as a remote MCP server on your VPS. All tools enforce dry-run defaults, output limits, and path restrictions. Escape-hatch commands are session-capped and hard-blocked against destructive patterns.

---

## What it does

**Monitoring**
- `get_pm2_status` — name, status, restarts, memory, CPU, uptime for all PM2 processes
- `get_recent_errors` — last N lines of a process error log (max 50 lines)
- `get_system_health` — disk usage, memory, and system uptime

**File access**
- `read_file_section` — read a line range from a file (max 100 lines, restricted to allowed directories)
- `search_file` — grep a file for a pattern with context lines

**Git**
- `git_status` — working tree status
- `git_log` — recent commit history (max 20)
- `git_pull` — pull latest from origin main (`dry_run=true` by default)
- `git_push` — push committed changes (`dry_run=true` by default, requires description)

**Process control**
- `restart_process` — restart a PM2 process by name (`dry_run=true` by default)

**Deployment**
- `deploy` — full deploy sequence: `git pull → pnpm install → node build.mjs → pm2 restart all → pm2 status`. Returns a job ID immediately; runs in background.
- `deploy_vps_mcp` — deploy sequence for the MCP server itself: `git pull → npm install → npm run build → pm2 restart vps-mcp → pm2 status`
- `get_deploy_status` — poll the result of a background deploy job

**Escape hatch**
- `run_approved_command` — arbitrary shell command, `dry_run=true` by default. Session-capped (default 10 uses). Hard-blocked patterns enforced server-side.

---

## Requirements

- Linux VPS (Ubuntu 20.04+ recommended)
- Node.js v18 or later
- PM2 (`npm install -g pm2`)
- Claude Desktop with `mcp-remote` support

---

## Installation

```bash
# On your VPS
git clone https://github.com/claudedussy/vps-control-mcp
cd vps-control-mcp
chmod +x setup.sh
./setup.sh
```

`setup.sh` will:
- Check Node and PM2
- Build the project
- Generate a random auth token and save it to `.env`
- Register the server with PM2 and configure startup persistence
- Print the `claude_desktop_config.json` snippet to paste

Add the printed snippet to your Claude Desktop config, then restart Claude Desktop.

---

## Uninstalling

```bash
./uninstall.sh
```

Stops the PM2 process and prompts before deleting the install directory.

---

## Configuration

All settings live in `.env` on the VPS (see `.env.example`):

| Variable | Default | Description |
|---|---|---|
| `MCP_AUTH_TOKEN` | required | Bearer token required on every request |
| `PORT` | `3001` | Port the MCP server listens on |
| `APP_DIR` | `/root/your-app` | Application directory for git and deploy operations |
| `PM2_LOG_DIR` | `/root/.pm2/logs` | Where PM2 writes log files |
| `AUDIT_LOG_PATH` | `/root/mcp-audit.log` | Audit log location |
| `ALLOWED_PROCESSES` | _(empty)_ | Comma-separated PM2 process names Claude may restart |
| `MAX_CUSTOM_COMMANDS_PER_SESSION` | `10` | Session cap on `run_approved_command` |

---

## Security model

- **Auth:** Every request requires a Bearer token. Keep it in `claude_desktop_config.json` on your local machine — never commit it.
- **Allowed processes:** `restart_process` and `get_recent_errors` only operate on names listed in `ALLOWED_PROCESSES`. All others are rejected.
- **Path restrictions:** `read_file_section` and `search_file` are restricted to `APP_DIR` and `PM2_LOG_DIR`. Absolute paths outside these directories are rejected.
- **Dry-run defaults:** `git_pull`, `git_push`, `restart_process`, `deploy`, `deploy_vps_mcp`, and `run_approved_command` all default to `dry_run=true`. Claude must explicitly pass `dry_run=false` to execute.
- **Hard-blocked patterns in `run_approved_command`:** `rm`, `rmdir`, `unlink`, `dd`, `mkfs`, `fdisk`, pipe-to-shell (`| sh/bash`), direct DB access (`psql`, `mysql`, `mongo`), redirect to absolute path, `curl`/`wget` pipe, `eval`, `sudo`, backtick subshells, `$()` subshells, and command chaining with `;`.
- **Session cap:** `run_approved_command` is limited to `MAX_CUSTOM_COMMANDS_PER_SESSION` uses per server restart (default 10). Blocked or dry-run calls do not count against the quota.
- **Audit log:** Every tool call is written to `AUDIT_LOG_PATH` with timestamp, tool name, and arguments.

---

## Connecting from Claude Desktop

```json
{
  "mcpServers": {
    "vps-control": {
      "command": "mcp-remote",
      "args": [
        "http://<your-vps-ip>:3001/sse",
        "--allow-http",
        "--header",
        "Authorization: Bearer <your-token>"
      ]
    }
  }
}
```

Replace `<your-vps-ip>` and `<your-token>` with the values from `setup.sh` output.

---

## License

MIT
