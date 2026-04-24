# vps-control-mcp — Marketplace Listing


## Product Overview

![vps-control tools panel](https://raw.githubusercontent.com/ForgeRift/vps-control-mcp/main/docs/media/vps-control_01_tools.gif)

**vps-control-mcp** gives Claude structured, audited SSH access to a remote Linux VPS. Deploy apps, inspect PM2 processes, read logs, restart services, and check system health — all from Cowork, without opening a terminal or handing Claude an unguarded SSH session.

Every command passes through a three-tier security model with 275+ hard-blocked dangerous patterns. PM2-aware, systemd-aware, audit-logged. Designed for the common "I have a DigitalOcean droplet running Node/Python/Docker and want Claude to help me operate it" case.

## Key Features

- **Three-Tier Command Authorization** — RED (hard-blocked), AMBER (warning-required), GREEN (allowed with audit). Blocks `rm -rf`, package removal, user/group management, kernel module ops, scheduled-task creation, and 275+ hard-blocked patterns across 26 categories.

- **Destination-Path Write Protection (D10)** — `cp`/`mv`/`install`/`tee`/`dd of=...` writes to `/etc`, `/root`, `/home`, `/usr/bin`, `/bin`, `/boot`, `/lib`, and adjacent OS-critical paths are hard-blocked. Redirect (`>`, `>>`) targets covered by the same matcher. Env-var and tilde expansion fail closed.

- **Structured Operational Tools** — `get_pm2_status`, `git_status`, `git_pull`, `git_log`, `get_system_health`, `get_recent_errors`, `deploy`, `restart_process`, `read_file_section`, `search_file`. Each tool has a defined shape; Claude doesn't have to learn shell syntax.

- **Per-Binary Bypass Allowlist** — `BYPASS_BINARIES` env var lets operators demote specific `<binary>:<category>` pairs from hard-block to AI-reviewed for legitimate admin workflows (e.g. `cp:sensitive-path-write` for `/home` backup-restore scripts). Every bypass is logged as `[SECURITY-BYPASS]` in the audit stream.

- **Audit Logging** — Every tool call logged with timestamp, tool name, security tier, blocked status, arguments. Secrets auto-redacted. Logs rotate at 10MB with one backup retained.

- **Rate Limiting** — 60 requests per minute per auth token. Prevents brute-force probing.

- **Twelve Adversarial Review Rounds** — Hardened against 80+ filed bypass findings. Every closure is documented in `ADVERSARIAL_REVIEW.md`.

## What Claude Can Do

![Deploy pipeline demo](https://raw.githubusercontent.com/ForgeRift/vps-control-mcp/main/docs/media/vps-control_03_deploy.gif)

Sixteen tools across multiple categories:

**Read-only operational**
- `get_pm2_status` — PM2 process list with status, restarts, memory, CPU, uptime
- `get_system_health` — disk usage, memory, uptime
- `get_recent_errors` — error-log tail for a named PM2 process
- `read_audit_log` — read the immutable audit trail of all tool calls
- `git_status`, `git_log` — repo state in the deploy dir
- `read_file_section`, `search_file` — read files in allowed directories

**Deploy pipeline**
- `deploy` / `deploy_vps_mcp` — `git pull` → `npm install` → `npm run build` → `pm2 restart` → `pm2 status`
- `get_deploy_status`, `get_job_status` — poll background deploy jobs
- `git_pull`, `git_push` — explicit git ops
- `restart_process` — PM2 restart with optional env refresh

**Escape hatch**
- `run_approved_command` — allowlisted binaries only (`ls`, `cat`, `grep`, `node`, `npm`, `pm2`, etc.), RED/AMBER/GREEN filtered, always `dry_run=true` first.

## Requirements

- Linux VPS (Ubuntu/Debian tested)
- Node.js v18 or later
- PM2 installed (`npm install -g pm2`)
- SSH access to the VPS
- A local client with Claude Desktop + Cowork

## Quick Start

On the VPS:

```bash
# 1. Clone the repo
git clone https://github.com/forgerift/vps-control-mcp
cd vps-control-mcp

# 2. Install
./setup.sh
```

The installer:
- Installs Node dependencies
- Builds the project (`npm run build`)
- Creates `.env` with a random auth token, `APP_DIR`, `PM2_LOG_DIR`, `AUDIT_LOG_PATH`
- Registers the MCP under PM2 as `vps-mcp`
- Prints the `claude_desktop_config.json` snippet

On your local machine: copy the snippet into Claude Desktop config, restart Claude. Connected.

## Configuration

All settings live in `.env` (auto-generated):

| Variable | Default | Description |
|---|---|---|
| `MCP_AUTH_TOKEN` | auto-generated | Bearer token for all requests |
| `PORT` | `3001` | Port the MCP listens on |
| `APP_DIR` | `/root/myapp` | Where the managed app lives |
| `PM2_LOG_DIR` | `/root/.pm2/logs` | PM2 log root |
| `AUDIT_LOG_PATH` | `{APP_DIR}/mcp-audit.log` | Audit log destination |
| `RATE_LIMIT_PER_MIN` | `60` | Max requests per minute |
| `ANTHROPIC_API_KEY` | unset | Enables Layer 2/3 AI classifier review (optional, falls open if unset) |
| `BYPASS_BINARIES` | empty | Advanced: `<binary>:<category>,...` demotion list |

![RED-tier block demo](https://raw.githubusercontent.com/ForgeRift/vps-control-mcp/main/docs/media/vps-control_04_red-block.gif)

## Security Highlights

- **HTTPS transport** — MCP runs on the VPS behind nginx + TLS (sslip.io + Let's Encrypt); Claude connects via OAuth 2.0 or static bearer token over HTTPS. Port 3001 is localhost-only; all external traffic goes through port 443.
- **Hard command blocks** — 275+ dangerous patterns permanently blocked across 26 categories. `BYPASS_BINARIES` available for legitimate admin workflows but every bypass is logged.
- **Sensitive-path write protection** — D10 (argv-aware matcher) + M7-extended (redirect matcher) prevent writes to OS-critical paths under any syntax variant (see `SECURITY.md` D10 subsection).
- **Credential protection** — Sensitive files (`.env`, SSH keys, cloud credentials) blocked at read time.
- **Audit trail** — Every call logged with full context. Secrets auto-redacted.
- **Responsible disclosure** — Report security issues to `security@forgerift.io` (90-day responsible disclosure).

See `SECURITY.md` for the full threat model and the S65 adversarial-review trail.

## Updating

```bash
cd /path/to/vps-control-mcp
git fetch origin
git reset --hard origin/main
npm install --include=dev
npm run build
pm2 restart vps-mcp
```

`git pull` alone works for normal releases. After the one-time v1.10.4 history rewrite, the `fetch + reset --hard` pattern above is required once per existing clone; future updates can use plain `git pull`.

## Uninstalling

```bash
pm2 delete vps-mcp
pm2 save
rm -rf /path/to/vps-control-mcp
```

## Pricing

| Plan | Monthly | Annual |
|------|---------|--------|
| Individual (this plugin) | $14.99/mo | $149/yr |
| Bundle (both plugins) | $19.99/mo | $199/yr |

**14-day free trial** included. No charge during trial period. No refunds after trial ends.

**Founder Cohort:** First 100 subscribers or 3 months post-marketplace approval (whichever comes first) lock in $9.99/mo (individual) or $14.99/mo (bundle) for life.

See [forgerift.io/#pricing](https://forgerift.io/#pricing) for full details.

## Support & Security

- **Documentation** — See `README.md`, `SECURITY.md`, and `TROUBLESHOOTING.md` in the repository.
- **Issues** — Report bugs via GitHub issues.
- **Security** — Report vulnerabilities to `security@forgerift.io`.

## License

Source available under the [Business Source License 1.1](LICENSE) (BUSL 1.1). Converts to MIT four years after each version's release date.
