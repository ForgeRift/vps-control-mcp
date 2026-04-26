# vps-control-mcp — Marketplace Listing

## Product Overview

![vps-control tools panel](https://raw.githubusercontent.com/ForgeRift/vps-control-mcp/main/docs/media/vps-control_01_tools.gif)

**Tagline:** *Let Claude operate your server. Without the risk.*

You use Claude to write deploy scripts, debug errors, and figure out why your server is slow — but you still have to copy every command into a terminal yourself. vps-control-mcp closes that gap.

Give Claude structured, audited access to your Linux VPS. It can restart your app, tail error logs, run a deploy, check disk and memory, and pull the latest git commits — all from Claude, without you ever opening a terminal.

Every command passes through 275+ permanently blocked dangerous patterns. `rm -rf`, package removal, firewall changes, credential files — none of it can run. What Claude *can* do is clearly defined, logged to an audit trail, and reviewed across 13 adversarial security passes.

For developers and non-technical users running a DigitalOcean, Vultr, Linode, or similar VPS with Node, Python, or Docker apps.

---

## What Claude Can Do

![Deploy pipeline demo](https://raw.githubusercontent.com/ForgeRift/vps-control-mcp/main/docs/media/vps-control_03_deploy.gif)

Seventeen tools across multiple categories:

- **Deploy your app** — `git pull` → install → build → PM2 restart, in one conversation turn
- **Read your logs** — tail error and output logs for any PM2 process without leaving Claude
- **Check server health** — disk, memory, uptime, process list on demand
- **Restart processes** — safe, confirmed PM2 restarts with dry-run preview
- **Browse and search files** — read source files, search for patterns, in allowed directories only
- **Run approved commands** — `ls`, `grep`, `cat`, `pm2`, `npm`, `dig`, `systemctl status` and more — with every blocked attempt explained, not just rejected

**Full tool list:** `get_pm2_status`, `get_system_health`, `get_recent_errors`, `get_recent_output`, `read_audit_log`, `git_status`, `git_log`, `git_pull`, `git_push`, `read_file_section`, `search_file`, `deploy`, `deploy_vps_mcp`, `get_deploy_status`, `get_job_status`, `restart_process`, `run_approved_command`

---

## Why Direct Access Changes How You Use Claude

Without a plugin, every Claude conversation about your server is a relay race. You describe a problem, Claude asks what the logs say, you SSH in and paste the logs, Claude asks for the config, you paste that, Claude suggests a command, you run it, paste the output back. A lot of that time gets spent figuring out *what Claude is asking for* — not reading the answer.

Direct access breaks that loop. Claude tails the error log itself. Checks the PM2 status. Reads the config. Gets the full picture without a back-and-forth. For large outputs — full deploy logs, long stack traces, PM2 process lists — the difference is especially significant: no truncated pastes, no guessing what context Claude needs, no token overhead from repeatedly re-explaining what you're looking at.

The result: you describe what's wrong once. Claude figures out what to look at, reads it, diagnoses the problem, and either tells you what's happening or just fixes it — all without you opening a terminal.

**The honest caveat:** This plugin dramatically reduces the need to touch a terminal for most workflows — but not to zero. A defined set of operations (recursive deletion, firewall changes, package removal, credential access, and other high-risk actions) are permanently blocked and will always require you to run them yourself via SSH. When Claude hits one of those, it tells you exactly what to run and why it can't do it for you. For reading logs, checking server health, running deploys, diagnosing problems, and managing your app, Claude handles it without your intervention. For anything in the dangerous category, you stay in control by design.

---

## Not a Developer? This Is Still for You.

If you have a website, app, or side project running on a VPS — and someone (a developer friend, a tutorial, a hosting setup wizard) got it running for you — this plugin is built for exactly your situation.

You know the feeling: something breaks at 11pm, you need to restart the app or check what went wrong, and you're staring at a terminal window that feels like a foreign language. Or you need to deploy an update and you're copying commands from a doc, hoping you got them right.

With vps-control-mcp, you just tell Claude what you need. *"Is my app running?" "Restart the payments service." "What errors happened in the last hour?" "Deploy the latest version."* Claude handles the terminal. You see the result.

You don't need to know what PM2 is, what a process ID means, or how git pull works. Claude knows. You just describe what you want done.

**What you don't have to worry about:** Claude can't delete your files, can't remove your software, can't change your firewall, can't touch your passwords or SSH keys. Those actions are permanently blocked — no prompt can override them. It can operate your app. It can't break your server.

---

## Developers — Here's What's Actually Under the Hood.

![RED-tier block demo](https://raw.githubusercontent.com/ForgeRift/vps-control-mcp/main/docs/media/vps-control_04_red-block.gif)

**Security architecture:** Three-tier command authorization (RED/AMBER/GREEN) with two independent enforcement layers — a static regex pattern matcher and a binary allowlist with per-binary arg validators. Both layers must pass for any command to execute. Defense-in-depth: dangerous sub-commands are blocked at the RED pattern layer *and* the arg validator layer, so a bypass of one doesn't constitute a bypass.

**Hard-blocked surface:** 275+ patterns across 26 categories including recursive deletion, destructive git ops, database destruction, disk-level writes, system power state, credential/key destruction, firewall teardown, audit log destruction, container nuclear ops, kernel namespace escape, SSH pivot flags (`systemctl -H/--host/-M/--machine`), and more. HARD_BLOCKED patterns run synchronously before the AI classification layer and cannot be overridden. The full enumeration is in `COMMAND_POLICY.md`.

**AI classification:** Optional Layer 2/3 pipeline using `ANTHROPIC_API_KEY`. Layer 2 is a single Claude classifier. Layer 3 is a multi-persona security board (Developer, Security Auditor, Ops Engineer) that must reach consensus. Fails closed when the API key is absent or the layer returns an unexpected format — you never get silent permissiveness.

**Positive allowlist:** `run_approved_command` operates on a binary allowlist with per-binary arg validators, not a blocklist. Binaries not on the list are rejected outright. Validators enforce sub-command whitelists (e.g. `systemctl` only accepts `status`, `is-active`, `is-enabled`, `is-failed`, `list-units`, `list-unit-files`, `list-sockets`, `list-timers`, `help`) and flag restrictions.

**Audit trail:** Every tool call logged as structured JSON with timestamp, tool name, tier classification, blocked status, sanitized arguments. Secrets auto-redacted via expanded prefix + key-name regex. Readable via `read_audit_log` tool. Rotates at 10MB, one backup retained.

**Adversarial review:** 13 rounds of Opus-level adversarial review with 97 filed findings (F-OP-1 through F-OP-97), all documented and closed in `ADVERSARIAL_REVIEW.md`. Findings include Unicode homoglyph bypasses, newline injection, symlink escape, path traversal, arg-position bugs, remote pivot flags, zone transfer via DNS tools, and AI classifier prompt injection patterns. Every closure has a verification step.

**Transport:** Streamable HTTP over HTTPS. nginx + TLS (sslip.io + Let's Encrypt). Port 3001 localhost-only; external traffic on 443 only. Bearer token auth with optional Supabase multi-token (billing-integrated) mode.

**License:** BUSL 1.1 — source available, converts to MIT 4 years after each version release. Full source at [github.com/ForgeRift/vps-control-mcp](https://github.com/ForgeRift/vps-control-mcp).

---

## Requirements

- Linux VPS (Ubuntu/Debian tested)
- Node.js v18 or later
- PM2 installed (`npm install -g pm2`)
- SSH access to the VPS
- Claude Desktop + Cowork

---

## Quick Start

On the VPS:

```bash
git clone https://github.com/forgerift/vps-control-mcp
cd vps-control-mcp
./setup.sh
```

The installer builds the project, generates a random auth token, registers `vps-mcp` under PM2, and prints the `claude_desktop_config.json` snippet. Copy it into Claude Desktop config, restart Claude. Connected.

---

## Configuration

All settings live in `.env` (auto-generated by `setup.sh`):

| Variable | Default | Description |
|---|---|---|
| `MCP_AUTH_TOKEN` | auto-generated | Bearer token for all requests |
| `PORT` | `3001` | Port the MCP listens on |
| `APP_DIR` | `/root/myapp` | Where the managed app lives |
| `PM2_LOG_DIR` | `/root/.pm2/logs` | PM2 log root |
| `AUDIT_LOG_PATH` | `{APP_DIR}/mcp-audit.log` | Audit log destination |
| `RATE_LIMIT_PER_MIN` | `60` | Max requests per minute |
| `ANTHROPIC_API_KEY` | unset | Enables Layer 2/3 AI classifier review (optional, fails closed if unset) |
| `BYPASS_BINARIES` | empty | Advanced: `<binary>:<category>,...` demotion list |
| `ALLOWED_PROCESSES` | `vps-mcp` | Comma-separated PM2 process names whose logs `get_recent_errors` and `get_recent_output` are permitted to read |
| `MAX_LOG_LINES` | `50` | Lines returned per call by `get_recent_errors` and `get_recent_output` |

---

## Pricing

| Plan | Monthly | Annual |
|------|---------|--------|
| Individual (this plugin) | $14.99/mo | $149/yr |
| Bundle (both plugins) | $19.99/mo | $199/yr |

**14-day free trial** included. No charge during trial period. No refunds after trial ends.

**Founder Cohort:** First 100 subscribers or 3 months post-marketplace approval (whichever comes first) lock in $9.99/mo (individual) or $14.99/mo (bundle) for life.

See [forgerift.io/#pricing](https://forgerift.io/#pricing) for full details.

---

## Support & Security

- **Documentation** — `README.md`, `SECURITY.md`, `TROUBLESHOOTING.md`, `COMMAND_POLICY.md`
- **Issues** — [github.com/ForgeRift/vps-control-mcp/issues](https://github.com/ForgeRift/vps-control-mcp/issues)
- **Security** — `security@forgerift.io` (90-day responsible disclosure)
- **General** — `support@forgerift.io`

---

## License

Source available under the [Business Source License 1.1](LICENSE) (BUSL 1.1). Converts to MIT four years after each version's release date.
