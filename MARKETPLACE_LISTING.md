# vps-control-mcp — Marketplace Listing

## Product Overview

![vps-control tools panel](https://raw.githubusercontent.com/ForgeRift/vps-control-mcp/main/docs/media/vps-control_01_tools.gif)

**Tagline:** *Let Claude operate your server. Without the risk.*

*ForgeRift LLC is an independent third-party developer and is not affiliated with, endorsed by, or sponsored by Anthropic PBC.*

**A remote MCP endpoint built for production-ops.** vps-control-mcp self-hosts on your Linux VPS and exposes a structured tool surface that any Claude client (Claude Desktop, Cowork, or another MCP client) can connect to with a bearer token. You operate the production server through Claude — restart your app, tail error logs, run a deploy, check disk and memory, pull the latest git commits — without SSH'ing in, without running a CLI session on the VPS, and without giving Claude unrestricted shell access.

**Designed for teams and solo operators who run real infrastructure.** Per-operator bearer tokens (multi-token mode integrates with the ForgeRift licensing back-end), per-token rate limits, per-token audit log. When a teammate joins or leaves, you provision or revoke their token; the audit log shows exactly which operator did what, when. The tool is built for the case where giving every operator SSH access to the production VPS is the wrong answer, and where "trust the developer's judgment" is too weak a control for the operations being performed.

Every command passes through 275+ permanently blocked dangerous patterns. `rm -rf`, package removal, firewall changes, credential files — none of it can run. Optional AI-assisted second-pass safety classification (Layer 2 + Layer 3 multi-perspective board) when an Anthropic API key is configured, **fail-closed by default** — when the API call fails, commands are refused, not silently permitted. What Claude *can* do is clearly defined, logged to an audit trail with secret scrubbing, and reviewed across 13 adversarial security passes.

For developers, agencies, and ops teams running a DigitalOcean, Vultr, Linode, AWS Lightsail, or similar VPS with Node, Python, or Docker apps in production.

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

## Not a Developer? This Is Still for You.

If you have a website, app, or side project running on a VPS — and someone (a developer friend, a tutorial, a hosting setup wizard) got it running for you — this plugin is built for exactly your situation.

You know the feeling: something breaks at 11pm, you need to restart the app or check what went wrong, and you're staring at a terminal window that feels like a foreign language. Or you need to deploy an update and you're copying commands from a doc, hoping you got them right.

With vps-control-mcp, you just tell Claude what you need. *"Is my app running?" "Restart the payments service." "What errors happened in the last hour?" "Deploy the latest version."* Claude handles the terminal. You see the result.

You don't need to know what PM2 is, what a process ID means, or how git pull works. Claude knows. You just describe what you want done.

**What you don't have to worry about:** Claude can't delete your files, can't remove your software, can't change your firewall, can't touch your passwords or SSH keys. Those actions are blocked at the static-pattern layer before any AI review runs -- a malicious prompt cannot talk Claude into running them. (For advanced operators, the `BYPASS_BINARIES` env var documented in README can demote specific binaries with every use logged as `[SECURITY-BYPASS]` -- this is opt-in and audited, not silent.) It can operate your app. It can't break your server.

---

## Developers — Here's What's Actually Under the Hood.

![RED-tier block demo](https://raw.githubusercontent.com/ForgeRift/vps-control-mcp/main/docs/media/vps-control_04_red-block.gif)

**Security architecture:** Three-tier command authorization (RED/AMBER/GREEN) with two independent enforcement layers — a static regex pattern matcher and a binary allowlist with per-binary arg validators. Both layers must pass for any command to execute. Defense-in-depth: dangerous sub-commands are blocked at the RED pattern layer *and* the arg validator layer, so a bypass of one doesn't constitute a bypass.

**Hard-blocked surface:** 275+ patterns across 44 categories including recursive deletion, destructive git ops, database destruction, disk-level writes, system power state, credential/key destruction, firewall teardown, audit log destruction, container nuclear ops, kernel namespace escape, SSH pivot flags (`systemctl -H/--host/-M/--machine`), and more. HARD_BLOCKED patterns run synchronously before the AI classification layer; they can only be loosened via the audit-logged `BYPASS_BINARIES` env (each demotion logged as `[SECURITY-BYPASS]`). The full enumeration is in `COMMAND_POLICY.md`.

**AI classification:** Optional Layer 2/3 pipeline using `ANTHROPIC_API_KEY`. Layer 2 is a single Claude classifier. Layer 3 is a multi-persona security board (Developer, Security Auditor, Ops Engineer) that must reach consensus. Fails closed by default (`LAYER_STRICT_MODE=true`) when the API key is absent or the layer returns an unexpected format — you never get silent permissiveness. Operators may set `LAYER_STRICT_MODE=false` to opt into degraded mode (Layer 1 deterministic deny-list only). **Important:** the plugin's safety story depends on the *combination* of the static deny-list and the AI classification. Operating in strict-mode-off / no-AI-key configuration is supported but is "degraded mode" — outside the intended security model. Operators in degraded mode accept all risk for any command the static layer alone fails to block; ForgeRift's liability is limited per the [MCP EULA §§6.1, 10–12](https://forgerift.io/legal/mcp-eula). Deliberately disabling, patching, or replacing the static deny-list, validators, audit log, or secret-scrubbing pipeline is a EULA violation under §3.

**Positive allowlist:** `run_approved_command` operates on a binary allowlist with per-binary arg validators, not a blocklist. Binaries not on the list are rejected outright. Validators enforce sub-command whitelists (e.g. `systemctl` only accepts `status`, `is-active`, `is-enabled`, `is-failed`, `list-units`, `list-unit-files`, `list-sockets`, `list-timers`, `help`) and flag restrictions.

**Audit trail:** Every tool call logged as structured JSON with timestamp, tool name, tier classification, blocked status, sanitized arguments. Secrets auto-redacted via expanded prefix + key-name regex. Readable via `read_audit_log` tool. Rotates at 10MB, one backup retained.

**Adversarial review:** 13 rounds of Opus-level adversarial review with 97 finding IDs issued, 65 documented in `ADVERSARIAL_REVIEW.md`; remaining IDs were merged or rolled up during triage. Findings include Unicode homoglyph bypasses, newline injection, symlink escape, path traversal, arg-position bugs, remote pivot flags, zone transfer via DNS tools, and AI classifier prompt injection patterns. Every closure has a verification step.

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
git clone https://github.com/ForgeRift/vps-control-mcp
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
| `ALLOWED_PROCESSES` | (empty) | Comma-separated PM2 process names whose logs `get_recent_errors` and `get_recent_output` are permitted to read; default is empty so log-reading tools are no-ops until the operator opts a process in |
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

Source available under the [Business Source License 1.1](LICENSE) (BUSL 1.1). Converts to MIT four years after each vers