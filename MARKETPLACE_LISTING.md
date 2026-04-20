# vps-control — Marketplace Listing

> This is the marketplace-facing copy for the vps-control Claude Code plugin.
> Anything in this file should be accurate on the day of submission. Aspirational
> features, pricing tiers, and URLs belong in the roadmap, not here.

## Short description (≤ 140 chars)

Direct, audited control of your Linux VPS from Claude. Deploy, monitor PM2 processes, read logs, manage git — all with a three-tier security model.

## Long description

vps-control gives Claude structured, audited access to a Linux VPS you already run. It exposes 15 tools — PM2 status and restart, tail PM2 error logs, disk/memory/uptime health, file reads from an allowlist, regex search, git status/log/pull/push, full deploy pipeline (pull → install → build → restart → health check), and a rate-limited escape hatch for commands that don't fit a structured tool.

Every command runs through a three-tier authorization model:

- **RED** — over 100 patterns across 20 categories are hard-blocked with no override: file deletion, disk ops, shutdown/reboot, process killing, user management, permission changes, network config, scheduled execution, service management, code execution via `-c`/`-e`, shell invocation, data exfiltration (`curl`, `wget`, `scp`, `rsync`, `nc`, `socat`, `ssh`, `ftp`), persistence, database writes, package install/remove, container ops, privilege escalation.
- **AMBER** — `apt-get update`, `find -exec`, `xargs`, `awk`, `sed -i` force `dry_run=true` with a visible warning. Must be explicitly re-invoked to execute.
- **GREEN** — everything else, subject to a 60 req/min rate limit, a 10-use-per-session cap on the escape-hatch tool, a 30-second command timeout, and immutable audit logging.

Authentication is OAuth 2.0 or a static bearer token. Audit logs redact tokens, secrets, keys, and passwords before write and rotate at 10 MB. Sensitive files (`.env`, `.ssh/`, `.aws/`, `.gcloud/`, `.azure/`, `kubeconfig`, `.my.cnf`, `credentials.json`, `*.pem`, `*.key`, `/etc/shadow`, `/etc/passwd`) are blocked from read operations even within allowed directories.

## Behavioral transparency (please read before installing)

**Known behavior defect: probabilistic rule-following.**

This plugin tells Claude, through tool descriptions and a SessionStart hook, to operate your VPS through the structured tools — not by asking you to SSH in and paste command output. The rules win the vast majority of the time. They do not win 100% of the time. LLMs follow instructions probabilistically, and strong training priors toward "demonstrate commands for the user to run" can occasionally leak through.

We treat every instance of this as a defect, not a limitation. The mitigations are:

- Anti-pattern clauses embedded in every tool description (re-sent to the model every turn, not subject to system-prompt truncation).
- A SessionStart hook that plants a behavioral briefing at startup, resume, clear, and compact.
- An iterative "every support ticket becomes a new anti-pattern sentence" improvement loop.

If Claude ever hands you a command to run in your terminal instead of running it through the plugin, tell Claude: *"Use the vps-control tools instead of asking me to run commands."* That usually resolves it for the rest of the session. Starting a fresh session resets the probability in our favor. Report specifics at the GitHub issue tracker — real examples are how we sharpen the rules.

See `KNOWN_ISSUES.md` in the repo for the full list of current limitations and caveats.

## What's in the box

- 15 structured tools (monitoring, file access, git, deployment, process control, escape hatch)
- SessionStart hook with a behavioral briefing
- OAuth 2.0 + bearer token auth
- 60 req/min rate limiting, per-token
- Audit log at a configurable path with secret redaction and 10 MB rotation
- 181-case security test suite (RED/AMBER/GREEN coverage, Unicode bypass rejection, \r\n injection rejection, ReDoS-shape rejection, path allowlist, sensitive-file coverage, false-positive guards)
- Symlink realpath check before allowlist enforcement (prevents alias-based allowlist escapes)
- 10-minute background-job ceiling with SIGTERM → SIGKILL escalation
- Streamable HTTP transport with EventStore resumability

## What it does NOT do

- No GUI dashboard. All interaction is through Claude.
- No multi-host management. One plugin instance → one VPS.
- No TLS certificate management inside the plugin; `setup.sh` wires Let's Encrypt via sslip.io for you but you can bring your own cert.
- No automatic rollback on a deploy that builds successfully but fails at runtime — `deploy` checks the PM2 process status at the end and surfaces errors, but restoring to a previous commit is a decision you make.
- No database access. Database writes (`CREATE`, `DROP`, `ALTER`, `DELETE`, `TRUNCATE`) are RED-blocked.

## Requirements

- Linux VPS (Ubuntu 20.04+ / Debian 11+)
- Node.js 18+
- Ports 80 (Let's Encrypt), 443 (TLS), 3001 (app) open
- A PM2 process you want Claude to be able to restart

## Install

```bash
curl https://raw.githubusercontent.com/forgerift/vps-control-mcp/main/setup.sh | bash
```

Then connect the MCP URL that `setup.sh` prints in your Claude client.

## Source, issues, changelog

- Source: https://github.com/forgerift/vps-control-mcp
- Issues: https://github.com/forgerift/vps-control-mcp/issues
- Changelog: [CHANGELOG.md](CHANGELOG.md)
- Known issues: [KNOWN_ISSUES.md](KNOWN_ISSUES.md)
- Security model: [SECURITY.md](SECURITY.md)
- What we ask Claude to do: [docs/USING_WITH_CLAUDE.md](docs/USING_WITH_CLAUDE.md)

## License

MIT.
