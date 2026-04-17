# Known Issues

This is the current list of known limitations and caveats for vps-control-mcp. We keep it honest and current. If you hit something that isn't here, open a [GitHub issue](https://github.com/claudedussy/vps-control-mcp/issues) and we'll add it.

---

## Behavioral (Claude-side)

### Probabilistic rule-following

**What you might see:** Claude occasionally suggests you run a command in your terminal (like `pm2 status`, `tail /var/log/syslog`, or an SSH session) instead of using the corresponding structured tool this MCP provides.

**Why this happens:** Large language models follow instructions probabilistically, not deterministically. Our guidance to Claude — "use the tools, don't suggest SSH, don't ask the user to paste commands" — lives in tool descriptions and a SessionStart briefing, and it wins the vast majority of the time. But strong training priors toward demonstrating commands for users to run can occasionally leak through, especially in very long sessions with a lot of prior pattern buildup.

**What we do about it (shipped as of v1.4.0):**
- **Per-turn lever:** every tool description embeds an explicit "USE THIS — never ask the user to run…" anti-pattern clause. These descriptions are re-sent to the model on every tool-list request and are not subject to system-prompt truncation, so they ride along in the freshest part of context every turn.
- **Per-session lever:** a `SessionStart` hook (`hooks/briefing.js`) emits a behavioral briefing at startup, resume, clear, and compact. The briefing maps common user intents to the correct tool and restates the three-tier security model and the dry-run-first rule. Fails closed — a broken briefing never blocks a session.
- **Iteration loop:** each support ticket reporting an instance of this behavior becomes a new anti-pattern sentence in the next release, making the rules progressively sharper.

**What to do if you hit it:**
1. Tell Claude explicitly: "Use the vps-control tools instead of asking me to run commands." — this usually resolves it for the rest of the session
2. Starting a fresh Claude session clears accumulated context and resets the probability in our favor
3. Report the specific prompt and Claude's response to [GitHub issues](https://github.com/claudedussy/vps-control-mcp/issues) — real examples are how we sharpen the rules

We consider every instance of this behavior a defect, not a limitation. We're iterating toward zero. If you care about the topic, you can watch the `behavioral` label in our issue tracker.

---

## Platform

### Command timeouts at 30 seconds

Any single `run_approved_command` call hard-terminates after 30 seconds. For longer-running operations, use `run_in_background=true` and poll with `get_job_status`. This is intentional (prevents runaway processes) but is a common "why did my build just stop?" moment.

### Command chaining is blocked

The patterns `&&`, `||`, `;`, backticks, and shell pipes into other shells are RED-tier blocked. Split into multiple tool calls. For directory-scoped commands, use the `-C` flag where supported (e.g., `git -C /root/project status`).

### Commit messages with quotes or spaces can mangle

The MCP transport layer can corrupt shell quoting in some commit messages. Use hyphenated or single-word messages in `run_approved_command`, or use the structured git tools which handle quoting correctly.

### Sensitive files cannot be read

`.env`, `.ssh/`, and other credential files are blocked from all read operations, even when within `ALLOWED_READ_DIRS`. This is deliberate and non-configurable. If you need to inspect one of these, do so outside this MCP.

---

## Deployment

### deploy_vps_mcp restarts the connection

When you use `deploy_vps_mcp` to update the MCP server itself, the server restarts mid-deploy and the SSE connection drops. Tool calls will timeout until the session reconnects. Verify the server is healthy with `curl -s <your-url>/health` — if it returns `{"status":"ok"}`, the server is fine and you just need to restart your Claude client or reconnect the MCP.

**Workaround:** run `deploy_vps_mcp` at the *end* of a work session to avoid mid-session disruption.

---

## Reporting an issue

Please include:
- The MCP version (from `plugin.json` or `package.json`)
- What you asked Claude to do
- What Claude did
- What you expected Claude to do

File at: https://github.com/claudedussy/vps-control-mcp/issues
