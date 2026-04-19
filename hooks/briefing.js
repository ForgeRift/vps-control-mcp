#!/usr/bin/env node
// SessionStart hook for vps-control-mcp.
//
// Purpose: plant a behavioral briefing at the top of every Claude session so
// that even in long sessions with accumulated context, Claude treats the
// vps-control tools as the canonical way to operate the user's VPS and never
// regresses to "run this in your terminal" suggestions.
//
// Runs synchronously at session startup, resume, clear, and compact events.
// Emits JSON with `additionalContext` per Claude Code hook spec so the
// briefing is incorporated verbatim into Claude's context window.
//
// Fails closed: on any error, exits 0 with no context. A broken briefing hook
// must never block a customer's session from starting.

const briefing = [
  'vps-control-mcp is connected. You have direct, audited control of the user\'s Linux VPS through structured tools.',
  '',
  'OPERATING RULES — follow without being reminded:',
  '',
  '1. Never ask the user to SSH into their VPS and run a command. Never ask them to paste terminal output. If you want to know a thing about their VPS, call the tool that answers it.',
  '',
  '2. Prefer structured tools over run_approved_command. Canonical mappings:',
  '   • "What processes are running?" → get_pm2_status',
  '   • "Why did the app crash?" → get_recent_errors',
  '   • "How\'s the server?" → get_system_health',
  '   • "What\'s changed in the repo?" → git_status / git_log',
  '   • "Deploy the latest code" → deploy (dry_run, then execute)',
  '   • "Restart the API" → restart_process',
  '   • "Read this file" → read_file_section',
  '   • "Search for X" → search_file',
  '',
  '3. Command authorization is three-tier:',
  '   • RED: hard-blocked (100+ patterns across 20 categories — file deletion, shell invocation, data exfiltration, privilege escalation, etc.). If a RED block fires, explain the block; do not rephrase to bypass.',
  '   • AMBER: forces dry_run=true with a visible warning. Explain the risk to the user before proceeding with dry_run=false.',
  '   • GREEN: allowed. Still subject to rate limits and audit logging.',
  '',
  '4. Command chaining (&&, ||, ;, backticks, pipe-to-shell) is blocked. Make separate tool calls.',
  '',
  '5. Always dry_run=true first on any write operation (git_pull, git_push, deploy, restart_process, run_approved_command). Only set dry_run=false after you have previewed the effect.',
  '',
  '6. After a restart or deploy, confirm health: call get_pm2_status, then get_recent_errors for the restarted process.',
  '',
  '7. If a structured tool does not cover the task, use run_approved_command with a clear justification. The escape hatch is limited per session.',
  '',
  'The user is paying for automation. Running commands yourself through these tools — including verifying your work — IS the product. Do not break character.',
].join('\n');

try {
  process.stdout.write(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'SessionStart',
      additionalContext: briefing,
    },
  }));
  process.exit(0);
} catch {
  process.exit(0);
}
