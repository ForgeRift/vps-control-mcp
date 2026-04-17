# Changelog

All notable changes to vps-control-mcp.

The format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning is [SemVer](https://semver.org/spec/v2.0.0.html).

---

## [1.4.0] — 2026-04-17

### Added
- **SessionStart hook** (`hooks/briefing.js`) that plants a behavioral briefing into Claude's context every time a new session starts, resumes, clears, or compacts. The briefing maps common user intents to the correct structured tool ("Why did the app crash?" → `get_recent_errors`), and restates the three-tier RED/AMBER/GREEN model and the dry-run-first requirement. Wired in `.claude-plugin/plugin.json` via `"hooks": "./hooks/hooks.json"`. Fails closed — any error in the hook exits 0 silently so a broken briefing never blocks a customer's session.

### Changed
- **Every tool description now embeds an explicit "USE THIS — never ask the user to …" anti-pattern clause.** This targets the probabilistic rule-following defect described in `KNOWN_ISSUES.md`: tool descriptions are re-sent to the model on every tool-list request and are not subject to system-prompt truncation, making them the strongest behavioral lever we have. Fifteen tools updated (`get_pm2_status`, `get_recent_errors`, `read_file_section`, `search_file`, `git_status`, `git_log`, `git_pull`, `git_push`, `restart_process`, `get_system_health`, `run_approved_command`, `get_job_status`, `deploy`, `deploy_vps_mcp`, `get_deploy_status`).

### Why
- The v1.3.1 transparency docs acknowledged that Claude sometimes regresses to "run this in your terminal" suggestions despite the rules. v1.4.0 is the mechanical fix: two new behavioral levers (per-turn tool-description anti-patterns, per-session briefing hook) that land the rules in the freshest parts of the model's context.
- Full security test suite (181/181) still passes; no validation contracts changed.

---

## [1.3.1] — 2026-04-17

### Changed
- Moved `.claude-plugin/CLAUDE.md` to `docs/USING_WITH_CLAUDE.md`. The original path implied a plugin auto-load mechanism that Claude Code does not currently provide; the new path is unambiguous and discoverable.
- Restructured repo documentation: added `KNOWN_ISSUES.md` and `CHANGELOG.md` at repo root.
- README gained a "Working with Claude" section and a Known Issues link under Support.

### Why
- Transparency: devs evaluating the repo should be able to see limitations, iteration velocity, and design intent at a glance. Hidden caveats erode trust faster than disclosed ones.
- Accuracy: filenames should describe what they do. A `CLAUDE.md` in a plugin path that isn't actually auto-loaded is a trap for future contributors.

---

## [1.3.0] — 2026-04-17

### Added
- Explicit sensitive-file pattern for AWS config files without leading dots (`/aws/config`, `/aws/credentials`). Catches the common case where users store AWS creds without the `.` prefix.

### Changed
- Repository attribution updated from Anthropic placeholders to SharpEdge across README, `.claude-plugin/plugin.json`, and security contact email.
- Version bump to align `plugin.json` with `package.json`, which had drifted.

### Removed
- `check-failing.mjs` (internal diagnostic script, not intended for distribution).
- `.mcp.json` (personal developer config that contained a hardcoded VPS IP). Added to `.gitignore`.

---

## [1.2.0] — earlier

Baseline: three-tier command security model (RED/AMBER/GREEN), OAuth 2.0 + bearer auth, rate limiting, audit logging, PM2 management tools, streamable HTTP transport with EventStore resumability.
