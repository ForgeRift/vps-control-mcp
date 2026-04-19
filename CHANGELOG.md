# Changelog

All notable changes to vps-control-mcp.

The format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning is [SemVer](https://semver.org/spec/v2.0.0.html).

---

## [1.6.0] — 2026-04-18

### Security hardening — third-pass Opus adversarial review (S47)

Closes all CRITICAL/HIGH findings from the third-pass adversarial review. All changes tested against 284-test suite (all pass).

**F-OP-1 (CRITICAL): awk removed from POSITIVE_ALLOWLIST**
- `awk` removed entirely. `awk system()` and `getline` both invoke `/bin/sh -c`, providing full root RCE. No safe subset exists via argv inspection.

**F-OP-2 (CRITICAL): sed e command and -i promoted to RED**
- Added RED pattern for `sed Xe<cmd>` (line-address+e shell execution, e.g. `sed 1ewhoami`).
- `sed -i` and `sed --in-place` promoted from AMBER to RED (arbitrary file mutation).
- `validateSedArgs` added as defense-in-depth: rejects `-i`, `--in-place`, combined flags containing `i`, the `e` address command, and the substitution `e` flag (`s/.../.../ e`).

**F-OP-3 (CRITICAL): find -exec promoted to RED**
- `find -exec` and `find -execdir` promoted from AMBER to RED — spawns child processes that bypass all MCP command validation.
- `validateFindArgs` added as defense-in-depth: also blocks `-ok`, `-okdir`, `-fprint`, `-fprintf`, `-delete`.

**F-OP-4 (CRITICAL): grep -r/-R recursive blocked**
- `validateGrepArgs` added: rejects `-r`, `-R`, `--recursive`, `-d`, and combined short flags containing `r`/`R`.
- Plain single-file grep remains allowed. Route recursive search through `search_file` which enforces `validatePath`.

**F-OP-5 (CRITICAL): SENSITIVE_FILE_PATTERNS .env regex tightened**
- Old: `/\.env($|\.)/i` — missed `.env"`, `.env)`, `.env/`, `.env$IFS` suffix variants.
- New: `/\.env(?![a-zA-Z0-9])/i` — any non-alphanumeric suffix (or end-of-string) triggers the block.

**F-OP-6/7 (CRITICAL): pm2 env-dumping sub-commands blocked**
- Removed `jlist`, `prettylist`, `describe`, `info`, `show` from `validatePm2Args` READ_ONLY set.
- These sub-commands include the full `pm2_env` block which contains `MCP_AUTH_TOKEN` and all other secrets. Use the structured `get_pm2_status` tool instead.

**F-OP-15 (LOW): CURRENT_VERSION hardcoded string corrected**
- Fixed hardcoded `'1.3.0'` in `src/index.ts:571` to `'1.6.0'`.

**F-OP-18 (CRITICAL): ps removed from POSITIVE_ALLOWLIST**
- `ps` removed entirely. `ps auxe`, `ps -eo cmd,env`, and other env-dump flag combinations expose `MCP_AUTH_TOKEN` from the process environment. Use `get_pm2_status` or `get_system_health` instead.
- Added belt-and-suspenders RED patterns for `ps auxe` and `ps -eo*` forms.

**F-OP-19 (CRITICAL): node --inspect* blocked**
- `validateNodeArgs` `BLOCKED_FLAGS` expanded to include: `--inspect`, `--inspect-brk`, `--inspect-port`, `--inspect-publish-uid`, `--loader`, `--experimental-loader`, `--import`, `--cpu-prof*`, `--heap-prof*`, `--diagnostic-dir`, `--report-dir`, `--report-filename`, `--redirect-warnings`.
- Prefix-based matching added so `--inspect=0.0.0.0:9229` (flag=value form) is also blocked.
- `node --inspect` opens a V8 debugger port to the network — root RCE if port is reachable.

---

## [1.5.0] — 2026-04-18

### Security hardening — second-pass Opus adversarial review (S45)

Closes all findings from the second-pass adversarial review. All changes tested against 233-test suite (all pass).

**P3a — F-NEW-5 (CRITICAL): git_pull hook-chained RCE**
- `gitPull()` now ignores the `directory` parameter entirely; locked to `CONFIG.APP_DIR`.
- Added `-c core.hooksPath=/dev/null` to git args — prevents execution of any hooks from the pulled repo, closing the two-step `git init /tmp/pwn && git remote add origin <evil> → git_pull` attack chain.

**P3b — 1-day denylist batch (F-NEW-8, 9, 11, 13, 15, 18, 19)**
- F-NEW-8: `env -0` / `env -i` / `env --null` / `env --ignore-environment` blocked (env var dump).
- F-NEW-9: `/etc/ssh/ssh_host_*_key` path pattern blocked (host key read).
- F-NEW-11: `ln --symbolic` long-form blocked (symlink creation bypass).
- F-NEW-13: `host`, `dig`, `nslookup`, `getent` blocked (DNS/NSS info leak).
- F-NEW-15: `/health` endpoint now gates full response behind `validateAuth`; unauthenticated callers only receive `{ status, uptime_s }`.
- F-NEW-18: `journalctl`, `dmesg`, `last`, `lastlog` blocked (system log access).
- F-NEW-19: `searchFile()` grep args array now prepends `--` before pattern — closes injection via patterns starting with `-`.

**P3c — F-NEW-1/2/3/4 (CRITICAL/HIGH): positive allowlist redesign**
- `POSITIVE_ALLOWLIST`: 30-entry default-deny binary allowlist for `run_approved_command`. Any binary not in the list is hard-blocked regardless of denylist coverage. Closes the ~30 file-reader gap (`xxd`, `strings`, `hexdump`, `less`, `more`, `od`, `tac`, `base64`, etc.).
- `validateAgainstAllowlist()`: called before RED checks. Rejects path-qualified binary names (e.g. `/bin/cat`) to close the path-prefix bypass. Per-binary arg validators: `pm2` restricts to read-only sub-commands; `node` blocks inline-execution flags; `npm`/`pnpm` allow only read-only operations; all file-argument validators reject paths matching `SENSITIVE_FILE_PATTERNS`.
- AMBER fix (F-NEW-1/F-NEW-4): `checkAmberWarnings()` no longer takes a `dryRun` param — it always returns the warning text when matched. `runApprovedCommand` blocks for `dry_run=true`; prepends warning prefix to output for `dry_run=false`. The warning is never silently dropped.
- `allowFlags()` updated to expand combined short flags (e.g. `-tulpn`) before per-character validation.

**P3d — F-NEW-12 + F-NEW-6 (MEDIUM)**
- F-NEW-12: `readFileSection()` rewritten to stream line-by-line via `readline.createInterface`. Stops reading after `clampedEnd`, so only the requested window is buffered. Closes OOM risk from large log files in `ALLOWED_READ_DIRS`.
- F-NEW-6: Full PKCE S256 enforcement implemented. `/authorize` now accepts and stores `code_challenge`/`code_challenge_method`; rejects `plain` method. `/token` verifies `SHA256(code_verifier) === code_challenge` when a challenge was registered — missing or wrong verifier returns `invalid_grant`. The discovery document no longer falsely claims PKCE support it did not enforce.

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
- Repository attribution updated from Anthropic placeholders to ForgeRift LLC across README, `.claude-plugin/plugin.json`, and security contact email.
- Version bump to align `plugin.json` with `package.json`, which had drifted.

### Removed
- `check-failing.mjs` (internal diagnostic script, not intended for distribution).
- `.mcp.json` (personal developer config that contained a hardcoded VPS IP). Added to `.gitignore`.

---

## [1.2.0] — earlier

Baseline: three-tier command security model (RED/AMBER/GREEN), OAuth 2.0 + bearer auth, rate limiting, audit logging, PM2 management tools, streamable HTTP transport with EventStore resumability.
