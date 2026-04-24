# Changelog

All notable changes to vps-control-mcp.

The format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning is [SemVer](https://semver.org/spec/v2.0.0.html).

---

## [1.10.4] - 2026-04-23

### Security - F-OP-81 / F-OP-83 / F-OP-84 / F-OP-85 (S65 closure)

#### History rewrite (F-OP-81)
- **F-OP-81** - Three files purged from all reachable git history via `git filter-branch --index-filter 'git rm --cached --ignore-unmatch ...' --prune-empty --tag-name-filter cat -- --all`: `.env.test`, `.env.test.fixture.bak`, `scripts/prepare-test-env.mjs.bak`. The `.env.test` blob had leaked Cowork session identifiers and user-handle paths across multiple commits. Stale `origin/dependabot/...` branch (which still pointed at a pre-rewrite commit containing `.env.test`) deleted, `refs/original/*` backup refs cleaned, `git gc --prune=now --aggressive` run, force-push to `origin main` and `origin --tags`. GitHub visibility toggled PUBLIC -> PRIVATE -> PUBLIC to trigger server-side GC of unreachable blobs.

> **Breaking change for existing clones.** All commit SHAs were rewritten. Collaborators and deploy targets must `git fetch origin && git reset --hard origin/main`. No forward-going code or API surface change; this is a history-cleaning release.

#### Documentation
- **F-OP-83** - SECURITY.md D10 subsection now points at `BYPASS_BINARIES` as the documented operator override for legitimate `/home` persistence-adjacent workflows (backup-restore, `~/.config` updates, CI runner provisioning under `/home/runner/...`). Example override string included.

#### Supply-chain hygiene
- **F-OP-84** - `.githooks/pre-commit` enforces refusal of merge-conflict artifacts (`_BRANCH`/`_HEAD`/`_LOCAL`/`_REMOTE`/`_BASE`/`_MERGED`/`_YOURS`/`_THEIRS.ts`) plus backup/editor files (`.orig`, `.orig.N`, `.rej`, `.bak`, `.swp`, `*~`, `.env.test`). `package.json` `prepare` script wires `core.hooksPath` to `.githooks` automatically on `npm install`.
- **F-OP-85** (parity) - `.gitignore` expanded from 5 lines (`node_modules/`, `dist/`, `.env`, `*.log`, `deploy-jobs.json`) to cover the full merge-artifact class plus `.env.test*` and `*.bak`. Brings VPS up to parity with LT.

#### Testing
- No source code touched (all fixes are docs / hygiene / history purge). Full VPS suite still passes **476/476**. DO-side deploy verified: `/root/vps-control-mcp` force-synced, `npm install`, `npm run build`, `pm2 restart vps-mcp` - restart counter incremented, process returned to `online`.

---


## [1.9.7] — 2026-04-22

### Security — H18: Per-binary bypass allowlist

- **H18** — `BYPASS_BINARIES` env var allows admins to demote specific binary+category pairs from hard-block (Layer 1) to AI-reviewed (L2/L3 pipeline); disabled by default; every bypass is logged with `[SECURITY-BYPASS]` prefix
- **Legal** — Added Disclaimer of Warranties and Limitation of Liability section to SECURITY.md; explicit acknowledgement requirements for `BYPASS_BINARIES` users

---

## [1.9.6] — 2026-04-22

### Security — D10, M7, H17, H20, M8

#### Hard-block additions to `HARD_BLOCKED_PATTERNS` (Layer 1)

- **D10** — Destination-path write protection: argv-aware matcher blocks `cp`/`mv`/`install` writing to `/etc`, `/root`, `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`, `/lib`, `/lib64`, `/boot`; also blocks `tee` targeting those paths and `dd of=<sensitive>`
- **M7** — Redirect path traversal: blocks `>>?` redirections to `../` relative escapes and absolute OS-critical paths (`/etc`, `/root`, `/boot`, `/usr/bin`, `/usr/sbin`, `/bin/`, `/sbin/`)

#### AI classifier enhancements (Layer 2 + Layer 3)

- **H17 / M8** — `commandRiskMeta()` helper: detects chain operators (`|`, `&&`, `||`, `;`, `&`) and scores a risk level (`low`/`medium`/`high`) based on chaining and high-risk keyword presence; risk level and chain operators are injected into both L2 and L3 classifier prompts; chained commands trigger a `CHAIN WARNING` directive
- **H20** — L3 safety-board now uses `LAYER3_MODEL` (default `claude-sonnet-4-6`) instead of Haiku, giving the critical final review more capability; overridable via `LAYER3_MODEL` env var

---

## [1.9.5] — 2026-04-22

### Security — Phase 3 hardening (H1–H15 + M3 + M13)

#### Hard-block additions to `HARD_BLOCKED_PATTERNS` (Layer 1)

- **H1** — Deletion alternatives: `unlink`, `find --delete`, argv-aware `mv <src> /dev/null` matcher
- **H3** — Uncovered script interpreters with inline-exec flags: `perl -e`, `ruby -e`, `lua -e`, `php -r`, `tclsh`, `expect -c`, `m4 syscmd`, `awk system()`, `bpftrace -e`
- **H6** — Kernel namespace / capability primitives: `nsenter`, `unshare`, `capsh`, `chroot`, `pivot_root`, `ip netns`
- **H7** — Additional container runtimes: `podman`, `runc`, `crun`, `lxc`, `nerdctl`, `buildah`, `singularity`, `apptainer`
- **H8** — `/sys/` filesystem and raw device access: `/sys/…`, `/dev/mem`, `/dev/kmem`, `/dev/port`
- **H9** — BPF / kernel probing: `bpftool`, `perf trace`, `perf probe`
- **H12** — `xargs` fan-out (gives `find -exec` equivalent without `-exec` syntax)
- **H13** — Privilege-escalation alternatives: `sudoedit`, `pkexec`, `doas`, `runuser`, `machinectl shell`
- **H14** — `systemd-run` scheduled execution
- **H15** — Package-manager destructive ops: `apt purge/remove/dist-upgrade`, `apt-get`, `dpkg`, `yum`, `dnf`, `zypper`, `rpm`, `snap`, `flatpak`, `conda`, `brew`, `cargo`, `gem`, `go install`, `emerge`, `pacman`
- **M3** — `ncat` (netcat variant not caught by `\bnc\b`)
- **M13** — Git history-rewrite: `git reset --hard`, `git clean -f`, `git push --force/--mirror`, `git filter-branch/filter-repo`

#### Architecture

- `validateCommand` now also calls `checkHardBlocked` synchronously so all `HARD_BLOCKED_PATTERNS` are enforced in every code path, not only when the async three-layer pipeline runs.

#### Tests

- 63 new Phase 3 bypass-corpus tests added (415 total, 415 pass).

## [1.9.4] — 2026-04-22

### Security (S61 Phase 2 — architectural hardening)
- C11/D4: Hardened Layer 2 + Layer 3 prompts against injection — command wrapped in nonce-tagged `<cmd nonce="…">` delimiter; anti-injection clause added to both user and system prompts; classifiers now require nonce echo on PASS verdicts; default-BLOCKED on any unexpected response format; post-classifier Layer 1 re-check after every L2 PASS so a forged PASS cannot bypass static patterns (`tools.ts`)
- C12/D6: Fail-closed on Layer 2 + Layer 3 errors — missing `ANTHROPIC_API_KEY` or any API exception now returns BLOCKED instead of silently passing; opt-out via `LAYER_STRICT_MODE=false` env var; all skip/error events logged at WARN/ERROR severity (`tools.ts`)
- D7: Startup-time audit log path validation — `AUDIT_LOG_PATH` values of `/dev/null`, `NUL`, `/dev/zero`, `/dev/stdout`, `/dev/stderr`, and any `/tmp/*` path are rejected with a hard error at boot; parent directory existence is verified before the server starts (`config.ts`)

---

## [1.9.3] — 2026-04-22

### Security (S60 Phase 1)
- Blocked `modprobe`, `insmod`, `rmmod`, `depmod` (C5 — kernel module operations; `modprobe` was already blocked, others were missing)
- Blocked `LD_PRELOAD`, `LD_AUDIT`, `LD_LIBRARY_PATH` in command strings (C7 — dynamic-linker injection)
- Widened shell `-c` flag pattern from `\s+-c` to `[^\n]*\s+-c`, catching flags-before-c variants (e.g. `bash -x -c payload`) (C8)
- Blocked `vssadmin`, `wbadmin`, `wevtutil`, `ntdsutil` (C10 — anti-forensics toolkit)
- Added bypass-corpus test suite: 21 adversarial vectors, all blocked

### Fixed (S61 test suite)
- Fixed 11 pre-existing test failures (341/352 → 352/352 pass)
- `validatePath`: EACCES error now surfaces as "path not permitted" instead of crashing
- `validateArgPath`: added `COUNT_FLAGS` set so numeric counts after `-n`/`-c`/`--lines` etc. are not treated as file paths (`tail -n 50 file.log` no longer blocked)
- `validateSedArgs`: sed expression argument is now skipped for path validation (mirrors `patternConsumed` logic in `validateGrepArgs`)
- `validateFindArgs`: glob patterns and predicates (e.g. `"*.log"`) excluded from path validation
- `scripts/prepare-test-env.mjs` restored and extended to create test directory scaffolding
- `.env.test.fixture` restored (had been deleted between v1.8.4 and v1.9.1)

---

## [1.9.2] — 2026-04-21

### Fixed
- Removed `confirm` gate from `deploy_vps_mcp` (self-deploy of MCP server). Gate retained on `deploy` (app pipeline) per ToS §8. `deploy_vps_mcp` already requires `dry_run=false` as confirmation intent; the additional `confirm` parameter caused a bootstrapping deadlock when the Cowork schema cache was stale.

---

## [1.9.1] — 2026-04-21

### Security (S59-gap)
- Layer 1: Fixed pip3/pip2 install bypass (versioned pip was not matched by previous pattern)
- Layer 1: Added `find -exec` and `xargs` dangerous-command patterns to `code-exec`
- Layer 1: Added `sed -i` and `awk` absolute-path write patterns to `file-write`
- Layer 1: Added `strace`, `ltrace`, `gdb`, `ptrace` to `info-leak`
- Layer 1: Added `git clone` to `code-exec`
- Layer 1: Added `base64-exec` category (base64 -d, openssl base64 -d)
- Layer 1: Added `apt upgrade` / `apt dist-upgrade` to `pkg-install`

## [1.9.0] — 2026-04-21

### S59 pre-publication hardening — BLOCKED tier, deploy gating, OAuth deactivation, CVSS SLA

**BLOCKED tier: Three-layer pipeline for unrecoverable operations (ToS §8)**

A new BLOCKED tier sits above RED. Any command matching one of 11 static pattern categories is refused before execution with a structured error message and manual-steps guidance. If `ANTHROPIC_API_KEY` is set, Layer 2 (AI pre-classification via `claude-haiku-4-5`) and Layer 3 (multi-persona adversarial safety board) run in parallel for every `run_approved_command` call. All three layer verdicts are written to the audit log regardless of outcome. Layers 2 and 3 fail-open if the API key is unset — Layer 1 (static patterns) always runs.

Blocked categories:
1. Recursive / bulk file deletion (`rm -r`, `find -delete`, `rsync --delete`)
2. Redirect / truncation overwrite (`truncate -s 0`, `cat /dev/null >`)
3. Destructive git history rewrite (`--force`, `--mirror`, `filter-branch`, `+` prefix push)
4. Database destruction (`DROP DATABASE/TABLE`, `TRUNCATE TABLE`, `DELETE FROM` without WHERE, `FLUSHALL`)
5. Disk-level write operations (`mkfs`, `wipefs`, `dd if=/dev/zero`, `blkdiscard`)
6. System power-state changes (`poweroff`, `halt`, `systemctl reboot`, `kill -9 1`)
7. Credential / key material destruction (`rm`/`shred` of `.pem`, `.ssh/`, `/etc/shadow`)
8. OS permission / user destruction (`chmod -R 000`, `chown -R /`, `visudo`)
9. Firewall / network security destruction (`iptables -F`, `ufw disable`, `setenforce 0`)
10. Audit log / evidence destruction (`rm /var/log/`, `history -c`, `unset HISTFILE`)
11. Container / orchestration nuclear (`docker system prune -af`, `kubectl delete --all`)

**Deploy gated confirmation (ToS §8 + §B.2)**

`deploy` and `deploy_vps_mcp` now require `confirm=true` per invocation. Without it, a detailed confirmation prompt is returned showing the target directory, last git commit, description, and the exact step list. Session-level consent is not accepted — each call requires explicit confirmation. Confirmed deploys are written to the audit log via `logDeployConfirmation` (new export from `audit.ts`).

**OAuth deactivation in `uninstall.sh` (ToS §14.2)**

Added section 3 to the uninstall script. If `.oauth-client.json` is present, the script extracts the `client_id`, optionally POSTs a revocation request to `$OAUTH_REVOCATION_ENDPOINT`, and removes the local config file. Instructs users to contact support if the endpoint is not configured. DNS/sslip.io cleanup guidance added as section 4.

**CVSS patch SLA process doc (ToS §A.3)**

Created `docs/CVSS_PATCH_SLA.md` — internal process document defining the 72-hour (CVSS 9+) and 30-day (CVSS 7–8.9) patch SLA, the monitoring stack (npm audit + Dependabot), triage/patch/release/document steps, and escalation path.

**Package and config**
- `@anthropic-ai/sdk: ^0.38.0` added to `dependencies` (used by BLOCKED-tier Layers 2 and 3)
- `ANTHROPIC_API_KEY` added to `.env.example`
- Version bumped from 1.8.4 → 1.9.0

---

## [1.8.4] — 2026-04-19

### Token frugality patch — Policy §5.B alignment (S58)

Re-audited all 15 tool output paths against Anthropic Software Directory Policy §5.B ("Output size should be commensurate with task complexity"). Four output paths were missing the existing `truncate()` helper. Mechanical wraps applied — no behavioral change to bounded outputs, defensive cap on previously-unbounded outputs.

- **`git_status` (F-TOK-5)** — wrap return in `truncate()`. A repo with many untracked files (uncontrolled `dist/`, accidental bulk install) could blow past `MAX_OUTPUT_CHARS`.
- **`git_pull` (F-TOK-5)** — wrap return in `truncate()` for symmetry with other output-returning paths.
- **`git_push` (F-TOK-5)** — wrap return in `truncate()`. Push can emit hook output plus warnings.
- **`get_system_health` (F-TOK-5)** — wrap return in `truncate()` for symmetry with other health-output paths.

No code-path changes. Tool behavior is identical to v1.8.3 for inputs that produce output below `MAX_OUTPUT_CHARS` (3,000 chars). Outputs that exceed the cap now return a truncation marker instead of an unbounded string.

`npm audit` clean (0 vulnerabilities across 167 deps).

---

## [1.8.3] — 2026-04-19

### Policy-compliance tool-description tightening (S57)

Re-audited all 15 tool descriptions against Anthropic Software Directory Policy §2.A–G before marketplace submission. One parity tweak — no functional changes.

- **`deploy_vps_mcp` description** — `npm install` → `npm install --include=dev` so the documented sequence matches the actual deploy invocation exactly. The code always ran the `--include=dev` form; only the description was loose.

All other tool descriptions passed the audit clean. The `run_approved_command` behavioral instructions ("do not rephrase to bypass a RED block") are plain-English and safety-positive — compliant with Policy 2.G (no hidden/obfuscated/encoded instructions).

No code changes. Tool behavior is identical to v1.8.2.

---

## [1.8.2] — 2026-04-19

### Security hardening — seventh-pass Opus adversarial review (S56)

Clean pass: zero CRITICAL, zero HIGH findings against the v1.8.1 rebrand. Three LOW findings and two defence-in-depth notes addressed. See `ADVERSARIAL_REVIEW.md` "Seventh pass — rebrand audit" for the full report.

**F-OP-46 (LOW): `.env.test` leak vector**
- The committed `.env.test` fixture ships in the public tarball; a future careless edit adding a developer token would publish it to every installed user.
- Fix: `.env.test` moved to `.gitignore`; canonical fixture now at `.env.test.fixture` (name signals intent); new `pretest` npm script regenerates `.env.test` from the fixture every test run.

**F-OP-47 (LOW): `setup.sh` APP_DIR foot-gun**
- `setup.sh` previously wrote `.env` with `APP_DIR` commented out. Fresh installs crashed in a PM2 restart loop; frustrated operators often "fixed" it with `APP_DIR=/root` or `APP_DIR=/`, silently broadening the MCP's read surface.
- Fix: `.env` now ships with `APP_DIR=/root/CHANGE_ME_BEFORE_START` sentinel. `setup.sh` explicitly rejects the sentinel at the end of the setup run with clear guidance on why `/root` or `/` are wrong.

**F-OP-48 (LOW): stale `CURRENT_VERSION` fallback**
- `src/index.ts:724` fallback literal was `'1.7.0'`, reached when `package.json` parsing fails. Gave `/health` an honest-looking but stale version.
- Fix: fallback is now `'unknown'`. If the real read succeeds, it's overwritten with the truth; if it fails, `unknown` is an honest signal that cannot rot.

**Defence-in-depth — audit log filename block**
- `SENSITIVE_FILE_PATTERNS` now includes `mcp-audit.log` and `/audit.log` so operators who relocate `AUDIT_LOG_PATH` inside `APP_DIR` don't accidentally make the audit log readable via `read_file_section`.

**Defence-in-depth — `getRecentErrors` path validation**
- `tools.ts` `getRecentErrors` now routes its constructed `logPath` through `validatePath` after the existence check. Symmetric with `readFileSection`; neutralises any future regression that loosens `validateProcess`.

---

## [1.8.1] — 2026-04-19

### Rebrand + public release

- Rebranded from single-app-specific to generic multi-cloud VM control plane.
- `APP_DIR` now required env (no default); deploy enum collapsed to `app | self`; sensitive-path carveout derived from `path.basename(CONFIG.APP_DIR)` at module load; `ALLOWED_PROCESSES=[]` default.
- Repo flipped public on the ForgeRift org with security features enabled (Dependabot, CodeQL, secret scanning, push protection).
- First single-commit public release. Bundled sixth-pass adversarial findings F-OP-37/38/44/45.

## [1.7.x] — 2026-04-18

Fourth, fifth, and sixth-pass Opus adversarial reviews closed. See `ADVERSARIAL_REVIEW.md` for the full finding log (F-OP-20–F-OP-45).

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
- Transparency: devs evaluating the repo should be able to see limitati