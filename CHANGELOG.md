# Changelog

All notable changes to vps-control-mcp.

The format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning is [SemVer](https://semver.org/spec/v2.0.0.html).


## [Unreleased] - 2026-05-06 (External-AI bypass-discovery round closeout — round 2)

External multi-model adversarial bypass-discovery audit (DeepSeek + Grok +
Gemini, 67 raw findings → 22 deduplicated unique) against existing Layer 1
patterns and per-binary validators. Two P0 (audit-claimed-uncovered) and six
P1 findings closed, plus the A1 binary-alias normalization architectural
improvement. Bundled with the prior NF-S69-A round (below) into the next
version-archive bump.

Full triage at `forgerift-license-api/docs/legal/external-ai-bypass-triage_2026-05.md`;
per-finding dispositions in `ADVERSARIAL_REVIEW.md`.

### Architectural

- **A1 — binary-alias normalization** (commit `c9f39cb`) -- new
  `BINARY_ALIASES` map normalizes binary references to canonical forms
  before pattern matching: `pwsh` → `powershell`, `pip3` → `pip`, `nodejs`
  → `node`, `ncat`/`netcat`/`nc.openbsd` → `nc`, and similar variants.
  Complements the positive allowlist (which rejects any binary not on the
  canonical list outright) by ensuring known-aliased forms resolve to the
  canonical entry. 9 regression tests pinned.

### Security (P0 -- audit-claimed coverage gaps)

- **P0.1 / call operator + P0.4 priv-esc tightening** (commit `edb501a`)
  -- new explicit rule for PowerShell call operator (`& { ... }`) and
  tightened priv-esc patterns to catch sister-binaries (`sudoedit`,
  `doas`, `pkexec`, `runuser`). The prior `\bsudo\b` failed against
  `sudoedit` (word-boundary requires non-word char between `sudo` and
  `edit`); new pattern explicitly enumerates priv-esc family. 7 + 5
  regression tests.
- **P0.6 (regression pin)** (commit `4f59e88`) -- path-qualified binary
  forms incidentally closed by existing `\b`-anchored patterns; pinned
  via 7 regression tests under round-2 finding ID.

### Security (P1)

- **P1.1 / base64 long-form decode** (commit `4ebf291`) -- `base64 -D`,
  `--decode`, `--decode-line` covered. 5 regression tests.
- **P1.3 / P1.4 / P1.5 — git pre-subcommand RCE** (commit `495000a`) --
  new defense-in-depth RED rules for `git -c alias.X='!cmd'` aliasing,
  `git --config-env`, and `git -C /<sensitive>` directory relocation.
  `validateGitArgs` already catches these on the positive-allowlist path
  via `FORBIDDEN_GIT_PRE_SUBCOMMAND_TOKENS`; new RED rules close the gap
  for any code path that runs `validateCommand` without then routing
  through `validateAgainstAllowlist`. 9 regression tests across the
  cluster, false-positive guarded against legitimate `/root/myapp`-style
  deployments.
- **P1.6 / GIT_* env-var smuggling** (commit `6fdc42e`) -- same shape
  as LT P1.6: `GIT_DIR`, `GIT_INDEX_FILE`, `GIT_WORK_TREE`,
  `GIT_SSH_COMMAND`, `GIT_EDITOR`, `GIT_EXEC_PATH`, `GIT_TEMPLATE_DIR`,
  `GIT_CEILING_DIRECTORIES`, `GIT_CONFIG*`, `GIT_PAGER`, `GIT_ASKPASS`,
  `GIT_OBJECT_DIRECTORY`, `GIT_NAMESPACE`, `GIT_SSH`. 8 regression tests.
- **P1.7 / alternative downloaders** (commit `5658752`) -- `fetch`,
  `axel`, `aria2c`, `httpie`, `http <METHOD>`, `https <METHOD>`. 7
  regression tests.
- **P1.12 / chattr** (commit `28a5cb4`) -- file-attribute manipulation
  including `chattr +i` and `+a`. 4 regression tests.

### Tests

- **665/665 → 726/726 pass.** 61 new regression tests added across this
  round. Zero regressions on the prior 665.

### Documentation

- `ADVERSARIAL_REVIEW.md` updated with full disposition table (commit
  `ce0c1ee`).
- `SECURITY.md` updated with binary-alias canonicalization note.

### Method note

For the genuinely uncovered cases (P0.1 call operator, P0.4 `sudoedit foo`,
P1.1 `base64 --decode`, P1.3/P1.4/P1.5 git pre-subcommand RCE on
validateCommand-only paths, P1.6 GIT_DIR, P1.7 `fetch`, P1.12 `chattr`), the
new RED rules are the first defense-in-depth layer at the BLOCKED_PATTERNS
tier. The structured per-binary validators (`validateGitArgs`, etc.)
already caught most of P1.3/4/5 on the positive-allowlist path; the new
RED rules close the gap for any code path that runs `validateCommand`
without then routing through `validateAgainstAllowlist`.

---

## [Unreleased] - 2026-05-05 (NF-S69-A deny-list audit closeout)

Internal adversarial audit pass against the Layer 1 deny-list and per-binary
arg validators (denylist_audit_triage_2026-05.md). Three P0 (critical) and
three FP-A (UX) findings closed in this batch. No version-archive bump yet --
next release will package these together with any further P1 work.

### Security (P0 -- exploitable today)

- **NF-S69-A1 / FN-VPS-001** (commit `7c27613`) -- `validateGitArgs` now walks
  pre-subcommand tokens and rejects the options git accepts before the
  subcommand: `-c`, `-C`, `--git-dir`, `--work-tree`, `--exec-path`,
  `--config-env`, `--namespace`, `--super-prefix`, `-P`, `--paginate`,
  `--no-pager`, `--list-cmds`, `--attr-source`. The prior validator only
  inspected `args[0]`, so `git -c core.pager='/bin/sh -c whoami' log` (RCE on
  routine `git log` because `core.pager` fires on output) and
  `git -C /etc log` / `git --git-dir=/tmp/.git status` (relocate working
  tree) slipped through. Both bare and `=value` glued forms rejected.
- **NF-S69-A2 / FN-VPS-004** (commit `153fd55`) -- `validateGitArgs` rejects
  `--no-index` anywhere in the post-subcommand args. `git diff --no-index
  /etc/shadow /tmp/x` is a path-pair diff that ignores the repo and reads
  any two files git can stat. `/etc/shadow` content is not caught by
  `SECRET_OUTPUT_PATTERNS`, so contents reached the model. Defensively also
  rejected on `git show`.
- **NF-S69-A3 / FN-VPS-012** (commit `f435a05`) -- `validateDockerArgs`
  expanded. Prior coverage caught `--privileged`, `--network=host`,
  `--pid=host`, `--ipc=host`, `--cap-add=all` only. Now also blocks
  `--userns=host`, `--uts=host`, prefix-match `--cap-add=*` (any granular
  cap, not just `=all`), `--security-opt`, `--device`. `-v` / `--volume` /
  `--mount type=bind,source=...` source paths must resolve inside `APP_DIR`;
  named volumes (no leading `/`) still allowed. Each missing flag was, on
  its own, equivalent to root on the host (e.g. `-v /:/host alpine cat
  /host/shadow`).

### UX (FP-A -- friction-killers)

- **FP-VPS-001** (commit `78a4a0a`) -- `\bsource\b` and `\bexport\b` patterns
  re-anchored to start-of-token / shell-separator boundary. The prior
  unanchored form blocked `grep export /app/x.js`,
  `find /app/source -name '*.js'`, `ls /app/exports/`. The shell builtin
  form (`export FOO=bar`, `; source /tmp/x`, `&& export ...`) is still
  caught.
- **FP-VPS-003** (commit `c237d3c`) -- `journalctl` moved from blanket RED
  to `POSITIVE_ALLOWLIST` with `validateJournalctlArgs`. Operator opts in
  by setting `ALLOWED_UNITS=nginx,my-api` (env, comma-separated). Every
  invocation must name a unit on the allowlist via `-u`/`--unit`. `--follow`,
  `--vacuum-*`, `--rotate`, `-D`/`--directory`/`--root` rejected. Sysadmins
  can finally read their own service's logs through MCP instead of falling
  out to SSH.
- **FP-VPS-011** (commit `b018929`) -- `validateAgainstAllowlist` detects
  shell metacharacters (`|`, `>`, `>>`, `<`, `<<`, `<<<`, `&`) up front and
  emits a clear `BLOCKED [shell-metachar]` error naming the offending token
  and suggesting workarounds. The prior failure mode was an opaque
  "File not found: '|'" thrown by `validateArgPath` when it tried to
  realpath the literal `|` string.

### Tests

- 665/665 pass (was 593 before this batch -- 72 new regression tests across
  the six findings, every one covering both the rejected bypass attempt and
  a representative legitimate case to guard against false positives).
- `.env.test.fixture` now sets `ALLOWED_UNITS=nginx,my-api` so the test
  fixture exercises a non-empty allowlist.


## [1.13.5] - 2026-05-04 (NF-S69-8 ANSI strip)

Independent reviewer pass after Gemini chat highlighted ANSI escape
sequence injection as a defense-in-depth gap. Mirror of LT 1.13.3.

### Security

- **NF-S69-8** -- New `stripAnsi()` helper applied at the `truncate()`
  chokepoint, which means ALL read-side output paths (PM2 logs, git
  output, command output, file reads, search results) now strip
  ANSI/CSI/OSC sequences before reaching the model. VPS previously
  had no ANSI handling at all; this brings it to parity with LT's
  newly-centralised handling. Pattern same as LT:
  `\x1b(?:\[[0-9;]*[mGKHFABCDJst]|\][^\x07]*\x07)`.

### Internal

- Version constants synced to 1.13.5 across package.json,
  .claude-plugin/plugin.json.
- marketplace.json ref pinned 'v1.13.4' -> 'v1.13.5'.

### Tests

- npm test 593/593 still pass. ANSI codes are not in test fixtures so
  behaviour is unchanged for normal data.
## [1.13.4] - 2026-05-03

Independent line-by-line audit of `src/tools.ts` after 1.13.3 surfaced
a defense-in-depth gap. Closed in this release.

### Security

- **NF-S69-6** -- `validateGitArgs` now blocks `git pull` and `git fetch`
  via `run_approved_command`. Background: every structured git tool
  (`git_status`, `git_log`, `git_pull`, `git_push`, `deploy`,
  `deploy_vps_mcp`) injects `GIT_HARDENING_FLAGS` -- 10 `-c key=value`
  overrides covering `core.sshCommand`, `core.editor`, `core.pager`,
  `core.askpass`, `credential.helper`, `protocol.ext.allow`,
  `protocol.file.allow`, `core.fsmonitor`, `core.hooksPath`, and
  `uploadpack.packObjectsHook`. The escape-hatch `run_approved_command`
  path (line 2834) does `exec(cmd, args)` directly with no flag
  injection. So `git pull` via the escape hatch was running
  unhardened, honouring whatever the local `.git/config` contained for
  those keys. Same family as F010 (per-binary validator gap that a
  chained primitive could weaponise into RCE). Customers who
  legitimately need `git pull` already have the structured `git_pull`
  tool, which carries the hardening. `fetch` was already caught by a
  RED pattern (`/\bgit\s+fetch\b/`) but is listed in the validator's
  `blocked` Set for symmetry with `pull`.

### Tests

- `npm test` 593/593 pass. No behaviour change for healthy installs;
  only the escape-hatch path that was running unhardened is now
  redirected to the structured tool.
## [1.13.3] - 2026-05-03

Independent reviewer pass after 1.13.2 surfaced four post-audit
documentation/config drifts. None were active code-path security
regressions. Closed in commit `c16f2ec`. No release archive bump --
all changes are doc + config-default.

### Documentation

- **NF-S69-1** -- `docs/security/WHITEPAPER.md` Â§"Authentication /
  licensing" rewritten. Prior version mirrored the LT POSTURE shape
  (POST to `payments.forgerift.io` with machine_id + product_id,
  calls `register_activation_with_cap`, enforces per-machine cap).
  `src/auth.ts` does none of that -- it does per-request token
  lookup against Supabase `customers` with a plan-based check, with
  OAuth 2.0 + PKCE on top. New "What VPS does NOT do today"
  subsection explicitly notes the per-machine cap is LT-only with
  VPS migration tracked as post-marketplace roadmap.
- **NF-S69-2** -- `README.md` "cryptographic audit trails"
  overstatement removed (`src/audit.ts` has no crypto). RED-tier
  table row "no override possible" replaced with accurate
  "auditable opt-out via `BYPASS_BINARIES` env (logged as
  `[SECURITY-BYPASS]`)" -- the prior wording contradicted the same
  README's config table.
- **NF-S69-4** -- `docs/security/WHITEPAPER.md` Â§"Data handling"
  outbound HTTP claim corrected (Supabase + `api.anthropic.com`,
  not `payments.forgerift.io` -- VPS never makes that call). Audit
  log default path corrected to `${APP_DIR}/mcp-audit.log` to match
  `config.ts:84`. README version badge bumped 1.12.0 -> 1.13.2 to
  match `package.json`.
- `MARKETPLACE_LISTING.md` "no prompt can override them" overstatement
  loosened to mention `BYPASS_BINARIES`. ALLOWED_PROCESSES default
  in config table changed from `vps-mcp` to `(empty)`.
- `SECURITY.md` "Process Log Access Gating" default `vps-mcp` ->
  `empty`. README + SECURITY category count synced 43 -> 44.
- `CLAUDE_CONTEXT.md` version 1.12.0 -> 1.13.2; RED-tier "No
  Override" header rephrased to acknowledge BYPASS_BINARIES.

### Config

- **NF-S69-3** -- `src/config.ts` `ALLOWED_PROCESSES` default
  fallback changed from `['sharpedge-api', 'vps-mcp',
  'forgerift-payments']` to `[]`. The in-code comment already
  claimed the default was empty; this was a code/comment drift in
  addition to a leak of the operator's personal process names to
  marketplace customers.

### Tests

- `npm test` 593/593 still pass. No code-behavior change for
  healthy installs.
## [1.13.2] - 2026-05-03

Opus pre-marketplace review close-out. Two findings on top of 1.13.1:

### Security

- **NF-2 (commit 7d36194)** -- Ported `scrubSecrets()` regex bank
  from `local-terminal-mcp/src/tools.ts` (lines 1541-1605). The
  POSTURE/WHITEPAPER docs claimed VPS ran tool stdout/stderr through
  `scrubSecrets()` before returning to the model; the function did
  not actually exist in `vps-control-mcp/src/`. `audit.ts` only
  redacted call args via `sanitizeArgs`, not output. Now `truncate()`
  applies the regex bank before its size cap, so all 14 existing call
  sites pick up the redaction with zero per-site change. Patterns
  cover well-known SaaS API key shapes, AWS/STS access keys,
  PEM-armored private keys, and high-entropy base64 blobs (>=80
  chars). Brings VPS to parity with LT.

### Documentation

- **NF-3** -- `docs/security/WHITEPAPER.md` had a leftover
  backtick-backslash-backtick placeholder where the audit log path
  variable should be referenced. Replaced with `CONFIG.AUDIT_LOG_PATH`
  + a note about the `AUDIT_LOG_PATH` env var override.

### Tests

- `npm test` 593/593 pass (no behaviour regression; `scrubSecrets()`
  is transparent to existing assertions because no fixtures embed
  real secret-shaped strings).

## [1.13.1] — 2026-04-27

### Security — Adversarial Review Round 15 (F-S68-1..F-S68-21) — Remediation Pass

S68 Fifteenth-Pass adversarial review remediation. All 8 BLOCKERs and 13 MINORs closed. 4 JUDGEMENT-REQUIRED items documented.

- **F-S68-1** — Working tree committed and v1.13.1 tagged (v1.13.0 was never tagged).
- **F-S68-4/F-S68-19** — `audit.ts`: all string fields now capped at 512 chars (not just `command`/`justification`); `tool` field capped at 256. Eliminates audit-log rotation amplification via oversized args.
- **F-S68-5** — `validateNodeArgs`: `--env-file` and `--conditions` (and `=` forms) added to `BLOCKED_EXACT`/`BLOCKED_PREFIXES`. Closes Node 20.6+ env-preload vector.
- **F-S68-6** — `validateNpmArgs`: `npm audit fix` and `npm audit signatures` (write ops) now rejected. `npm audit --json` still allowed.
- **F-S68-7** — Deploy and background job IDs now include `crypto.randomBytes(4).toString('hex')` suffix. Eliminates same-millisecond ID collision.
- **F-S68-8** — `validatePath` now opens file with `O_NOFOLLOW` and returns `{ real, fd }`. `readFileSection` passes fd to `createReadStream`; `searchFile` uses `/proc/self/fd/${fd}`. Closes TOCTOU symlink-swap window.
- **F-S68-10** — Doc category count corrected: 43 → 44 in `MARKETPLACE_LISTING.md` and `.claude-plugin/CLAUDE.md`.
- **F-S68-14** — `persistJob` now serialises concurrent writes through a Promise-chain mutex, preventing second-writer-wins data loss.
- **F-S68-15** — `validatePm2Args`: explicit `BLOCKED_SUBS` set added — `pm2 install`, `pm2 update`, `pm2 kill`, `pm2 deepMonitoring`, and 12 others now rejected before fall-through.
- **F-S68-17** — `AbortSignal.timeout(15_000)` added to Layer 2 and Layer 3 API calls.
- **F-S68-18/F-S68-33** — `SECURITY.md` now documents `LAYER_STRICT_MODE=false` fail-open behaviour with prominent warning.
- **F-S68-20** — `.github/workflows/dist-freshness.yml` added.
- **F-S68-21** — `typescript` moved from `dependencies` to `devDependencies` in `package.json`.


## [1.13.0] — 2026-04-27

### Security — Adversarial Review Round 14 (F-S67-1..F-S67-59, VPS-applicable)

S67 Fourteenth-Pass adversarial review of v1.12.0. All VPS-applicable BLOCKERs and MINORs closed. Both plugins bumped to v1.13.0.

**BLOCKERS**

- **F-S67-1 — Version mismatch** — `.claude-plugin/plugin.json` declared `1.2.0` instead of `1.13.0`. Bumped. `src/index.ts:133` literal `'1.1.0'` replaced with `CURRENT_VERSION`. `scripts/check-versions.mjs` CI guard added.
- **F-S67-16 — pm2 logs flag exfil** — `pm2 logs` in READ_ONLY had no flag validation. `--raw` (unbounded byte stream) and `--json` (bulk structured dump) flags now blocked with redirect to `get_recent_errors`/`get_recent_output`. Plain `pm2 logs` still passes.
- **F-S67-17 — dig zone-transfer case bypass** — `isBlockedQtype` rewritten: (1) strips IXFR serial suffix (`=NNN`), (2) handles RFC-3597 `type<NNN>` numeric form, (3) case-insensitive comparison. `dig google.com Axfr`, `dig -tAXFR …`, `dig google.com type252`, `dig google.com IxFR=2` all now blocked. HARD_BLOCKED defense-in-depth patterns added.
- **F-S67-18 — AUDIT_LOG_PATH validator gaps** — `/dev/full`, `/dev/console`, `/dev/tty` added to FORBIDDEN list. `fs.statSync` check rejects non-regular files (char/block/FIFO). `fs.realpathSync` resolves symlinks before FORBIDDEN check (mirrors F-OP-91). `audit.ts` catch block upgraded to guaranteed stderr flush.

**MINOR**

- **F-S67-19** — `marketplace.json` `source.ref` pinned `main` → `v1.13.0`.
- **F-S67-20** — VPS `plugin.json`: count `100+` → `275+/43 categories`; `OAuth 2.0` → `Supabase token-based auth`; `rate limiting` dropped.
- **F-S67-35** — `pm2 monit` removed from READ_ONLY (interactive curses UI). Users directed to `get_pm2_status`.
- **F-S67-36** — `README.md` AMBER table examples corrected (removed promoted-to-RED items `find -exec`, `awk`, `sed -i`).
- **F-S67-37** — `.claude-plugin/CLAUDE.md`: RED count `100+` → `275+/43`; AMBER examples corrected; all 17 tools enumerated.
- **F-S67-38** — `REMEDIATION-PROGRESS.md` replaced with redirect paragraph (was severely stale, claimed 114 failing tests and non-existent layers).
- **F-S67-39** — `COMMAND_POLICY.md` four `**Proposed:**` annotations replaced with `**GREEN**` (all already shipped).
- **F-S67-40** — `CLAUDE_CONTEXT.md` Layer 2 label corrected from "AMBER classifier" to "Claude Haiku BLOCKED-tier pre-classifier".
- **F-S67-41** — `COMMAND_POLICY.md` pm2 logs row updated with flag restrictions (closed with F-S67-16).
- **F-S67-42** — `validateServiceArgs`: `service --status-all` now allowed; `service nginx status -v` (extra arg) now rejected.
- **F-S67-43** — `validateSystemctlArgs` `--host`/`--machine` matching tightened to exact equality + `=` prefix (prevents `--hostname` false-positive).
- **F-S67-44** — `tr`/`paste`/`jq` removed from POSITIVE_ALLOWLIST (non-path positionals break `validateArgPath`). `cut` restored: all its option flags begin with `-` so `validateArgPath` skips them safely; path traversal still caught.
- **F-S67-45** — `marketplace.json` + `MARKETPLACE_LISTING.md` repo case aligned to `ForgeRift/vps-control-mcp`.
- **F-S67-46** — `.env.test.fixture` placeholder changed to `__REPLACE_ME__` with explanatory comment.
- **F-S67-53** — `auth.ts` `constantTimeEqual`: length comparison moved inside `crypto.timingSafeEqual` to close length-oracle timing side-channel.
- **F-S67-54** — `audit.ts`: per-field caps replace flat 300-char JSON truncation (`command` 1024, `justification` 512, others 256).
- **F-S67-55** — `validateSystemctlArgs`: combined short-flag cluster rejection (`-MH`, `-HM`) added for symmetry with HARD_BLOCKED defense-in-depth.
- **F-S67-56** — Pre-commit hook extended: `npm run build && git diff --exit-code dist/` added to catch stale `dist/` at commit time.

**Test results:** 562/562 pass (552 pre-existing + 10 new). Zero regressions.

---

## [1.12.0] — 2026-04-25

### Security — Adversarial Review Round 13 (F-OP-85..F-OP-97)

13 findings from targeted Opus review of v1.10.8 + v1.11.0 changes. 0 CRITICAL, 3 HIGH, 5 MEDIUM, 5 LOW.

**HIGH**

- **F-OP-85 — service validator arg-position bug** — `validateServiceArgs` was checking `args[args.length - 1]` (last arg) instead of `args[1]` (action position). In `service nginx restart`, both positions coincide — so tests passed — but `service nginx status extra` would have passed (last arg = "extra" ≠ "status" → blocked). More critically: `service -H nginx status` (flag-injection in name slot) was passing. Fixed: check `args[1]`, enforce `args.length === 2`, reject name values starting with `-`. Service RED pattern extended to cover `force-reload`, `try-restart`, `condrestart`, `force-stop`.
- **F-OP-86 — systemctl -H/--host/-M/--machine SSH pivot not blocked** — `-H`/`--host` and `-M`/`--machine` route systemctl commands to a remote host over SSH, enabling lateral movement. Fixed: arg loop in `validateSystemctlArgs` checks for these flags before sub-command dispatch. HARD_BLOCKED pattern added as defense-in-depth.
- **F-OP-87 — systemctl show/cat env leak** — `show` and `cat` were in `validateSystemctlArgs` READ_ONLY set (v1.11.0). `systemctl show <unit>` dumps the full unit environment including any `Environment=` or `EnvironmentFile=` directives, which may contain `MCP_AUTH_TOKEN` or `DATABASE_URL`. Removed from READ_ONLY. Added to RED pattern (`systemctl show|cat` now triggers `service-mgmt` block). Same parity as F-OP-6/7 closures for `ps`/`env`.

**MEDIUM**

- **F-OP-88 — bare crontab opens interactive editor** — `validateCrontabArgs` allowed `args.length === 0` (bare `crontab`), which drops into an interactive vi/vi-compatible editor. Only `crontab -l` is intended. Removed the `args.length === 0` branch.
- **F-OP-89 — pm2 reload lifecycle-affecting** — `reload` was in the `validatePm2Args` READ_ONLY set. In fork mode it causes a full restart (brief downtime); in cluster mode it is zero-downtime rolling. Either way it's a lifecycle-affecting operation, not read-only. Removed from READ_ONLY. (AMBER warning via `checkAmberWarnings` remains.)
- **F-OP-90 — pm2 flush destroys log evidence** — `flush` was in the `validatePm2Args` READ_ONLY set. `pm2 flush` truncates all log files managed by PM2 — equivalent to evidence destruction. Removed from READ_ONLY. Added HARD_BLOCKED pattern in `audit-log-destruction` category.
- **F-OP-91 — findPm2Log symlink escape via path.resolve()** — `path.resolve()` does not follow symlinks; a symlink inside `PM2_LOG_DIR` pointing to `/etc/passwd` would pass the bounds check. Fixed: replaced `path.resolve(p)` with `fs.realpathSync(p)` (try/catch returning `false` on ENOENT/broken symlink).
- **F-OP-92 — dig @resolver pivot and AXFR/IXFR zone transfer** — `validateDigArgs` did not block `@<resolver>` args (routes DNS through attacker-controlled resolver) or AXFR/IXFR query types (full/incremental zone transfer = hostname enumeration). `nslookup` accepted zero args (drops into interactive mode). `host -l` performs a zone transfer. Fixed: `validateDigArgs` blocks `@`-prefixed args and `AXFR`/`IXFR` query types. New `validateHostArgs` blocks `-l`/`--list`. New `validateNslookupArgs` requires ≥ 1 arg. Both wired into POSITIVE_ALLOWLIST.

**LOW**

- **F-OP-93 — crontab long-form flags not blocked** — RED pattern `/\bcrontab\b.*-[eru]\b/` matched short flags only. `crontab --edit`, `--remove`, `--user` bypassed it. Fixed: pattern extended to `(-[eru]\b|--edit\b|--remove\b|--user\b)`.
- **F-OP-94 — systemctl env-manipulation and container-escape sub-commands not blocked** — RED pattern missed `set-environment`, `unset-environment`, `import-environment` (env poisoning), `link` (arbitrary unit file loading), `revert`, `switch-root` (container escape), `freeze`, `thaw`. Added all to RED pattern.
- **F-OP-95 — atq accepted arbitrary args** — POSITIVE_ALLOWLIST used `allowAny` for `atq`. Replaced with `allowFlags('-V', '--version', '-q')`.
- **F-OP-96 — AUDIT_LOG_PATH bypass of SENSITIVE_FILE_PATTERNS** — `readAuditLog` reads `CONFIG.AUDIT_LOG_PATH` directly, bypassing the standard `validatePath` gate. If an operator misconfigures `AUDIT_LOG_PATH=/etc/shadow`, the dedicated audit tool would expose it. Fixed: runtime check against `SENSITIVE_FILE_PATTERNS` added at the top of `readAuditLog`.
- **F-OP-97 — allowlist uses tokenizeCommand inconsistently** — Deferred. Low practical risk; refactor tracked for a future maintenance session.

### Testing

- 552/552 tests pass (56 new tests — one per finding sub-case, verifying both the attack path is blocked and the safe path still works).

---

## [1.11.0] — 2026-04-25

### Changed — Command Policy Audit (13 reclassifications)

- **`systemctl` unblocked** — Blanket `systemctl` RED block replaced with arg-validator gating. Read-only sub-commands (`status`, `is-active`, `is-enabled`, `is-failed`, `list-units`, `list-unit-files`, `list-sockets`, `list-timers`, `show`, `cat`, `help`) are now GREEN. Destructive sub-commands (`start`, `stop`, `restart`, `reload`, `enable`, `disable`, `mask`, `unmask`, `daemon-reload`, `poweroff`, `reboot`, etc.) remain hard-blocked by both targeted RED patterns and the arg validator (defense-in-depth).
- **`service` unblocked** — Blanket `service` RED block replaced with arg-validator gating. Only `service <name> status` is permitted. Write sub-commands (`start`, `stop`, `restart`, `reload`, `enable`, `disable`) remain hard-blocked at both layers.
- **`crontab -l` unblocked** — Blanket `crontab` RED block replaced with targeted pattern blocking only `-e`/`-r`/`-u`. `crontab -l` (list) is now GREEN. Modification flags remain hard-blocked at both layers.
- **`dig`, `nslookup`, `host` unblocked** — Removed from RED-tier info-leak category. DNS lookups are routine diagnostics. `dig -f` (batch file) and `dig -b` (source bind) blocked by arg validator.
- **`atq` added** — New GREEN command for listing scheduled at-jobs (read-only).
- **`pm2 save` added to read-only set** — Persists current process list to disk; non-destructive. Previously required manual VPS access.
- **`pm2 reload` added to read-only set + AMBER warning** — Graceful zero-downtime reload. Marked AMBER (warning required) because cluster vs. fork mode behavior differs. Dangerous PM2 sub-commands (`delete`, `kill`, `start`, `stop`, `flush`) remain blocked.

### Added

- **`COMMAND_POLICY.md`** — Full transparency reference: every GREEN, AMBER, and RED command enumerated with category, rationale, and what Claude uses instead. Includes per-binary sub-command tables for `pm2`, `systemctl`, `service`, `crontab`, `dig`, and `git`.

### Testing

- 496/496 tests pass (20 new tests covering new GREEN commands and confirming dangerous sub-commands blocked at arg-validator layer).

---

## [1.10.8] — 2026-04-25

### Added

- **`get_recent_output` tool** — New monitoring tool mirroring `get_recent_errors` but for PM2 stdout logs (`-out-*.log`). Gated by `ALLOWED_PROCESSES` env var. Returns last N lines (configurable via `MAX_LOG_LINES`). Tool count is now 17.
- **`ALLOWED_PROCESSES` env var** — Comma-separated list of PM2 process names whose logs `get_recent_errors` and `get_recent_output` are permitted to read. Defaults to `vps-mcp`. Multi-process example: `ALLOWED_PROCESSES=vps-mcp,forgerift-payments`.
- **`findPm2Log()` helper** — Scans `PM2_LOG_DIR` for files matching `{processName}-{type}*.log` pattern. Handles PM2's ID-suffix naming (e.g. `forgerift-payments-out-5.log`) which breaks explicit `out_file` config. Previously log reads were silently failing; now they work regardless of PM2 suffix behavior.

### Fixed

- **`getRecentErrors` log discovery** — Rewired to use `findPm2Log` instead of hardcoded filename. Fixes silent failures when PM2 appends an ID suffix to log filenames.

### Changed

- **Startup notice** — On the first tool call after each vps-mcp restart, a one-time banner is prepended explaining the restart was expected and providing reconnect instructions. Subsequent calls within the same process lifetime are silent.

### Documentation

- **`TROUBLESHOOTING.md`** — "Click to Reconnect" section added at top. Explains why the Cowork reconnect prompt appears, what to click, how often it occurs, and what not to do.

---

## [1.10.7] — 2026-04-24

### Fixed

- **Auto-reconnect** — Cowork SSE clients that reconnect after a vps-mcp restart now transparently restore their session instead of receiving a 404 and dropping the connection. A GET on an unknown session ID recreates the server+transport under the original session ID. PM2 `kill_timeout` bumped to 8 000 ms (from default 1 600 ms) to give in-flight requests time to complete before SIGKILL. SIGTERM/SIGINT handlers added for clean shutdown.
- **Layer 2 / Layer 3 parse-failure** — Verdict scan now checks all non-empty lines with BLOCKED > PROCEED WITH CAUTION > PASS priority order, instead of inspecting only the last non-empty line. Fixes intermittent BLOCKED responses caused by the model appending trailing notes after the verdict. Truncated response logged on unexpected format.
- **`get_recent_errors` log access** — PM2 logs at `/root/.pm2/logs/` were blocked by `APP_DIR_ROOT_CARVEOUT`. `getRecentErrors` now performs a targeted PM2_LOG_DIR bounds check instead of routing through `validatePath`.

---

## [1.10.6] — 2026-04-24

### Added

- **`read_audit_log` tool** — New read-only monitoring tool that surfaces the immutable MCP audit trail. Scoped to `AUDIT_LOG_PATH` (defaults to `{APP_DIR}/mcp-audit.log`). Respects `APP_DIR` access controls; audit path outside `APP_DIR` requires explicit `AUDIT_LOG_PATH` configuration. Returns last N lines with optional filter.

---

## [1.10.5] — 2026-04-24

### Fixed

- **`.mcp.json` removed from tracking** — Personal dev config file containing local VPS URL was accidentally tracked. Removed via `git rm --cached`, added to `.gitignore`. No sensitive tokens were in the file, but VPS IP was present; setup.sh example also updated to use a generic placeholder IP.

---

## [1.10.4] — 2026-04-23

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