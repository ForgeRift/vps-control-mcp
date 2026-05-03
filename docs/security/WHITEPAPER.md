# vps-control-mcp — security whitepaper

How `vps-control-mcp` keeps Claude's access to your Linux VPS
audited, deny-listed, and bounded. Intended for prospective customers,
security reviewers, and Anthropic's marketplace review.

This whitepaper covers the `vps-control-mcp` plugin specifically.
The family-level overview (license issuance, the validation backend,
the cross-product threat model) lives in
[forgerift-license-api/docs/security/WHITEPAPER.md](https://github.com/ForgeRift/forgerift-license-api/blob/main/docs/security/WHITEPAPER.md).

## What this plugin does (and what it does not)

`vps-control-mcp` is a Model Context Protocol server that exposes a
small surface to Claude:

  - `run_command` — execute one binary with one argv on the VPS,
    sync, returning stdout + stderr + exit code.
  - `list_directory` — read-only directory listing with the
    sensitive-path guard (`/etc/shadow`, `/proc/<pid>/environ`,
    `~/.ssh/id_*`, `.aws/credentials`, `.env*`, etc.).
  - `read_file_section` — bounded text-file read with the
    sensitive-path guard.
  - `find_files` — recursive name-pattern search.
  - `search_file` — grep-equivalent inside one file or directory.
  - `run_git_command` — curated allowlist over git read ops.
  - `run_npm_command` — curated allowlist over npm read ops.
  - `restart_process` — PM2 restart for a named, allowlisted
    process (`ALLOWED_PROCESSES` env).
  - `get_pm2_status`, `get_recent_output`, `get_recent_errors`,
    `get_system_health` — PM2-mediated read-only status hooks.
  - `deploy`, `deploy_vps_mcp` — controlled deploy hooks
    targeting only the names declared in `ALLOWED_PROCESSES`.

It does **not** expose:

  - Arbitrary outbound network egress (egress binaries are denylisted;
    `curl` is allowlist-restricted to localhost / 127.0.0.1 / [::1]
    after the F010 fix that closed the `--url=` and `--proxy=`
    bypasses).
  - Privilege escalation (`sudo`, `su -`, `setcap`, `setuid`,
    `newgrp`, capability-bit grants are denylisted).
  - Service install / config (`systemctl enable`, unit-file write,
    init-script create are denylisted; `service --status-all` is
    allowed for read-only health checks).
  - Credential read (`~/.ssh/` private keys, the SAM hive's POSIX
    analogues, `/etc/shadow`, browser credential stores, `ssh-keygen`).

## Threat model

Three threats drive the design:

1. **Prompt injection.** A page or file convinces Claude to issue a
   destructive command (recursive root delete, partition wipe, root
   shell via `sudo` or capability grant). Mitigation: the plugin's
   deny list fires before the binary is launched. Claude can suggest
   the command, the plugin refuses the execution.

2. **Compromised model variant.** A future Claude variant or a hostile
   fine-tune does the wrong thing. Mitigation: the plugin enforces
   the policy; the model never sees the policy code, only the deny
   message. Audit log captures every command + tier so any drift is
   visible after the fact.

3. **Outbound exfil via the plugin process.** A bypass in the curl /
   wget / nc / ssh allowlists turns the VPS into an exfil channel
   — curl can `-d @file` arbitrary contents the process can read.
   Mitigation: deny-list + URL-substring allowlist + arg-form
   normalisation. F010 closed the largest known hole here:
   `--url=URL` and `--proxy=URL` were previously waved through
   because the validator skipped any `-`-prefixed arg.

4. **License key theft and sharing.** A bad actor steals the
   customer's license key or the customer shares it. Mitigation: the
   `forgerift-license-api` backend binds each license to a Stripe
   product, and the plugin sends `product_id` on every validation
   call so a key bound to a different product is denied with
   `product_mismatch`. Per-machine activation cap is enforced
   atomically by a Postgres stored proc; a license-sharing cron sweep
   alerts the operator if one key shows up on >=5 distinct machines
   in 24h.

## Command pipeline detail

Every call into `run_command` / the curated wrappers traverses three
layers.

### Layer 1: BLOCKED tier (deny-first)

A regex deny list drawn from sixteen-plus prior security passes covers,
without quoting the literal exploit forms here:

  - Eval and eval-adjacent forms across every interpreter the plugin
    might exec on Linux (sh / bash / zsh / dash command-string forms,
    pwsh `-Command`, perl / python / ruby / groovy / scala / lua /
    julia / Rscript inline-eval).
  - Download cradles: web-fetch + pipe-to-shell, in-memory string
    download, base64-decode + pipe-to-shell.
  - Shell-out fronts: `find ... -exec` patterns that would let an
    attacker run a binary not on the allowlist; `xargs` chained from
    untrusted input.
  - Privilege escalation: `sudo`, `su -`, `setcap`, `setuid`,
    `newgrp`, capability-bit grants.
  - Filesystem destruction at root scope, recursive force-remove of
    system roots, partition primitives (`mkfs.*`, `dd if=`,
    `parted`, `fdisk` mutations).
  - Symbolic-link primitives that could escape the working directory.

Match in this layer = `tier=red`, refused, audit-logged with the
matched pattern + the input.

### Layer 2: ALLOWLIST gate

For commands that survive Layer 1, the binary itself must be on the
positive allowlist. Each allowed binary has its own argv validator.

**curl** (post-F010 shape):

  - URL must resolve to `localhost` / `127.0.0.1` / `[::1]`.
  - Validator walks every arg, normalises `--key=value` to its value
    half, matches URLs by substring, also covers `--proxy=URL`.
  - Host comparison is case-insensitive; DNS-rebinding shapes
    (`localhost.attacker.com`) are rejected.

**systemctl** (post-S67 shape):

  - `--host=` / `--machine=` prefix-checks lock the call to the
    local instance only.
  - Combined short-flag expansion (`-Hu host` -> `-H host -u`) so
    arg-order tricks can't hide a remote-host call.

**service**:

  - `service --status-all` allowed for read-only health checks
    (per F-S67-42).
  - Other invocations remain denied.

**git**:

  - upload-pack / receive-pack / askpass / credential-helper /
    protocol-ext config flags are stripped.
  - Repo-local hooks neutralised by pre-pending
    `-c core.hooksPath=/dev/null`.

**npm**:

  - Read-only sub-commands only (`ls`, `view`, `outdated`,
    `audit`); install / ci / publish / run / exec are denied.

### Layer 3: AMBER warning vs GREEN execution

A small set of commands — `pm2 restart` for an
`ALLOWED_PROCESSES` name, `git push`, deploy hooks, etc. —
fall into AMBER tier: they're allowed but require a dry-run-first
confirmation. The rest go through
`execFileSync(binary, argv, { shell: false })` with:

  - A scrubbed environment.
  - A bounded timeout per binary type.
  - `stdout` + `stderr` captured, run through `scrubSecrets()`
    (which redacts patterns matching API key / token / connection-
    string shapes).
  - Audit log entry with binary, argv, tier, exit code, output length,
    and the scrubbed-secret count.

## Authentication / licensing

The VPS plugin uses a different licensing model from `local-terminal-mcp`.
LT runs as a stdio MCP child process spawned by Claude Desktop and
validates its license once on startup against the central Worker. VPS
runs as a long-lived HTTP server on the customer's VPS and validates
each incoming MCP request against either Supabase or a single
configured token.

### Auth modes

Two modes, selected automatically by which env vars are present at
startup:

  - **Supabase multi-token mode** (when both `SUPABASE_URL` and
    `SUPABASE_SERVICE_KEY` are set). Per-request: the bearer token
    presented by the client is looked up in the `customers` table; the
    row must have `status IN ('active','trial','grace')` and
    `plan IN ('vps-control','bundle')`, and any non-NULL `expires_at`
    must be in the future. A 5-minute positive-result cache plus a
    30-minute negative-result cache fronts Supabase to bound the
    per-minute call rate (F-OP-23). A circuit breaker opens after
    `SUPABASE_CIRCUIT_THRESHOLD` (default 120) cache-misses per minute
    and short-circuits new lookups to deny until the window rolls
    (F-OP-36). This is the marketplace billing path.
  - **Single-token mode** (when Supabase env vars are absent and
    `MCP_AUTH_TOKEN` is set). Per-request: the bearer token is
    constant-time-compared (`timingSafeEqual` on equal-length
    zero-padded buffers, F-S67-53) against the configured token. Used
    for self-hosted / dev installs that do not connect to ForgeRift's
    billing backend.

Either mode rejects the request before any tool is dispatched. Tokens
are also pre-screened by shape (length 16-512, printable ASCII only)
before any Supabase round-trip, to prevent random-token floods from
exhausting the Supabase quota (F-OP-23).

### OAuth 2.0 + PKCE

For Cowork and other spec-compliant MCP clients, the plugin advertises
OAuth 2.0 discovery at `/.well-known/oauth-authorization-server` and
`/.well-known/oauth-protected-resource`, with `/authorize` and
`/token` endpoints implementing PKCE (mandatory at `/authorize` per
F-OP-35 / F-NEW-6 / F-OP-26). A successful PKCE exchange mints a
per-session access token with a configurable TTL; that session token is
checked first in `validateAuth` and never reveals the master
`MCP_AUTH_TOKEN` if leaked.

### What VPS does NOT do today (and why)

For honesty with reviewers and customers: the per-machine activation
cap and the `register_activation_with_cap` Postgres flow described in
the family WHITEPAPER and in
`local-terminal-mcp/docs/security/WHITEPAPER.md` apply to **LT only**.
VPS does not currently compute a machine fingerprint, does not POST
to `payments.forgerift.io/validate`, and does not increment the
per-key activation counter. The two product surfaces have different
shapes — LT runs as a single-PC stdio plugin where a per-machine cap
maps cleanly to one user's one PC; VPS is a long-lived HTTP server
that one customer may legitimately want to reach from multiple
clients (Cowork, Claude Desktop, a CLI) — so the LT cap design does
not transplant unchanged.

License-sharing detection on VPS today depends on the operator-side
review of the per-request audit log plus rotation of
`customers.token`, not on the cron-driven five-distinct-machine alert
that fires for LT. Migrating VPS onto the same
`register_activation_with_cap` contract (parameterised so a single
license can authorise N concurrent VPS clients) is on the
post-marketplace roadmap.

If validation fails, the request returns `401 Unauthorized`, or `503
Service Unavailable` when the Supabase circuit breaker is open. No
tool is ever dispatched on a failed auth.

## Data handling

The plugin never sends raw shell output, paths, or filenames anywhere
external. The plugin makes outbound HTTP only to Supabase
(`SUPABASE_URL`) for per-request token lookup in Supabase mode, and
to `api.anthropic.com` for Layer 2 / Layer 3 AI safety classification
when `ANTHROPIC_API_KEY` is configured. Both endpoints are caller-
configurable and a self-hosted single-token deploy that omits both
makes no outbound HTTP at all.

Audit logs are local: a JSONL file at the path resolved by
`CONFIG.AUDIT_LOG_PATH` (default `${APP_DIR}/mcp-audit.log` — kept inside `APP_DIR` so `read_file_section` can access it without extra allowlist config,
overridable via the `AUDIT_LOG_PATH` env var; the directory is
created on first start). Per-field arg capture caps
(per F-S67-54) preserve more forensic detail than the legacy flat
truncation. Operator can ship them off-machine via their own log-
collection setup if desired; the plugin doesn't.

## Reporting a vulnerability

See [SECURITY.md](../../SECURITY.md) at the repo root.
`support@forgerift.io`, 90-day coordinated disclosure.

## Audit cadence

Posture refreshes on every commit prefixed `security:`. The central
`findings.csv` (in `forgerift-license-api/docs/security/`) is the
machine-readable cross-repo view; the repo-local
[POSTURE.md](POSTURE.md) is the per-repo summary. Re-runs of
`npm audit` and `npm test` are gated by the pre-commit hook in
`.githooks/pre-commit`.
