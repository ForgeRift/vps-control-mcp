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

On startup, the plugin reads `VPS_LICENSE_KEY` from env and POSTs to
`https://payments.forgerift.io/validate` with:

```json
{
  "license_key":     "FRFT-XXXX-XXXX-XXXX-XXXX",
  "machine_id":      "<sha256 of /etc/machine-id>",
  "product_id":      "<vps-control-mcp Stripe product id>",
  "plugin_version":  "1.13.0"
}
```

The Worker hashes the key once more, looks up the license, then calls
the `register_activation_with_cap` Postgres proc which atomically:

  - checks status (active / past_due tolerated within grace,
    expired / revoked rejected),
  - checks the product_id binding (NULL on the row = permissive,
    enabling Bundle subscriptions to satisfy both plugins),
  - checks the per-machine activation cap (default max=1; first machine
    "wins" the slot until the operator deactivates it),
  - registers the activation if needed, increments the counter,
  - returns `ok` / `already_active` / `deactivated` /
    `cap_exceeded` / `product_mismatch`.

If validation fails the plugin exits with a clear error message
pointing the user at `forgerift.io` to manage their subscription.
The plugin never serves any tools to Claude before validation
succeeds.

### Machine fingerprint

The fingerprint is `SHA-256(/etc/machine-id)`. `machine-id` is the
canonical per-VM stable identifier on systemd-based distros; on systems
without it the plugin reads
`/var/lib/dbus/machine-id` then falls back to a fail-closed error
(no hostname fallback — the per-machine cap can't be defeated by a
stable cross-machine fingerprint).

## Data handling

The plugin never sends raw shell output, paths, or filenames anywhere
external. The only outbound HTTP it makes is the validation call to
`payments.forgerift.io`, and that carries only the license key, the
double-hashed machine id, the product id, and the plugin version.

Audit logs are local: a JSONL file at the path resolved by
`CONFIG.AUDIT_LOG_PATH` (default `/var/log/vps-control-mcp/audit.log`,
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