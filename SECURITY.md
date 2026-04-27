# VPS-Control-MCP Security Framework

## Executive Summary

vps-control-mcp implements a three-tier command authorization model designed to give Claude safe, audited access to Linux VPS environments while preventing unauthorized system modification, data exfiltration, and privilege escalation attacks. This document describes the complete security architecture, threat model, and policy enforcement mechanisms.

## Three-Tier Command Authorization Model

### Overview

All commands are classified into three security tiers: RED (hard-blocked), AMBER (warning-required), and GREEN (allowed with audit logging). This tiered approach balances operational capability with risk mitigation.

### RED Tier: Hard-Blocked Commands

RED tier commands are permanently blocked regardless of context. Attempts to execute RED tier commands fail with a clear error message and are logged as security events. The block list encompasses 100+ patterns across 20 security categories.

**File Deletion & Data Destruction**

Commands that permanently delete files or directories are blocked unconditionally. This includes `rm`, `rmdir`, `unlink`, `truncate`, `shred`, `wipe`, `dd if=/dev/zero`, and recursive deletion patterns. Symlink removal is also blocked. The rationale is simple: permanent data loss cannot be audited or recovered after the fact, and accidental deletions would be catastrophic.

**Disk Operations & Filesystem Modification**

Low-level filesystem operations are blocked including `fdisk`, `parted`, `mkfs`, `fsck`, `resize2fs`, and mount/unmount commands. These operations can render a VPS unbootable or corrupt critical filesystems. Volume and partition management must be handled through cloud provider APIs.

**System State Modification**

Commands that change system-wide configuration are blocked: `sysctl` configuration changes, `/proc` writes, `/sys` manipulation, `modprobe`, kernel module loading/unloading, and BIOS/firmware tools. These affect all processes on the VPS and are infrastructure-level decisions.

**Process Termination**

Process killing (`kill`, `killall`, `pkill`, `pkill -9`) is blocked. Uncontrolled process termination breaks application recovery guarantees and can orphan resources. Legitimate service restarts are available through the controlled `pm2 restart` interface.

**User & Group Management**

User and group modification commands (`useradd`, `userdel`, `usermod`, `groupadd`, `groupdel`, `passwd`, `sudo`) are blocked. User management has security and compliance implications and must be handled through infrastructure-as-code tooling.

**File Permissions & Ownership**

Commands that modify file permissions and ownership (`chmod`, `chown`, `chgrp`) are blocked. Permission changes can escalate privileges or expose sensitive data. All files created by vps-control-mcp retain appropriate default permissions.

**Network Configuration**

Network configuration commands are blocked: `ip route`, `ip addr`, `iptables` (except the firewall's own rules), `ifconfig`, `route`, `tc` (traffic control), and DNS configuration tools. Network topology changes should be managed through infrastructure tooling.

**Scheduled Execution**

Cron job creation and modification (`crontab -e`, `at`, `systemd-run --on-calendar`) are blocked. Persistent scheduled tasks create unaudited execution paths. The `schedule` capability is available through the control plane API.

**Service Management**

Direct systemd management (`systemctl start/stop/enable/disable`) is blocked except for the vps-control-mcp service itself. Service state changes should be orchestrated through application-level APIs or infrastructure tooling.

**Code Execution & Shell Invocation**

Direct shell invocation patterns are blocked: `bash -c`, `sh -c`, `eval`, `exec`, backticks, `$()` in certain contexts, and pipe chains that invoke interpreters. These patterns bypass command parsing and audit logging. All code execution is restricted to named binary invocation with structured arguments.

**Data Exfiltration**

Commands designed to copy or transmit data outside the VPS are blocked: `scp`, `sftp`, `rsync` to external hosts, `curl/wget` to untrusted domains, `nc` (netcat), `socat`, and raw socket tools. These prevent unauthorized data exfiltration while allowing monitoring API calls.

**Persistence Mechanisms**

Commands that establish persistence are blocked: `rc.local` modification, `.bashrc/.bash_profile` injection, `~/.ssh/authorized_keys` modification, and other shell initialization files. These prevent backdoor creation.

**Direct Database Access**

Direct database tools are restricted to read-only mode: `mysql` and `psql` can be used for queries, but commands containing `CREATE`, `DROP`, `ALTER`, `DELETE` (except through structured APIs), `TRUNCATE`, and `GRANT` are blocked.

**Package Management**

Package manager commands (`apt-get install`, `apt-get remove`, `yum install`, `yum remove`, `npm install -g`, `pip install --system-wide`) are blocked. Package installation and removal are infrastructure decisions that should be managed through container rebuilds or deployment manifests.

**Container & Orchestration**

Docker and Kubernetes commands are blocked: `docker run`, `docker exec`, `kubectl apply`, `kubectl delete`, and container image manipulation. Container operations require infrastructure-level access control.

**File Write Protection**

Direct file write operations to system files are heavily restricted. Writing to files in protected directories (see Sensitive File Protection below) is always blocked. File writes outside these directories must pass through structured write APIs.

**Environment Variable Manipulation**

Commands that modify environment variables for subsequent commands (`export`, `env` with modifications) in shell contexts are blocked. Environment state is managed through configuration files accessed via the structured API.

**Privilege Escalation**

Any command that attempts privilege escalation is blocked: `sudo` without password, `sudo -i`, `su`, `sudo su`, setuid binary creation, and capability manipulation (`setcap`). The vps-control-mcp process runs at the minimum required privilege level.

**Information Leakage**

Commands that enumerate sensitive system information are blocked: `cat /etc/shadow`, `getent shadow`, `/proc/[pid]/environ` reading, `/proc/[pid]/fd` enumeration, and other kernel interface exploration. System diagnostics are available only through structured APIs.

**Process Log Access Gating** — `get_recent_errors` and `get_recent_output` (the structured tools for tailing PM2 error and stdout logs) are gated by the `ALLOWED_PROCESSES` environment variable. Only PM2 process names explicitly listed in `ALLOWED_PROCESSES` (comma-separated; default: `vps-mcp`) can have their logs read. This prevents a compromised Claude session from reading logs of arbitrary processes not under its operational scope.

**Command Chaining Exploits**

Advanced command chaining patterns are blocked: semicolon chaining in contexts where it can circumvent parsing (`; rm -rf /`), command substitution in critical contexts, and pipe-to-shell patterns. These are detected at the parser level before execution.

**HTTP Server & Listener Binding**

Commands that bind to network listening ports are blocked: `nc -l`, `python -m http.server`, `node -e "require('http').createServer..."`, and direct socket binding. This prevents unauthorized services or proxies.

### AMBER Tier: Warning-Required Commands

AMBER tier commands are allowed but require explicit user confirmation and a ToS warning. These commands are moderately risky but have legitimate use cases in advanced DevOps scenarios.

**Package Manager Updates**

Commands like `apt-get update`, `apt-get upgrade`, and `yum check-update` require dry_run=false confirmation. These commands are safe to preview but can have side effects on system state.

**Advanced Text Processing with Side Effects**

Commands using `find -exec`, `xargs`, `awk`, and `sed -i` require explicit confirmation because they can operate on many files at once. The dry-run mode shows the command that would be executed without actually modifying files.

**Large File Operations**

Commands that operate on large numbers of files or large file sizes are AMBER tier, as they can consume significant disk I/O and memory.

### GREEN Tier: Allowed with Audit Logging

GREEN tier commands execute immediately with full audit logging. This includes:

- Read-only commands: `ls`, `cat`, `grep`, `find` (without -exec), `ps`, `df`, `du`, `netstat`, `curl` (to monitoring systems)
- Log viewing: `tail`, `head`, `journalctl`
- Service status: `systemctl status`, `pm2 status`, `pm2 logs`
- Process inspection: `top`, `htop`, `pidof`
- File inspection: `file`, `wc`, `md5sum`
- Diagnostic tools: `ping`, `traceroute`, `dig`, `nslookup`
- Version checks: `node --version`, `npm --version`
- VCS operations: `git status`, `git log`, `git diff` (read-only)
- System info: `uname`, `hostname`, `uptime`, `free`, `lsb_release`

## Sensitive File Protection

Beyond command-level blocking, vps-control-mcp enforces file-level access control. Even when a command is in the GREEN tier and would normally be allowed, reads of sensitive files are blocked unconditionally.

**Blocked File Patterns**

The following files and directories are never readable, regardless of the command context:

- Environment files: `.env`, `.env.local`, `.env.*.local`
- SSH infrastructure: `~/.ssh/`, `~/.ssh/authorized_keys`, `~/.ssh/config`, `~/.ssh/id_*`
- Private key files: `*.pem`, `*.key`, `*.pk8`, `*.p12`
- Credential files: `.credentials`, `.aws/credentials`, `~/.gcloud/`, `~/.azure/`
- Password files: `/etc/shadow`, `/etc/gshadow`, `.htpasswd`, `.netrc`, `.pgpass`, `.my.cnf`
- Docker config: `~/.docker/config.json`
- Kubernetes: `~/.kube/config`, `kubeconfig`
- Cloud provider credentials: `~/.aws/`, `~/.gcloud/`, `~/.azure/`, `~/.digitalocean`, `~/.linode`
- Git credentials: `.git/config` (when containing credentials), `~/.git-credentials`
- Application secrets: `secrets.yml`, `secrets.json`, `secrets.yaml` (when in system directories)
- API keys and tokens: any file containing `API_KEY`, `TOKEN`, `SECRET` in common locations

The file protection mechanism operates at the OS level using read-time filtering on command output. If a command would output a sensitive file, that output is redacted and logged as a security event.

### Destination-Path Write Protection (D10)

Command-surface destination-path protection (D10) blocks `cp`, `mv`, `install`, `tee`, and `dd of=...` when the destination path resolves — after `../` canonicalization — to any of:

`/etc/`, `/root/`, `/home/`, `/usr/bin/`, `/usr/sbin/`, `/bin/`, `/sbin/`, `/lib/`, `/lib64/`, `/boot/`

The same sensitive-prefix list applies to shell-redirect destinations (`>`, `>>`) via M7-extended. GNU `--target-directory` / `-t` (short form and glued short-option clusters like `-fvt`) are handled by D10's argv-aware matcher. Env-var and tilde expansion (`$HOME`, `~`, `%SystemRoot%`) in destination paths fail closed.

**Operator override.** If legitimate workflows require writes under one of the sensitive prefixes above — backup-restore scripts copying into `/home/user/`, deploy tooling populating `~/.config/...`, CI runners writing under `/home/runner/...` — the `BYPASS_BINARIES` environment variable (see *Advanced Feature: BYPASS_BINARIES* below) can demote specific `<binary>:<category>` pairs from hard-block to AI-reviewed. Example: `BYPASS_BINARIES=cp:sensitive-path-write,mv:sensitive-path-write,install:sensitive-path-write` re-enables `cp` / `mv` / `install` writes under `/home/*` while keeping redirect (`> /home/.../authorized_keys`) and `dd of=/home/...` blocked. Each bypass hit is logged as `[SECURITY-BYPASS]` in the audit stream.

### Security Release Notes — v1.10.x

| Version | Closed | Scope |
|---|---|---|
| v1.10.0 | F-OP-62 / F-OP-63 / F-OP-64 | PowerShell `Copy-Item` / `Move-Item` destination detection, `-LiteralPath` gating, parameter-prefix abbreviations (`-De`, `-Des`, …) |
| v1.10.1 | F-OP-66 | M7-extended redirect no-`..` form (`> ./etc/passwd`) |
| v1.10.2 | F-OP-68 / F-OP-69 / F-OP-70 | LT normalizePath separator consistency; LT PS colon-syntax (`-Destination:<path>`) token-split; VPS `/home` source-side false-positive elimination |
| v1.10.3 | F-OP-71 / F-OP-74 / F-OP-75 | **VPS `/home` destination-side protection restored** — v1.10.2 removed `/home` from the cp/mv backstop to fix source-side false-positives, but D10's SENSITIVE regex did not then include `/home`, silently dropping destination-side coverage for `~/.ssh/authorized_keys`, `~/.bashrc`, `~/.config/systemd/user/*.service`, etc. Also: LT `SENSITIVE_WIN` unified across D10 and M7-extended (F-OP-74); LT `tools_BRANCH.ts` / `tools_HEAD.ts` merge-conflict artifacts removed (F-OP-75). |
| v1.10.4 | F-OP-83 / F-OP-84 | SECURITY.md D10 subsection now points operators at `BYPASS_BINARIES` as the documented override for legitimate `/home` copy / redirect workflows (F-OP-83); `.githooks/pre-commit` added (with `.gitignore` broadened to cover `.env.test*` and `*.bak`) to enforce the merge-artifact / backup-file guard beyond the .gitignore-only posture of v1.10.3 (F-OP-84). |

**Known pre-v1.10.3 bypass scope:** operators running v1.10.0–v1.10.2 of VPS could not rely on destination-side `/home` write protection via the synchronous layer; the tier-3 AI review would still flag `authorized_keys` as high-risk but AI layers fail open when `ANTHROPIC_API_KEY` is unset. Upgrading to v1.10.3 closes this gap.

**Known pre-v1.10.4 bypass scope:** v1.10.3 relied on `.gitignore`-only patterns to prevent re-introduction of merge-conflict and backup artifacts. A developer using `git add -f` or a file name outside the declared shapes (e.g. `tools_LOCAL.ts`, `foo.ts.orig.1`) could land artifacts through the normal commit flow with no defense. v1.10.4 adds `.githooks/pre-commit` that refuses the commit outright, with `package.json` `prepare` script wiring `core.hooksPath` to `.githooks` automatically on `npm install`. The guard is defense-in-depth; no credential or command-surface security gap is affected by the pre-v1.10.4 state.
| v1.10.8 | — | `get_recent_output` tool (stdout log tail); `findPm2Log()` helper fixes log-file discovery when PM2 appends ID suffixes; `ALLOWED_PROCESSES` env var gates which PM2 processes log tools can read; startup notice on first tool call post-restart |
| v1.11.0 | — | Command policy audit: 13 command reclassifications (systemctl read-only, service status, crontab -l, dig, nslookup, host unblocked; pm2 save + reload added to read-only set); `COMMAND_POLICY.md` published — full GREEN/AMBER/RED transparency reference |
| v1.12.1 | — | S70 pre-submission cleanup: deleted `tools.ts.orig` merge artifact, reclassified `typescript` to devDependencies, added `prepack` artifact guard, removed all stale BUSL license references (license stays MIT), fixed `README.md` Quick Start curl-pipe TTY bug, rewrote `TROUBLESHOOTING.md` for .mcpb install model, added `LAYER_STRICT_MODE` disclosure to `MARKETPLACE_LISTING.md`. No security logic changes. |
| v1.12.0 | — | Round 13 adversarial review (F-OP-85..F-OP-97): service arg-position bug, systemctl -H SSH pivot, systemctl show/cat env leak, bare crontab, pm2 flush/reload reclassified, findPm2Log symlink escape, dig @resolver+AXFR, host zone transfer, nslookup interactive mode, crontab long-form flags, systemctl env-manipulation, atq narrowed, AUDIT_LOG_PATH sensitive-file check. 552/552 tests. |

## Session-Level Security Controls

### Rate Limiting

All requests are rate-limited to 60 requests per minute per authentication token (configurable via `RATE_LIMIT_PER_MIN`). This prevents abuse and resource exhaustion. Rate limit violations are logged and fail with a 429 error code. The rate limit is applied uniformly regardless of command tier.

### Request Timeout

All synchronous command execution has a 30-second hard timeout. Commands that exceed this threshold are killed with SIGTERM, then SIGKILL after 2 seconds. Timeout violations are logged as security events. This prevents runaway processes from blocking the control plane.

### Session Command Cap

Sessions have a configurable maximum number of custom commands (default: 10 per session, configurable via `MAX_CUSTOM_COMMANDS_PER_SESSION`). This prevents token exhaustion attacks where an attacker uses a single token to execute unlimited reconnaissance. Once the cap is reached, the session must be rotated.

### Audit Logging

Every command execution is logged with the following metadata:

- Timestamp (UTC)
- Command text (redacted of secrets)
- Authentication token (hashed)
- Execution status (success, timeout, blocked, error)
- Command tier (RED, AMBER, GREEN)
- Session ID
- Source IP address
- Output size and status code

Logs are stored at `AUDIT_LOG_PATH` (defaults to `{APP_DIR}/mcp-audit.log`) with 10MB rotation and one backup retained. All sensitive data (passwords, API keys, credit cards, SSH keys) are automatically redacted using pattern matching. Configure `AUDIT_MAX_SIZE_MB` to adjust the rotation threshold.

## Authentication & Authorization

### Bearer Token Authentication

vps-control-mcp supports two authentication modes: single-token and Supabase multi-token billing mode.

**Single-Token Mode**

A single bearer token is configured at startup via the `MCP_AUTH_TOKEN` environment variable. All requests must include this token in the HTTP `Authorization: Bearer <token>` header. This is suitable for personal or small-team deployments.

**Supabase Multi-Token Billing Mode**

In this mode, vps-control-mcp verifies JWT tokens issued by a Supabase Auth instance. Each user has a unique token, enabling per-user billing and usage tracking. Token verification uses Supabase's published public keys (JWKS endpoint). Token expiration and revocation are enforced.

### OAuth 2.0 Integration

vps-control-mcp implements full OAuth 2.0 support with RFC 8414 (OAuth 2.0 Authorization Server Metadata) discovery and RFC 7591 (Dynamic Client Registration) support. This allows Claude instances and other clients to authenticate via OAuth without pre-sharing credentials.

The OAuth endpoints are:

- `/.well-known/oauth-authorization-server` — metadata discovery
- `/oauth/authorize` — authorization endpoint
- `/oauth/token` — token endpoint
- `/oauth/introspect` — token introspection
- `/oauth/revoke` — token revocation

OAuth tokens are issued with a configurable lifetime (default: 1 hour) and can be refreshed using a refresh token. All OAuth flows use PKCE (Proof Key for Code Exchange) to prevent authorization code injection attacks.

## Transport Security

### TLS/HTTPS

All communication with vps-control-mcp must use TLS 1.2 or higher. HTTP connections are rejected with a 403 error. TLS certificates are provisioned using sslip.io (a wildcard DNS service that maps IP addresses to DNS names) and Let's Encrypt. The certificate is automatically renewed 30 days before expiration.

The TLS configuration includes:

- Strong cipher suites (TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, ECDHE-RSA-AES256-GCM-SHA384)
- HSTS header (Strict-Transport-Security: max-age=31536000)
- Certificate pinning optional (for high-security deployments)

### Firewall Rules

The vps-control-mcp server binds to `127.0.0.1:3001` by default, making it accessible only to local processes. For remote access, an nginx reverse proxy with TLS termination is required. The VPS firewall is configured to DROP (not REJECT) all unsolicited inbound traffic to prevent port enumeration.

```
iptables -A INPUT -p tcp --dport 3001 -j DROP
iptables -A INPUT -p tcp --dport 443 -j ACCEPT  (nginx reverse proxy)
```

## Threat Model & Mitigations

### Threat: Unauthorized Command Execution

**Attack Vector:** An attacker with a valid authentication token executes privileged commands.

**Mitigation:** Token rotation policies, rate limiting, session caps, and comprehensive audit logging enable detection and response. Security-critical commands are blocked outright.

### Threat: Credential Exfiltration

**Attack Vector:** An attacker reads sensitive files or environment variables.

**Mitigation:** File-level access control blocks reads of credential files. Environment variables are never exposed through the command API.

### Threat: Lateral Movement

**Attack Vector:** An attacker uses vps-control-mcp to establish persistence or create backdoors.

**Mitigation:** Persistence mechanisms (shell initialization files, cron jobs, ssh keys) are blocked. No commands can write to system areas or modify user accounts.

### Threat: Supply Chain Compromise

**Attack Vector:** An attacker compromises the vps-control-mcp dependencies.

**Mitigation:** Dependencies are pinned to specific versions in package-lock.json. Build process uses npm ci (clean install) to ensure reproducibility. Dependency scanning via npm audit is run in CI/CD.

### Threat: Social Engineering

**Attack Vector:** An attacker convinces Claude to circumvent security controls.

**Mitigation:** Clear error messages when controls are triggered. No "admin override" modes or bypass flags. Documentation explicitly forbids workarounds.

## Terms of Service Violations

The following actions are considered violations of vps-control-mcp's Terms of Service and may result in account termination:

**Circumvention Attempts:** Any attempt to circumvent or bypass the command authorization system, including but not limited to:
- Finding and exploiting parsing bugs in the command validator
- Using encode/decode tricks to obfuscate commands
- Chaining commands to achieve blocked operations (e.g., using `find` to locate and then exfiltrate files)
- Social engineering Claude to execute commands in ways the system intended to prevent

**Unauthorized Access:** Attempting to access credentials, authentication tokens, or system infrastructure you do not own.

**Data Exfiltration:** Copying, transmitting, or otherwise exfiltrating data from the VPS to external systems without authorization.

**Malware & Botnet Activity:** Installing or running malware, cryptominers, botnets, or other malicious software.

**Denial of Service:** Consuming excessive resources (CPU, memory, disk, network) in a way that affects other users or services.

**Abuse of Third-Party Services:** Using vps-control-mcp to attack, scan, or otherwise abuse third-party systems.

**Illegal Activity:** Using vps-control-mcp for any illegal purpose.

Suspected violations are logged and may trigger account review, suspension, or permanent termination.

## Compliance & Standards

vps-control-mcp is designed to support compliance with:

- **CIS Benchmarks:** File access controls and command restrictions align with CIS Linux hardening guidelines
- **OWASP Top 10:** Addresses authentication, authorization, injection, and data protection
- **SOC 2 Type II:** Audit logging, access control, and incident response capabilities support SOC 2 compliance
- **ISO 27001:** Information security management practices

## Security Review & Testing

vps-control-mcp undergoes regular security review:

- **Static Analysis:** Code is scanned with SonarQube and npm audit
- **Dynamic Testing:** Penetration testing against the command parser and authorization system
- **Dependency Scanning:** Regular updates to address known vulnerabilities
- **Incident Response:** Security issues are handled through responsible disclosure and rapid patching

Organizations with specific security requirements should contact the security team at security@forgerift.io.

## Contact & Reporting

To report a security vulnerability, email security@forgerift.io with:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested remediation (if any)

Please allow 90 days for a fix before public disclosure. Critical vulnerabilities may be addressed more quickly.

---

## Disclaimer of Warranties and Limitation of Liability

**THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY ARISING FROM, OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.**

vps-control-mcp is a security-enhancing layer that operates on top of your existing infrastructure. It does not guarantee prevention of all unauthorized actions and should be used as one component of a broader security posture, not as a sole safeguard.

### Advanced Feature: BYPASS_BINARIES

The `BYPASS_BINARIES` environment variable (H18) allows administrators to demote specific binary+category combinations from hard-block to AI-reviewed status. This is an **advanced configuration intended for experienced administrators only.**

**By enabling `BYPASS_BINARIES`, you acknowledge and accept that:**

- You are reducing the default protection level for the specified binary/category combinations.
- Bypassed commands are still subject to AI review (L2/L3 classifier pipeline) but are no longer hard-blocked at Layer 1.
- Every bypass event is logged to the audit trail, but logging does not prevent execution if the AI classifiers approve the command.
- Misconfiguration of this setting may allow destructive or unauthorized commands to execute on your server.
- The authors and distributors of this software bear no liability for damages resulting from the use or misconfiguration of this feature.
- You are solely responsible for evaluating whether this feature is appropriate for your environment and risk tolerance.

**This feature is disabled by default. Do not enable it unless you have a specific, well-understood operational requirement.**

If you are unsure whether you need this feature, you do not need it.
