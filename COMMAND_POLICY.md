# VPS Control MCP — Command Policy Reference

*Last updated: 2026-04-24 | vps-control-mcp v1.10.8*

This document describes exactly what Claude can and cannot run on your VPS through the `run_approved_command` tool. Every command family is listed. No guesswork.

The security model has three tiers:

- **GREEN** — Allowed. Executes immediately. Subject to audit logging and a session-scoped rate limit.
- **AMBER** — Risky but sometimes legitimate. First call returns a warning; you must re-call with `dry_run=false` to proceed.
- **RED** — Hard-blocked. Cannot be executed through this plugin under any circumstances. Use a direct SSH session instead.

There is also a **BLOCKED** tier above RED: a three-layer AI pipeline (static patterns + Claude pre-classification + multi-persona board review) for catastrophic operations. This sits above RED and is not overridable.

---

## GREEN — Allowed Commands

These commands execute without friction. They are still audit-logged and subject to session caps.

### Process & System Observability
| Command | Notes |
|---------|-------|
| `ps aux`, `ps -ef` | Process list. `ps auxe` is RED (env dump). |
| `top -bn1` | Snapshot mode only (non-interactive). Interactive `top` will hang. |
| `uptime` | System uptime. |
| `free -h` | Memory usage. |
| `df -h` | Disk usage by filesystem. |
| `du -sh /path` | Directory size. |
| `lsof` | Open file handles and network sockets. |
| `netstat -tlnp`, `ss -tlnp` | Listening ports. |
| `ifconfig` (read only) | Network interface info. `ifconfig eth0 up/down` is RED. |
| `ip link show`, `ip addr show`, `ip route show` | Read-only network inspection. `ip link/addr/route add/del/set` is RED. |
| `ping -c 4 host` | Network reachability. |
| `traceroute host` | Network path. |
| `whoami`, `id` | Current user and group. |
| `hostname` | Server hostname. |
| `uname -a` | Kernel and OS info. |
| `date`, `timedatectl status` | System time. |

### File & Directory Inspection
| Command | Notes |
|---------|-------|
| `ls`, `ls -la /path` | Directory listing. |
| `cat /path/file` | File contents. Blocked for `.env`, `.ssh/`, `/etc/shadow`, `/etc/passwd`, and other sensitive patterns. |
| `head /path/file` | First N lines. Blocked for `.env` and `/etc/` files. |
| `tail /path/file` | Last N lines. Same restrictions as `head`. |
| `wc -l /path/file` | Line count. |
| `find /path -name pattern` | File search. `-exec` and `-execdir` are RED. `-delete` is RED. |
| `grep pattern /path` | Text search in files. |
| `grep -r pattern /dir` | Recursive text search. |
| `stat /path` | File metadata. |
| `file /path` | File type detection. |
| `sort`, `uniq`, `cut`, `tr` | Text processing (stdout only; no redirect to files). |
| `sed 's/foo/bar/' file` | Stdout transform. `sed -i` (in-place) is RED. |
| `awk '{print $1}' file` | Field extraction. `awk > /path` writes are RED. |
| `jq .field file.json` | JSON parsing. |
| `diff file1 file2` | File diff. |

### Node.js & npm
| Command | Notes |
|---------|-------|
| `node --version`, `node -v` | Version check. |
| `node script.js` | Run a script file. `node -e` (inline eval) is RED. |
| `npm --version` | Version check. |
| `npm list` | Installed packages. |
| `npm outdated` | Outdated packages. |
| `npm audit` | Vulnerability scan (read-only). |
| `npm run <script>` | Run package.json scripts. |
| `pnpm list`, `pnpm outdated` | pnpm equivalents. |

### Git (read-only via run_approved_command)
| Command | Notes |
|---------|-------|
| `git status` | Working tree status. Prefer the `git_status` structured tool. |
| `git log --oneline -20` | Commit history. Prefer the `git_log` structured tool. |
| `git diff` | Unstaged changes. |
| `git branch -a` | Branch list. |
| `git tag` | Tag list. |
| `git show <ref>` | Commit contents. |
| `git remote -v` | Remote URLs (read-only). |

> ⚠️ Git commands run through `run_approved_command` do **not** have the GIT_HARDENING_FLAGS applied (core.hooksPath=/dev/null, etc.). Use the structured `git_pull`, `git_status`, `git_log`, `git_push` tools for operations that involve remote interaction or hook-sensitive paths.

### System Info
| Command | Notes |
|---------|-------|
| `which cmd`, `whereis cmd` | Binary location. |
| `type cmd` | Shell command type. |
| `env` (with arguments) | Bare `env` with no args is RED (full env dump). `env VAR=val cmd` is still evaluated. |
| `lsb_release -a` | OS version. |
| `cat /etc/os-release` | OS info. Blocked because `/etc/` is on the sensitive path list — use `lsb_release` instead. |

---

## AMBER — Warning Tier

These commands require explicit confirmation. Claude will block on first call and explain the risk; re-calling with `dry_run=false` proceeds with a warning prepended to the output.

| Command | Risk |
|---------|------|
| `apt-get update` | Package index update. Safe but slow — can timeout the connection (30-60s). Use `run_in_background=true`. |
| `xargs` (general) | Pipes stdin as arguments to another command. Risk depends on target command. |

> Note: `xargs` piped to dangerous commands (`sh`, `bash`, `rm`, `curl`, `wget`, `python`, `node`, `perl`, `ruby`, `php`) is RED, not AMBER.

---

## PM2 Sub-Command Policy

PM2 is the process manager running your applications. Access is split between read-only sub-commands (via `run_approved_command`) and lifecycle operations (via the `restart_process` structured tool).

### GREEN — Allowed via run_approved_command

| Sub-command | Notes |
|-------------|-------|
| `pm2 status` | Process list with state, CPU, memory. |
| `pm2 list` | Alias for status. |
| `pm2 ls` | Alias for status. |
| ~~`pm2 logs <name>`~~ | **Removed (F-S67-16/F-S67-41).** Use `get_recent_errors` / `get_recent_output` tools instead — they return structured, capped output without hanging the connection. `pm2 logs` is no longer accepted by the validator. |
| ~~`pm2 monit`~~ | **Removed (F-S67-35).** `pm2 monit` opens an interactive ncurses UI that hangs in stdio mode. Use `get_pm2_status` instead. |
| `pm2 id <name>` | Process ID lookup. |
| `pm2 version`, `pm2 --version`, `pm2 -v` | Version check. |
| `pm2 save` | Persists the current process list to disk so it survives reboots. Write op but bounded risk — recoverable. |
| `pm2 startup show` | Prints the startup script command without executing it. Pure read. |


### RED — Blocked (env-leak risk)
These sub-commands print the full process environment, which includes `MCP_AUTH_TOKEN`, `SUPABASE_SERVICE_KEY`, and other secrets. Use the `get_pm2_status` structured tool instead — it returns a scrubbed view.

| Sub-command | Reason |
|-------------|--------|
| `pm2 jlist` | JSON output includes full `pm2_env` with all env vars. |
| `pm2 prettylist` | Same as jlist, formatted. |
| `pm2 describe <name>` | Full process detail including env. |
| `pm2 info <name>` | Alias for describe. |
| `pm2 show <name>` | Alias for describe. |

### RED — Blocked (lifecycle)
These are handled by the `restart_process` structured tool, which applies rate limiting, dry-run confirmation, and audit logging.

| Sub-command | Reason |
|-------------|--------|
| `pm2 start` | Use `restart_process` tool. |
| `pm2 stop` | Use `restart_process` tool. |
| `pm2 restart` | Use `restart_process` tool. |
| `pm2 delete` | Use `restart_process` tool. |
| `pm2 flush` | Destroys all PM2 log evidence. Classified as `audit-log-destruction` (F-OP-90). |
| `pm2 reload` | Triggers live process restart (lifecycle-affecting). Use `restart_process` tool (F-OP-89). |
| `pm2 kill` | Kills the PM2 daemon. Hard-blocked. |

---

## RED — Hard-Blocked Commands

Nothing below can be executed through this plugin. No justification overrides it. Use a direct SSH session for any legitimate operations in these categories.

### File Destruction
| Command | Reason |
|---------|--------|
| `rm` | File deletion. |
| `unlink` | Syscall-level file deletion. |
| `shred` | Secure file deletion. |
| `truncate` | File truncation. |
| `srm`, `secure-delete` | Secure deletion utilities. |

### Disk & Filesystem
| Command | Reason |
|---------|--------|
| `dd` | Raw disk I/O. `dd if=/dev/zero of=/dev/sda` would wipe the VPS. |
| `mkfs`, `mkfs.ext4`, etc. | Filesystem creation — wipes target device. |
| `fdisk`, `parted`, `gdisk` | Disk partitioning. |
| `wipefs` | Filesystem signature wipe. |
| `hdparm --security-erase` | ATA secure erase. |
| `nvme format` | NVMe format command. |
| `blkdiscard` | Block device discard (SSD erase). |
| `mount`, `umount` | Filesystem mounting. |

### System State
| Command | Reason |
|---------|--------|
| `shutdown` | Server shutdown. |
| `reboot` | Server reboot. |
| `halt`, `poweroff` | Server halt/poweroff. |
| `init 0`–`init 6` | Runlevel changes. |
| `telinit 0`, `telinit 6` | Runlevel changes. |
| `modprobe`, `insmod` | Kernel module loading — can load rootkits. |
| `rmmod`, `depmod` | Kernel module management. |

### Process Killing
| Command | Reason |
|---------|--------|
| `kill` | Arbitrary process termination. Use `restart_process` for PM2 processes. |
| `killall` | Kill by name — can take down critical processes. |
| `pkill` | Pattern-based kill. |

### User & Permission Management
| Command | Reason |
|---------|--------|
| `useradd`, `adduser` | Create user accounts. |
| `userdel`, `deluser` | Delete user accounts. |
| `passwd` | Change passwords. |
| `usermod -L` | Lock user accounts. |
| `chmod` | Permission changes. Use the deploy tool for file permission management. |
| `chown`, `chgrp` | Ownership changes. |
| `setfacl` | ACL modifications. |
| `visudo`, `/etc/sudoers` | Sudoers editing. |

### Service Management
| Command | Reason |
|---------|--------|
| `systemctl` (all sub-commands) | Service lifecycle management. **Proposed: allow read-only sub-commands** (`status`, `is-active`, `is-enabled`, `list-units`) via argv-aware allowlist similar to the PM2 validator. |
| `service` (all sub-commands) | Service management. **Proposed: allow `service X status`** read-only via allowlist. |
| `systemd-run` | Scheduled execution via systemd. |

### Firewall & Network Configuration
| Command | Reason |
|---------|--------|
| `iptables`, `ip6tables` | Firewall rules. A single wrong rule can lock you out. |
| `ufw` | UFW firewall management. |
| `nft` | nftables management. |
| `ifconfig eth0 up/down` | Interface state changes. |
| `ip link/addr/route add/del/set` | Network configuration changes. |
| `setenforce 0` | Disable SELinux. |
| `aa-teardown` | Disable AppArmor. |
| `firewall-cmd --panic-off` | Disable firewalld panic mode. |

### Scheduled Execution
| Command | Reason |
|---------|--------|
| `crontab -e`, `crontab -r` | Create/delete cron jobs — persistent backdoor risk. `crontab -l` (read-only list) is allowed via argv-aware allowlist. |
| `at` | Schedule one-time commands. |
| `atq` | Lists scheduled jobs, read-only. Allowed with restricted flags. |

### Code Execution Bypasses
| Command | Reason |
|---------|--------|
| `node -e`, `node --eval` | Inline JavaScript execution. |
| `python -c` | Inline Python execution. |
| `perl -e`, `perl -E` | Inline Perl execution. |
| `ruby -e`, `ruby -E` | Inline Ruby execution. |
| `php -r` | Inline PHP execution. |
| `lua -e`, `lua -E` | Inline Lua execution. |
| `tclsh` | Tcl interpreter. |
| `expect -c` | Expect scripting. |
| `bpftrace -e` | BPF program execution. |
| `eval` | Shell eval. |
| `awk … system()` | awk system() call. |
| `m4 … syscmd` | m4 macro shell execution. |

### Shell Invocation
| Command | Reason |
|---------|--------|
| `… \| bash`, `… \| sh`, etc. | Piping to a shell — executes arbitrary commands. |
| `bash -c '…'`, `sh -c '…'` | Shell with inline command. |
| `` `cmd` `` | Backtick subshell. |
| `$(cmd)` | Command substitution subshell. |

### Data Exfiltration (Outbound Network)
| Command | Reason |
|---------|--------|
| `curl` | HTTP client — can exfiltrate data to attacker-controlled endpoints. **See note below.** |
| `wget` | HTTP download — same risk as curl. |
| `nc`, `ncat`, `netcat` | Raw TCP/UDP — reverse shell vector. |
| `socat` | Bidirectional relay — reverse shell vector. |
| `ssh` | Outbound SSH — tunnel and exfil risk. |
| `scp` | Secure copy — file exfiltration. |
| `sftp` | Secure FTP — file exfiltration. |
| `rsync` | File sync — data exfiltration at scale. |
| `ftp` | FTP — data exfiltration. |
| `git fetch` | Fetches from remote repos — hook execution risk. |
| `git clone` | Arbitrary remote code via install scripts. |

> **curl / wget note:** These are currently hard-RED. A case can be made for AMBER (many legitimate admin scenarios — health checks, API testing). The blocker is that exfiltration is hard to distinguish from legitimate use at the pattern level. Being discussed for a future version with allowlisted destination domains.

### Persistence Mechanisms
| Command | Reason |
|---------|--------|
| `nohup` | Detaches process from session — backdoor persistence. |
| `disown` | Detaches process from shell. |
| `screen` | Terminal multiplexer — persistent session. |
| `tmux` | Terminal multiplexer — persistent session. |

### Direct Database Access
| Command | Reason |
|---------|--------|
| `psql` | Direct Postgres access — use structured query tools. |
| `mysql` | Direct MySQL access. |
| `mongo` | Direct MongoDB access. |
| `redis-cli` | Direct Redis access. |
| `sqlite3` | Direct SQLite access. |

### Package Installation / Removal
Package managers run install scripts with the privileges of the current user. A malicious or compromised package can execute arbitrary code during install.

| Command | Reason |
|---------|--------|
| `apt-get install`, `apt install` | Package install. |
| `apt-get remove`, `apt remove` | Package removal. |
| `apt-get purge`, `apt purge` | Package purge. |
| `apt upgrade`, `apt-get upgrade`, `apt dist-upgrade` | Bulk upgrade — can install compromised packages. |
| `dpkg -i`, `dpkg --purge` | Direct Debian package management. |
| `yum install`, `yum remove` | RPM-based package management. |
| `dnf install`, `dnf remove` | DNF package management. |
| `zypper install`, `zypper remove` | OpenSUSE package management. |
| `rpm -i`, `rpm -e` | Raw RPM management. |
| `snap install`, `flatpak install` | Snap/Flatpak. |
| `pip install`, `pip2 install`, `pip3 install` | Python packages with setup.py scripts. |
| `npm install` | npm with lifecycle scripts. Use the `deploy` tool for application deployments. |
| `npx` | Remote code execution disguised as a tool runner. |
| `conda install/remove` | Conda environment management. |
| `brew install/uninstall` | Homebrew. |
| `cargo install` | Rust package install. |
| `gem install/uninstall` | Ruby gems. |
| `go install` | Go package install. |
| `emerge` | Gentoo portage. |
| `pacman -S`, `pacman -R` | Arch Linux. |

### Container Operations
Container commands can escape isolation boundaries and access host resources.

| Command | Reason |
|---------|--------|
| `docker` (all) | Docker commands. **Proposed: allow read-only sub-commands** (`docker ps`, `docker images`, `docker stats`, `docker logs <name>`) via argv-aware allowlist. |
| `podman`, `runc`, `crun` | Alternative container runtimes. |
| `kubectl` | Kubernetes — cluster-wide destructive potential. |
| `helm` | Kubernetes package manager. |
| `lxc`, `nerdctl`, `buildah` | Additional container runtimes. |
| `singularity`, `apptainer` | HPC container runtimes. |
| `k3s-uninstall.sh` | Uninstalls K3s cluster. |
| `nsenter`, `unshare` | Kernel namespace manipulation — container escape. |
| `chroot`, `pivot_root` | Root filesystem change. |
| `capsh` | Capability shell — privilege escalation. |
| `ip netns` | Network namespace management. |

### File Write Operations
| Command | Reason |
|---------|--------|
| `> /path` | Redirect to absolute path — overwrites files. |
| `> ~/path` | Redirect to home directory. |
| `>>` | Append redirect. |
| `tee` | Split stdout to file — file write. |
| `ln -s`, `ln --symbolic` | Symlink creation — can redirect writes to sensitive paths. |
| `cp` to system dirs | Copying to `/etc`, `/root`, `/bin`, `/sbin`, `/usr`, `/var`, `/boot`, `/lib`, `/opt`. |
| `mv` to system dirs | Same as above. |
| `install` to system dirs | Same as above. |
| `sed -i`, `sed --in-place` | In-place file modification. |
| `awk … > /path` | awk writing to absolute paths. |

### Environment Manipulation
| Command | Reason |
|---------|--------|
| `export VAR=val` | Sets environment variables — can manipulate PATH, LD_PRELOAD, etc. |
| `source file`, `. /file` | Sources shell scripts — arbitrary code execution. |
| `LD_PRELOAD=…` | Dynamic linker injection. |
| `LD_AUDIT=…` | Dynamic linker audit injection. |
| `LD_LIBRARY_PATH=…` | Library path injection. |

### Privilege Escalation
| Command | Reason |
|---------|--------|
| `sudo` | Run as root. Plugin already runs as root on this VPS; sudo is a re-exec surface. |
| `su ` | Switch user. |
| `pkexec` | Polkit privilege escalation. |
| `doas` | OpenBSD sudo alternative. |
| `sudoedit` | Sudoers-based editor escalation. |
| `runuser` | Run commands as another user. |
| `machinectl shell` | systemd-machined shell. |

### Information Leakage
| Command | Reason |
|---------|--------|
| `printenv` | Dumps all environment variables including secrets. |
| `env` (bare, no args) | Same as printenv. |
| `env -0`, `env -i`, `env --null` | Variations that dump the full environment. |
| `history` | Command history — may contain secrets typed on the command line. |
| `cat /etc/shadow` | Password hashes. |
| `cat /etc/passwd` | User list (information disclosure). |
| `cat .env` | Environment file with secrets. (Also blocked via path validator.) |
| `head`/`tail` on `.env` | Same. |
| `head`/`tail` on `/etc/*` | System config files. |
| `/proc/` access | Kernel VFS — `/proc/self/environ` exposes all env vars including secrets. |
| `strace` | System call tracing — extracts runtime secrets from process memory. |
| `ltrace` | Library call tracing. |
| `gdb`, `ptrace` | Debugger — can read arbitrary process memory. |
| `strings` | Extracts printable strings from binaries — can expose compiled-in secrets. |
| `hexdump`, `xxd`, `od` | Binary inspection — same risk as strings. |
| `ps auxe` | `ps` with environment flag — dumps all process env vars. |
| `ps -eo` | `ps` with custom output including environment. |
| `journalctl` | System journal — may contain secrets logged by services. **Proposed: AMBER** with warning about potential env var exposure. |
| `dmesg` | Kernel ring buffer. **Proposed: AMBER** — exposes system info but rarely contains application secrets. |
| `last`, `lastlog` | Login history — server access patterns. |
| `dig`, `nslookup`, `host` | DNS lookups. **Proposed: GREEN** — DNS queries don't expose server secrets and are standard observability. |
| `getent` | NSS lookups — `getent passwd` exposes user list. |
| `/etc/ssh/ssh_host_*_key` | SSH host private keys. |

### Command Chaining
Single-command execution only. Chaining creates compound commands that can bypass per-command validation.

| Operator | Reason |
|----------|--------|
| `;` | Sequential execution — second command runs regardless of first. |
| `&&` | Conditional chaining — second command runs on success. |
| `\|\|` | Conditional chaining — second command runs on failure. |
| `` `cmd` `` | Subshell — see Shell Invocation above. |
| `$(cmd)` | Subshell — see Shell Invocation above. |

### HTTP Servers
| Command | Reason |
|---------|--------|
| `python -m http.server` | Serves current directory over HTTP — exposes all readable files. |
| `php -S` | PHP built-in web server. |

### Kernel & BPF Probing
| Command | Reason |
|---------|--------|
| `bpftool` | BPF program management — can trace kernel activity. |
| `bpftrace -e` | BPF inline program execution. |
| `perf trace`, `perf probe` | Performance/syscall tracing. |
| `bpftool` | eBPF management. |

### Sensitive Path Writes (Kernel VFS)
| Path | Reason |
|------|--------|
| `/sys/…` | sysfs — exposes cgroup controls, debugfs, YAMA ptrace scope, firmware loading. |
| `/dev/mem`, `/dev/kmem`, `/dev/port` | Direct physical memory access. |

### Windows-Specific (Blocked on all platforms)
| Command | Reason |
|---------|--------|
| `vssadmin` | Volume Shadow Copy manipulation — backup destruction. |
| `wbadmin` | Windows Backup destruction. |
| `wevtutil` | Windows Event Log tampering. |
| `ntdsutil` | Active Directory database extraction. |

### Base64 Decode-to-Execute
| Command | Reason |
|---------|--------|
| `base64 -d` | Decoding is a common obfuscation layer for shell injection payloads. |
| `openssl base64 -d`, `openssl enc -d` | Same risk. |

### Destructive Git Operations
Beyond the standard `git_pull` / `git_push` structured tools, these specific git operations are hard-blocked:

| Command | Reason |
|---------|--------|
| `git push --force`, `git push -f` | Force-push rewrites remote history — irreversible. |
| `git push --mirror` | Mirrors local state to remote — can delete all remote branches. |
| `git push --delete` | Deletes remote branches. |
| `git filter-branch`, `git filter-repo` | History rewrite — irreversible. |
| `git reset --hard` | Discards all uncommitted changes. |
| `git clean -f` | Deletes untracked files. |
| `git checkout -- .` | Discards all working tree changes. |
| `git clone` | Ingests attacker-controlled remote code with executable install scripts. |
| `git init` | Creates new repos for hook-chained RCE attacks. |
| `git remote add` | Adds remotes enabling hook-chained RCE via subsequent fetch. |
| `git fetch` | Fetches from remotes — hook execution risk even with hardening. |

---

## Additional Validation: File Path Restrictions

The `read_file_section` and `search_file` tools are restricted to specific directories:
- **Allowed:** `APP_DIR` (your application directory) and `~/.pm2/logs`
- **Blocked:** Everything else, including `/root` outside APP_DIR, `/etc`, `/var`, `/home`

Even within allowed directories, these file patterns are blocked:

| Pattern | Reason |
|---------|--------|
| `.env` files | Credentials |
| `.ssh/` directory | SSH keys |
| `id_rsa`, `id_ed25519`, etc. | SSH key files |
| `authorized_keys`, `known_hosts` | SSH authentication |
| `.pem`, `.key`, `.p12`, `.jks` | TLS/SSL keys and keystores |
| `credentials.*`, `secrets.*` | Credential files |
| `password.*`, `token.*` | Password and token files |
| `/etc/shadow`, `/etc/sudoers`, `/etc/gshadow` | System auth files |
| `.htpasswd`, `.netrc`, `.pgpass` | Application credentials |
| `.my.cnf`, `.docker/config.json` | Service credentials |
| `kubeconfig` | Kubernetes credentials |
| `.aws/`, `.gcloud/`, `.azure/` | Cloud provider credentials |
| `.npmrc`, `.yarnrc` | npm/yarn auth tokens |
| `.bashrc`, `.zshrc`, `.profile` | Shell configs (may export secrets) |
| `.envrc` | direnv configs |
| `/etc/` | All system configuration |
| `/var/log/` | Host logs (PM2 app logs are accessible via `get_recent_errors` / `get_recent_output`) |
| `/proc/`, `/sys/` | Kernel virtual filesystems |
| `mcp-audit.log`, `/audit.log` | MCP audit log |

---

## Proposed Changes (S64)

The following changes are proposed for v1.11.0 to reduce friction for legitimate admin operations:

**v1.11.0 — applied:**

| Change | Was | Now | Rationale |
|--------|-----|-----|-----------|
| `pm2 save` | RED | GREEN | Persists process list. Bounded, recoverable. |
| `pm2 startup show` | RED | GREEN | Prints startup command, doesn't execute. |
| `pm2 reload <name>` | RED | AMBER | Graceful reload — see v1.12.0 reversal below. |
| `systemctl status/is-active/is-enabled/is-failed/list-units/list-unit-files/list-sockets/list-timers/help` | RED | GREEN | Read-only sub-commands. |
| `service <name> status` | RED | GREEN | Read-only. |
| `crontab -l` | RED | GREEN | Read-only list. |
| `atq` | RED | GREEN | Read-only list. |
| `dig <domain>` | RED | GREEN | DNS lookup. |
| `nslookup <domain>` | RED | GREEN | DNS lookup. |
| `host <domain>` | RED | GREEN | DNS lookup. |

**v1.12.0 — security corrections (Round 13 adversarial review):**

| Change | Was | Now | Finding |
|--------|-----|-----|---------|
| `pm2 flush` | GREEN | RED | F-OP-90: destroys all log evidence (`audit-log-destruction`) |
| `pm2 reload` | AMBER | RED | F-OP-89: lifecycle-affecting — use `restart_process` tool |
| `systemctl show/cat` | GREEN | RED | F-OP-87: dumps full unit env (may contain secrets) |
| `systemctl -H/-M` | unblocked | RED | F-OP-86: SSH pivot to remote hosts |
| Bare `crontab` | GREEN | RED | F-OP-88: drops into interactive editor |
| `dig @resolver` | GREEN | RED | F-OP-92: custom resolver pivot |
| `dig AXFR/IXFR` | GREEN | RED | F-OP-92: zone transfer = hostname enumeration |
| `host -l` | GREEN | RED | F-OP-92: zone transfer |
| Bare `nslookup` | GREEN | RED | F-OP-92: drops into interactive mode |
| `atq` | `allowAny` | `allowFlags(-V,--version,-q)` | F-OP-95: restrict flag surface |
| `journalctl -u <unit> -n 100` | RED | AMBER | System logs with unit filter. May expose secrets logged by services; user must confirm. |
| `dmesg --level=err` | RED | AMBER | Kernel error log. Rarely contains app secrets. |

> **Implementation note:** `systemctl`, `service`, `crontab`, and `pm2` changes require argv-aware validators (same pattern as the existing `validatePm2Args`), not simple regex pattern additions. A blanket `systemctl` allowlist would be dangerous — only the specific read-only sub-commands listed above should pass.

---

## What Claude Uses Instead of Blocked Commands

Many RED commands have structured tool equivalents that are safer, scoped, and audited:

| Instead of... | Use... |
|---------------|--------|
| `pm2 status` / `pm2 describe` | `get_pm2_status` tool (env-scrubbed) |
| `pm2 restart <name>` | `restart_process` tool |
| `pm2 logs <name>` | `get_recent_errors` / `get_recent_output` tools |
| `git pull` | `git_pull` tool (with hardening flags) |
| `git push` | `git_push` tool |
| `git status` | `git_status` tool |
| `git log` | `git_log` tool |
| Long-running background commands | `run_in_background=true` + `get_job_status` tool |
| Application deployment | `deploy` tool (orchestrates build, test, pm2 restart) |
| Self-deployment | `deploy_vps_mcp` tool |
| Reading PM2 log files | `get_recent_errors`, `get_recent_output` tools |
| Reading app files | `read_file_section`, `search_file` tools |
| System health overview | `get_system_health` tool |

---

*This policy is enforced server-side and cannot be overridden by Claude, the user, or any system prompt. The only way to change these limits is to update the plugin source and redeploy.*
