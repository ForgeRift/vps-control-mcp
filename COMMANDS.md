# Command Reference — vps-control-mcp

This document describes what types of commands you can ask Claude to run on your VPS through vps-control-mcp, and why certain commands require extra review or are blocked entirely.

**Three tiers of commands:**
- ✅ **GREEN** — Runs immediately, no extra review
- ⚠️ **AMBER** — Reviewed by AI safety layer before running; may be blocked if context looks risky
- 🔴 **RED** — Always blocked, no exceptions, no override

If you try a RED command, Claude will tell you it's blocked and why. If you try an AMBER command that gets rejected, Claude will explain what triggered the review and suggest a safer alternative if one exists.

---

## ✅ GREEN — Runs Freely

These are safe, read-only, or low-risk operations that don't require AI safety review.

| What you can ask | Examples |
|---|---|
| View system health | `What's my CPU and memory usage?` |
| Check running processes | `What's running under PM2?` |
| Read log files | `Show me the last 100 lines of my app logs` |
| Check service status | `Is nginx running?` `Is postgres up?` |
| List files and directories | `What's in /var/www/?` |
| View file contents | `Show me my nginx config` |
| Check disk usage | `How much disk space am I using?` |
| Inspect git state | `What's the git status of my app?` `Show me recent commits` |
| View network connections | `What ports are open on this server?` |
| View the audit log | `Show me what commands were run today` |
| Search files | `Find all .env files on this server` |
| Check cron jobs (read-only) | `What cron jobs are scheduled?` |
| View error logs | `Any errors in the last hour?` |

**Rule of thumb:** If it reads, lists, searches, or reports without changing anything, it's GREEN.

---

## ⚠️ AMBER — AI-Reviewed Before Running

These categories of commands can be completely legitimate but also dangerous depending on context. Claude's AI safety board (Layer 3) reviews them before running and decides based on what you're actually trying to do.

You don't need to do anything special — just ask naturally. The more context you give about what you're trying to accomplish, the more accurately the safety board can assess intent.

---

### Base64-Encoded Commands
**What it is:** Commands that decode a base64 string and execute the result
**Why reviewed:** Base64 encoding is a common technique for obfuscating malicious payloads. Legitimate use cases exist (some API payloads use base64), but executing decoded base64 as a shell command is suspicious.
**Usually approved:** Reading and displaying a base64-encoded value for inspection
**May be blocked:** Decoding and immediately executing base64 as a command

---

### Command Chaining
**What it is:** Combining multiple commands with `&&`, `||`, `;`, or `|`
**Why reviewed:** Chaining is essential for efficient server administration, but it can also bundle a malicious command with a legitimate-looking one. The safety board reads the entire chain.
**Usually approved:** `git pull && npm run build && pm2 restart myapp` during a deployment you've been discussing
**May be blocked:** Chains where the purpose of later commands isn't clear from context, or where commands mix read and destructive operations unexpectedly

---

### Code Execution
**What it is:** Running code from a string — `python3 -c "..."`, `node -e "..."`, inline scripts
**Why reviewed:** Inline code execution can hide what's actually running. The safety board reads the inline code before approving.
**Usually approved:** Simple one-liners for data processing, testing a quick script you wrote
**May be blocked:** Obfuscated code, code that downloads and executes more code

---

### Container Operations
**What it is:** Docker, Podman, containerd commands — starting, stopping, building, removing containers
**Why reviewed:** Containers can mount host filesystems and expose ports. Container management is a common VPS task, but some operations need context.
**Usually approved:** `docker ps`, `docker logs`, rebuilding a container you've been discussing deploying
**May be blocked:** Mounting sensitive host paths, running privileged containers, pulling images with no context

---

### Data Destruction
**What it is:** Commands that wipe or overwrite data — clearing log files, resetting databases, wiping directories
**Why reviewed:** Sometimes you need to clear a test database or rotate old logs. But these operations are often irreversible.
**Usually approved:** Clearing a specific old log file you've identified as safe to remove, truncating a dev database you explicitly set up
**May be blocked:** Anything targeting production data, data you haven't mentioned, or data paths that look critical

---

### Data Exfiltration
**What it is:** Sending data out of your server — curl posting data to external URLs, copying files to external destinations, piping output to a remote server
**Why reviewed:** The most common way compromised data leaves a server is via a command that looks like a normal API call or file transfer.
**Usually approved:** Posting to your own API endpoint, `scp` to your own backup server you've mentioned
**May be blocked:** Unexplained outbound transfers, transfers to URLs that weren't mentioned in the conversation

---

### Direct Database Access
**What it is:** Raw SQL via `psql`, `mysql`, `sqlite3` — especially write operations
**Why reviewed:** Direct database access can corrupt production data. Read queries are lower risk; write queries need context.
**Usually approved:** `SELECT` queries for debugging, schema inspection, viewing a specific record
**May be blocked:** `DROP`, `DELETE`, `TRUNCATE` without clear context that this is a dev/staging database

---

### Disk Operations
**What it is:** Low-level disk tools — `fdisk`, `mkfs`, `mount`, `umount`, `parted`
**Why reviewed:** Disk tools can permanently destroy data on entire partitions.
**Usually approved:** `lsblk`, `df`, `du` — read-only disk inspection
**May be blocked:** Formatting, repartitioning, or mounting external disks without context

---

### Environment Variable Manipulation
**What it is:** Exporting or modifying environment variables — `export`, modifying `.env` files, `systemctl edit`
**Why reviewed:** Environment variables control where programs look for credentials, config, and executables. Changes here can have wide-ranging effects.
**Usually approved:** Adding a new variable to your app's `.env` file during a setup task you've been discussing
**May be blocked:** Modifying system-wide variables, changing PATH or security-relevant config

---

### File Deletion
**What it is:** Deleting individual files or directories — `rm`, `rmdir`, `unlink`
**Why reviewed:** Deletion is usually permanent on a server (no Recycle Bin). The safety board checks whether the file being deleted makes sense to delete given what you're working on.
**Usually approved:** Deleting build artifacts, old log files, temp files from a deploy you just ran
**May be blocked:** Deleting files outside your project directory, config files, anything that looks like it might be needed

---

### File Write
**What it is:** Creating or overwriting files — `>`, `tee`, `echo >> file`, writing via text editors
**Why reviewed:** Writing files is essential for server administration, but the destination and content both matter.
**Usually approved:** Writing to your project directory, updating a config file you're actively editing, saving script output
**May be blocked:** Writing to system directories, writing executable scripts to unusual locations, writing obfuscated content

---

### HTTP Server
**What it is:** Starting a local or public-facing HTTP server — `python3 -m http.server`, custom web servers
**Why reviewed:** HTTP servers expose your filesystem or application to the network. Fine for debugging, risky if unintended.
**Usually approved:** Starting a temporary HTTP server on localhost for a specific debugging task
**May be blocked:** Servers that bind to 0.0.0.0 with no auth, or that expose sensitive directories

---

### Information Leakage
**What it is:** Commands that print sensitive system information — private keys, credential files, API keys, `/etc/shadow`, `/etc/passwd`
**Why reviewed:** These commands are sometimes legitimate for debugging, but they're also the first thing an attacker runs after gaining access.
**Usually approved:** Reading your own app's config file you've been discussing
**May be blocked:** Reading SSH private keys, system credential files, or sensitive paths you haven't mentioned

---

### Network Configuration
**What it is:** Changing network settings — adding routes, modifying `/etc/hosts`, changing firewall rules, binding ports
**Why reviewed:** Network changes persist and can affect all services on the server.
**Usually approved:** Checking network settings (read-only), opening a specific port you're developing on
**May be blocked:** Modifying firewall rules, changing default routes, disabling network interfaces

---

### Permission Changes
**What it is:** Changing file or directory permissions — `chmod`, `chown`, `chgrp`
**Why reviewed:** Incorrect permissions can expose protected files or lock you out of your own system.
**Usually approved:** Fixing permissions on a file you just deployed (`chmod 755 /var/www/myapp/public`)
**May be blocked:** Recursive permission changes on system paths, making sensitive files world-readable

---

### Persistence
**What it is:** Creating things that run automatically — systemd units, cron jobs, init scripts, startup files
**Why reviewed:** Persistence is also how malware survives a reboot. Legitimate use cases are common but need context.
**Usually approved:** Adding a cron job for a backup script you just wrote, creating a systemd unit for a new service you're setting up
**May be blocked:** Adding startup entries for scripts outside your project, creating hidden cron jobs

---

### Package Installation
**What it is:** Installing new packages — `apt install`, `pip install`, `npm install -g`, `snap install`
**Why reviewed:** Installing packages changes the server environment and can introduce dependencies with vulnerabilities.
**Usually approved:** Installing a package you've explicitly asked about, adding a dependency for a project you're setting up
**May be blocked:** Installing packages unrelated to the current task, packages that look like security tools being disabled or installed for attack use

---

### Package Removal
**What it is:** Uninstalling packages — `apt remove`, `apt purge`
**Why reviewed:** Removing packages can break dependencies or remove security tools.
**Usually approved:** Removing a package you just installed to test something, cleaning up an old version
**May be blocked:** Removing system-critical packages, security software, or packages unrelated to the current task

---

### Privilege Escalation
**What it is:** Running commands as a different user or gaining elevated access — `sudo su`, `su -`, `runuser`
**Why reviewed:** Elevating privileges expands what subsequent commands can do.
**Usually approved:** Using `sudo` for a specific command that requires root, if you've established root is needed
**May be blocked:** Switching to root and staying there, escalating for commands that don't need it

---

### Process Termination
**What it is:** Killing running processes — `kill`, `killall`, `pkill`
**Why reviewed:** Killing the wrong process can crash your application or cause data loss.
**Usually approved:** Killing a specific stuck process you've been discussing, killing a PM2 process before redeployment
**May be blocked:** Killing system processes, security daemons, or processes you haven't mentioned

---

### Scheduled Execution
**What it is:** Scheduling commands to run at a later time — `crontab`, `at`, `systemd timers`
**Why reviewed:** Scheduled tasks run without you watching. They're a common automation need but also a persistence vector.
**Usually approved:** Setting up a nightly backup cron job you've been designing in the conversation
**May be blocked:** Tasks that run as root with no clear purpose, tasks scheduled from commands that look suspicious

---

### Service Management
**What it is:** Starting, stopping, enabling, or disabling system services — `systemctl`, `service`
**Why reviewed:** Services run with elevated privileges and persist across reboots.
**Usually approved:** Restarting nginx after a config change, enabling a new service you've installed
**May be blocked:** Disabling security services, stopping monitoring agents, modifying services you haven't mentioned

---

### Shell Invocation
**What it is:** Spawning subshells — `bash -c "..."`, `sh -c "..."`, here-strings that execute
**Why reviewed:** Subshell invocation can hide what's actually running inside the shell.
**Usually approved:** `bash -c "cd /myapp && ./deploy.sh"` during a deploy you're orchestrating
**May be blocked:** Subshells with obfuscated or unclear content

---

### System State Changes
**What it is:** Changing kernel parameters, sysctl values, system-wide configuration
**Why reviewed:** System state changes are persistent and can be difficult to reverse.
**Usually approved:** Adjusting a specific kernel parameter (like file descriptor limits) for a performance task you've been discussing
**May be blocked:** Most cases — these are uncommon in typical workflows

---

### User Management
**What it is:** Creating, modifying, or deleting user accounts — `useradd`, `usermod`, `passwd`, `userdel`
**Why reviewed:** User management changes who has access to your server.
**Usually approved:** Creating a service account for an application you're deploying
**May be blocked:** Creating admin/sudo users, modifying existing user accounts you haven't mentioned

---

## 🔴 RED — Always Blocked

These are hard stops. No amount of context, explanation, or rephrasing will make them run. The plugin rejects them immediately in code — before the AI safety layer is even consulted.

If you have a legitimate need for something in this list, you'll need to SSH into your server and run it yourself. Claude can write the exact command for you and explain each step.

---

### Audit Log Destruction
**What it is:** Deleting or clearing the plugin's audit log, or clearing system audit logs (`/var/log/auth.log`, `journald` rotation tricks)
**Why blocked:** The audit log is your evidence trail. Clearing it is the first thing an attacker does after gaining access. No legitimate automation should destroy its own audit trail.

---

### Code Execution (Hard Blocked Variants)
**What it is:** The most dangerous forms of inline code execution — `eval` piped from untrusted sources, exec() calls that load remote code
**Why blocked:** These specific patterns are used almost exclusively to execute code that wasn't on the system before — the classic "fileless malware" technique.

---

### Container Nuclear Operations
**What it is:** Destroying all containers at once — `docker system prune -af`, `docker rm -f $(docker ps -aq)`
**Why blocked:** Mass container destruction is irreversible. If you need to clean up, Claude will help you identify specific containers to remove.

---

### Credential and Key Destruction
**What it is:** Deleting SSH private keys, certificate private keys, credential files, API key stores
**Why blocked:** Key destruction is irreversible and can permanently lock you out of systems. No automation should be deleting your key material.

---

### Database Destruction
**What it is:** `DROP DATABASE`, `DROP TABLE` in a production context, truncating critical tables
**Why blocked:** Irreversible. For dev/test database resets, Claude can help you write and review the script — but won't auto-execute irreversible database operations.

---

### Destructive Git History Rewrite
**What it is:** `git push --force` to a remote, `git filter-branch` runs that alter pushed history
**Why blocked:** Force-pushing to a remote branch destroys history for everyone using the repository. This is a one-way door.

---

### Disk-Level Writes
**What it is:** Writing directly to raw disk or partition devices — `dd if=... of=/dev/sda`, `fdisk` write operations on live partitions
**Why blocked:** Disk-level writes bypass the filesystem entirely. A mistake here can make your server unbootable.

---

### Download Cradles
**What it is:** Downloading and immediately executing code — `curl https://... | bash`, `wget -O- ... | sh`
**Why blocked:** Download-and-execute is the textbook first stage of a malware infection. If you need to run a script from the internet, download it first, review it, then run it as two separate steps.

---

### Firewall Destruction
**What it is:** Disabling `ufw`, `iptables -F` (flush all rules), removing all firewall rules
**Why blocked:** Disabling the firewall exposes your server to the entire internet with no protection. This is a common attacker step after gaining initial access.

---

### Git History Rewrite (General)
**What it is:** Rewriting committed history on pushed branches — `git rebase -i` with squash/drop on commits that are already pushed
**Why blocked:** Rewriting pushed history affects everyone using the repository and can corrupt it permanently.

---

### Kernel Namespace Operations
**What it is:** Creating or modifying kernel namespaces — `unshare`, `nsenter` into privileged namespaces
**Why blocked:** Kernel namespace manipulation is used for container escapes and privilege escalation. No typical server management task requires this.

---

### Kernel Probe Insertion
**What it is:** Loading kernel modules — `insmod`, `modprobe` with custom modules, `kprobe` insertion
**Why blocked:** Kernel modules run with full kernel privileges. A malicious kernel module can make a server completely undetectable and unrecoverable. Server management doesn't require inserting custom kernel modules.

---

### OS Permission Destruction
**What it is:** `chmod -R 777 /`, `chown -R nobody /etc`, mass permission changes that destroy access controls
**Why blocked:** Recursively opening up permissions on system directories can make your server permanently insecure or unusable.

---

### Destructive Package Manager Operations
**What it is:** `apt purge` of system-critical packages, uninstalling security tools, removing init systems
**Why blocked:** Removing critical system packages can make a server unbootable. These operations are human decisions, not automation tasks.

---

### Recursive File Deletion
**What it is:** `rm -rf /`, `rm -rf /*`, `rm -rf ~` or similar patterns targeting home, root, or system directories
**Why blocked:** Recursive deletion from root or home paths is almost always a catastrophic mistake. There is no legitimate automation workflow that should be doing this.

---

### Redirect Truncation / Overwrite
**What it is:** Using `>` to overwrite critical system files, `> /dev/null` patterns on output that should be preserved, redirecting into config or executable files
**Why blocked:** Redirecting into the wrong path can silently destroy configuration or make a service unloadable.

---

### Scheduled Execution (Hard Blocked Variants)
**What it is:** The most dangerous forms of scheduled task creation — cron jobs that run as root from obfuscated commands, `at` jobs scheduled from non-interactive sessions
**Why blocked:** These patterns are almost exclusively used for persistence in compromised systems.

---

### Sensitive Path Writes
**What it is:** Writing files to `/etc/`, `/bin/`, `/sbin/`, `/usr/bin/`, `/lib/`, or other system directories
**Why blocked:** Writing to system directories is how attackers replace legitimate binaries with malicious ones (binary hijacking). Legitimate application deployments write to `/var/www/`, `/opt/`, or user home directories — not system paths.

---

### System Power State
**What it is:** Shutdown, reboot, halt — `shutdown -h now`, `reboot`, `init 0`
**Why blocked:** An AI assistant shutting down your server would terminate the Claude session and potentially take down production services. Power state changes are always a human decision.

---

## Frequently Asked Questions

**Q: I need to do something that's blocked. What do I do?**
SSH into your server and run it yourself. Claude can write the exact commands for you, explain each step, and help you verify the results afterward — it just won't execute it through the plugin.

**Q: My legitimate task is getting AMBER-blocked. How do I help Claude understand?**
Just explain what you're trying to do and why. The AI safety layer reads your full conversation context. "I'm deploying a new version of my API and need to restart the nginx service" gives the review much more signal than just `systemctl restart nginx` with no context.

**Q: Can I adjust what's blocked or allowed?**
The RED tier is not configurable — those are hard limits in the plugin code. The AMBER tier uses AI judgment, which responds to context. If a specific legitimate pattern is consistently over-blocked, contact support@forgerift.io with the pattern and use case.

**Q: What happens if I try a RED command?**
Claude will tell you it's blocked, explain which category triggered it, and offer to help you accomplish the underlying goal by writing the commands for you to run manually via SSH.

**Q: How do I see what commands were run?**
Ask Claude: *"Show me the audit log"* — every command attempt (including blocked ones) is logged with a timestamp. Or SSH in and check `/root/vps-control-mcp/audit.log` directly.

**Q: Is my server safe if someone gets my MCP_AUTH_TOKEN?**
The RED-tier blocks still apply regardless of the token. But someone with your token can run a lot of AMBER-tier commands and might be able to do significant damage. Rotate your `MCP_AUTH_TOKEN` immediately if you think it was exposed, and check your audit log for unexpected activity.

---

*For setup instructions, see [GETTING_STARTED.md](GETTING_STARTED.md). For troubleshooting, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md).*
