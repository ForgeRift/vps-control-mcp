import { execFile, spawn } from 'child_process';
import fs from 'fs';
import path from 'path';
import { promisify } from 'util';
import { fileURLToPath } from 'url';
import { CONFIG, ALLOWED_READ_DIRS } from './config.js';

const exec = promisify(execFile);
function runCmd(cmd: string, args: string[], cwd?: string): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const cb = (err: Error | null, stdout: string, stderr: string) => {
      if (err) { reject(err); return; }
      resolve({ stdout: stdout || '', stderr: stderr || '' });
    };
    if (cwd) { execFile(cmd, args, { cwd }, cb); }
    else      { execFile(cmd, args, cb); }
  });
}


// Session-scoped custom command counter (resets on process restart)
let customCommandCount = 0;

// ─── Async Deploy Job Store ───────────────────────────────────────────────────
interface DeployJob {
  id:          string;
  type:        'sharpedge' | 'vps-mcp';
  description: string;
  startedAt:   Date;
  status:      'running' | 'success' | 'failed';
  log:         string[];
}
const deployJobs = new Map<string, DeployJob>();

// ─── Background Command Job Store ─────────────────────────────────────────────
// Stores results of long-running run_approved_command calls (run_in_background=true).
// Fixes SSE connection drops on commands >60s (apt-get, npm install, etc.).
interface BackgroundJob {
  id:        string;
  command:   string;
  startedAt: Date;
  status:    'running' | 'success' | 'failed';
  stdout:    string;
  stderr:    string;
  exitCode:  number | null;
}
const bgJobs = new Map<string, BackgroundJob>();

// ─── File-based job persistence (VC-8) ───────────────────────────────────────
// deploy_vps_mcp restarts this process mid-deploy, wiping the in-memory Map.
// We persist each job to a JSON file so get_deploy_status can recover it.

const __tools_dir = path.dirname(fileURLToPath(import.meta.url));
const JOBS_FILE   = path.join(__tools_dir, '..', 'deploy-jobs.json');

function persistJob(job: DeployJob): void {
  try {
    let store: Record<string, unknown> = {};
    if (fs.existsSync(JOBS_FILE)) {
      store = JSON.parse(fs.readFileSync(JOBS_FILE, 'utf8')) as Record<string, unknown>;
    }
    store[job.id] = {
      id:          job.id,
      type:        job.type,
      description: job.description,
      startedAt:   job.startedAt.toISOString(),
      status:      job.status,
      log:         job.log,
    };
    fs.writeFileSync(JOBS_FILE, JSON.stringify(store, null, 2), 'utf8');
  } catch { /* fail-silent -- persistence is best-effort */ }
}

function loadJobFromFile(jobId: string): DeployJob | null {
  try {
    if (!fs.existsSync(JOBS_FILE)) return null;
    const store = JSON.parse(fs.readFileSync(JOBS_FILE, 'utf8')) as Record<string, Record<string, unknown>>;
    const raw   = store[jobId];
    if (!raw) return null;
    return {
      id:          raw['id']          as string,
      type:        raw['type']        as 'sharpedge' | 'vps-mcp',
      description: raw['description'] as string,
      startedAt:   new Date(raw['startedAt'] as string),
      status:      raw['status']      as 'running' | 'success' | 'failed',
      log:         raw['log']         as string[],
    };
  } catch { return null; }
}

function startDeployJob(
  type: 'sharpedge' | 'vps-mcp',
  description: string,
  steps: Array<{ label: string; cmd: string; args: string[]; cwd?: string }>
): string {
  const id = `deploy-${Date.now()}`;
  const label = type === 'sharpedge' ? 'SharpEdge' : 'vps-control-mcp';
  const job: DeployJob = {
    id,
    type,
    description,
    startedAt: new Date(),
    status:    'running',
    log:       [`=== ${label} deploy started ===`, `Description: ${description}`, ''],
  };

  deployJobs.set(id, job);
  persistJob(job);

  // Fire-and-forget — returns before steps complete to avoid MCP timeout
  (async () => {
    for (const step of steps) {
      job.log.push(`--- ${step.label} ---`);
      persistJob(job);
      try {
        const result = await runCmd(step.cmd, step.args, step.cwd);
        if (result.stdout) job.log.push(result.stdout.trim());
        if (result.stderr) job.log.push(result.stderr.trim());
      } catch (err) {
        job.log.push('FAILED: ' + (err as Error).message);
        job.log.push('');
        job.log.push('Deploy aborted. Remaining steps were not executed.');
        job.status = 'failed';
        persistJob(job); // persist failed state
        return;
      }
      job.log.push('');
    }
    job.log.push('=== Deploy complete ===');
    job.status = 'success';
    persistJob(job); // persist success state
  })().catch(err => {
    job.log.push('Unexpected error: ' + (err as Error).message);
    job.status = 'failed';
  });

  return id;
}

// ─── Background Command Jobs ──────────────────────────────────────────────────
// For run_approved_command with run_in_background=true.
// spawn() streams output in real time; tool returns job_id immediately.
// Claude polls with get_job_status until status is success|failed.

function startBackgroundJob(command: string): string {
  const id = `job-${Date.now()}`;
  const job: BackgroundJob = {
    id,
    command,
    startedAt: new Date(),
    status:    'running',
    stdout:    '',
    stderr:    '',
    exitCode:  null,
  };
  bgJobs.set(id, job);

  const parts = command.trim().split(/\s+/);
  const [cmd, ...args] = parts;
  const child = spawn(cmd, args, { detached: false });

  child.stdout.on('data', (chunk: Buffer) => { job.stdout += chunk.toString(); });
  child.stderr.on('data', (chunk: Buffer) => { job.stderr += chunk.toString(); });
  child.on('close', (code: number | null) => {
    job.exitCode = code;
    job.status   = (code === 0) ? 'success' : 'failed';
  });
  child.on('error', (err: Error) => {
    job.stderr  += '\nProcess error: ' + err.message;
    job.status   = 'failed';
    job.exitCode = -1;
  });

  return id;
}

async function getJobStatus(jobId: string): Promise<string> {
  if (!jobId || !jobId.trim()) {
    if (bgJobs.size === 0) return 'No background jobs this session.';
    const list = [...bgJobs.values()]
      .sort((a, b) => b.startedAt.getTime() - a.startedAt.getTime())
      .map(j => {
        const elapsed = Math.round((Date.now() - j.startedAt.getTime()) / 1000);
        return `  ${j.id}  [${j.status}]  ${elapsed}s ago  "${j.command}"`;
      });
    return 'Background jobs this session:\n' + list.join('\n');
  }

  const job = bgJobs.get(jobId.trim());
  if (!job) {
    const ids = [...bgJobs.keys()].join(', ') || '(none)';
    return `No job found with id "${jobId}". Known job IDs: ${ids}`;
  }

  const elapsed = Math.round((Date.now() - job.startedAt.getTime()) / 1000);
  const combined = [job.stdout, job.stderr].filter(Boolean).join('\n');
  const lines = [
    `Job:     ${job.id}`,
    `Command: ${job.command}`,
    `Status:  ${job.status}`,
    `Elapsed: ${elapsed}s`,
    job.exitCode !== null ? `Exit:    ${job.exitCode}` : '',
    '',
    combined ? '--- Output ---\n' + combined : '(no output yet)',
  ].filter(l => l !== '').join('\n');

  return truncate(lines);
}


// ─── Output Safety ────────────────────────────────────────────────────────────

function truncate(output: string): string {
  if (output.length <= CONFIG.MAX_OUTPUT_CHARS) return output;
  return (
    output.slice(0, CONFIG.MAX_OUTPUT_CHARS) +
    `\n\n[TRUNCATED — ${output.length} chars total. Only first ${CONFIG.MAX_OUTPUT_CHARS} shown. Refine your query to narrow results.]`
  );
}

// ─── Type coercion helpers ────────────────────────────────────────────────────
// MCP frameworks sometimes serialise booleans/numbers as strings.
// These helpers normalise the value rather than relying on a bare type cast.

function parseBool(val: unknown, defaultVal: boolean): boolean {
  if (val === undefined || val === null) return defaultVal;
  if (typeof val === 'boolean') return val;
  if (typeof val === 'string') return val.toLowerCase() === 'true';
  return defaultVal;
}

function parseNum(val: unknown, defaultVal: number): number {
  if (val === undefined || val === null) return defaultVal;
  if (typeof val === 'number') return val;
  const n = Number(val);
  return isNaN(n) ? defaultVal : n;
}

// ─── Validators ───────────────────────────────────────────────────────────────

// Sensitive filenames and patterns blocked even inside ALLOWED_READ_DIRS.
// These contain credentials, keys, or secrets that must never be exposed via MCP.
const SENSITIVE_FILE_PATTERNS: RegExp[] = [
  /\.env($|\.)/i,                    // .env, .env.local, .env.production, etc.
  /\.ssh\//,                         // SSH keys
  /id_(rsa|ed25519|ecdsa|dsa)/,      // SSH key files by name
  /authorized_keys/,
  /known_hosts/,
  /\.pem$/i,                         // TLS/SSL private keys
  /\.key$/i,                         // Generic key files
  /\.p12$/i,                         // PKCS12 keystores
  /\.jks$/i,                         // Java keystores
  /credentials/i,                    // credentials.json, etc.
  /secrets?\.(json|ya?ml|toml)/i,    // secrets.json, secret.yaml
  /password/i,                       // password files
  /token/i,                          // token files (but not tokenize.js etc — path context matters)
  /\/etc\/shadow/,
  /\/etc\/sudoers/,
  /\/etc\/gshadow/,
  /\.htpasswd/,
  /\.netrc/,
  /\.pgpass/,
  /\.my\.cnf/,                       // MySQL credentials
  /\.docker\/config\.json/,          // Docker registry credentials
  /kubeconfig/i,                     // Kubernetes credentials
  /\.aws\//,                         // AWS credentials
  /\.gcloud\//,                      // GCP credentials
  /\.azure\//,                       // Azure credentials
];

function validatePath(filePath: string): string {
  const resolved = path.resolve(filePath);
  const allowed = ALLOWED_READ_DIRS.some(dir => {
    const d = path.resolve(dir);
    return resolved === d || resolved.startsWith(d + '/');
  });
  if (!allowed) {
    throw new Error(
      `Path not permitted: "${filePath}". Reads are restricted to: ${ALLOWED_READ_DIRS.join(', ')}`
    );
  }

  // Block sensitive files even within allowed directories
  for (const pattern of SENSITIVE_FILE_PATTERNS) {
    if (pattern.test(resolved)) {
      throw new Error(
        `⛔ BLOCKED: "${path.basename(filePath)}" matches a sensitive file pattern. ` +
        `Reading credential files, keys, tokens, or secrets via MCP is prohibited. ` +
        `Access these files directly on the server via SSH.`
      );
    }
  }

  return resolved;
}

function validateProcess(name: string): void {
  if (!CONFIG.ALLOWED_PROCESSES.includes(name)) {
    throw new Error(
      `Process not permitted: "${name}". Allowed processes: ${CONFIG.ALLOWED_PROCESSES.join(', ')}`
    );
  }
}

// ─── Three-Tier Command Security ─────────────────────────────────────────────
//
// RED   = Hard-blocked. Cannot be overridden. Command is rejected immediately.
// AMBER = Dangerous but sometimes legitimate. Forces dry_run=true on first call
//         and returns a ToS warning. User must explicitly re-call with dry_run=false.
// GREEN = Allowed (still subject to session cap and audit logging).
//
// Every command runs through RED first, then AMBER. If neither matches, it's GREEN.

// ── RED: Hard-blocked patterns (no override, no exceptions) ──────────────────
const BLOCKED_PATTERNS: Array<{ pattern: RegExp; category: string; reason: string }> = [
  // --- File destruction ---
  { pattern: /\brm\b/,                  category: 'file-delete',     reason: 'File deletion is prohibited. Use structured tools or SSH directly.' },
  { pattern: /\bunlink\b/,              category: 'file-delete',     reason: 'File deletion is prohibited.' },
  { pattern: /\bshred\b/,               category: 'file-delete',     reason: 'Secure file deletion is prohibited.' },
  { pattern: /\btruncate\b/,            category: 'file-delete',     reason: 'File truncation is prohibited.' },

  // --- Disk / filesystem ---
  { pattern: /\bdd\b/,                  category: 'disk-ops',        reason: 'Raw disk operations are prohibited.' },
  { pattern: /\bmkfs\b/,                category: 'disk-ops',        reason: 'Filesystem creation is prohibited.' },
  { pattern: /\bfdisk\b/,               category: 'disk-ops',        reason: 'Disk partitioning is prohibited.' },
  { pattern: /\bparted\b/,              category: 'disk-ops',        reason: 'Disk partitioning is prohibited.' },
  { pattern: /\bmount\b/,               category: 'disk-ops',        reason: 'Filesystem mount/unmount is prohibited.' },
  { pattern: /\bumount\b/,              category: 'disk-ops',        reason: 'Filesystem mount/unmount is prohibited.' },

  // --- System state ---
  { pattern: /\bshutdown\b/,            category: 'system-state',    reason: 'System shutdown is prohibited.' },
  { pattern: /\breboot\b/,              category: 'system-state',    reason: 'System reboot is prohibited. Use restart_process for PM2 processes.' },
  { pattern: /\bhalt\b/,                category: 'system-state',    reason: 'System halt is prohibited.' },
  { pattern: /\bpoweroff\b/,            category: 'system-state',    reason: 'System poweroff is prohibited.' },
  { pattern: /\binit\s+[0-6]\b/,        category: 'system-state',    reason: 'Runlevel changes are prohibited.' },

  // --- Process killing ---
  { pattern: /\bkill\b/,                category: 'process-kill',    reason: 'Process killing is prohibited. Use restart_process for PM2 processes.' },
  { pattern: /\bkillall\b/,             category: 'process-kill',    reason: 'Process killing is prohibited.' },
  { pattern: /\bpkill\b/,               category: 'process-kill',    reason: 'Process killing is prohibited.' },

  // --- User / permission management ---
  { pattern: /\buseradd\b/,             category: 'user-mgmt',       reason: 'User management is prohibited.' },
  { pattern: /\buserdel\b/,             category: 'user-mgmt',       reason: 'User management is prohibited.' },
  { pattern: /\badduser\b/,             category: 'user-mgmt',       reason: 'User management is prohibited.' },
  { pattern: /\bdeluser\b/,             category: 'user-mgmt',       reason: 'User management is prohibited.' },
  { pattern: /\bpasswd\b/,              category: 'user-mgmt',       reason: 'Password changes are prohibited.' },
  { pattern: /\bchmod\b/,               category: 'permissions',     reason: 'Permission changes are prohibited.' },
  { pattern: /\bchown\b/,               category: 'permissions',     reason: 'Ownership changes are prohibited.' },
  { pattern: /\bchgrp\b/,               category: 'permissions',     reason: 'Group ownership changes are prohibited.' },
  { pattern: /\bsetfacl\b/,             category: 'permissions',     reason: 'ACL modifications are prohibited.' },

  // --- Firewall / network config ---
  { pattern: /\biptables\b/,            category: 'network-config',  reason: 'Firewall changes are prohibited.' },
  { pattern: /\bip6tables\b/,           category: 'network-config',  reason: 'Firewall changes are prohibited.' },
  { pattern: /\bufw\b/,                 category: 'network-config',  reason: 'Firewall changes are prohibited.' },
  { pattern: /\bnft\b/,                 category: 'network-config',  reason: 'Nftables changes are prohibited.' },
  { pattern: /\bifconfig\b.*\b(up|down)\b/, category: 'network-config', reason: 'Network interface changes are prohibited.' },
  { pattern: /\bip\s+(link|addr|route)\s+(add|del|set)/, category: 'network-config', reason: 'Network config changes are prohibited.' },

  // --- Scheduled execution ---
  { pattern: /\bcrontab\b/,             category: 'scheduled-exec',  reason: 'Cron job modification is prohibited.' },
  { pattern: /\bat\b\s/,                category: 'scheduled-exec',  reason: 'Scheduled command execution is prohibited.' },

  // --- Service management ---
  { pattern: /\bsystemctl\b/,           category: 'service-mgmt',    reason: 'Service management is prohibited. Use restart_process for PM2 processes.' },
  { pattern: /\bservice\b/,             category: 'service-mgmt',    reason: 'Service management is prohibited.' },

  // --- Code execution bypasses ---
  { pattern: /\bnode\s+(-e\b|--eval\b)/,    category: 'code-exec',  reason: 'Inline code execution is prohibited.' },
  { pattern: /\bpython[\d.]*\s+-c\b/,       category: 'code-exec',  reason: 'Inline code execution is prohibited.' },
  { pattern: /\bperl\s+-e\b/,               category: 'code-exec',  reason: 'Inline code execution is prohibited.' },
  { pattern: /\bruby\s+-e\b/,               category: 'code-exec',  reason: 'Inline code execution is prohibited.' },
  { pattern: /\bphp\s+-r\b/,                category: 'code-exec',  reason: 'Inline code execution is prohibited.' },
  { pattern: /\beval\b/,                    category: 'code-exec',  reason: 'Eval is prohibited.' },

  // --- Shell invocation ---
  { pattern: /\|\s*(sh|bash|zsh|fish|dash|ksh|csh)\b/, category: 'shell-invoke', reason: 'Piping to shell is prohibited.' },
  { pattern: /\b(bash|sh|zsh|fish|csh|ksh|dash)\s+-c\b/, category: 'shell-invoke', reason: 'Shell invocation with -c is prohibited.' },
  { pattern: /`[^`]*`/,                     category: 'shell-invoke', reason: 'Backtick subshells are prohibited.' },
  { pattern: /\$\([^)]*\)/,                 category: 'shell-invoke', reason: '$() subshells are prohibited.' },

  // --- Data exfiltration (outbound network) ---
  { pattern: /\bcurl\b/,                category: 'data-exfil',      reason: 'curl is prohibited. Data cannot leave the server via MCP.' },
  { pattern: /\bwget\b/,                category: 'data-exfil',      reason: 'wget is prohibited. Data cannot leave the server via MCP.' },
  { pattern: /\bnc\b/,                  category: 'data-exfil',      reason: 'netcat is prohibited.' },
  { pattern: /\bncat\b/,                category: 'data-exfil',      reason: 'ncat is prohibited.' },
  { pattern: /\bnetcat\b/,              category: 'data-exfil',      reason: 'netcat is prohibited.' },
  { pattern: /\bsocat\b/,               category: 'data-exfil',      reason: 'socat is prohibited.' },
  { pattern: /\bssh\b/,                 category: 'data-exfil',      reason: 'Outbound SSH is prohibited.' },
  { pattern: /\bscp\b/,                 category: 'data-exfil',      reason: 'Outbound SCP is prohibited.' },
  { pattern: /\brsync\b/,               category: 'data-exfil',      reason: 'rsync is prohibited.' },
  { pattern: /\bftp\b/,                 category: 'data-exfil',      reason: 'FTP is prohibited.' },
  { pattern: /\bsftp\b/,                category: 'data-exfil',      reason: 'SFTP is prohibited.' },

  // --- Reverse shell / persistence ---
  { pattern: /\bnohup\b/,               category: 'persistence',     reason: 'Background process persistence is prohibited.' },
  { pattern: /\bdisown\b/,              category: 'persistence',     reason: 'Process disown is prohibited.' },
  { pattern: /\bscreen\b/,              category: 'persistence',     reason: 'Screen sessions are prohibited.' },
  { pattern: /\btmux\b/,                category: 'persistence',     reason: 'Tmux sessions are prohibited.' },

  // --- Direct DB access ---
  { pattern: /\bpsql\b/,                category: 'direct-db',       reason: 'Direct database access is prohibited. Use structured query tools.' },
  { pattern: /\bmysql\b/,               category: 'direct-db',       reason: 'Direct database access is prohibited.' },
  { pattern: /\bmongo\b/,               category: 'direct-db',       reason: 'Direct database access is prohibited.' },
  { pattern: /\bredis-cli\b/,           category: 'direct-db',       reason: 'Direct database access is prohibited.' },
  { pattern: /\bsqlite3\b/,             category: 'direct-db',       reason: 'Direct database access is prohibited.' },

  // --- Package installation (arbitrary code via install scripts) ---
  { pattern: /\bapt-get\s+install\b/,   category: 'pkg-install',     reason: 'Package installation is prohibited (postinst scripts can execute arbitrary code).' },
  { pattern: /\bapt\s+install\b/,       category: 'pkg-install',     reason: 'Package installation is prohibited.' },
  { pattern: /\bdpkg\s+-i\b/,           category: 'pkg-install',     reason: 'Package installation is prohibited.' },
  { pattern: /\byum\s+install\b/,       category: 'pkg-install',     reason: 'Package installation is prohibited.' },
  { pattern: /\bdnf\s+install\b/,       category: 'pkg-install',     reason: 'Package installation is prohibited.' },
  { pattern: /\bpip\s+install\b/,       category: 'pkg-install',     reason: 'pip install is prohibited (arbitrary code execution via setup.py).' },
  { pattern: /\bnpm\s+install\b/,       category: 'pkg-install',     reason: 'npm install is prohibited (arbitrary code execution via install scripts). Use the deploy tool.' },
  { pattern: /\bnpx\b/,                 category: 'pkg-install',     reason: 'npx is prohibited (remote code execution).' },
  { pattern: /\bapt-get\s+remove\b/,    category: 'pkg-remove',      reason: 'Package removal is prohibited.' },
  { pattern: /\bapt-get\s+purge\b/,     category: 'pkg-remove',      reason: 'Package purge is prohibited.' },
  { pattern: /\bapt\s+remove\b/,        category: 'pkg-remove',      reason: 'Package removal is prohibited.' },

  // --- Container escape ---
  { pattern: /\bdocker\b/,              category: 'container',        reason: 'Docker commands are prohibited.' },
  { pattern: /\bpodman\b/,              category: 'container',        reason: 'Podman commands are prohibited.' },
  { pattern: /\bkubectl\b/,             category: 'container',        reason: 'kubectl commands are prohibited.' },

  // --- Write-path attacks ---
  { pattern: />\s*\//,                  category: 'file-write',       reason: 'Redirect to absolute path is prohibited.' },
  { pattern: />\s*~/,                   category: 'file-write',       reason: 'Redirect to home directory is prohibited.' },
  { pattern: />>/,                      category: 'file-write',       reason: 'Append redirect is prohibited.' },
  { pattern: /\btee\b/,                 category: 'file-write',       reason: 'tee (file write) is prohibited.' },
  { pattern: /\bln\s+-s/,              category: 'file-write',       reason: 'Symlink creation is prohibited.' },
  { pattern: /\bcp\b.*\/(etc|root|bin|sbin|usr|var)\//,  category: 'file-write', reason: 'Copying to system directories is prohibited.' },
  { pattern: /\bmv\b.*\/(etc|root|bin|sbin|usr|var)\//,  category: 'file-write', reason: 'Moving to system directories is prohibited.' },

  // --- Environment manipulation ---
  { pattern: /\bexport\b/,              category: 'env-manip',        reason: 'Environment variable export is prohibited.' },
  { pattern: /\bsource\b/,              category: 'env-manip',        reason: 'Sourcing files is prohibited.' },
  { pattern: /\b\.\s+\//,               category: 'env-manip',        reason: 'Sourcing files is prohibited.' },

  // --- Privilege escalation ---
  { pattern: /\bsudo\b/,                category: 'priv-esc',         reason: 'sudo is prohibited.' },
  { pattern: /\bsu\b\s/,                category: 'priv-esc',         reason: 'su (switch user) is prohibited.' },
  { pattern: /\bpkexec\b/,              category: 'priv-esc',         reason: 'pkexec is prohibited.' },
  { pattern: /\bdoas\b/,                category: 'priv-esc',         reason: 'doas is prohibited.' },

  // --- History / info leakage ---
  { pattern: /\bhistory\b/,             category: 'info-leak',        reason: 'Command history access is prohibited.' },
  { pattern: /\bcat\b.*\/etc\/shadow/,  category: 'info-leak',        reason: 'Shadow file access is prohibited.' },
  { pattern: /\bcat\b.*\/etc\/passwd/,  category: 'info-leak',        reason: 'Passwd file access is prohibited.' },
  { pattern: /\bcat\b.*\.env/,          category: 'info-leak',        reason: 'Reading .env files via commands is prohibited. Credential exposure risk.' },
  { pattern: /\bcat\b.*\.ssh/,          category: 'info-leak',        reason: 'Reading SSH keys via commands is prohibited.' },
  { pattern: /\bprintenv\b/,            category: 'info-leak',        reason: 'Environment variable dumping is prohibited.' },
  { pattern: /\benv\b$/,                category: 'info-leak',        reason: 'Environment variable dumping is prohibited.' },
  { pattern: /\/proc\//,                category: 'info-leak',        reason: '/proc filesystem access is prohibited. /proc/self/environ exposes all env vars including secrets.' },

  // Read utilities — blocked to prevent sensitive file exfiltration via non-cat paths
  { pattern: /\bhead\b.*\.env/,         category: 'info-leak',        reason: 'Reading .env files is prohibited.' },
  { pattern: /\btail\b.*\.env/,         category: 'info-leak',        reason: 'Reading .env files is prohibited.' },
  { pattern: /\bhead\b.*\/etc\//,       category: 'info-leak',        reason: 'Reading /etc system files is prohibited.' },
  { pattern: /\btail\b.*\/etc\//,       category: 'info-leak',        reason: 'Reading /etc system files is prohibited.' },
  { pattern: /\bstrings\b/,             category: 'info-leak',        reason: 'strings command is prohibited (binary secret extraction).' },
  { pattern: /\bhexdump\b/,             category: 'info-leak',        reason: 'hexdump is prohibited (binary secret extraction).' },
  { pattern: /\bxxd\b/,                 category: 'info-leak',        reason: 'xxd is prohibited (binary secret extraction).' },
  { pattern: /\bod\b\s/,                category: 'info-leak',        reason: 'od (octal dump) is prohibited (binary secret extraction).' },

  // --- Command chaining / sequencing ---
  { pattern: /;/,                        category: 'chaining',        reason: 'Command chaining with ; is prohibited.' },
  { pattern: /&&/,                       category: 'chaining',        reason: 'Command chaining with && is prohibited.' },
  { pattern: /\|\|/,                     category: 'chaining',        reason: 'Command chaining with || is prohibited.' },

  // --- HTTP server (exposes files) ---
  { pattern: /\bpython[\d.]*\s+-m\s+http/,  category: 'http-server', reason: 'Starting an HTTP server is prohibited.' },
  { pattern: /\bphp\s+-S\b/,                category: 'http-server', reason: 'Starting an HTTP server is prohibited.' },
];

// ── AMBER: Warning-tier patterns ─────────────────────────────────────────────
// These commands are sometimes legitimate but carry risk. When matched:
// - dry_run is forced to true
// - A structured warning is returned with the command, risk, and ToS notice
// - The user must re-call with dry_run=false to execute

interface AmberWarning { pattern: RegExp; risk: string; }
const AMBER_PATTERNS: AmberWarning[] = [
  { pattern: /\bapt-get\s+update\b/,    risk: 'Package index update. Safe but slow — may timeout the SSE connection. Use run_in_background=true.' },
  { pattern: /\bfind\b.*-exec\b/,       risk: 'find -exec can execute commands on matched files. Ensure the -exec payload is safe.' },
  { pattern: /\bxargs\b/,               risk: 'xargs pipes input as arguments to another command. Ensure the target command is safe.' },
  { pattern: /\bawk\b/,                 risk: 'awk can write files and execute shell commands via system(). Ensure the script is safe.' },
  { pattern: /\bsed\s+-i/,              risk: 'sed -i modifies files in-place. This cannot be undone. Ensure the pattern and target are correct.' },
];

function validateCommand(command: string): void {
  // Non-ASCII check — blocks Unicode homoglyph bypasses (e.g. ｒｍ, ｃｕｒｌ)
  if (/[^\x00-\x7F]/.test(command)) {
    throw new Error(
      `⛔ BLOCKED [unicode]: Non-ASCII characters are not permitted in commands.\n` +
      `Command: ${command}\n` +
      `This restriction cannot be overridden. Run this command directly on the server via SSH.\n` +
      `Attempting to circumvent security controls violates the Terms of Service.`
    );
  }

  // Newline / carriage-return check — blocks newline injection bypasses
  if (/[\r\n]/.test(command)) {
    throw new Error(
      `⛔ BLOCKED [newline-inject]: Newline or carriage-return characters are not permitted in commands.\n` +
      `Command: ${JSON.stringify(command)}\n` +
      `This restriction cannot be overridden. Run this command directly on the server via SSH.\n` +
      `Attempting to circumvent security controls violates the Terms of Service.`
    );
  }

  // RED tier — hard block
  for (const { pattern, category, reason } of BLOCKED_PATTERNS) {
    if (pattern.test(command)) {
      throw new Error(
        `⛔ BLOCKED [${category}]: ${reason}\n` +
        `Command: ${command}\n` +
        `This restriction cannot be overridden. Run this command directly on the server via SSH.\n` +
        `Attempting to circumvent security controls violates the Terms of Service.`
      );
    }
  }
}

function checkAmberWarnings(command: string, dryRun: boolean): string | null {
  for (const { pattern, risk } of AMBER_PATTERNS) {
    if (pattern.test(command)) {
      if (dryRun) {
        return (
          `⚠️  WARNING — This command requires explicit confirmation.\n` +
          `Command: ${command}\n` +
          `Risk: ${risk}\n` +
          `\n` +
          `By proceeding with dry_run=false you acknowledge:\n` +
          `  • You understand the risk described above\n` +
          `  • You accept responsibility for the outcome\n` +
          `  • Misuse may violate the Terms of Service\n` +
          `\n` +
          `Call again with dry_run=false to execute.`
        );
      }
      // If dry_run=false, let it through (user confirmed)
      return null;
    }
  }
  return null;
}

// ─── Tool Implementations ─────────────────────────────────────────────────────

async function getPm2Status(): Promise<string> {
  const { stdout } = await exec('pm2', ['jlist']);

  interface Pm2Process {
    name: string;
    pm2_env: { status: string; restart_time: number; pm_uptime: number };
    monit: { memory: number; cpu: number };
  }

  const processes = JSON.parse(stdout) as Pm2Process[];
  const rows = processes.map(p => ({
    name:     p.name,
    status:   p.pm2_env.status,
    restarts: p.pm2_env.restart_time,
    memory:   `${Math.round(p.monit.memory / 1024 / 1024)}MB`,
    cpu:      `${p.monit.cpu}%`,
    uptime:   p.pm2_env.pm_uptime
      ? new Date(p.pm2_env.pm_uptime).toISOString()
      : 'n/a',
  }));
  return JSON.stringify(rows, null, 2);
}

async function getRecentErrors(processName: string, lines: number): Promise<string> {
  validateProcess(processName);
  const cappedLines = Math.min(Math.max(1, lines), CONFIG.MAX_LOG_LINES);
  const logPath = path.join(CONFIG.PM2_LOG_DIR, `${processName}-error.log`);

  if (!fs.existsSync(logPath)) {
    return `No error log at ${logPath}. The process may not have produced errors yet, or the log path differs on this system.`;
  }

  const { stdout } = await exec('tail', ['-n', String(cappedLines), logPath]);
  const result = stdout.trim();
  return truncate(result || `[No content in last ${cappedLines} lines of ${logPath}]`);
}

async function readFileSection(
  filePath: string,
  startLine: number,
  endLine: number
): Promise<string> {
  const safePath = validatePath(filePath);

  // Cap range
  const clampedEnd = Math.min(endLine, startLine + CONFIG.MAX_FILE_LINES - 1);

  const content = fs.readFileSync(safePath, 'utf8');
  const lines = content.split('\n');
  const totalLines = lines.length;

  if (startLine < 1 || startLine > totalLines) {
    throw new Error(`start_line ${startLine} is out of range. File has ${totalLines} lines.`);
  }

  const slice = lines.slice(startLine - 1, clampedEnd);
  const header = `Lines ${startLine}–${Math.min(clampedEnd, totalLines)} of ${totalLines} total in ${path.basename(safePath)}:\n\n`;
  const body = slice.map((l, i) => `${startLine + i}: ${l}`).join('\n');

  return truncate(header + body);
}

async function searchFile(
  filePath: string,
  pattern: string,
  contextLines: number
): Promise<string> {
  const safePath = validatePath(filePath);
  const ctx = Math.min(Math.max(0, contextLines), 10);

  try {
    const { stdout } = await exec('grep', [
      '-n',
      `-A${ctx}`,
      `-B${ctx}`,
      pattern,
      safePath,
    ]);
    return truncate(stdout.trim() || 'No matches found.');
  } catch (err) {
    const e = err as { code?: number };
    if (e.code === 1) return `No matches found for pattern "${pattern}" in ${path.basename(safePath)}.`;
    throw err;
  }
}

async function gitStatus(): Promise<string> {
  const { stdout } = await exec('git', ['-C', CONFIG.APP_DIR, 'status']);
  return stdout.trim();
}

async function gitLog(count: number): Promise<string> {
  const n = Math.min(Math.max(1, count), 20);
  const { stdout } = await exec('git', ['-C', CONFIG.APP_DIR, 'log', '--oneline', `-${n}`]);
  return stdout.trim();
}

async function gitPull(dryRun: boolean, directory?: string): Promise<string> {
  const dir = directory?.trim() || CONFIG.APP_DIR;
  if (dryRun) {
    return [
      'DRY RUN — nothing executed.',
      'Would run: git pull origin main',
      `Working directory: ${dir}`,
      'Call with dry_run=false to execute.',
    ].join('\n');
  }
  const { stdout, stderr } = await exec('git', ['-C', dir, 'pull', 'origin', 'main']);
  return [stdout, stderr].filter(Boolean).join('\n').trim();
}

async function gitPush(dryRun: boolean, description: string): Promise<string> {
  if (dryRun) {
    return [
      'DRY RUN — nothing executed.',
      'Would run: git push origin main',
      `Working directory: ${CONFIG.APP_DIR}`,
      'Call with dry_run=false and a description to execute.',
    ].join('\n');
  }
  if (!description || description.trim().length < 5) {
    throw new Error('description is required (min 5 chars) when dry_run=false. Describe what is being pushed.');
  }
  const { stdout, stderr } = await exec('git', ['-C', CONFIG.APP_DIR, 'push', 'origin', 'main']);
  return [stdout, stderr].filter(Boolean).join('\n').trim();
}

async function restartProcess(processName: string, dryRun: boolean): Promise<string> {
  validateProcess(processName);
  if (dryRun) {
    return [
      'DRY RUN — nothing executed.',
      `Would run: pm2 restart ${processName}`,
      'This causes ~5 seconds of downtime for this process only.',
      'Call with dry_run=false to execute.',
    ].join('\n');
  }
  const { stdout } = await exec('pm2', ['restart', processName]);
  return stdout.trim() || `Process "${processName}" restarted successfully.`;
}

async function getSystemHealth(): Promise<string> {
  const [disk, memory, uptime] = await Promise.all([
    exec('df', ['-h', '/']),
    exec('free', ['-m']),
    exec('uptime', []),
  ]);
  return [
    '=== DISK ===', disk.stdout.trim(),
    '\n=== MEMORY (MB) ===', memory.stdout.trim(),
    '\n=== UPTIME ===', uptime.stdout.trim(),
  ].join('\n');
}

// Default timeout for synchronous commands (30 seconds). Prevents hung sessions.
const COMMAND_TIMEOUT_MS = 30_000;

async function runApprovedCommand(
  command: string,
  justification: string,
  dryRun: boolean,
  runInBackground: boolean
): Promise<string> {
  // RED tier — hard block (throws on match)
  validateCommand(command);

  if (!justification || justification.trim().length < 10) {
    throw new Error('justification must be at least 10 characters explaining why structured tools are insufficient.');
  }

  // AMBER tier — warning system
  const amberWarning = checkAmberWarnings(command, dryRun);
  if (amberWarning) return amberWarning;

  if (dryRun) {
    return [
      'DRY RUN — nothing executed.',
      `Would run: ${command}`,
      `Justification: ${justification}`,
      runInBackground
        ? 'Mode: background job (returns job_id immediately; poll with get_job_status)'
        : 'Mode: synchronous (waits for completion, 30s timeout)',
      `Session usage: ${customCommandCount}/${CONFIG.MAX_CUSTOM_COMMANDS_PER_SESSION} custom commands used.`,
      'Call with dry_run=false to execute.',
    ].join('\n');
  }

  // Pre-check: reject before executing — limit reached commands never run and never cost quota
  if (customCommandCount >= CONFIG.MAX_CUSTOM_COMMANDS_PER_SESSION) {
    throw new Error(
      `Custom command session limit (${CONFIG.MAX_CUSTOM_COMMANDS_PER_SESSION}) reached. ` +
      `Use structured tools, or ask the user to run this command manually.`
    );
  }

  // Increment before branching — both sync and async paths consume one quota slot
  customCommandCount++;

  if (runInBackground) {
    const jobId = startBackgroundJob(command);
    return [
      `Background job started: ${jobId}`,
      `Command: ${command}`,
      '',
      `Use get_job_status with job_id="${jobId}" to poll for output.`,
      'Typical poll interval: 15–30s for long commands.',
    ].join('\n');
  }

  const parts = command.trim().split(/\s+/);
  const [cmd, ...args] = parts;
  try {
    const { stdout, stderr } = await exec(cmd, args, { timeout: COMMAND_TIMEOUT_MS });
    const output = [stdout, stderr].filter(Boolean).join('\n');
    return truncate(output.trim() || '[Command completed with no output]');
  } catch (err) {
    const e = err as Error & { killed?: boolean; signal?: string };
    if (e.killed || e.signal === 'SIGTERM') {
      throw new Error(
        `Command timed out after ${COMMAND_TIMEOUT_MS / 1000}s and was killed. ` +
        `For long-running commands, use run_in_background=true.`
      );
    }
    throw err;
  }
}

// ─── Deploy Tools ──────────────────────────────────────────────────────────────────

async function deploySharpEdge(dryRun: boolean, description: string): Promise<string> {
  if (!description || description.trim().length < 5) {
    throw new Error('description is required (min 5 chars) — describe what is being deployed.');
  }

  const apiServerDir = path.join(CONFIG.APP_DIR, 'artifacts', 'api-server');

  const steps: Array<{ label: string; cmd: string; args: string[]; cwd?: string }> = [
    { label: 'git pull origin main', cmd: 'git',  args: ['-C', CONFIG.APP_DIR, 'pull', 'origin', 'main'] },
    { label: 'pnpm install',         cmd: 'pnpm', args: ['install'],     cwd: CONFIG.APP_DIR            },
    { label: 'node build.mjs',       cmd: 'node', args: ['build.mjs'],   cwd: apiServerDir              },
    { label: 'pm2 restart all',      cmd: 'pm2',  args: ['restart', 'all']                              },
    { label: 'pm2 status',           cmd: 'pm2',  args: ['status']                                      },
  ];

  if (dryRun) {
    const stepList = steps.map((s, i) =>
      '  ' + (i + 1) + '. ' + s.label + (s.cwd ? ' (cwd: ' + s.cwd + ')' : '')
    ).join('\n');
    return [
      'DRY RUN — nothing executed.',
      'Description: ' + description,
      '',
      'Would run the following deploy sequence:',
      stepList,
      '',
      'Call with dry_run=false to execute.',
    ].join('\n');
  }

  const jobId = startDeployJob('sharpedge', description, steps);
  const stepList = steps.map((s, i) => '  ' + (i + 1) + '. ' + s.label).join('\n');
  return [
    'Deploy job started: ' + jobId,
    'Description: ' + description,
    '',
    'Steps running in background:',
    stepList,
    '',
    'Use get_deploy_status with job_id="' + jobId + '" to check progress.',
    'Typical deploy takes 90–150 seconds.',
  ].join('\n');
}

async function deployVpsMcp(dryRun: boolean, description: string): Promise<string> {
  if (!description || description.trim().length < 5) {
    throw new Error('description is required (min 5 chars) — describe what is being deployed.');
  }

  const VPS_MCP_DIR = '/root/vps-control-mcp';

  const steps: Array<{ label: string; cmd: string; args: string[]; cwd?: string }> = [
    { label: 'git pull origin main', cmd: 'git', args: ['-C', VPS_MCP_DIR, 'pull', 'origin', 'main'] },
    { label: 'npm install --include=dev', cmd: 'npm', args: ['install', '--include=dev'], cwd: VPS_MCP_DIR },
    { label: 'npm run build',        cmd: 'npm', args: ['run', 'build'],  cwd: VPS_MCP_DIR            },
    { label: 'pm2 restart vps-mcp', cmd: 'pm2', args: ['restart', 'vps-mcp']                         },
    { label: 'pm2 status',           cmd: 'pm2', args: ['status']                                     },
  ];

  if (dryRun) {
    const stepList = steps.map((s, i) =>
      '  ' + (i + 1) + '. ' + s.label + (s.cwd ? ' (cwd: ' + s.cwd + ')' : '')
    ).join('\n');
    return [
      'DRY RUN — nothing executed.',
      'Description: ' + description,
      '',
      'Would run the following deploy sequence:',
      stepList,
      '',
      'Call with dry_run=false to execute.',
    ].join('\n');
  }

  const jobId = startDeployJob('vps-mcp', description, steps);
  const stepList = steps.map((s, i) => '  ' + (i + 1) + '. ' + s.label).join('\n');
  return [
    'Deploy job started: ' + jobId,
    'Description: ' + description,
    '',
    'Steps running in background:',
    stepList,
    '',
    'Use get_deploy_status with job_id="' + jobId + '" to check progress.',
    'Typical deploy takes 60–90 seconds.',
  ].join('\n');
}

async function getDeployStatus(jobId: string): Promise<string> {
  if (!jobId || !jobId.trim()) {
    // List all jobs if no ID given
    if (deployJobs.size === 0) return 'No deploy jobs this session.';
    const list = [...deployJobs.values()]
      .sort((a, b) => b.startedAt.getTime() - a.startedAt.getTime())
      .map(j => {
        const elapsed = Math.round((Date.now() - j.startedAt.getTime()) / 1000);
        return `  ${j.id}  [${j.status}]  ${j.type}  ${elapsed}s ago  "${j.description}"`;
      });
    return 'Deploy jobs this session:\n' + list.join('\n');
  }

  const job = deployJobs.get(jobId.trim()) ?? loadJobFromFile(jobId.trim());
  const fromFile  = !deployJobs.has(jobId.trim()) && !!job;
  if (!job) {
    const ids = [...deployJobs.keys()].join(', ') || '(none)';
    return `No job found with id "${jobId}". Known job IDs: ${ids}`;
  }

  const elapsed = Math.round((Date.now() - job.startedAt.getTime()) / 1000);
  const selfRestartNote = fromFile
    ? '\n[Recovered from file — vps-mcp restarted during this deploy, which is expected for deploy_vps_mcp.]\n'
    : '';

  const lines = [
    `Job:         ${job.id}`,
    `Type:        ${job.type}`,
    `Description: ${job.description}`,
    `Status:      ${job.status}`,
    `Elapsed:     ${elapsed}s`,
    selfRestartNote,
    '--- Log ---',
    ...job.log,
  ].join('\n');

  return truncate(lines);
}

export const TOOLS = [
  {
    name: 'get_pm2_status',
    description: 'Get status of all PM2 processes — name, status, restarts, memory, CPU, uptime. Always safe, no side effects.',
    inputSchema: { type: 'object', properties: {}, required: [] as string[] },
  },
  {
    name: 'get_recent_errors',
    description: `Read error log for a PM2 process. Hard capped at ${CONFIG.MAX_LOG_LINES} lines and ${CONFIG.MAX_OUTPUT_CHARS} chars. Returns errors only.`,
    inputSchema: {
      type: 'object',
      properties: {
        process_name: {
          type: 'string',
          description: `Which process to read. Allowed: ${CONFIG.ALLOWED_PROCESSES.join(', ')}`,
        },
        lines: {
          description: `Lines to retrieve. Default 20. Hard max ${CONFIG.MAX_LOG_LINES}.`,
        },
      },
      required: ['process_name'],
    },
  },
  {
    name: 'read_file_section',
    description: `Read a line range from a file. Max ${CONFIG.MAX_FILE_LINES} lines per call. Must be within allowed directories.`,
    inputSchema: {
      type: 'object',
      properties: {
        file_path:  { type: 'string', description: 'Absolute path to file.' },
        start_line: { type: 'number', description: 'First line to read (1-indexed).' },
        end_line:   { type: 'number', description: 'Last line to read (inclusive).' },
      },
      required: ['file_path', 'start_line', 'end_line'],
    },
  },
  {
    name: 'search_file',
    description: `Search a file for a pattern. Returns matching lines with context. Output capped at ${CONFIG.MAX_OUTPUT_CHARS} chars.`,
    inputSchema: {
      type: 'object',
      properties: {
        file_path:     { type: 'string', description: 'Absolute path to file.' },
        pattern:       { type: 'string', description: 'Regex or literal pattern to search for.' },
        context_lines: { type: 'number', description: 'Lines of context before/after each match. Default 3, max 10.' },
      },
      required: ['file_path', 'pattern'],
    },
  },
  {
    name: 'git_status',
    description: 'Run git status in the app directory. Read-only, no side effects.',
    inputSchema: { type: 'object', properties: {}, required: [] as string[] },
  },
  {
    name: 'git_log',
    description: 'Show recent git commit history. Read-only, no side effects.',
    inputSchema: {
      type: 'object',
      properties: {
        count: { type: 'number', description: 'Commits to show. Default 10, max 20.' },
      },
      required: [] as string[],
    },
  },
  {
    name: 'git_pull',
    description: 'Pull latest from origin main. Always use dry_run=true first to preview. Requires dry_run=false to execute.',
    inputSchema: {
      type: 'object',
      properties: {
        dry_run:   { description: 'Default true. Set false only after previewing.' },
        directory: { type: 'string', description: `Optional. Absolute path to repo. Defaults to ${CONFIG.APP_DIR}.` },
      },
      required: [] as string[],
    },
  },
  {
    name: 'git_push',
    description: 'Push committed changes to origin main. Requires description when executing. Always dry_run=true first.',
    inputSchema: {
      type: 'object',
      properties: {
        dry_run: { description: 'Default true. Set false only after previewing.' },
        description: { type: 'string',  description: 'Required when dry_run=false. What is being pushed and why.' },
      },
      required: [] as string[],
    },
  },
  {
    name: 'restart_process',
    description: 'Restart a specific PM2 process. Always dry_run=true first to preview impact.',
    inputSchema: {
      type: 'object',
      properties: {
        process_name: {
          type: 'string',
          description: `Process to restart. Allowed: ${CONFIG.ALLOWED_PROCESSES.join(', ')}`,
        },
        dry_run: { description: 'Default true. Set false only after previewing.' },
      },
      required: ['process_name'],
    },
  },
  {
    name: 'get_system_health',
    description: 'Get disk usage, memory, and system uptime. Read-only, no side effects.',
    inputSchema: { type: 'object', properties: {}, required: [] as string[] },
  },
  {
    name: 'run_approved_command',
    description: `Escape hatch for edge cases not covered by structured tools. Hard-blocked patterns enforced. Limited to ${CONFIG.MAX_CUSTOM_COMMANDS_PER_SESSION} uses per session. Always dry_run=true first.`,
    inputSchema: {
      type: 'object',
      properties: {
        command:           { type: 'string',  description: 'Command to run. Destructive patterns are blocked server-side.' },
        justification:     { type: 'string',  description: 'Why structured tools cannot cover this. Min 10 chars.' },
        dry_run:           { description: 'Default true. Set false only after previewing.' },
        run_in_background: { type: 'boolean', description: 'Default false. Set true for commands that take >30s (apt-get, npm install, etc.). Returns a job_id immediately; poll with get_job_status.' },
      },
      required: ['command', 'justification'],
    },
  },
  {
    name: 'get_job_status',
    description: 'Check the status and output of a background command job started by run_approved_command with run_in_background=true. Omit job_id to list all jobs this session.',
    inputSchema: {
      type: 'object',
      properties: {
        job_id: { type: 'string', description: 'Job ID returned by run_approved_command. Omit to list all jobs.' },
      },
      required: [] as string[],
    },
  },
  {
    name: 'deploy',
    description: 'Run the full SharpEdge deploy sequence: git pull → pnpm install → node build.mjs → pm2 restart all → pm2 status. Always dry_run=true first to preview.',
    inputSchema: {
      type: 'object',
      properties: {
        dry_run: { description: 'Default true. Set false only after previewing the sequence.' },
        description: { type: 'string',  description: 'Required. What is being deployed and why.' },
      },
      required: ['description'] as string[],
    },
  },
  {
    name: 'deploy_vps_mcp',
    description: 'Run the full vps-control-mcp deploy sequence: git pull → npm install → npm run build → pm2 restart vps-mcp → pm2 status. Always dry_run=true first to preview.',
    inputSchema: {
      type: 'object',
      properties: {
        dry_run: { description: 'Default true. Set false only after previewing the sequence.' },
        description: { type: 'string',  description: 'Required. What is being deployed and why.' },
      },
      required: ['description'] as string[],
    },
  },
  {
    name: 'get_deploy_status',
    description: 'Check the status and log of a background deploy job started by deploy or deploy_vps_mcp. Pass job_id from the deploy response. Omit job_id to list all jobs this session.',
    inputSchema: {
      type: 'object',
      properties: {
        job_id: { type: 'string', description: 'Job ID returned by deploy or deploy_vps_mcp. Omit to list all jobs.' },
      },
      required: [] as string[],
    },
  },
];

// ─── Dispatcher ───────────────────────────────────────────────────────────────

export async function executeTool(
  name: string,
  args: Record<string, unknown>
): Promise<string> {
  try {
    switch (name) {
      case 'get_pm2_status':
        return await getPm2Status();

      case 'get_recent_errors':
        return await getRecentErrors(
          args.process_name as string,
          parseNum(args.lines, 20)
        );

      case 'read_file_section':
        return await readFileSection(
          args.file_path as string,
          parseNum(args.start_line, 1),
          parseNum(args.end_line, 1)
        );

      case 'search_file':
        return await searchFile(
          args.file_path as string,
          args.pattern as string,
          parseNum(args.context_lines, 3)
        );

      case 'git_status':
        return await gitStatus();

      case 'git_log':
        return await gitLog(parseNum(args.count, 10));

      case 'git_pull':
        return await gitPull(parseBool(args.dry_run, true), args.directory as string | undefined);

      case 'git_push':
        return await gitPush(
          parseBool(args.dry_run, true),
          (args.description as string) ?? ''
        );

      case 'restart_process':
        return await restartProcess(
          args.process_name as string,
          parseBool(args.dry_run, true)
        );

      case 'get_system_health':
        return await getSystemHealth();

      case 'run_approved_command':
        return await runApprovedCommand(
          args.command as string,
          args.justification as string,
          parseBool(args.dry_run, true),
          parseBool(args.run_in_background, false)
        );

      case 'get_job_status':
        return await getJobStatus((args.job_id as string) ?? '');

      case 'deploy':
        return await deploySharpEdge(
          parseBool(args.dry_run, true),
          (args.description as string) ?? ''
        );

      case 'deploy_vps_mcp':
        return await deployVpsMcp(
          parseBool(args.dry_run, true),
          (args.description as string) ?? ''
        );

      case 'get_deploy_status':
        return await getDeployStatus((args.job_id as string) ?? '');

      default:
        return `Unknown tool: "${name}". Available tools: ${TOOLS.map(t => t.name).join(', ')}`;
    }
  } catch (err) {
    const e = err as Error;
    return `ERROR [${name}]: ${e.message}`;
  }
}
