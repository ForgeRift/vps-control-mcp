import { execFile } from 'child_process';
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
    id, type, description,
    startedAt: new Date(),
    status: 'running',
    log: [`=== ${label} Deploy: ${description} ===`, ''],
  };
  deployJobs.set(id, job);
  persistJob(job); // initial write

  // Fire-and-forget — returns before steps complete to avoid MCP timeout
  (async () => {
    for (const step of steps) {
      job.log.push('--- ' + step.label + ' ---');
      try {
        const { stdout, stderr } = await runCmd(step.cmd, step.args, step.cwd);
        job.log.push([stdout, stderr].filter(Boolean).join('\n').trim() || '[no output]');
        persistJob(job); // update after each step
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

function validatePath(filePath: string): string {
  const resolved = path.resolve(filePath);
  const allowed = ALLOWED_READ_DIRS.some(dir => resolved.startsWith(path.resolve(dir)));
  if (!allowed) {
    throw new Error(
      `Path not permitted: "${filePath}". Reads are restricted to: ${ALLOWED_READ_DIRS.join(', ')}`
    );
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

// Patterns that are hard-blocked in the escape hatch — no override
const BLOCKED_PATTERNS: RegExp[] = [
  /\brm\b/,               // delete files
  /\brmdir\b/,
  /\bunlink\b/,
  /\bdd\b/,               // disk operations
  /\bmkfs\b/,
  /\bfdisk\b/,
  /\|\s*(sh|bash|zsh|fish)/,  // pipe to shell
  /\bpsql\b/,             // direct DB access
  /\bmysql\b/,
  /\bmongo\b/,
  />\s*\//,               // redirect to absolute path
  /\bcurl\b.*\|/,         // curl pipe
  /\bwget\b.*\|/,
  /\beval\b/,
  /\bsudo\b/,
  /`[^`]*`/,              // backtick subshell
  /\$\([^)]*\)/,          // $() subshell
  /;/,                    // command chaining
];

function validateCommand(command: string): void {
  for (const pattern of BLOCKED_PATTERNS) {
    if (pattern.test(command)) {
      throw new Error(
        `Blocked pattern detected (${pattern}). Use structured tools instead, or ask the user to run this manually.`
      );
    }
  }
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

async function runApprovedCommand(
  command: string,
  justification: string,
  dryRun: boolean
): Promise<string> {
  validateCommand(command);

  if (!justification || justification.trim().length < 10) {
    throw new Error('justification must be at least 10 characters explaining why structured tools are insufficient.');
  }

  if (dryRun) {
    return [
      'DRY RUN — nothing executed.',
      `Would run: ${command}`,
      `Justification: ${justification}`,
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

  const parts = command.trim().split(/\s+/);
  const [cmd, ...args] = parts;
  const { stdout, stderr } = await exec(cmd, args);
  // Only increment after successful execution — failed commands do not consume quota
  customCommandCount++;
  const output = [stdout, stderr].filter(Boolean).join('\n');
  return truncate(output.trim() || '[Command completed with no output]');
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
  const selfRestartNote = fromFile && job.status === 'running'
    ? '\n[Note: job was still "running" when vps-mcp restarted itself (VC-8). Deploy likely succeeded — verify with get_pm2_status.]'
    : '';
  return [
    `Job:     ${job.id}`,
    `Type:    ${job.type}`,
    `Status:  ${job.status}` + (fromFile ? ' (recovered from file)' : ''),
    `Elapsed: ${elapsed}s`,
    '',
    '--- Log ---',
    job.log.join('\n') + selfRestartNote,
  ].join('\n');
}

// ─── Tool Definitions (MCP schema) ───────────────────────────────────────────

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
        command:       { type: 'string', description: 'Command to run. Destructive patterns are blocked server-side.' },
        justification: { type: 'string', description: 'Why structured tools cannot cover this. Min 10 chars.' },
        dry_run: { description: 'Default true. Set false only after previewing.' },
      },
      required: ['command', 'justification'],
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
          parseBool(args.dry_run, true)
        );

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
