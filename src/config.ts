import dotenv from 'dotenv';
import fs from 'fs';
import path from 'path';
dotenv.config();

function parseProcessList(raw: string | undefined, fallback: string[]): string[] {
  if (!raw || !raw.trim()) return fallback;
  return raw.split(',').map(s => s.trim()).filter(Boolean);
}

function requireEnv(key: string, example: string): string {
  const v = process.env[key];
  if (!v || !v.trim()) {
    throw new Error(
      `${key} is not set. vps-control-mcp requires ${key} in your environment (.env or systemd unit). ` +
      `Example: ${key}=${example}`
    );
  }
  return v.trim();
}

// D7: Validate AUDIT_LOG_PATH at startup — reject paths that would silently
// disable or compromise the audit trail.
// F-S67-18: extended to block /dev/full, /dev/console, /dev/tty; reject char/block devices;
//           resolve symlinks (realpathSync) and re-check the resolved path against FORBIDDEN.
function validateAuditLogPath(p: string): string {
  const normalized = path.normalize(p).toLowerCase();
  const FORBIDDEN = [
    '/dev/null', '/dev/zero', '/dev/random', '/dev/urandom',
    '/dev/full', '/dev/console', '/dev/tty',
    'nul', 'con', '/dev/stdout', '/dev/stderr',
  ];
  if (FORBIDDEN.includes(normalized)) {
    throw new Error(`AUDIT_LOG_PATH "${p}" is a forbidden sink — audit logging would be silently disabled.`);
  }
  if (normalized.startsWith('/tmp/') || normalized.startsWith('/var/tmp/') || normalized === '/tmp' || normalized === '/var/tmp') {
    throw new Error(`AUDIT_LOG_PATH "${p}" is in a world-writable temp directory — use a hardened log path (e.g. /var/log/forgerift/mcp-audit.log).`);
  }
  // Reject character and block devices — /dev/full silently discards writes,
  // /dev/console and /dev/tty write to a terminal rather than a persistent log.
  const stat = (() => { try { return fs.statSync(p); } catch { return null; } })();
  if (stat && !stat.isFile() && !stat.isDirectory()) {
    throw new Error(`AUDIT_LOG_PATH "${p}" is a special device — only regular files and directories are permitted.`);
  }
  // Resolve symlinks and re-check the real path against FORBIDDEN.
  // Wrapping in try/catch: ENOENT is acceptable (file not yet created).
  try {
    const resolved = fs.realpathSync(p).toLowerCase();
    if (FORBIDDEN.includes(resolved)) {
      throw new Error(`AUDIT_LOG_PATH "${p}" resolves to a forbidden sink "${resolved}" — audit logging would be silently disabled.`);
    }
    const resolvedStat = (() => { try { return fs.statSync(resolved); } catch { return null; } })();
    if (resolvedStat && !resolvedStat.isFile() && !resolvedStat.isDirectory()) {
      throw new Error(`AUDIT_LOG_PATH "${p}" resolves to a special device "${resolved}" — only regular files are permitted.`);
    }
  } catch (e: unknown) {
    // Re-throw our own errors; ENOENT (path doesn't exist yet) is acceptable.
    if (e instanceof Error && e.message.startsWith('AUDIT_LOG_PATH')) throw e;
    // Other errors (e.g. ENOENT) are fine — file may not exist yet.
  }
  // Ensure the parent directory exists; refuse to create arbitrary directories.
  const dir = path.dirname(p);
  if (!fs.existsSync(dir)) {
    throw new Error(`AUDIT_LOG_PATH parent directory "${dir}" does not exist. Create it before starting the server.`);
  }
  return p;
}

// Resolve APP_DIR first so AUDIT_LOG_PATH can default to a path inside it,
// guaranteeing the audit log is always within the read allowlist without any
// extra configuration.
const APP_DIR = requireEnv('APP_DIR', '/root/myapp');

// CLIENT_WEB_ROOT is the FIXED publish destination for the deploy_client tool.
// Empty default = the feature is disabled (mirrors ALLOWED_UNITS): deploy_client
// is a safe no-op until the operator opts in by setting this in the environment.
// We validate it is an absolute path here so a misconfiguration fails fast at
// startup rather than at deploy time. We do NOT require the directory to exist
// (it is created out-of-band by the operator / nginx provisioning).
function validateClientWebRoot(raw: string | undefined): string {
  const v = (raw || '').trim();
  if (!v) return '';
  if (!path.isAbsolute(v)) {
    throw new Error(
      `CLIENT_WEB_ROOT "${v}" must be an absolute path (e.g. /var/www/servicecycle/html). ` +
      `Leave it empty to disable the deploy_client tool.`
    );
  }
  return v;
}

export const CONFIG = {
  PORT:           parseInt(process.env.PORT || '3001'),
  // APP_DIR is the absolute path to the user's application on this VM — the
  // directory vps-control-mcp is permitted to read files from and deploy into.
  // Required. No default: a wrong default would silently expand the server's
  // read surface to someone else's filesystem layout.
  APP_DIR,
  PM2_LOG_DIR:    process.env.PM2_LOG_DIR    || '/root/.pm2/logs',
  // Default audit log lives inside APP_DIR so read_file_section can access it
  // without extra allowlist config. Override via AUDIT_LOG_PATH env var.
  AUDIT_LOG_PATH: validateAuditLogPath(process.env.AUDIT_LOG_PATH || path.join(APP_DIR, 'mcp-audit.log')),

  // Hard read limits — enforced at server level, not by judgment
  MAX_LOG_LINES:    50,
  MAX_FILE_LINES:   100,
  MAX_OUTPUT_CHARS: 3000,

  // Escape hatch rate limit — configurable via env var
  MAX_CUSTOM_COMMANDS_PER_SESSION: parseInt(process.env.MAX_CUSTOM_COMMANDS_PER_SESSION || '10'),

  // Allowed PM2 process names — set ALLOWED_PROCESSES env var as comma-separated list
  // e.g. ALLOWED_PROCESSES=my-api,my-worker
  // Default is empty: restart_process / get_pm2_status are no-ops until configured,
  // so there is no implicit allowlist that might match an unrelated process on this host.
  ALLOWED_PROCESSES: parseProcessList(process.env.ALLOWED_PROCESSES, []),

  // FP-VPS-003: systemd units the operator wants `journalctl -u <unit>` access to.
  // Set ALLOWED_UNITS env var as comma-separated list, e.g. ALLOWED_UNITS=nginx,my-api.
  // NGINX-DIAG: default is the standard ServiceCycle web/TLS/auth-guard unit set so nginx and
  // certificate issues can be diagnosed through the MCP instead of falling out to SSH.
  // journalctl still requires an explicit -u naming one of these (no system-wide dump);
  // set ALLOWED_UNITS in the env to override this list entirely.
  ALLOWED_UNITS: parseProcessList(process.env.ALLOWED_UNITS, [
    'nginx.service',
    'certbot.service',
    'certbot.timer',
    'sc-auth-guard.service',
    'sc-auth-guard.timer',
  ]),

  // ── deploy_client tool config (opt-in; empty CLIENT_WEB_ROOT = disabled) ──────
  // deploy_client builds the front-end container and publishes its compiled dist/
  // into a fixed nginx web root. The destination is ALWAYS CLIENT_WEB_ROOT and is
  // never taken from caller input — that fixed, operator-configured target is what
  // makes the copy safe to allow without weakening the generic cp-to-system-dir
  // guardrail in run_approved_command.
  //
  // CLIENT_WEB_ROOT REQUIRED for the tool to do anything. Validated absolute if set.
  CLIENT_WEB_ROOT:     validateClientWebRoot(process.env.CLIENT_WEB_ROOT),
  // Compose file, service name, and in-container dist path. Sensible defaults so a
  // standard ServiceCycle droplet only needs CLIENT_WEB_ROOT to enable the tool.
  CLIENT_COMPOSE_FILE: process.env.CLIENT_COMPOSE_FILE || '/root/ServiceCycle/docker-compose.yml',
  CLIENT_SERVICE:      process.env.CLIENT_SERVICE      || 'client',
  CLIENT_DIST_PATH:    process.env.CLIENT_DIST_PATH    || '/app/dist',

  // ── ServiceCycle app-operations tools (FIXED compose file) ────────────────────
  // get_app_status / get_app_logs / migrate_status / reseed_demo / restart_app all
  // operate on this single docker-compose project. The path is operator-config only
  // and is NEVER taken from caller input — every tool's service argument is a strict
  // enum whitelist, and the compose file is fixed here. Defaults to the standard
  // ServiceCycle location; override via COMPOSE_FILE only if the droplet differs.
  COMPOSE_FILE:        process.env.COMPOSE_FILE        || '/root/ServiceCycle/docker-compose.yml',

  // ── Read-only diagnostic dirs (NGINX-DIAG 2026-07-18) ───────────────────────────────────────────
  // nginx config + host logs, so `nginx -T`, `cat /etc/nginx/...`, and
  // `tail /var/log/nginx/error.log` / `/var/log/sc-auth-guard.log` are diagnosable
  // through the MCP. READ surface only — these are added to ALLOWED_READ_DIRS and
  // nothing else. Every write/destructive guardrail is unchanged, and the
  // credential-name patterns in SENSITIVE_FILE_PATTERNS (*.key, *.pem, *password*,
  // *token*, *credentials*, .htpasswd, ...) still apply INSIDE these directories.
  NGINX_CONF_DIR:      process.env.NGINX_CONF_DIR      || '/etc/nginx',
  HOST_LOG_DIR:        process.env.HOST_LOG_DIR        || '/var/log',
};

// Derived — do not edit directly
export const ALLOWED_READ_DIRS = [
  CONFIG.APP_DIR,
  CONFIG.PM2_LOG_DIR,
  CONFIG.NGINX_CONF_DIR,
  CONFIG.HOST_LOG_DIR,
];
