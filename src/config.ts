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
function validateAuditLogPath(p: string): string {
  const normalized = path.normalize(p).toLowerCase();
  const FORBIDDEN = ['/dev/null', '/dev/zero', '/dev/random', 'nul', 'con', '/dev/stdout', '/dev/stderr'];
  if (FORBIDDEN.includes(normalized)) {
    throw new Error(`AUDIT_LOG_PATH "${p}" is a forbidden sink — audit logging would be silently disabled.`);
  }
  if (normalized.startsWith('/tmp/') || normalized.startsWith('/var/tmp/') || normalized === '/tmp' || normalized === '/var/tmp') {
    throw new Error(`AUDIT_LOG_PATH "${p}" is in a world-writable temp directory — use a hardened log path (e.g. /var/log/forgerift/mcp-audit.log).`);
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
};

// Derived — do not edit directly
export const ALLOWED_READ_DIRS = [CONFIG.APP_DIR, CONFIG.PM2_LOG_DIR];
