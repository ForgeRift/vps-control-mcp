import fs from 'fs';
import { CONFIG } from './config.js';

// Maximum audit log size before rotation (10 MB default, configurable via AUDIT_MAX_SIZE_MB)
const MAX_AUDIT_BYTES = (parseInt(process.env.AUDIT_MAX_SIZE_MB || '10', 10)) * 1024 * 1024;

export function auditLog(
  tool: string,
  args: Record<string, unknown>,
  outputChars: number,
  isCustomCommand = false
): void {
  const entry = {
    ts:            new Date().toISOString(),
    tool,
    args:          JSON.stringify(sanitizeArgs(args)).slice(0, 300),
    output_chars:  outputChars,
    dry_run:       args.dry_run ?? null,
    custom:        isCustomCommand || undefined,
  };

  const line = JSON.stringify(entry) + '\n';

  try {
    // Rotate if log exceeds size limit
    rotateIfNeeded();
    fs.appendFileSync(CONFIG.AUDIT_LOG_PATH, line, { flag: 'a' });
  } catch {
    // Never crash the server over an audit write failure — log to stdout instead
    console.error('[AUDIT FAIL]', line.trim());
  }
}

// Strip values that look like secrets before logging args
function sanitizeArgs(args: Record<string, unknown>): Record<string, unknown> {
  const clean: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(args)) {
    if (typeof v === 'string' && (
      /token|secret|key|password|auth/i.test(k) ||
      /^sk-|^Bearer |^eyJ/i.test(v)
    )) {
      clean[k] = '[REDACTED]';
    } else {
      clean[k] = v;
    }
  }
  return clean;
}

// Simple rotation: when the log exceeds MAX_AUDIT_BYTES, rename to .old and start fresh.
// Keeps exactly one backup. Checked at most once per 60 seconds to avoid stat() on every call.
let lastRotationCheck = 0;
function rotateIfNeeded(): void {
  const now = Date.now();
  if (now - lastRotationCheck < 60_000) return;
  lastRotationCheck = now;

  try {
    if (!fs.existsSync(CONFIG.AUDIT_LOG_PATH)) return;
    const stats = fs.statSync(CONFIG.AUDIT_LOG_PATH);
    if (stats.size >= MAX_AUDIT_BYTES) {
      const oldPath = CONFIG.AUDIT_LOG_PATH + '.old';
      // Remove previous backup, rename current, start fresh
      if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
      fs.renameSync(CONFIG.AUDIT_LOG_PATH, oldPath);
      console.log(`[vps-control-mcp] Audit log rotated (${Math.round(stats.size / 1024 / 1024)}MB). Old log: ${oldPath}`);
    }
  } catch {
    // Rotation failure is non-fatal
  }
}
