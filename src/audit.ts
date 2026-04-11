import fs from 'fs';
import { CONFIG } from './config.js';

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
