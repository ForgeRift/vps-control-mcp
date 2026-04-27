import fs from 'fs';
import { CONFIG } from './config.js';

// Maximum audit log size before rotation (10 MB default, configurable via AUDIT_MAX_SIZE_MB)
const MAX_AUDIT_BYTES = (parseInt(process.env.AUDIT_MAX_SIZE_MB || '10', 10)) * 1024 * 1024;

// F-S67-54: per-field caps instead of a flat 300-char slice on the JSON blob.
// command is the most forensically important field: cap at 1024.
// justification is free-text from the user: cap at 512.
// Other fields are short by design; still falls back to JSON.stringify.
function capField(v: unknown, maxLen: number): unknown {
  return typeof v === 'string' && v.length > maxLen ? v.slice(0, maxLen) + '...[truncated]' : v;
}

export function auditLog(
  tool: string,
  args: Record<string, unknown>,
  outputChars: number,
  isCustomCommand = false
): void {
  const sanitized = sanitizeArgs(args);
  // F-S68-4: Apply per-field caps before JSON serialization — every string field is
  // capped to prevent a single oversized arg from inflating the log line beyond 8 KiB,
  // which would trigger premature rotation and delete forensic evidence.
  const cappedArgs: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(sanitized)) {
    if (k === 'command') {
      cappedArgs[k] = capField(v, 1024);
    } else if (k === 'justification') {
      cappedArgs[k] = capField(v, 512);
    } else {
      // All other string fields capped at 512 chars; non-strings pass through unchanged.
      cappedArgs[k] = capField(v, 512);
    }
  }
  // F-S68-19: cap the tool name too — a custom MCP server could register a 1 MiB tool name.
  const cappedTool = typeof tool === 'string' && tool.length > 256
    ? tool.slice(0, 256) + '...[truncated]'
    : tool;
  const entry = {
    ts:            new Date().toISOString(),
    tool:          cappedTool,
    args:          cappedArgs,
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
// F-OP-46 (S55): expanded token-shape list + expanded key-name regex to match
// local-terminal-mcp F-LT-85 (S54). Audit log is in the trust boundary; missing a
// token prefix here means a secret survives in plaintext in audit.log even though
// tools.ts scrubs it from tool output.
const SECRET_VALUE_PREFIXES = /^(?:sk-|Bearer |eyJ|ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|xox[abprs]-|xoxe\.xox[bp]-|glpat-|sbp_|supabase_svcRole_|AKIA|ASIA|AIza|pk_live_|pk_test_|sk_live_|sk_test_|rk_live_|rk_test_|whsec_|SG\.|ATATT|ATCTT|do_v1_|dop_v1_|dockercfg\.|sq0[ac][st]p-|key-[0-9a-f]{32}|ya29\.|1\/\/|AC[a-z0-9]{32}|npm_[A-Za-z0-9]{36}|-----BEGIN )/i;
function sanitizeArgs(args: Record<string, unknown>): Record<string, unknown> {
  const clean: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(args)) {
    if (typeof v === 'string' && (
      /token|secret|key|password|auth|credential|bearer|api[_-]?key|cookie|session/i.test(k) ||
      SECRET_VALUE_PREFIXES.test(v)
    )) {
      clean[k] = '[REDACTED]';
    } else {
      clean[k] = v;
    }
  }
  return clean;
}

// Log a confirmed deploy event — one entry per confirmed deploy invocation (ToS §8 + §B.2).
export function logDeployConfirmation(
  tool: string,
  description: string,
  target: string
): void {
  const entry = {
    ts:          new Date().toISOString(),
    event:       'deploy-confirmation',
    tool,
    description: description.slice(0, 200),
    target,
    confirmed:   true,
  };

  const line = JSON.stringify(entry) + '\n';
  try {
    rotateIfNeeded();
    fs.appendFileSync(CONFIG.AUDIT_LOG_PATH, line, { flag: 'a' });
  } catch {
    console.error('[AUDIT FAIL — deploy confirmation]', line.trim());
  }
  console.log(`[audit] ✓ DEPLOY CONFIRMED — ${tool}: ${description.slice(0, 60)}`);
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
