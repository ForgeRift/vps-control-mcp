import type { Request } from 'express';

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY;

// Plans that grant access to vps-control-mcp
const ALLOWED_PLANS = new Set(['vps-control', 'bundle']);

// ─── Token cache ──────────────────────────────────────────────────────────────
// Avoids a Supabase round-trip on every MCP request.
// TTL is 5 minutes. On cancellation, worst-case grace period before lockout
// is 5 minutes — acceptable for a monthly subscription product.

interface CacheEntry { valid: boolean; cachedAt: number; }
const authCache = new Map<string, CacheEntry>();
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

function cacheGet(token: string): boolean | null {
  const entry = authCache.get(token);
  if (!entry) return null;
  if (Date.now() - entry.cachedAt > CACHE_TTL_MS) {
    authCache.delete(token);
    return null;
  }
  return entry.valid;
}

function cacheSet(token: string, valid: boolean): void {
  // Limit cache size — evict oldest entry if over 1000 tokens
  if (authCache.size >= 1000) {
    const oldest = authCache.keys().next().value;
    if (oldest) authCache.delete(oldest);
  }
  authCache.set(token, { valid, cachedAt: Date.now() });
}

// ─── Supabase lookup ──────────────────────────────────────────────────────────

interface CustomerRow {
  id:         string;
  plan:       string;
  expires_at: string | null;
}

async function validateAgainstSupabase(token: string): Promise<boolean> {
  if (!SUPABASE_URL || !SUPABASE_KEY) return false;

  try {
    const url =
      `${SUPABASE_URL}/rest/v1/customers` +
      `?token=eq.${encodeURIComponent(token)}` +
      `&status=eq.active` +
      `&select=id,plan,expires_at`;

    const resp = await fetch(url, {
      headers: {
        'apikey':        SUPABASE_KEY,
        'Authorization': `Bearer ${SUPABASE_KEY}`,
      },
    });

    if (!resp.ok) return false;

    const rows = await resp.json() as CustomerRow[];
    if (!rows.length) return false;

    const row = rows[0];

    // Plan must grant vps-control access
    if (!ALLOWED_PLANS.has(row.plan)) return false;

    // Honour expiry if set
    if (row.expires_at && new Date(row.expires_at) < new Date()) return false;

    return true;
  } catch {
    // Network error, parse failure, etc. — fail closed
    return false;
  }
}

// ─── Constant-time comparison (fallback mode) ─────────────────────────────────
// Used when Supabase is not configured (local dev / self-hosted without billing).

function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) {
    mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return mismatch === 0;
}

// ─── Main export ──────────────────────────────────────────────────────────────

export async function validateAuth(req: Request): Promise<boolean> {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) return false;

  const token = authHeader.slice(7).trim();
  if (!token) return false;

  // Mode A: Supabase multi-token validation (marketplace / billing mode)
  if (SUPABASE_URL && SUPABASE_KEY) {
    const cached = cacheGet(token);
    if (cached !== null) return cached;

    const valid = await validateAgainstSupabase(token);
    cacheSet(token, valid);
    return valid;
  }

  // Mode B: Single-token fallback (no Supabase configured — self-hosted / dev)
  const expected = process.env.MCP_AUTH_TOKEN;
  if (!expected) return false;
  return constantTimeEqual(token, expected);
}
