import type { Request } from 'express';

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY;

// Plans that grant access to vps-control-mcp
const ALLOWED_PLANS = new Set(['vps-control', 'bundle']);

// ─── Token shape pre-validation (F-OP-23) ────────────────────────────────────
// Before hitting Supabase, reject tokens that cannot possibly be valid.
// This prevents an attacker flooding /mcp with random Bearer tokens to exhaust
// the Supabase plan quota: random tokens (hex, UUID) would all miss the cache,
// evict real cached entries, and trigger Supabase calls at the rate-limit cap.
//
// Valid tokens are: MCP_AUTH_TOKEN (arbitrary string ≥ 16 chars) or Supabase-
// issued refresh tokens (base64url, 43+ chars). We accept any token that is:
//   - Length: 16–512 characters (blocks trivially short/long inputs)
//   - Charset: printable ASCII, no control characters (blocks binary garbage)
// This is deliberately loose — we don't want false negatives on legitimate tokens.
const TOKEN_MIN_LEN = 16;
const TOKEN_MAX_LEN = 512;
const TOKEN_CHARSET_RE = /^[\x20-\x7E]+$/; // printable ASCII only

function isValidTokenShape(token: string): boolean {
  return (
    token.length >= TOKEN_MIN_LEN &&
    token.length <= TOKEN_MAX_LEN &&
    TOKEN_CHARSET_RE.test(token)
  );
}

// ─── Token cache ──────────────────────────────────────────────────────────────
// Avoids a Supabase round-trip on every MCP request.
// TTL is 5 minutes. On cancellation, worst-case grace period before lockout
// is 5 minutes — acceptable for a monthly subscription product.
//
// F-OP-23: separate negative cache with longer TTL and larger cap.
// Rationale: a random token that misses Supabase should be cached "invalid" for
// longer than 5 minutes, so a flood of unique random tokens eventually fills the
// negative cache instead of continuously evicting the positive cache and re-querying
// Supabase. Real tokens only ever go invalid for a short period (plan cancellation),
// so the 30-min negative TTL doesn't cause visible lockout issues.

interface CacheEntry { valid: boolean; cachedAt: number; }
const authCachePositive = new Map<string, CacheEntry>(); // valid tokens
const authCacheNegative = new Map<string, CacheEntry>(); // rejected tokens
const CACHE_TTL_POSITIVE_MS = 5  * 60 * 1000; // 5 minutes — same as before
const CACHE_TTL_NEGATIVE_MS = 30 * 60 * 1000; // 30 minutes — keep rejections longer
const CACHE_MAX_POSITIVE = 1000;
const CACHE_MAX_NEGATIVE = 5000; // larger — absorbs flood of random tokens

// ─── F-OP-35: OAuth session tokens ────────────────────────────────────────────
// Per-OAuth-flow minted access tokens, bound to a specific authorization_code
// exchange. Decouples OAuth access_token from the master MCP_AUTH_TOKEN so that
// any future auth-flow flaw can never leak the root token.
// Session tokens are registered by /token (in index.ts) and checked FIRST in
// validateAuth — no Supabase lookup, no MCP_AUTH_TOKEN compare.

interface SessionTokenEntry { expiresAt: number; }
const sessionTokens = new Map<string, SessionTokenEntry>();
const SESSION_TOKENS_MAX = 5000;

export function registerSessionToken(token: string, ttlSeconds: number): void {
  // FIFO eviction at cap
  if (sessionTokens.size >= SESSION_TOKENS_MAX) {
    const oldest = sessionTokens.keys().next().value;
    if (oldest) sessionTokens.delete(oldest);
  }
  sessionTokens.set(token, { expiresAt: Date.now() + ttlSeconds * 1000 });
}

export function invalidateSessionToken(token: string): void {
  sessionTokens.delete(token);
}

function sessionTokenValid(token: string): boolean {
  const entry = sessionTokens.get(token);
  if (!entry) return false;
  if (Date.now() > entry.expiresAt) {
    sessionTokens.delete(token);
    return false;
  }
  return true;
}

// Prune expired entries every 5 minutes to bound memory
setInterval(() => {
  const now = Date.now();
  for (const [t, e] of sessionTokens) {
    if (now > e.expiresAt) sessionTokens.delete(t);
  }
}, 5 * 60_000);

// ─── F-OP-36: Supabase circuit breaker ────────────────────────────────────────
// Bounds total Supabase call rate across all callers. When the cap is exceeded,
// the circuit opens for one window — new-token lookups skip Supabase (and fail
// closed, translated to 503 by the HTTP layer). Positive-cache hits still succeed.

const CIRCUIT_WINDOW_MS = 60_000;
const CIRCUIT_THRESHOLD = parseInt(process.env.SUPABASE_CIRCUIT_THRESHOLD || '120', 10);
let supabaseCallTimestamps: number[] = [];
let circuitOpenUntil = 0;

export function supabaseCircuitOpen(): boolean {
  return Date.now() < circuitOpenUntil;
}

function supabaseCircuitAllow(): boolean {
  const now = Date.now();
  if (now < circuitOpenUntil) return false;
  supabaseCallTimestamps = supabaseCallTimestamps.filter(ts => now - ts < CIRCUIT_WINDOW_MS);
  if (supabaseCallTimestamps.length >= CIRCUIT_THRESHOLD) {
    circuitOpenUntil = now + CIRCUIT_WINDOW_MS;
    return false;
  }
  supabaseCallTimestamps.push(now);
  return true;
}

function cacheGet(token: string): boolean | null {
  const pos = authCachePositive.get(token);
  if (pos) {
    if (Date.now() - pos.cachedAt <= CACHE_TTL_POSITIVE_MS) return true;
    authCachePositive.delete(token);
  }
  const neg = authCacheNegative.get(token);
  if (neg) {
    if (Date.now() - neg.cachedAt <= CACHE_TTL_NEGATIVE_MS) return false;
    authCacheNegative.delete(token); // stale negative entry — let it re-validate against Supabase
  }
  return null;
}

function cacheSet(token: string, valid: boolean): void {
  if (valid) {
    // Positive cache: FIFO eviction at CACHE_MAX_POSITIVE
    if (authCachePositive.size >= CACHE_MAX_POSITIVE) {
      const oldest = authCachePositive.keys().next().value;
      if (oldest) authCachePositive.delete(oldest);
    }
    authCachePositive.set(token, { valid: true, cachedAt: Date.now() });
  } else {
    // Negative cache: FIFO eviction at CACHE_MAX_NEGATIVE
    if (authCacheNegative.size >= CACHE_MAX_NEGATIVE) {
      const oldest = authCacheNegative.keys().next().value;
      if (oldest) authCacheNegative.delete(oldest);
    }
    authCacheNegative.set(token, { valid: false, cachedAt: Date.now() });
  }
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

  // F-OP-23: shape pre-validation — reject tokens that can never be valid before
  // touching Supabase. Prevents quota exhaustion via flood of random Bearer tokens.
  if (!isValidTokenShape(token)) return false;

  // F-OP-35: OAuth session tokens checked FIRST — zero external I/O, decoupled
  // from MCP_AUTH_TOKEN. Any PKCE-successful /token exchange lands here.
  if (sessionTokenValid(token)) return true;

  // Mode A: Supabase multi-token validation (marketplace / billing mode)
  if (SUPABASE_URL && SUPABASE_KEY) {
    const cached = cacheGet(token);
    if (cached !== null) return cached;

    // F-OP-36: circuit breaker — skip Supabase when too many cache-misses per minute.
    // Positive cache (above) still returns cached valid tokens; new tokens fail closed
    // and the HTTP layer converts that to 503 when supabaseCircuitOpen() is true.
    if (!supabaseCircuitAllow()) {
      return false;
    }

    const valid = await validateAgainstSupabase(token);
    cacheSet(token, valid);
    return valid;
  }

  // Mode B: Single-token fallback (no Supabase configured — self-hosted / dev)
  const expected = process.env.MCP_AUTH_TOKEN;
  if (!expected) return false;
  return constantTimeEqual(token, expected);
}
