import express from 'express';
import crypto from 'crypto';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import type { JSONRPCMessage } from '@modelcontextprotocol/sdk/types.js';
import type { EventStore, StreamId, EventId } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import dotenv from 'dotenv';
import { CONFIG } from './config.js';
import { validateAuth } from './auth.js';
import { auditLog } from './audit.js';
import { TOOLS, executeTool } from './tools.js';

dotenv.config();

// Auth token is required in single-token mode; optional if Supabase is configured.
const supabaseConfigured = !!(process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_KEY);

if (!process.env.MCP_AUTH_TOKEN && !supabaseConfigured) {
  console.error('FATAL: Set MCP_AUTH_TOKEN or configure SUPABASE_URL + SUPABASE_SERVICE_KEY.');
  process.exit(1);
}

if (supabaseConfigured) {
  console.log('[vps-control-mcp] Auth mode: Supabase multi-token (billing-integrated)');
} else {
  console.log('[vps-control-mcp] Auth mode: single-token (MCP_AUTH_TOKEN)');
}

// --- In-memory EventStore for resumability ------------------------------------
// When an SSE stream drops (network blip, nginx timeout), the client reconnects
// with Last-Event-ID. The EventStore replays missed events so no messages are lost.
// Events are pruned after 30 minutes to bound memory.

const EVENT_TTL_MS = 30 * 60 * 1000;

interface StoredEvent {
  streamId: StreamId;
  message:  JSONRPCMessage;
  storedAt: number;
}

class InMemoryEventStore implements EventStore {
  private events = new Map<EventId, StoredEvent>();
  private streamEvents = new Map<StreamId, EventId[]>();

  async storeEvent(streamId: StreamId, message: JSONRPCMessage): Promise<EventId> {
    const eventId = crypto.randomUUID();
    this.events.set(eventId, { streamId, message, storedAt: Date.now() });
    const list = this.streamEvents.get(streamId) || [];
    list.push(eventId);
    this.streamEvents.set(streamId, list);
    this.prune();
    return eventId;
  }

  async getStreamIdForEventId(eventId: EventId): Promise<StreamId | undefined> {
    return this.events.get(eventId)?.streamId;
  }

  async replayEventsAfter(
    lastEventId: EventId,
    { send }: { send: (eventId: EventId, message: JSONRPCMessage) => Promise<void> }
  ): Promise<StreamId> {
    const origin = this.events.get(lastEventId);
    if (!origin) throw new Error(`Unknown event ID: ${lastEventId}`);

    const streamId = origin.streamId;
    const list = this.streamEvents.get(streamId) || [];
    const idx = list.indexOf(lastEventId);
    if (idx === -1) throw new Error(`Event ID not in stream: ${lastEventId}`);

    // Replay everything after the last-seen event
    for (let i = idx + 1; i < list.length; i++) {
      const ev = this.events.get(list[i]);
      if (ev) await send(list[i], ev.message);
    }

    return streamId;
  }

  private prune(): void {
    const cutoff = Date.now() - EVENT_TTL_MS;
    for (const [id, ev] of this.events) {
      if (ev.storedAt < cutoff) {
        this.events.delete(id);
        const list = this.streamEvents.get(ev.streamId);
        if (list) {
          const filtered = list.filter(e => e !== id);
          if (filtered.length) this.streamEvents.set(ev.streamId, filtered);
          else this.streamEvents.delete(ev.streamId);
        }
      }
    }
  }
}

const eventStore = new InMemoryEventStore();

// --- MCP Server + Transport management ----------------------------------------
// Each session gets its own Server + Transport pair.
// StreamableHTTP handles reconnection natively — the client POSTs each message
// independently and can GET to open SSE streams. If a stream drops, the client
// reconnects with Last-Event-ID and missed events are replayed.

const sessions = new Map<string, { server: Server; transport: StreamableHTTPServerTransport }>();

// F-VM-4: Hard cap on concurrent MCP sessions. Prevents a rogue or misbehaving
// client from exhausting memory by POSTing unbounded initialize requests.
// 200 is well above realistic demand (one session per Claude desktop / Cowork
// instance). Configurable via MAX_SESSIONS env.
const MAX_SESSIONS = parseInt(process.env.MAX_SESSIONS || '200', 10);

function createMcpServer(): Server {
  const server = new Server(
    { name: 'vps-control-mcp', version: '1.1.0' },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args = {} } = request.params;
    const isCustom = name === 'run_approved_command';
    try {
      const result = await executeTool(name, args as Record<string, unknown>);
      auditLog(name, args as Record<string, unknown>, result.length, isCustom);
      return { content: [{ type: 'text', text: result }] };
    } catch (err) {
      auditLog(name, args as Record<string, unknown>, 0, isCustom);
      throw err;
    }
  });

  return server;
}

// --- Express App -------------------------------------------------------------

const app = express();

// --- CORS (browser-based MCP clients need this) ------------------------------
app.use((_req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, Mcp-Session-Id, MCP-Protocol-Version');
  res.setHeader('Access-Control-Expose-Headers', 'Mcp-Session-Id');
  if (_req.method === 'OPTIONS') { res.status(204).end(); return; }
  next();
});

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// --- Rate limiting (per-token, sliding window) -------------------------------
// Prevents runaway Claude loops and leaked-token abuse.
// Default: 60 requests per minute. Configurable via RATE_LIMIT_PER_MIN env var.

const RATE_LIMIT_PER_MIN = parseInt(process.env.RATE_LIMIT_PER_MIN || '60', 10);
const RATE_LIMIT_WINDOW_MS = 60_000;
const rateLimitBuckets = new Map<string, number[]>();

function checkRateLimit(token: string): boolean {
  const now = Date.now();
  const bucket = rateLimitBuckets.get(token) || [];
  const filtered = bucket.filter(ts => now - ts < RATE_LIMIT_WINDOW_MS);
  if (filtered.length >= RATE_LIMIT_PER_MIN) {
    rateLimitBuckets.set(token, filtered);
    return false;
  }
  filtered.push(now);
  rateLimitBuckets.set(token, filtered);
  return true;
}

// Prune expired entries every 5 minutes to bound memory
setInterval(() => {
  const now = Date.now();
  for (const [token, bucket] of rateLimitBuckets) {
    const filtered = bucket.filter(ts => now - ts < RATE_LIMIT_WINDOW_MS);
    if (filtered.length === 0) rateLimitBuckets.delete(token);
    else rateLimitBuckets.set(token, filtered);
  }
}, 5 * 60_000);

// requireAuth is async because validateAuth now does a Supabase lookup in billing mode
async function requireAuth(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
): Promise<void> {
  if (!(await validateAuth(req))) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }

  // Rate limit check (extract token for bucket key)
  const token = (req.headers.authorization || '').slice(7).trim();
  if (token && !checkRateLimit(token)) {
    res.status(429).json({
      error: 'Rate limit exceeded',
      message: `Maximum ${RATE_LIMIT_PER_MIN} requests per minute. Please slow down.`,
      retry_after_seconds: 60,
    });
    return;
  }

  next();
}

// --- OAuth 2.0 discovery endpoints (RFC 8414 + RFC 9728) --------------------
// Cowork (and any spec-compliant MCP client) discovers OAuth endpoints via
// .well-known metadata before starting the handshake. Without these, the
// client cannot find /authorize and /token and gives up.

app.get('/.well-known/oauth-authorization-server', (_req, res) => {
  const baseUrl = process.env.PUBLIC_URL || `http://localhost:${CONFIG.PORT}`;
  res.json({
    issuer:                  baseUrl,
    authorization_endpoint:  `${baseUrl}/authorize`,
    token_endpoint:          `${baseUrl}/token`,
    registration_endpoint:   `${baseUrl}/register`,
    response_types_supported: ['code'],
    grant_types_supported:   ['authorization_code', 'refresh_token'],
    token_endpoint_auth_methods_supported: ['none'],
    code_challenge_methods_supported: ['S256'],
  });
});

app.get('/.well-known/oauth-protected-resource', (_req, res) => {
  const baseUrl = process.env.PUBLIC_URL || `http://localhost:${CONFIG.PORT}`;
  res.json({
    resource:                 `${baseUrl}/mcp`,
    authorization_servers:    [baseUrl],
    bearer_methods_supported: ['header'],
  });
});

// Path-specific variant — some clients check /.well-known/oauth-protected-resource/{path}
app.get('/.well-known/oauth-protected-resource/mcp', (_req, res) => {
  const baseUrl = process.env.PUBLIC_URL || `http://localhost:${CONFIG.PORT}`;
  res.json({
    resource:                 `${baseUrl}/mcp`,
    authorization_servers:    [baseUrl],
    bearer_methods_supported: ['header'],
  });
});

// --- RFC 7591 Dynamic Client Registration -----------------------------------
// Cowork registers itself as an OAuth client before starting the auth flow.
// We accept any registration and return a client_id. The real security gate
// is the bearer token validated on every MCP request, not the OAuth client_id.

interface RegisteredClient {
  client_id:     string;
  client_name?:  string;
  redirect_uris: string[];
  created_at:    number;
}
const registeredClients = new Map<string, RegisteredClient>();

app.post('/register', (req, res) => {
  const body = req.body as Record<string, unknown>;
  const clientId = crypto.randomUUID();
  const client: RegisteredClient = {
    client_id:     clientId,
    client_name:   (body.client_name as string) || 'unknown',
    redirect_uris: (body.redirect_uris as string[]) || [],
    created_at:    Date.now(),
  };
  registeredClients.set(clientId, client);

  // Prune old registrations (keep last 100)
  if (registeredClients.size > 100) {
    const oldest = registeredClients.keys().next().value;
    if (oldest) registeredClients.delete(oldest);
  }

  res.status(201).json({
    client_id:                   clientId,
    client_name:                 client.client_name,
    redirect_uris:               client.redirect_uris,
    grant_types:                 ['authorization_code', 'refresh_token'],
    response_types:              ['code'],
    token_endpoint_auth_method:  'none',
  });
});

// --- OAuth 2.0 endpoints (required by Cowork to initiate connection) ---------
// Cowork starts an OAuth flow on first connect. We issue long-lived tokens
// (30 days) and support refresh_token grant so Cowork can silently re-auth
// without opening a browser window every session.
//
// redirect_uri is validated against an allow-list of known Cowork/Claude
// domains. Self-hosted users can add custom origins via ALLOWED_REDIRECT_HOSTS.

// F-NEW-6: store PKCE challenge alongside auth code so /token can verify it.
interface AuthCodeEntry {
  issuedAt:             number;
  codeChallenge?:       string; // S256 challenge (base64url-encoded SHA-256 of verifier)
  codeChallengeMethod?: string; // 'S256' only
}
const authCodes = new Map<string, AuthCodeEntry>();
const refreshTokens = new Map<string, { accessToken: string; issuedAt: number }>();
const REFRESH_TOKENS_MAX = 500; // cap against crash-loop seeding unbounded timers

const TOKEN_TTL_SECONDS = 30 * 24 * 3600; // 30 days

// Allow-listed redirect URI hosts.
//
// F-VM-1 (CRITICAL) fix: loopback hosts are NOT in the default list.
// Previously, an unauthenticated attacker could GET /authorize?redirect_uri=http://127.0.0.1/cb
// and receive a real authorization code (their own machine is 127.0.0.1),
// then exchange it at /token for the root MCP_AUTH_TOKEN.
//
// Loopback redirects are now gated behind an explicit opt-in env flag.
// Production installs should never enable this. For local dev, set
// ALLOW_LOOPBACK_REDIRECTS=true in .env.
const DEFAULT_REDIRECT_HOSTS = [
  'claude.ai',
  'www.claude.ai',
  'console.anthropic.com',
  'app.anthropic.com',
];
const customHosts = (process.env.ALLOWED_REDIRECT_HOSTS || '')
  .split(',')
  .map(h => h.trim().toLowerCase())
  .filter(Boolean);
const loopbackHosts = (process.env.ALLOW_LOOPBACK_REDIRECTS || '').toLowerCase() === 'true'
  ? ['localhost', '127.0.0.1']
  : [];
const ALLOWED_REDIRECT_HOSTS = new Set([...DEFAULT_REDIRECT_HOSTS, ...customHosts, ...loopbackHosts]);

if (loopbackHosts.length > 0) {
  console.warn('[vps-control-mcp] ⚠️  ALLOW_LOOPBACK_REDIRECTS=true — localhost/127.0.0.1 accepted as OAuth redirect_uri. Do not use in production.');
}

function isRedirectAllowed(uri: string): boolean {
  try {
    const parsed = new URL(uri);
    return ALLOWED_REDIRECT_HOSTS.has(parsed.hostname.toLowerCase());
  } catch {
    return false;
  }
}

// Step 1: Cowork opens this in a browser — auto-redirect with code
app.get('/authorize', (req, res) => {
  const {
    redirect_uri = '',
    state = '',
    code_challenge = '',
    code_challenge_method = '',
  } = req.query as Record<string, string>;

  if (!redirect_uri) {
    res.status(400).send('Missing redirect_uri');
    return;
  }

  if (!isRedirectAllowed(redirect_uri)) {
    res.status(403).send('redirect_uri host not in allow-list. Set ALLOWED_REDIRECT_HOSTS to add custom origins.');
    return;
  }

  // F-NEW-6: PKCE enforcement.
  // If client sends a challenge, only S256 is accepted.
  // Rejecting 'plain' method closes the downgrade attack (plain = no security gain).
  if (code_challenge_method && code_challenge_method !== 'S256') {
    res.status(400).send('Unsupported code_challenge_method. Use S256.');
    return;
  }

  // F-VM-6: crypto-random, not Math.random(). 32 bytes = 256 bits of entropy.
  const code = crypto.randomBytes(32).toString('base64url');
  const entry: AuthCodeEntry = { issuedAt: Date.now() };
  if (code_challenge) {
    entry.codeChallenge = code_challenge;
    entry.codeChallengeMethod = 'S256';
  }
  authCodes.set(code, entry);
  setTimeout(() => authCodes.delete(code), 5 * 60 * 1000);

  const url = new URL(redirect_uri);
  url.searchParams.set('code', code);
  if (state) url.searchParams.set('state', state);

  res.redirect(url.toString());
});

// Step 2: Cowork exchanges code (or refresh_token) for access token
app.post('/token', (req, res) => {
  const { grant_type, code, refresh_token } = req.body as Record<string, string>;

  // --- Refresh token grant ---
  if (grant_type === 'refresh_token') {
    if (!refresh_token || !refreshTokens.has(refresh_token)) {
      res.status(400).json({ error: 'invalid_grant', error_description: 'Unknown or expired refresh_token.' });
      return;
    }

    // Rotate: invalidate old refresh token, issue new pair
    const entry = refreshTokens.get(refresh_token)!;
    refreshTokens.delete(refresh_token);

    // F-VM-6: crypto-random refresh tokens
    const newRefresh = crypto.randomBytes(32).toString('base64url');
    if (refreshTokens.size >= REFRESH_TOKENS_MAX) {
      const oldest = refreshTokens.keys().next().value;
      if (oldest) refreshTokens.delete(oldest);
    }
    refreshTokens.set(newRefresh, { accessToken: entry.accessToken, issuedAt: Date.now() });
    // setTimeout max is ~24.8 days (2^31-1 ms). Use 24 days; tokens also checked at use time.
    setTimeout(() => refreshTokens.delete(newRefresh), 24 * 24 * 3600 * 1000);

    res.json({
      access_token:  entry.accessToken,
      token_type:    'bearer',
      expires_in:    TOKEN_TTL_SECONDS,
      refresh_token: newRefresh,
    });
    return;
  }

  // --- Authorization code grant (default) ---
  if (!code || !authCodes.has(code)) {
    res.status(400).json({ error: 'invalid_grant' });
    return;
  }

  // F-NEW-6: PKCE verification (S256).
  // If a code_challenge was registered at /authorize, the client MUST present
  // a code_verifier whose SHA-256 matches. Missing or wrong verifier = invalid_grant.
  const codeEntry = authCodes.get(code)!;
  if (codeEntry.codeChallenge) {
    const verifier = (req.body as Record<string, string>).code_verifier ?? '';
    if (!verifier) {
      res.status(400).json({ error: 'invalid_grant', error_description: 'code_verifier required for PKCE flow.' });
      return;
    }
    const computed = crypto.createHash('sha256').update(verifier).digest('base64url');
    if (computed !== codeEntry.codeChallenge) {
      res.status(400).json({ error: 'invalid_grant', error_description: 'code_verifier does not match code_challenge.' });
      return;
    }
  }

  authCodes.delete(code);

  const accessToken = process.env.MCP_AUTH_TOKEN!;
  // F-VM-6: crypto-random refresh token
  const newRefresh = crypto.randomBytes(32).toString('base64url');
  if (refreshTokens.size >= REFRESH_TOKENS_MAX) {
    const oldest = refreshTokens.keys().next().value;
    if (oldest) refreshTokens.delete(oldest);
  }
  refreshTokens.set(newRefresh, { accessToken, issuedAt: Date.now() });
  setTimeout(() => refreshTokens.delete(newRefresh), 24 * 24 * 3600 * 1000);

  res.json({
    access_token:  accessToken,
    token_type:    'bearer',
    expires_in:    TOKEN_TTL_SECONDS,
    refresh_token: newRefresh,
  });
});

// --- Streamable HTTP MCP endpoint --------------------------------------------
// Single /mcp endpoint handles GET (SSE stream), POST (messages), DELETE (session teardown).
// Replaces the old /sse + /message pair. Supports auto-reconnection and resumability.

app.all('/mcp', requireAuth, async (req, res) => {
  // Extract session ID from request header
  const sessionId = req.headers['mcp-session-id'] as string | undefined;

  // For existing sessions, route to the stored transport
  if (sessionId && sessions.has(sessionId)) {
    const { transport } = sessions.get(sessionId)!;
    await transport.handleRequest(req, res, req.body);
    return;
  }

  // Stale/unknown session ID handling:
  // - If this is an initialize request (client reconnecting after server restart):
  //   strip the stale ID and fall through to fresh session creation. The client
  //   receives a new session ID in the response header and continues seamlessly.
  //   This eliminates manual plugin reconnect for end users after deploys/restarts.
  // - If this is a non-initialize request with a stale ID: return 404 per MCP spec.
  //   Do NOT create a new Server+Transport — abandoned pairs leak memory.
  if (sessionId) {
    const body = req.body as Record<string, unknown>;
    const isInitialize = typeof body?.method === 'string' && body.method === 'initialize';

    if (isInitialize) {
      // Strip stale session ID so the SDK treats this as a fresh connection
      delete req.headers['mcp-session-id'];
      console.log(`[vps-control-mcp] Stale session ${sessionId} — re-initializing transparently`);
      // Fall through to fresh session creation below
    } else {
      res.status(404).json({
        jsonrpc: '2.0',
        error: { code: -32000, message: 'Session not found. Client should re-initialize.' },
        id: null,
      });
      return;
    }
  }

  // No session ID (or stale session stripped above) — only allow on POST (initialization)
  if (req.method === 'POST') {
    // F-VM-4: refuse to allocate beyond MAX_SESSIONS
    if (sessions.size >= MAX_SESSIONS) {
      console.warn(`[vps-control-mcp] Session cap reached (${sessions.size}/${MAX_SESSIONS}) — rejecting initialize`);
      res.status(503)
        .setHeader('Retry-After', '30')
        .json({
          jsonrpc: '2.0',
          error: { code: -32000, message: `Server at session capacity (${MAX_SESSIONS}). Retry in 30s.` },
          id: null,
        });
      return;
    }

    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => crypto.randomUUID(),
      eventStore,
      onsessioninitialized: (id) => {
        console.log(`[vps-control-mcp] Session initialized: ${id}`);
        sessions.set(id, { server, transport });
      },
      onsessionclosed: (id) => {
        console.log(`[vps-control-mcp] Session closed: ${id}`);
        sessions.delete(id);
      },
    });

    transport.onclose = () => {
      if (transport.sessionId) {
        sessions.delete(transport.sessionId);
      }
    };

    const server = createMcpServer();
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
    return;
  }

  // GET or DELETE without valid session → 400
  res.status(400).json({
    jsonrpc: '2.0',
    error: { code: -32000, message: 'No valid session. Send an initialize POST first.' },
    id: null,
  });
});

// --- Backwards-compatible /sse endpoint (redirect to /mcp) -------------------
// Old clients or cached Cowork configs pointing to /sse get a helpful redirect.
app.get('/sse', (_req, res) => {
  res.status(410).json({
    error: 'SSE transport removed. Use /mcp endpoint (Streamable HTTP).',
    mcp_endpoint: '/mcp',
  });
});

// --- Health check ------------------------------------------------------------

const CURRENT_VERSION = '1.6.0';

app.get('/health', async (req, res) => {
  // F-NEW-15: unauthenticated callers get a minimal response only.
  // Full diagnostics (session count, version, security config) require a valid token.
  const authenticated = await validateAuth(req);
  if (!authenticated) {
    res.json({ status: 'ok', uptime_s: Math.round(process.uptime()) });
    return;
  }

  // Check for updates from GitHub releases (cached 1 hour)
  let latestVersion: string | null = null;
  try {
    const cached = (global as Record<string, unknown>).__versionCache as { version: string; checkedAt: number } | undefined;
    if (cached && Date.now() - cached.checkedAt < 3600_000) {
      latestVersion = cached.version;
    } else {
      const resp = await fetch('https://api.github.com/repos/claudedussy/vps-control-mcp/releases/latest', {
        headers: { 'Accept': 'application/vnd.github.v3+json' },
        signal: AbortSignal.timeout(3000),
      });
      if (resp.ok) {
        const data = await resp.json() as { tag_name: string };
        latestVersion = data.tag_name?.replace(/^v/, '') || null;
        (global as Record<string, unknown>).__versionCache = { version: latestVersion, checkedAt: Date.now() };
      }
    }
  } catch { /* fail-silent — version check is best-effort */ }

  res.json({
    status:          'ok',
    uptime_s:        Math.round(process.uptime()),
    sessions:        sessions.size,
    version:         CURRENT_VERSION,
    latest_version:  latestVersion,
    update_available: latestVersion ? latestVersion !== CURRENT_VERSION : null,
    transport:       'streamable-http',
    auth_mode:       supabaseConfigured ? 'supabase' : 'single-token',
    rate_limit:      `${RATE_LIMIT_PER_MIN}/min`,
    security:        {
      three_tier_model:       'RED (hard-block) + AMBER (warning) + GREEN (allowed)',
      sensitive_file_guard:   true,
      symlink_realpath:       true,  // F-VM-2
      input_length_caps:      true,  // F-VM-3
      session_cap:            MAX_SESSIONS,  // F-VM-4
      bg_command_timeout_min: 10,    // F-VM-5
      crypto_random_tokens:   true,  // F-VM-6
      redos_shape_guard:      true,  // F-VM-7
      command_timeout_s:      30,
      per_session_custom_cap: CONFIG.MAX_CUSTOM_COMMANDS_PER_SESSION,
      loopback_redirects:     loopbackHosts.length > 0,  // true only if explicitly opted in
    },
  });
});

// --- Start -------------------------------------------------------------------

app.listen(CONFIG.PORT, () => {
  console.log('[vps-control-mcp] Running on port ' + CONFIG.PORT);
  console.log('[vps-control-mcp] Transport: Streamable HTTP (/mcp)');
  console.log('[vps-control-mcp] App dir: '        + CONFIG.APP_DIR);
  console.log('[vps-control-mcp] Audit log: '      + CONFIG.AUDIT_LOG_PATH);
});
