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
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

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

// --- OAuth 2.0 endpoints (required by Cowork to initiate connection) ---------
// Cowork starts an OAuth flow on first connect. We issue long-lived tokens
// (30 days) and support refresh_token grant so Cowork can silently re-auth
// without opening a browser window every session.
//
// redirect_uri is validated against an allow-list of known Cowork/Claude
// domains. Self-hosted users can add custom origins via ALLOWED_REDIRECT_HOSTS.

const authCodes = new Map<string, number>();
const refreshTokens = new Map<string, { accessToken: string; issuedAt: number }>();

const TOKEN_TTL_SECONDS = 30 * 24 * 3600; // 30 days

// Allow-listed redirect URI hosts. Cowork/Claude domains + localhost for dev.
// Self-hosted users can extend via comma-separated env var.
const DEFAULT_REDIRECT_HOSTS = [
  'claude.ai',
  'www.claude.ai',
  'console.anthropic.com',
  'app.anthropic.com',
  'localhost',
  '127.0.0.1',
];
const customHosts = (process.env.ALLOWED_REDIRECT_HOSTS || '')
  .split(',')
  .map(h => h.trim().toLowerCase())
  .filter(Boolean);
const ALLOWED_REDIRECT_HOSTS = new Set([...DEFAULT_REDIRECT_HOSTS, ...customHosts]);

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
  const { redirect_uri = '', state = '' } = req.query as Record<string, string>;

  if (!redirect_uri) {
    res.status(400).send('Missing redirect_uri');
    return;
  }

  if (!isRedirectAllowed(redirect_uri)) {
    res.status(403).send('redirect_uri host not in allow-list. Set ALLOWED_REDIRECT_HOSTS to add custom origins.');
    return;
  }

  const code = Buffer.from(Date.now() + ':' + Math.random()).toString('base64url');
  authCodes.set(code, Date.now());
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

    const newRefresh = Buffer.from(Date.now() + ':refresh:' + Math.random()).toString('base64url');
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

  authCodes.delete(code);

  const accessToken = process.env.MCP_AUTH_TOKEN!;
  const newRefresh = Buffer.from(Date.now() + ':refresh:' + Math.random()).toString('base64url');
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

  // For new sessions (initialization POST or no session yet)
  if (req.method === 'POST') {
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

app.get('/health', (_req, res) => {
  res.json({
    status:     'ok',
    uptime_s:   Math.round(process.uptime()),
    sessions:   sessions.size,
    version:    '1.1.0',
    transport:  'streamable-http',
    auth_mode:  supabaseConfigured ? 'supabase' : 'single-token',
  });
});

// --- Start -------------------------------------------------------------------

app.listen(CONFIG.PORT, () => {
  console.log('[vps-control-mcp] Running on port ' + CONFIG.PORT);
  console.log('[vps-control-mcp] Transport: Streamable HTTP (/mcp)');
  console.log('[vps-control-mcp] App dir: '        + CONFIG.APP_DIR);
  console.log('[vps-control-mcp] Audit log: '      + CONFIG.AUDIT_LOG_PATH);
});
