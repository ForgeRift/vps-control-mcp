import express from 'express';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
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

// --- MCP Server Factory ------------------------------------------------------
// Each SSE connection gets its own Server instance.
// A single global instance throws "Already connected to a transport" on reconnect.

function createMcpServer(): Server {
  const server = new Server(
    { name: 'vps-control-mcp', version: '1.0.0' },
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
    // Expire refresh tokens after 90 days
    setTimeout(() => refreshTokens.delete(newRefresh), 90 * 24 * 3600 * 1000);

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
  // Expire refresh tokens after 90 days
  setTimeout(() => refreshTokens.delete(newRefresh), 90 * 24 * 3600 * 1000);

  // Return the customer's MCP_AUTH_TOKEN as the access token.
  // In billing mode this IS the customer's unique license key,
  // which is then validated against Supabase on every request.
  res.json({
    access_token:  accessToken,
    token_type:    'bearer',
    expires_in:    TOKEN_TTL_SECONDS,
    refresh_token: newRefresh,
  });
});

// --- MCP transport endpoints -------------------------------------------------

const transports = new Map<string, SSEServerTransport>();

app.get('/sse', requireAuth, async (req, res) => {
  const transport = new SSEServerTransport('/message', res);
  transports.set(transport.sessionId, transport);
  res.on('close', () => transports.delete(transport.sessionId));
  const server = createMcpServer();
  await server.connect(transport);
});

app.post('/message', requireAuth, async (req, res) => {
  const sessionId = req.query.sessionId as string;
  const transport = transports.get(sessionId);
  if (!transport) {
    res.status(404).json({ error: 'Session not found. Re-connect via /sse.' });
    return;
  }
  await transport.handlePostMessage(req, res, req.body);
});

// --- Health check ------------------------------------------------------------

app.get('/health', (_req, res) => {
  res.json({
    status:     'ok',
    uptime_s:   Math.round(process.uptime()),
    sessions:   transports.size,
    version:    '1.0.0',
    auth_mode:  supabaseConfigured ? 'supabase' : 'single-token',
  });
});

// --- Start -------------------------------------------------------------------

app.listen(CONFIG.PORT, () => {
  console.log('[vps-control-mcp] Running on port ' + CONFIG.PORT);
  console.log('[vps-control-mcp] App dir: '        + CONFIG.APP_DIR);
  console.log('[vps-control-mcp] Audit log: '      + CONFIG.AUDIT_LOG_PATH);
});
