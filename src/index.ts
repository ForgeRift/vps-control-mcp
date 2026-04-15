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

if (!process.env.MCP_AUTH_TOKEN) {
  console.error('FATAL: MCP_AUTH_TOKEN is not set. Refusing to start without auth.');
  process.exit(1);
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

function requireAuth(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
): void {
  if (!validateAuth(req)) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }
  next();
}

// --- OAuth 2.0 endpoints (required by Cowork to initiate connection) ---------
// Cowork always starts an OAuth flow regardless of stored bearer token.
// Minimal auth-code flow: user enters the static bearer token in a browser
// form, server issues a one-time code, Cowork exchanges it for the token.

const authCodes = new Map<string, number>();

// Step 1: Cowork opens this in a browser
app.get('/authorize', (req, res) => {
  const { redirect_uri = '', state = '', client_id = '' } = req.query as Record<string, string>;
  const html = [
    '<!DOCTYPE html>',
    '<html><head><title>VPS Control MCP</title>',
    '<style>',
    'body{font-family:-apple-system,sans-serif;max-width:420px;margin:80px auto;padding:24px}',
    'h2{margin-bottom:4px}p{color:#555;margin-bottom:20px}',
    'input[type=password]{width:100%;padding:10px;border:1px solid #ccc;border-radius:4px;',
    'box-sizing:border-box;margin-bottom:12px;font-size:14px}',
    'button{background:#0070f3;color:#fff;border:none;padding:10px 0;',
    'width:100%;border-radius:4px;font-size:15px;cursor:pointer}',
    'button:hover{background:#005cc5}',
    '</style></head><body>',
    '<h2>VPS Control MCP</h2>',
    '<p>Enter your bearer token to authorise this connection.</p>',
    '<form method="POST" action="/authorize">',
    '<input type="hidden" name="redirect_uri" value="' + redirect_uri + '">',
    '<input type="hidden" name="state" value="' + state + '">',
    '<input type="hidden" name="client_id" value="' + client_id + '">',
    '<input type="password" name="token" placeholder="Bearer token" required autofocus>',
    '<button type="submit">Authorise</button>',
    '</form></body></html>',
  ].join('\n');
  res.send(html);
});

// Step 2: form submission — validate token, redirect with code
app.post('/authorize', (req, res) => {
  const { redirect_uri, state, token } = req.body as Record<string, string>;

  if (!token || token !== process.env.MCP_AUTH_TOKEN) {
    res.status(401).send('Invalid token. Close this window and try again.');
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

// Step 3: Cowork exchanges code for access token
app.post('/token', (req, res) => {
  const { code } = req.body as Record<string, string>;

  if (!code || !authCodes.has(code)) {
    res.status(400).json({ error: 'invalid_grant' });
    return;
  }

  authCodes.delete(code);

  res.json({
    access_token: process.env.MCP_AUTH_TOKEN,
    token_type:   'bearer',
    expires_in:   3600,
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
  res.json({ status: 'ok', uptime_s: Math.round(process.uptime()), sessions: transports.size, version: '1.0.0' });
});

// --- Start -------------------------------------------------------------------

app.listen(CONFIG.PORT, () => {
  console.log('[vps-control-mcp] Running on port ' + CONFIG.PORT);
  console.log('[vps-control-mcp] App dir: ' + CONFIG.APP_DIR);
  console.log('[vps-control-mcp] Audit log: ' + CONFIG.AUDIT_LOG_PATH);
  console.log('[vps-control-mcp] Auth token: SET');
});
