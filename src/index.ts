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
// The original code used a single global mcpServer which threw:
//   "Already connected to a transport. Call close() before connecting to a new transport"
// on every reconnect, causing the Cowork disconnect loop.

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
      return {
        content: [{ type: 'text', text: result }],
      };
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

// Active transports keyed by sessionId
const transports = new Map<string, SSEServerTransport>();

// SSE connection
app.get('/sse', requireAuth, async (req, res) => {
  const transport = new SSEServerTransport('/message', res);
  transports.set(transport.sessionId, transport);

  res.on('close', () => {
    transports.delete(transport.sessionId);
  });

  const server = createMcpServer();
  await server.connect(transport);
});

// Message endpoint
app.post('/message', requireAuth, async (req, res) => {
  const sessionId = req.query.sessionId as string;
  const transport = transports.get(sessionId);

  if (!transport) {
    res.status(404).json({ error: 'Session not found. Re-connect via /sse.' });
    return;
  }

  await transport.handlePostMessage(req, res, req.body);
});

// Health check
app.get('/health', (_req, res) => {
  res.json({
    status:    'ok',
    uptime_s:  Math.round(process.uptime()),
    sessions:  transports.size,
    version:   '1.0.0',
  });
});

// --- Start -------------------------------------------------------------------

app.listen(CONFIG.PORT, () => {
  console.log('[vps-control-mcp] Running on port ' + CONFIG.PORT);
  console.log('[vps-control-mcp] App dir: ' + CONFIG.APP_DIR);
  console.log('[vps-control-mcp] Audit log: ' + CONFIG.AUDIT_LOG_PATH);
  console.log('[vps-control-mcp] Auth token: SET');
});
