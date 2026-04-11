import type { Request } from 'express';

export function validateAuth(req: Request): boolean {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return false;

  const token = authHeader.slice(7).trim();
  const expected = process.env.MCP_AUTH_TOKEN;

  if (!token || !expected) return false;

  // Constant-time comparison to prevent timing attacks
  if (token.length !== expected.length) return false;
  let mismatch = 0;
  for (let i = 0; i < token.length; i++) {
    mismatch |= token.charCodeAt(i) ^ expected.charCodeAt(i);
  }
  return mismatch === 0;
}
