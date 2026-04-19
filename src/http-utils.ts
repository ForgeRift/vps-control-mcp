// HTTP helpers extracted from index.ts so tests can import them without
// triggering the side-effect of starting the Express server (app.listen at
// module top level).

import type { Request } from 'express';

/**
 * F-OP-37: Return the trusted client IP. Reads ONLY from req.ip, which Express
 * populates from X-Forwarded-For after applying the trust-proxy binding (set to
 * 'loopback' in index.ts). Never reads the raw header — doing so would let any
 * client forge a fresh IP per request and defeat per-IP rate limiting.
 *
 * Falls back to socket.remoteAddress if Express somehow couldn't resolve req.ip.
 */
export function callerIp(req: Request): string {
  return req.ip || req.socket?.remoteAddress || 'unknown';
}
