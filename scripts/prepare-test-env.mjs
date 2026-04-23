#!/usr/bin/env node
// Generates .env.test from the committed fixture at test time.
// .env.test is gitignored; only .env.test.fixture is tracked.

import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(__dirname, '..');
const fixture = join(repoRoot, '.env.test.fixture');
const target = join(repoRoot, '.env.test');

if (!existsSync(fixture)) {
  console.error(`[prepare-test-env] missing fixture: ${fixture}`);
  process.exit(1);
}

copyFileSync(fixture, target);

// Cross-platform test-app directory. On Linux this is `/tmp/testapp`; on Windows
// `path.resolve` converts it to e.g. `C:\tmp\testapp`. Tests inside security.test.ts
// pass the Linux-style string `/tmp/testapp/script.js` to validateAgainstAllowlist,
// which realpaths to the absolute platform form (`C:\tmp\testapp\script.js` on
// Windows). The allowlist prefix check compares against APP_DIR, so APP_DIR in
// .env.test must ALSO be the platform-absolute form or the string prefix won't match.
const testAppDir = resolve('/tmp/testapp');
const testPm2Dir = resolve('/tmp/pm2logs');
mkdirSync(testAppDir, { recursive: true });
mkdirSync(testPm2Dir, { recursive: true });
// Stub files used in "passes" test cases
// D7: create audit log dir inside repo (only non-/tmp writable location in CI sandbox)
const testLogDir = join(repoRoot, 'logs');
mkdirSync(testLogDir, { recursive: true });
// Rewrite .env.test with platform-resolved paths for APP_DIR / PM2_LOG_DIR and the
// real AUDIT_LOG_PATH. Linux no-op (resolve('/tmp/testapp') === '/tmp/testapp');
// Windows writes the `C:\tmp\testapp` form expected by the allowlist check.
const envTest = readFileSync(target, 'utf8')
  .replace(/^APP_DIR=.*$/m,        `APP_DIR=${testAppDir}`)
  .replace(/^PM2_LOG_DIR=.*$/m,    `PM2_LOG_DIR=${testPm2Dir}`)
  .replace(/^AUDIT_LOG_PATH=.*$/m, `AUDIT_LOG_PATH=${join(testLogDir, 'mcp-audit.log')}`);
writeFileSync(target, envTest);

writeFileSync(join(testAppDir, 'out.log'), '');           // used by cat/tail/grep/sed tests
writeFileSync(join(testAppDir, 'script.js'), '// stub\n'); // used by "node script.js passes"
