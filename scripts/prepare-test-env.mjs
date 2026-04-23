#!/usr/bin/env node
// Generates .env.test from the committed fixture at test time.
// .env.test is gitignored; only .env.test.fixture is tracked.

import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(__dirname, '..');
const fixture = join(repoRoot, '.env.test.fixture');
const target = join(repoRoot, '.env.test');

if (!existsSync(fixture)) {
  console.error(`[prepare-test-env] missing fixture: ${fixture}`);
  process.exit(1);
}

copyFileSync(fixture, target);

// Create the test directory structure expected by security.test.ts.
// APP_DIR in .env.test.fixture is /tmp/testapp -- the tests validate paths
// within this directory and realpathSync requires them to actually exist.
mkdirSync('/tmp/testapp_user', { recursive: true });
mkdirSync('/tmp/pm2logs', { recursive: true });
// Stub files used in "passes" test cases
// D7: create audit log dir inside repo (only non-/tmp writable location in CI sandbox)
const testLogDir = join(repoRoot, 'logs');
mkdirSync(testLogDir, { recursive: true });
// Override AUDIT_LOG_PATH in .env.test to the real absolute path
const envTest = readFileSync(target, 'utf8');
writeFileSync(target, envTest.replace(
  /^AUDIT_LOG_PATH=.*$/m,
  `AUDIT_LOG_PATH=${join(testLogDir, 'mcp-audit.log')}`
));

writeFileSync('/tmp/testapp_user/out.log', '');           // used by cat/tail/grep/sed tests
writeFileSync('/tmp/testapp_user/script.js', '// stub\n'); // used by "node script.js passes"
