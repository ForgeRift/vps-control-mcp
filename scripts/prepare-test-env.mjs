#!/usr/bin/env node
// Generates .env.test from the committed fixture at test time.
// Rationale (F-OP-46, seventh pass): .env.test riding in the public tarball is
// a secret-leak foot-gun — a careless edit could ship developer tokens to every
// installed user. .env.test is gitignored; only .env.test.fixture is tracked,
// and its name makes its purpose unambiguous.
//
// If you need to customize test env locally, edit .env.test directly AFTER
// running `npm test` once — .env.test is regenerated each test run, so your
// changes will be overwritten. Fork the fixture if you need a persistent local
// variant.

import { copyFileSync, existsSync } from 'node:fs';
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
