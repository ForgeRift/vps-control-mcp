// Diagnostic: run the assertions most likely to fail and log which ones don't pass
// Run on VPS: node --import tsx check-failing.mjs

import { __TEST_ONLY } from './src/tools.js';

const {
  validateCommand,
  validatePath,
  SENSITIVE_FILE_PATTERNS,
  INPUT_LIMITS,
  capString,
  checkAmberWarnings,
} = __TEST_ONLY;

let pass = 0;
let fail = 0;

function check(label, fn) {
  try {
    fn();
    console.log('PASS:', label);
    pass++;
  } catch (e) {
    console.log('FAIL:', label, '|', e.message.slice(0, 120));
    fail++;
  }
}

function expectBlocked(cmd) {
  let threw = false;
  try { validateCommand(cmd); } catch (e) { threw = true; }
  if (!threw) throw new Error(`Expected "${cmd}" to be blocked but it was allowed`);
}

function expectAllowed(cmd) {
  validateCommand(cmd); // throws if blocked
}

// Check the dot-source fix
check('env-manip: . sourcing', () => expectBlocked('. /tmp/evil'));
check('env-manip: export',     () => expectBlocked('export FOO=bar'));
check('env-manip: source',     () => expectBlocked('source /tmp/evil'));

// Sensitive file pattern for aws/config (was suspected to fail)
check('sensitive: aws/config', () => {
  const p = '/root/sharpedge/aws/config';
  const matched = SENSITIVE_FILE_PATTERNS.some(rx => rx.test(p));
  if (!matched) throw new Error(`${p} not matched by any SENSITIVE_FILE_PATTERN`);
});

// INPUT_LIMITS fields
check('INPUT_LIMITS.command',       () => { if (!INPUT_LIMITS.command) throw new Error('falsy'); });
check('INPUT_LIMITS.justification', () => { if (!INPUT_LIMITS.justification) throw new Error('falsy'); });
check('INPUT_LIMITS.description',   () => { if (!INPUT_LIMITS.description) throw new Error('falsy'); });
check('INPUT_LIMITS.path',          () => { if (!INPUT_LIMITS.path) throw new Error('falsy'); });
check('INPUT_LIMITS.pattern',       () => { if (!INPUT_LIMITS.pattern) throw new Error('falsy'); });
check('INPUT_LIMITS.process_name',  () => { if (!INPUT_LIMITS.process_name) throw new Error('falsy'); });

// validateCommand with long strings
check('validateCommand: 10KB rejected', () => expectBlocked('a'.repeat(10 * 1024)));
check('validateCommand: 4096B allowed', () => expectAllowed('echo ' + 'a'.repeat(4000)));

// AMBER
check('AMBER: apt-get update dry_run=true',  () => {
  const w = checkAmberWarnings('apt-get update', true);
  if (!w || !w.includes('WARNING')) throw new Error('no warning returned');
});
check('AMBER: apt-get update dry_run=false', () => {
  const w = checkAmberWarnings('apt-get update', false);
  if (w !== null) throw new Error(`expected null, got ${w}`);
});

// info-leak: env (pattern /\benv\b$/)
check('info-leak: env',     () => expectBlocked('env'));
check('info-leak: printenv', () => expectBlocked('printenv'));
check('info-leak: /proc/',   () => expectBlocked('cat /proc/self/environ'));

// chaining
check('chaining: ;',  () => expectBlocked('ls; rm foo'));
check('chaining: &&', () => expectBlocked('ls && rm foo'));
check('chaining: ||', () => expectBlocked('ls || rm foo'));

// file-write remaining
check('file-write: redirect to ~',  () => expectBlocked('echo foo > ~/evil'));
check('file-write: append redirect', () => expectBlocked('echo foo >> log.txt'));
check('file-write: tee',            () => expectBlocked('cat foo | tee bar'));
check('file-write: symlink',        () => expectBlocked('ln -s /etc/shadow /root/x'));
check('file-write: cp to /etc',     () => expectBlocked('cp foo /etc/'));
check('file-write: mv to /usr',     () => expectBlocked('mv foo /usr/local/bin/'));

// http-server
check('http-server: python http',    () => expectBlocked('python -m http.server 8080'));
check('http-server: versioned',      () => expectBlocked('python3.11 -m http.server'));
check('http-server: php -S',         () => expectBlocked('php -S 0.0.0.0:8000'));

// priv-esc
check('priv-esc: su - root', () => expectBlocked('su - root'));
check('priv-esc: sudo id',   () => expectBlocked('sudo id'));

console.log(`\nTotal: ${pass} passed, ${fail} failed`);
process.exit(fail > 0 ? 1 : 0);
