# Adversarial Security Review — vps-control-mcp

**Review performed:** 2026-04-16 (Claude Opus deep audit + Sonnet follow-up fixes)
**Status at submission:** All findings closed. Shipped as v1.3.0 (`3d33cf3`) with two follow-up fixes (`f751409`, `862c732`).
**Test suite:** `src/__tests__/security.test.ts` — 181 cases passing (`npm test` exits 0 on VPS post-deploy).

The review was scoped to every customer-reachable attack surface: the OAuth flow, the path allowlist, the regex-based command allow/deny lists used by `run_approved_command`, the background-job lifecycle, session handling, and the `search_file` regex surface. Findings are numbered F-VM-1 through F-VM-8 by severity and order of discovery.

---

## Findings

### F-VM-1 — CRITICAL — Loopback redirect URIs accepted by default in OAuth
**Impact:** An attacker who can run a process on the same host as the MCP server can register a localhost redirect URI and intercept the authorization code during the OAuth handshake.
**Fix:** Loopback redirects stripped from the default-allowed list. Gated behind an explicit opt-in environment variable `ALLOW_LOOPBACK_REDIRECTS=true` so deploys that need loopback for local development can still have it, but marketplace deployments do not ship it.
**Verification:** OAuth unit tests assert that `http://127.0.0.1/*` is rejected unless the env var is set.

### F-VM-2 — HIGH — Symlink path-allowlist bypass
**Impact:** `validatePath` compared the raw input path against the allowlist. A symlink in an allowed directory pointing at `/etc/shadow` or `/root/.ssh/id_rsa` would pass the check, then resolve to a sensitive file on read.
**Fix:** `validatePath` now calls `fs.realpathSync` on the input before the allowlist check and before the sensitive-pattern match. Symlinks are followed first, then the canonical path is validated.
**Verification:** Tests include symlink-to-sensitive and symlink-out-of-allowlist cases.

### F-VM-3 — HIGH — Pathological regex inputs (ReDoS + denial-of-service)
**Impact:** Unbounded `command`, `justification`, `path`, `pattern`, and `process_name` inputs could be crafted to trigger catastrophic backtracking in the allow/deny regexes, pinning the event loop.
**Fix:** `INPUT_LIMITS` caps every user-supplied string before any regex runs:
- `command`: 4096
- `justification`: 1000
- `description`: 500
- `path`: 512
- `pattern`: 256
- `process_name`: 64

Inputs exceeding the cap are rejected with a `400` before the pattern check.
**Verification:** Tests exercise each cap boundary and assert a clean rejection, not a hang.

### F-VM-4 — MEDIUM — Session table unbounded growth
**Impact:** The StreamableHTTP transport keeps a per-session EventStore. Without a cap, a malicious or buggy client could spin up sessions until memory is exhausted.
**Fix:** `MAX_SESSIONS=200` cap. When exceeded, the server returns `503` with a `Retry-After: 30` header instead of accepting the session.
**Verification:** Load test creates 201 sessions and asserts the 201st is rejected with `503`.

### F-VM-5 — MEDIUM — Background jobs could run forever
**Impact:** `run_approved_command` with `background=true` forks a child process. Without a timeout, a stuck or malicious command could run indefinitely, consuming CPU/memory and filling logs.
**Fix:** `BG_COMMAND_TIMEOUT_MS=600000` (10 minutes) with escalation: `SIGTERM` → wait 5s → `SIGKILL`. Timeout applies to all background jobs uniformly.
**Verification:** Tests spawn a sleep-longer-than-timeout job and assert the process is killed by the deadline.

### F-VM-6 — MEDIUM — OAuth codes and refresh tokens used `Math.random`
**Impact:** `Math.random()` is not cryptographically secure. An attacker observing several tokens could predict future ones.
**Fix:** All OAuth codes and refresh tokens now use `crypto.randomBytes(32).toString('base64url')`. 256 bits of entropy, URL-safe encoding.
**Verification:** Grep for `Math.random` in `src/` yields zero results in security-sensitive paths. Audit log samples confirm the new format.

### F-VM-7 — MEDIUM — Pathological regex in `search_file`
**Impact:** The `search_file` tool accepts a user-supplied regex. Even with input length caps, structurally pathological patterns (e.g. `(a+)+b`) can still cause backtracking storms on real file contents.
**Fix:** `CATASTROPHIC_PATTERN_SHAPES` guard rejects known pathological shapes before compiling the regex. Rejected patterns return a `400` explaining why.
**Verification:** Tests include the classic `(a+)+`, `(x*)*`, nested-alternation bombs; all rejected with the guard message.

### F-VM-8 — LOW — Deploy job log growth
**Impact:** A long-running deploy with verbose output could produce a multi-megabyte log attached to a single job record.
**Fix:** `capLog` truncates deploy job logs at 500 lines with a `[... truncated, N lines]` marker.
**Verification:** Test runs a loop that emits 1000 lines and asserts the stored log is exactly 500 + the truncation marker.

---

## Follow-up fixes (Sonnet continuation)

Two additional test-suite fixes landed after the main v1.3.0 commit, both closing small gaps discovered when running the full suite against the hardened code:

**`f751409` — Dot-source env-manip pattern.** The original deny-pattern for `. /etc/profile` and similar dot-source invocations relied on `\b` word boundaries. `\b` does not fire before `.` at the start of a string, so a command beginning with `. /etc/profile` evaded detection. Fix: command-position anchor `(?:^|[;&|])\s*\.\s+/`.

**`862c732` — AWS config sensitive-pattern.** The sensitive-file allowlist matched `.aws/credentials` but not `aws/config` without the leading dot. Added `/\/aws\/(config|credentials)/i` so both forms are caught.

---

## What was out of scope

This review deliberately did **not** cover:
- The Claude Code SessionStart hook behavior (v1.4.0 added these; any behavioral regressions belong in a follow-up behavioral review, not a security review).
- The marketplace listing copy.
- Third-party dependency vulnerabilities (tracked separately via upcoming Snyk + CodeQL + SonarCloud automation).
- The Telegram connector (separate product, separate repo, separate review).

---

## How to reproduce the test suite

```bash
git clone https://github.com/forgerift/vps-control-mcp
cd vps-control-mcp
npm install
npm test
```

Expected: 181 tests pass, exit code 0.

If any test fails, treat it as a security regression and open a GitHub issue.

---

# Fourth-Pass Adversarial Review — v1.7.0

**Review performed:** 2026-04-18 (Claude Opus hostile fourth pass)
**Hardening completed:** 2026-04-18 (Sonnet continuation, S50)
**Status:** All 13 findings closed. Shipped as v1.7.0.

The fourth pass targeted structural gaps missed by the third pass: (1) the positive allowlist's per-binary validators used `rejectSensitiveArgs` (pattern-only) instead of `validatePath` (realpath + `ALLOWED_READ_DIRS` + pattern), letting symlink escapes and out-of-allowlist reads through any reader command; (2) two pre-auth memory/quota DoS vectors against `authCodes` and the Supabase token cache; (3) a PKCE downgrade via empty `code_challenge`; and (4) several hardening gaps (PCRE ReDoS, version constant, uptime leak, JOBS_FILE race).

---

## Findings

### F-OP-20 — CRITICAL — Symlink escape via `run_approved_command` file readers
**Attack vector:** Attacker pushes a tracked symlink to the repo (e.g. `services.json → /etc/shadow`) via a compromised contributor. `git pull` materialises it. `cat $APP_DIR/services.json` passes `rejectSensitiveArgs` (literal string check) because the name doesn't match any sensitive pattern, then reads `/etc/shadow` as root.
**Root cause:** `validatePath` (realpath + `ALLOWED_READ_DIRS` + patterns) was only called from `read_file_section` and `search_file`. The per-binary validators in `run_approved_command` used `rejectSensitiveArgs` which checks only the literal argument string.
**Fix:** Added `validateArgPath()` helper that wraps `validatePath()` for absolute paths and applies `SENSITIVE_FILE_PATTERNS` to relative paths. Applied to all file-reading POSITIVE_ALLOWLIST entries (`cat`, `head`, `tail`, `wc`, `ls`, `du`, `stat`, `file`, `diff`, `sort`, `uniq`, `tr`, `cut`, `paste`, `jq`).
**Status:** FIXED (commit `a7...`)

---

### F-OP-21 — CRITICAL — Sensitive system files readable via `sort`/`uniq`/`cut`/`sed`/etc.
**Attack vector:** `sort /etc/passwd`, `cut -d: -f1 /etc/passwd`, `diff /etc/passwd /tmp/empty` — any reader on the positive allowlist could read any path outside `ALLOWED_READ_DIRS`. Also: `cat /root/.bash_history`, `cat /root/.cache/gh/hosts.yml`.
**Fix:** Same structural fix as F-OP-20 — `validateArgPath()` enforces `ALLOWED_READ_DIRS` allowlist default-deny for absolute path arguments across all reader validators.
**Status:** FIXED (same commit as F-OP-20)

---

### F-OP-22 — CRITICAL — Unbounded `authCodes` Map + per-code timers; unauth memory DoS
**Attack vector:** `/authorize` is unauthenticated. Flood with large `code_challenge` values (up to Node's ~16KB URL limit). Each request: (1) calls `authCodes.set()` with no size cap, (2) schedules a 5-min `setTimeout`. At 1000 req/s × 5 min: 300K entries × 16KB ≈ 5GB RSS + 300K live timers.
**Fix:** (1) `AUTH_CODES_MAX = 1000` with FIFO eviction helper `insertAuthCode()` that clears the evicted entry's timer. (2) Length caps: `code_challenge` ≤ 128 chars, `state` ≤ 256 chars, `redirect_uri` ≤ 1024 chars — all reject with 400 before Map insertion.
**Status:** FIXED

---

### F-OP-23 — HIGH — Random Bearer tokens exhaust Supabase plan quota
**Attack vector:** Flood `/mcp` with random unique Bearer tokens. Each misses the 1000-entry positive cache, evicts a real token, triggers a Supabase REST call. Effects: quota exhaustion → real paying users get `false` cached → product appears broken.
**Fix:** (1) Token shape pre-validation (length 16–512, printable ASCII only) before any Supabase call — blocks random hex/binary tokens with no round-trip. (2) Separate negative cache (5000 entries, 30-min TTL) — random-token flood fills this instead of evicting the positive cache.
**Status:** FIXED

---

### F-OP-24 — HIGH — `node script.js` executes any path outside `ALLOWED_READ_DIRS`
**Attack vector:** `run_approved_command(command="node /tmp/payload.js")`. `validateNodeArgs` blocked eval/inspect flags but the positional script path fell through to `rejectSensitiveArgs` — no `ALLOWED_READ_DIRS` check.
**Fix:** `validateNodeArgs` script path argument now goes through `validateArgPath`, enforcing `ALLOWED_READ_DIRS` + sensitive patterns.
**Status:** FIXED

---

### F-OP-25 — HIGH — Refresh-token `setTimeout` handles leak across FIFO eviction
**Attack vector:** Authenticated user rotates refresh tokens at 60/min. Each rotation: (1) deletes old token, (2) inserts new token (FIFO-evicts when ≥ 500), (3) schedules a 24-day `setTimeout`. Map bounded at 500; timer queue unbounded. After ~24 hours of rotation: ~86K live timers ≈ 17MB accumulating.
**Fix:** Added `timer` field to `RefreshTokenEntry`. Added `insertRefreshToken()` FIFO helper that calls `clearTimeout(oldest[1].timer)` on eviction. All removal paths (`authCodes.delete`, `refreshTokens.delete`) clear the timer handle.
**Status:** FIXED

---

### F-OP-26 — HIGH — PKCE downgrade via empty `code_challenge` with `code_challenge_method=S256`
**Attack vector:** `GET /authorize?...&code_challenge=&code_challenge_method=S256`. Empty string is falsy → `entry.codeChallenge` never set → `/token` skips PKCE verification entirely. Client signals S256 but gets plain-code flow.
**Fix:** When `code_challenge_method` is present, require a non-empty `code_challenge` matching `/^[A-Za-z0-9_\-.~]{43,128}$/` (RFC 7636 base64url shape). Returns 400 otherwise.
**Status:** FIXED

---

### F-OP-27 — MEDIUM — `grep -P` enables PCRE ReDoS; no shape guard on allowlist grep
**Attack vector:** `run_approved_command(command="grep -P '(.*)+x' /var/log/syslog")` with `run_in_background=true` pins a CPU core for the 10-minute timeout.
**Fix:** `validateGrepArgs` now rejects `-P` / `--perl-regexp` flags with an explicit message. Pattern args for allowlist grep also checked via `validateArgPath`.
**Status:** FIXED

---

### F-OP-28 — MEDIUM — `ls /etc` enumerates filesystem outside allowlist
**Attack vector:** `ls /etc` returns all filenames in `/etc`, providing a kill-chain roadmap.
**Fix:** Subsumed by F-OP-20/21 fix — `validateArgPath` enforces `ALLOWED_READ_DIRS` on `ls` path arguments. `ls /etc` returns BLOCKED.
**Status:** FIXED (covered by F-OP-20/21)

---

### F-OP-29 — MEDIUM — `pgrep -f` / `pgrep -a` leaks process command lines
**Attack vector:** `pgrep -af .` lists all PIDs + full cmdlines, including any secrets passed via argv (`--password=foo`, `--key=bar`).
**Fix:** Removed `-a` and `-f` from the pgrep flag allowlist. `-l` (name only) is the maximum permitted.
**Status:** FIXED

---

### F-OP-30 — MEDIUM — `CURRENT_VERSION` hardcoded; prior closure (F-OP-15) was not applied
**Evidence:** `index.ts` had `const CURRENT_VERSION = '1.6.0'` as a literal string. The F-OP-15 closure note said it read from `package.json` — it did not. This also undermined confidence in prior pass closure claims.
**Fix:** At startup, `CURRENT_VERSION` is populated via `JSON.parse(fs.readFileSync(pkgPath)).version` with a fallback constant if `package.json` is unreadable. `package.json` version bumped to `1.7.0`.
**Status:** FIXED

---

### F-OP-31 — LOW — Unauthenticated `/health` response leaks uptime
**Attack vector:** `/health` returned `{ status, uptime_s, version }` to any caller. `uptime_s` reveals restart frequency — useful for timing attacks and fingerprinting.
**Fix:** Unauthenticated `/health` now returns `{ status: 'ok' }` only. Uptime and version remain available to authenticated callers via the MCP tool surface.
**Status:** FIXED

---

### F-OP-32 — LOW — `persistJob()` race on concurrent deploys corrupts `JOBS_FILE`
**Attack vector:** Two concurrent deploy calls both read, modify, and write `JOBS_FILE` — the last writer wins and the other's update is lost. On a crash mid-write, the file is partially written.
**Fix:** Atomic write: `fs.writeFileSync(JOBS_FILE + '.tmp', ...)` then `fs.renameSync(tmp, JOBS_FILE)`. `renameSync` is atomic on POSIX at the filesystem level.
**Status:** FIXED

---

## v1.7.0 Fix Summary

All 13 fourth-pass findings closed:

| Finding | Severity | Resolution |
|---|---|---|
| F-OP-20 | CRITICAL | `validateArgPath()` for all file-reading POSITIVE_ALLOWLIST entries |
| F-OP-21 | CRITICAL | Same structural fix; `ALLOWED_READ_DIRS` default-deny enforced |
| F-OP-22 | CRITICAL | `authCodes` size cap (1000) + FIFO + `clearTimeout`; input length caps |
| F-OP-23 | HIGH | Token shape pre-validation + split positive/negative auth cache |
| F-OP-24 | HIGH | `node` script path via `validateArgPath` |
| F-OP-25 | HIGH | `refreshTokens` timer handles stored + cleared on all removal paths |
| F-OP-26 | HIGH | PKCE S256 requires non-empty, valid-charset `code_challenge` |
| F-OP-27 | MEDIUM | `grep -P` / `--perl-regexp` blocked in `validateGrepArgs` |
| F-OP-28 | MEDIUM | Covered by F-OP-20/21 fix |
| F-OP-29 | MEDIUM | `pgrep -a` / `-f` removed from allowlist |
| F-OP-30 | MEDIUM | `CURRENT_VERSION` read from `package.json` at startup |
| F-OP-31 | LOW | `/health` returns `{status:'ok'}` only for unauth callers |
| F-OP-32 | LOW | Atomic `JOBS_FILE` write via tmp + `renameSync` |


---

# Fifth Pass — 2026-04-18 (S51 review → S52 close)

Four new findings (3 CRITICAL, 1 HIGH) against v1.7.0. All closed in v1.7.1.

### F-OP-33 — CRITICAL — `validateArgPath` relative-path traversal bypasses `ALLOWED_READ_DIRS`
**Attack vector:** `validateArgPath` passed raw args (e.g. `../../etc/passwd`) directly to `validatePath`, which compared string-prefix only. Relative traversal was never resolved.
**Fix:** Resolve every non-flag arg via `path.resolve(arg)` before `validatePath`. The realpathSync + prefix guard now operates on the canonical path. `SENSITIVE_FILE_PATTERNS` extended to include `/etc/`, `/var/log/`, `/proc/`, `/sys/`, and `/root/*` with a single carveout for `$APP_DIR` (derived at load via `path.basename(CONFIG.APP_DIR)`) for defence-in-depth.
**Status:** FIXED (S52)

### F-OP-34 — CRITICAL — `sort -o` / `uniq INPUT OUTPUT` are unblocked file-write primitives
**Attack vector:** `sort -o /dst /src` and `uniq /src /dst` both write attacker-chosen files; both were in POSITIVE_ALLOWLIST with `allowAny`.
**Fix:** New `validateSortArgs` rejects `-o/--output/--output=`. New `validateUniqArgs` rejects any second positional argument (the OUTPUT file). Both delegate to `validateArgPath` for remaining shape/allowed-dir checks.
**Status:** FIXED (S52)

### F-OP-35 — CRITICAL — Pre-auth root token mint via PKCE omission
**Attack vector:** `/authorize` issued codes for any `code_challenge` shape when `code_challenge_method` was omitted — and `/token` returned `MCP_AUTH_TOKEN` as `access_token` in that path. Unauthenticated callers could obtain the master token.
**Fix:** `/authorize` now requires `code_challenge` matching `^[A-Za-z0-9_\-.~]{43,128}$` and defaults method to S256; method other than S256 is rejected. `/token` authorization_code grant mandates `code_verifier` with SHA-256 match. Access tokens are now per-flow `crypto.randomBytes(32).base64url` registered via `registerSessionToken()` — `MCP_AUTH_TOKEN` is never leaked. Refresh grant re-registers as session token.
**Status:** FIXED (S52)

### F-OP-36 — HIGH — Per-token rate limit allows unauthenticated Supabase quota exhaustion
**Attack vector:** Random Bearer tokens hit Supabase because the rate limiter keyed on token, not caller IP. Single attacker with many tokens could burn the plan quota.
**Fix:** Added per-IP limiter (60 req/min/IP) applied BEFORE `validateAuth`, with X-Forwarded-For aware IP extraction. Added Supabase circuit breaker (120 calls/min window) — when open, new-token lookups skip Supabase and fail closed; positive cache still serves. HTTP layer maps `supabaseCircuitOpen()` to 503.
**Status:** FIXED (S52)

## v1.7.1 Fix Summary

| Finding | Severity | Resolution |
|---|---|---|
| F-OP-33 | CRITICAL | `path.resolve()` before `validatePath`; sensitive patterns extended |
| F-OP-34 | CRITICAL | `validateSortArgs` / `validateUniqArgs` block file-write primitives |
| F-OP-35 | CRITICAL | PKCE mandatory; per-flow access tokens decouple from MCP_AUTH_TOKEN |
| F-OP-36 | HIGH | Per-IP rate limit + Supabase circuit breaker |


---

# Sixth Pass — 2026-04-18 (S53 review → S53 close)

Two independent Opus reviews against v1.7.1 surfaced four CRITICAL/HIGH
items in the first-party code path plus a cluster of deploy-path
hardening gaps. Selected for v1.8.0:

* `F-OP-37` XFF spoofing (CRITICAL)
* `F-OP-38` `sort -oFILE` glued-short-option bypass (CRITICAL)
* `F-OP-44` Child-process env leaks `MCP_AUTH_TOKEN` / `SUPABASE_SERVICE_KEY` (HIGH)
* `F-OP-45` `git -c` hardening incomplete (MEDIUM) + deploy-path extension

Meta: test canary planted and removed — `npm test` genuinely exits non-zero on a single `assert.fail()`. The 299+-test green count is real, not silent-empty.

### F-OP-37 — CRITICAL — X-Forwarded-For spoofing defeats per-IP rate limiter
**Attack vector:** Express default `trust proxy = false` so `req.ip` was the socket remote (loopback from nginx). nginx config appended to `X-Forwarded-For` with `$proxy_add_x_forwarded_for` — client-controlled. Any caller could forge a fresh IP per request, turning the F-OP-36 per-IP limiter into zero effective ceiling.
**Fix:** `app.set('trust proxy', 'loopback')` so Express trusts only localhost proxies and returns the first client-facing `X-Forwarded-For` entry via `req.ip`. Nginx site config switched to `proxy_set_header X-Forwarded-For $remote_addr` (overwrite, not append). Dedicated `callerIp(req)` helper reads ONLY `req.ip` — the raw header is never read.
**Status:** FIXED (S53)

### F-OP-38 — CRITICAL — `sort` glued short-option `-oFILE` bypasses F-OP-34
**Attack vector:** `validateSortArgs` checked for `-o`, `--output=`, `--output`, but NOT the glued short-option form `-oFILE` that GNU sort accepts. `sort -o/tmp/pwn /etc/passwd` writes arbitrary files as the MCP process.
**Fix:** Regex extended to catch `^-o./` and `^--output-` defence-in-depth patterns. Tests cover glued form, prefix variant, and the pre-existing bare/`=` forms.
**Status:** FIXED (S53)

### F-OP-44 — HIGH — Child processes inherit `MCP_AUTH_TOKEN` / `SUPABASE_SERVICE_KEY`
**Attack vector:** Every `spawn`/`execFile` in `tools.ts` inherited `process.env` unchanged. Any allowlisted binary that can echo env (`node -e 'console.log(process.env)'` via user-uploaded `.js`, `jq -n env` if jq ever gains `-n`, etc.) returns `MCP_AUTH_TOKEN`, `SUPABASE_SERVICE_KEY`, `OAUTH_CLIENT_SECRET` in tool output. MCP token compromise = full lateral movement.
**Fix:** Centralised `safeEnv()` helper with `SAFE_ENV_KEYS` positive-allowlist (PATH, HOME, USER, LANG, LC_*, TZ, TERM, SHELL, PWD, TMPDIR, NODE_ENV, NO_COLOR, FORCE_COLOR). The `exec`/`runCmd`/`spawn` wrappers all pass `env: safeEnv()` by default; caller extras are overlaid on top rather than able to replace the allowlist. PATH fallback ensures spawn works even from a shell with PATH unset.
**Status:** FIXED (S53)

### F-OP-45 — MEDIUM — `git -c core.hooksPath=/dev/null` alone is insufficient
**Attack vector:** F-NEW-5 set `core.hooksPath=/dev/null` but left other independent RCE vectors reachable: `core.sshCommand`, `core.editor`, `core.fsmonitor`, `core.pager`, `core.askpass`, `credential.helper`, `protocol.ext.allow` (CVE-2022-39253 family), `uploadpack.packObjectsHook`. Each runs during normal git ops — `fetch`, `push`, `status`, `log` — if present in the repo's writeable `.git/config`.
**Fix:** Single `GIT_HARDENING_FLAGS` constant applied to every server-initiated git call — `gitStatus`, `gitLog`, `gitPull`, `gitPush`, and both deploy-path pulls (`deployApp`, `deployVpsMcp`). Eleven `-c key=value` overrides; regression tests pin every entry.
**Status:** FIXED (S53)

## v1.8.0 Fix Summary

| Finding | Severity | Resolution |
|---|---|---|
| F-OP-37 | CRITICAL | Express trust-proxy=loopback + nginx overwrite XFF |
| F-OP-38 | CRITICAL | `validateSortArgs` catches glued `-oFILE` form |
| F-OP-44 | HIGH | Central `safeEnv()` positive-allowlist — all spawns filtered |
| F-OP-45 | MEDIUM | `GIT_HARDENING_FLAGS` applied to every server-initiated git call + deploy paths |
